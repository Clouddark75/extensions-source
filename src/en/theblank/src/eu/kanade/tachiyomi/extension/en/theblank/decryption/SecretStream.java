/*
 * Portions of this software are derived from libsodium.
 * Source: https://github.com/jedisct1/libsodium
 * Copyright (c) 2013-2024 Frank Denis <j at pureftpd dot org>
 */

package eu.kanade.tachiyomi.extension.en.theblank.decryption;

import java.util.Arrays;

public class SecretStream {
    // Constants
    public static final int ABYTES = 16; // MAC only (tag byte is handled separately)
    public static final int TAG_MESSAGE = 0x00;
    public static final int TAG_PUSH = 0x01;
    public static final int TAG_REKEY = 0x02;
    public static final int TAG_FINAL = TAG_PUSH | TAG_REKEY; // 0x03

    private static final byte[] PAD0 = new byte[16];

    public static class PullResult {
        public byte[] message;
        public byte tag;

        public PullResult(byte[] message, byte tag) {
            this.message = message;
            this.tag = tag;
        }
    }

    // crypto_secretstream_xchacha20poly1305_init_pull
    public int initPull(State state, byte[] header, byte[] key) {
        if (header.length < 24) {
            return -1;
        }
        if (key.length != 32) {
            return -1;
        }

        Core.HCaCha20(state.k, header, key, null);
        counterReset(state);
        System.arraycopy(header, 16, state.nonce, 4, 8);

        for (int i = 0; i < state._pad.length; i++) {
            state._pad[i] = 0;
        }

        return 0;
    }

    // crypto_secretstream_xchacha20poly1305_pull
    public PullResult pull(State state, byte[] in, int inlen) {
        return pull(state, in, inlen, null, 0);
    }

    public PullResult pull(State state, byte[] in, int inlen, byte[] ad, int adlen) {
        // Formato: tag(1) + encrypted_data + MAC(16)
        // Tamaño mínimo: 1 + 0 + 16 = 17 bytes
        if (inlen < 17) {
            return null; // message too short
        }

        // Extraer componentes
        byte encryptedTag = in[0];
        long mlen = inlen - 1 - 16; // Resto después de quitar tag y MAC
        
        // Inicializar Poly1305
        Poly1305.State poly1305State = new Poly1305.State();
        byte[] block = new byte[64];
        byte[] slen = new byte[8];
        byte[] mac = new byte[16];

        // Generar clave Poly1305 desde ChaCha20
        ChaCha20.streamIETF(block, 64, state.nonce, state.k);
        Poly1305.init(poly1305State, block);
        Arrays.fill(block, (byte) 0);

        // Procesar AD si existe
        if (ad != null && adlen > 0) {
            Poly1305.update(poly1305State, ad, 0, adlen);
            int padlen = (16 - (adlen % 16)) % 16;
            if (padlen > 0) {
                Poly1305.update(poly1305State, PAD0, 0, padlen);
            }
        }

        // Desencriptar el tag
        Arrays.fill(block, (byte) 0);
        block[0] = encryptedTag;
        ChaCha20.streamIETFXorIC(block, block, 64, state.nonce, 1, state.k);
        byte tag = block[0];
        
        // Volver a encriptar para el MAC (necesitamos el tag encriptado)
        block[0] = encryptedTag;
        Poly1305.update(poly1305State, block, 0, 64);

        // Procesar ciphertext si existe
        if (mlen > 0) {
            byte[] c = Arrays.copyOfRange(in, 1, 1 + (int) mlen);
            Poly1305.update(poly1305State, c, 0, (int) mlen);
        }

        // Padding del total (64 + mlen)
        long totalAuthLen = 64 + mlen;
        int padlen = (int) ((16 - (totalAuthLen % 16)) % 16);
        if (padlen > 0) {
            Poly1305.update(poly1305State, PAD0, 0, padlen);
        }

        // Longitudes
        store64_le(slen, 0, ad != null ? adlen : 0);
        Poly1305.update(poly1305State, slen, 0, 8);
        store64_le(slen, 0, 64 + mlen);
        Poly1305.update(poly1305State, slen, 0, 8);

        // Calcular MAC
        Poly1305.finalizeMAC(poly1305State, mac);

        // Verificar MAC (últimos 16 bytes)
        int macStart = 1 + (int) mlen;
        byte[] storedMac = Arrays.copyOfRange(in, macStart, macStart + 16);
        if (!constantTimeCompare(mac, storedMac)) {
            Arrays.fill(mac, (byte) 0);
            return null; // Autenticación fallida
        }

        // Desencriptar mensaje
        byte[] m = new byte[(int) mlen];
        if (mlen > 0) {
            byte[] c = Arrays.copyOfRange(in, 1, 1 + (int) mlen);
            ChaCha20.streamIETFXorIC(m, c, (int) mlen, state.nonce, 2, state.k);
        }

        // XOR inonce con MAC
        for (int i = 0; i < 8; i++) {
            state.nonce[4 + i] ^= mac[i];
        }

        // Incrementar contador
        incrementCounter(state);

        // Verificar si necesita rekey
        if ((tag & TAG_REKEY) != 0 || isCounterZero(state)) {
            rekey(state);
        }

        return new PullResult(m, tag);
    }

    // _crypto_secretstream_xchacha20poly1305_counter_reset
    private void counterReset(State state) {
        for (int i = 0; i < 4; i++) {
            state.nonce[i] = 0;
        }
        state.nonce[0] = 1;
    }

    // crypto_secretstream_xchacha20poly1305_rekey
    private void rekey(State state) {
        byte[] newKeyAndInonce = new byte[32 + 8];

        // Copy current key and inonce
        System.arraycopy(state.k, 0, newKeyAndInonce, 0, 32);
        System.arraycopy(state.nonce, 4, newKeyAndInonce, 32, 8);

        // XOR with ChaCha20 stream
        ChaCha20.streamIETFXorIC(newKeyAndInonce, newKeyAndInonce, 40, state.nonce, 0, state.k);

        // Update state
        System.arraycopy(newKeyAndInonce, 0, state.k, 0, 32);
        System.arraycopy(newKeyAndInonce, 32, state.nonce, 4, 8);

        counterReset(state);
    }

    private void incrementCounter(State state) {
        int carry = 1;
        for (int i = 0; i < 4; i++) {
            int val = (state.nonce[i] & 0xFF) + carry;
            state.nonce[i] = (byte) val;
            carry = val >> 8;
            if (carry == 0) break;
        }
    }

    private boolean isCounterZero(State state) {
        for (int i = 0; i < 4; i++) {
            if (state.nonce[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private boolean constantTimeCompare(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    private void store64_le(byte[] dst, int offset, long w) {
        dst[offset] = (byte) (w & 0xFF);
        dst[offset + 1] = (byte) ((w >>> 8) & 0xFF);
        dst[offset + 2] = (byte) ((w >>> 16) & 0xFF);
        dst[offset + 3] = (byte) ((w >>> 24) & 0xFF);
        dst[offset + 4] = (byte) ((w >>> 32) & 0xFF);
        dst[offset + 5] = (byte) ((w >>> 40) & 0xFF);
        dst[offset + 6] = (byte) ((w >>> 48) & 0xFF);
        dst[offset + 7] = (byte) ((w >>> 56) & 0xFF);
    }
}
