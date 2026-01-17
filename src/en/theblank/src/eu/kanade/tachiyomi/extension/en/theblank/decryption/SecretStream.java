/*
 * crypto_secretstream_xchacha20poly1305
 * Port directo y funcional para Tachiyomi / Mihon
 *
 * Basado en libsodium
 * https://github.com/jedisct1/libsodium
 */

package eu.kanade.tachiyomi.extension.en.theblank.decryption;

import java.security.MessageDigest;
import java.util.Arrays;

public final class SecretStream {

    private static final int KEYBYTES = 32;
    private static final int NONCEBYTES = 24;
    private static final int SUBKEYBYTES = 32;
    private static final int TAGBYTES = 16;
    private static final int HEADERBYTES = 24;

    private SecretStream() {}

    /* =========================
     * INIT (cliente)
     * ========================= */
    public static byte[] initPull(State state, byte[] header, byte[] key) {
        if (key.length != KEYBYTES || header.length != HEADERBYTES) {
            throw new IllegalArgumentException("Invalid key or header size");
        }

        byte[] subKey = new byte[SUBKEYBYTES];

        // Derivar subkey con HChaCha20
        Core.hChaCha20(subKey, header, key);

        // Copiar nonce (últimos 8 bytes = contador)
        System.arraycopy(header, 16, state.nonce, 4, 8);
        Arrays.fill(state.nonce, 0, 4, (byte) 0);

        System.arraycopy(subKey, 0, state.k, 0, 32);
        Arrays.fill(subKey, (byte) 0);

        return header;
    }

    /* =========================
     * DECRYPT
     * ========================= */
    public static byte[] pull(State state, byte[] cipher) throws Exception {
        if (cipher.length < TAGBYTES) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        int mlen = cipher.length - TAGBYTES;
        byte[] message = new byte[mlen];
        byte[] tag = new byte[TAGBYTES];

        System.arraycopy(cipher, mlen, tag, 0, TAGBYTES);

        // Generar Poly1305 key
        byte[] polyKey = new byte[32];
        ChaCha20.xor(polyKey, polyKey, 32, state.nonce, state.k);

        // Verificar MAC
        Poly1305 poly = new Poly1305(polyKey);
        poly.update(cipher, 0, mlen);
        poly.update(new byte[16], 0, (16 - (mlen % 16)) % 16);
        poly.update(new byte[8], 0, 8);
        poly.update(longToBytes(mlen), 0, 8);

        byte[] computedTag = poly.finish();

        if (!MessageDigest.isEqual(tag, computedTag)) {
            throw new SecurityException("Invalid MAC");
        }

        // Decrypt
        ChaCha20.xor(message, cipher, mlen, state.nonce, state.k);

        incrementNonce(state.nonce);

        return message;
    }

    /* =========================
     * UTILS
     * ========================= */
    private static void incrementNonce(byte[] nonce) {
        for (int i = 11; i >= 4; i--) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) (v >>> (8 * i));
        }
        return b;
    }
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
        dst[offset]     = (byte) (w & 0xFF);
        dst[offset + 1] = (byte) ((w >>> 8) & 0xFF);
        dst[offset + 2] = (byte) ((w >>> 16) & 0xFF);
        dst[offset + 3] = (byte) ((w >>> 24) & 0xFF);
        dst[offset + 4] = (byte) ((w >>> 32) & 0xFF);
        dst[offset + 5] = (byte) ((w >>> 40) & 0xFF);
        dst[offset + 6] = (byte) ((w >>> 48) & 0xFF);
        dst[offset + 7] = (byte) ((w >>> 56) & 0xFF);
    }
}
