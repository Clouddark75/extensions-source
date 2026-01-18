/*
 * Portions of this software are derived from libsodium.
 * Source: https://github.com/jedisct1/libsodium
 * Copyright (c) 2013-2024 Frank Denis
 */

package eu.kanade.tachiyomi.extension.en.theblank.decryption;

import java.util.Arrays;

public class SecretStream {

    // === CONSTANTES ===
    public static final int ABYTES = 17; // 1 tag + 16 MAC
    public static final int TAG_MESSAGE = 0x00;
    public static final int TAG_PUSH = 0x01;
    public static final int TAG_REKEY = 0x02;
    public static final int TAG_FINAL = TAG_PUSH | TAG_REKEY; // 0x03

    private static final byte[] PAD0 = new byte[16];

    // === RESULTADO ===
    public static final class PullResult {
        public final byte[] message;
        public final byte tag;
        public final int consumed;

        public PullResult(byte[] message, byte tag, int consumed) {
            this.message = message;
            this.tag = tag;
            this.consumed = consumed;
        }
    }

    // === INIT ===
    // crypto_secretstream_xchacha20poly1305_init_pull
    public int initPull(State state, byte[] header, byte[] key) {
        if (header.length < 24 || key.length != 32) {
            return -1;
        }

        Core.HChaCha20(state.k, header, key, null);
        counterReset(state);
        System.arraycopy(header, 16, state.nonce, 4, 8);
        Arrays.fill(state._pad, (byte) 0);

        return 0;
    }

    // === PULL (FRAME ÚNICO) ===
    // IMPORTANTE: `in` debe ser EXACTAMENTE UN FRAME
    public PullResult pull(State state, byte[] in, int inlen) {

        if (inlen < ABYTES) {
            return null;
        }

        final int mlen = inlen - ABYTES;

        // --- Poly1305 init ---
        Poly1305.State poly = new Poly1305.State();
        byte[] block = new byte[64];
        byte[] mac = new byte[16];
        byte[] slen = new byte[8];

        ChaCha20.streamIETF(block, 64, state.nonce, state.k);
        Poly1305.init(poly, block);
        Arrays.fill(block, (byte) 0);

        // --- TAG ---
        block[0] = in[0];
        ChaCha20.streamIETFXorIC(block, block, 64, state.nonce, 1, state.k);
        byte tag = block[0];

        block[0] = in[0];
        Poly1305.update(poly, block, 0, 64);

        // --- CIPHERTEXT ---
        byte[] c = Arrays.copyOfRange(in, 1, 1 + mlen);
        Poly1305.update(poly, c, 0, mlen);

        // --- PAD ---
        int padLen = (int) ((0x10 - ((64 + mlen) & 0x0F)) & 0x0F);
        if (padLen > 0) {
            Poly1305.update(poly, PAD0, 0, padLen);
        }

        // --- LENGTHS ---
        store64_le(slen, 0, 0);           // adlen = 0
        Poly1305.update(poly, slen, 0, 8);
        store64_le(slen, 0, 64 + mlen);
        Poly1305.update(poly, slen, 0, 8);

        Poly1305.finalizeMAC(poly, mac);

        // --- VERIFY MAC ---
        int macOffset = 1 + mlen;
        for (int i = 0; i < 16; i++) {
            if (mac[i] != in[macOffset + i]) {
                return null;
            }
        }

        // --- DECRYPT ---
        byte[] message = new byte[mlen];
        ChaCha20.streamIETFXorIC(
            message,
            c,
            mlen,
            state.nonce,
            2,
            state.k
        );

        // --- UPDATE NONCE ---
        for (int i = 0; i < 8; i++) {
            state.nonce[4 + i] ^= mac[i];
        }

        incrementCounter(state);

        if ((tag & TAG_REKEY) != 0 || isCounterZero(state)) {
            rekey(state);
        }

        return new PullResult(message, tag, inlen);
    }

    // === INTERNALS ===
    private void counterReset(State state) {
        Arrays.fill(state.nonce, 0, 4, (byte) 0);
        state.nonce[0] = 1;
    }

    private void incrementCounter(State state) {
        for (int i = 0; i < 4; i++) {
            int v = (state.nonce[i] & 0xff) + 1;
            state.nonce[i] = (byte) v;
            if (v <= 0xff) break;
        }
    }

    private boolean isCounterZero(State state) {
        for (int i = 0; i < 4; i++) {
            if (state.nonce[i] != 0) return false;
        }
        return true;
    }

    private void rekey(State state) {
        byte[] buf = new byte[40];
        System.arraycopy(state.k, 0, buf, 0, 32);
        System.arraycopy(state.nonce, 4, buf, 32, 8);

        ChaCha20.streamIETFXorIC(buf, buf, 40, state.nonce, 0, state.k);

        System.arraycopy(buf, 0, state.k, 0, 32);
        System.arraycopy(buf, 32, state.nonce, 4, 8);

        counterReset(state);
    }

    private static void store64_le(byte[] dst, int off, long v) {
        for (int i = 0; i < 8; i++) {
            dst[off + i] = (byte) (v >>> (8 * i));
        }
    }
}
