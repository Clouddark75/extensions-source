package eu.kanade.tachiyomi.extension.en.theblank.decryption;

import java.security.MessageDigest;
import java.util.Arrays;

public final class SecretStream {

    public static final int TAG_MESSAGE = 0;
    public static final int TAG_FINAL = 3;

    private static final int KEYBYTES = 32;
    private static final int NONCEBYTES = 24;
    private static final int TAGBYTES = 16;

    public static final class Result {
        public final byte[] message;
        public final byte tag;

        Result(byte[] message, byte tag) {
            this.message = message;
            this.tag = tag;
        }
    }

    public SecretStream() {
    }

    /* =========================
     * INIT
     * ========================= */
    public int initPull(State state, byte[] header, byte[] key) {
        if (key.length != KEYBYTES || header.length != NONCEBYTES) {
            return -1;
        }

        byte[] subKey = new byte[32];
        Core.hChaCha20(subKey, header, key);

        Arrays.fill(state.nonce, (byte) 0);
        System.arraycopy(header, 16, state.nonce, 4, 8);

        System.arraycopy(subKey, 0, state.k, 0, 32);
        Arrays.fill(subKey, (byte) 0);

        return 0;
    }

    /* =========================
     * DECRYPT
     * ========================= */
    public Result pull(State state, byte[] cipher, int cipherLen) throws Exception {
        if (cipherLen < TAGBYTES) {
            return null;
        }

        int msgLen = cipherLen - TAGBYTES;
        byte[] msg = new byte[msgLen];
        byte[] mac = new byte[TAGBYTES];

        System.arraycopy(cipher, msgLen, mac, 0, TAGBYTES);

        // Poly1305 key
        byte[] polyKey = new byte[32];
        ChaCha20.xor(polyKey, polyKey, 32, state.nonce, state.k);

        Poly1305 poly = new Poly1305(polyKey);
        poly.update(cipher, 0, msgLen);
        poly.update(new byte[16], 0, (16 - msgLen % 16) % 16);
        poly.update(new byte[8], 0, 8);
        poly.update(longToBytes(msgLen), 0, 8);

        byte[] computed = poly.finish();

        if (!MessageDigest.isEqual(mac, computed)) {
            throw new SecurityException("Invalid MAC");
        }

        ChaCha20.xor(msg, cipher, msgLen, state.nonce, state.k);
        incrementNonce(state.nonce);

        byte tag = TAG_MESSAGE;
        if (msgLen == 0) {
            tag = TAG_FINAL;
        }

        return new Result(msg, tag);
    }

    /* =========================
     * NONCE++
     * ========================= */
    private static void incrementNonce(byte[] nonce) {
        for (int i = 11; i >= 4; i--) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }

    private static byte[] longToBytes(long v) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (v >>> (8 * i));
        }
        return out;
    }
}
