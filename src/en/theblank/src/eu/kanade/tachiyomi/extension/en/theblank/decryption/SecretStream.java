/*
 * Portions of this software are derived from libsodium.
 * Source: https://github.com/jedisct1/libsodium
 * Copyright (c) 2013-2024 Frank Denis <j at pureftpd dot org>
 */

package eu.kanade.tachiyomi.extension.en.theblank.decryption;

import java.util.Arrays;

public class SecretStream {
    // Constants  
    public static final int ABYTES = 17; // 1 byte tag + 16 bytes MAC
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
        // Minimum: 0 bytes message + 1 byte tag + 16 bytes MAC = 17 bytes
        if (inlen < 17) {
            android.util.Log.e("SecretStream", "Input too short: " + inlen + " bytes");
            return null;
        }

        // mlen_p = inlen - ABYTES = inlen - 17, but we need message length without tag
        // So: mlen = inlen - 16 (MAC) - 1 (tag) = inlen - 17
        // But the ciphertext includes the tag, so clen = inlen - 16
        long mlen_max = inlen - 16; // This includes the encrypted tag byte
        
        android.util.Log.d("SecretStream", "Input length: " + inlen);
        android.util.Log.d("SecretStream", "Ciphertext length (with tag): " + mlen_max);
        
        // Initialize Poly1305
        Poly1305.State poly1305State = new Poly1305.State();
        byte[] block = new byte[64];
        byte[] slen = new byte[8];
        byte[] mac = new byte[16];

        // Generate Poly1305 key from ChaCha20 block 0
        ChaCha20.streamIETF(block, 64, state.nonce, state.k);
        Poly1305.init(poly1305State, block);
        Arrays.fill(block, (byte) 0);

        // Process AD if exists
        if (ad != null && adlen > 0) {
            Poly1305.update(poly1305State, ad, 0, adlen);
            int padlen = (16 - (adlen % 16)) % 16;
            if (padlen > 0) {
                Poly1305.update(poly1305State, PAD0, 0, padlen);
            }
        }

        // Put encrypted tag in block[0]
        block[0] = in[0];
        
        // Authenticate the 64-byte block (with encrypted tag in position 0, rest zeros)
        Poly1305.update(poly1305State, block, 0, 64);

        // Authenticate remaining ciphertext (everything after first byte, before MAC)
        long remaining = mlen_max - 1;
        if (remaining > 0) {
            Poly1305.update(poly1305State, in, 1, (int)remaining);
        }
        
        // Padding for (64 + remaining)
        long totalLen = 64 + remaining;
        int padlen = (int) ((16 - (totalLen % 16)) % 16);
        if (padlen > 0) {
            Poly1305.update(poly1305State, PAD0, 0, padlen);
        }

        // Add lengths: AD length, then ciphertext length
        store64_le(slen, 0, ad != null ? adlen : 0);
        Poly1305.update(poly1305State, slen, 0, 8);
        store64_le(slen, 0, totalLen);
        Poly1305.update(poly1305State, slen, 0, 8);

        // Finalize MAC
        Poly1305.finalizeMAC(poly1305State, mac);

        // Extract stored MAC (last 16 bytes)
        byte[] storedMac = Arrays.copyOfRange(in, (int)mlen_max, inlen);

        // Debug output
        android.util.Log.d("SecretStream", "Computed MAC: " + bytesToHex(mac));
        android.util.Log.d("SecretStream", "Stored MAC:   " + bytesToHex(storedMac));

        // Verify MAC
        if (!constantTimeCompare(mac, storedMac)) {
            android.util.Log.e("SecretStream", "MAC verification FAILED!");
            return null;
        }
        
        android.util.Log.d("SecretStream", "MAC verification SUCCESS!");

        // Decrypt the ciphertext (tag + message) using counter = 1
        byte[] out = new byte[(int)mlen_max];
        ChaCha20.streamIETFXorIC(out, in, (int)mlen_max, state.nonce, 1, state.k);

        // First byte is the decrypted tag
        byte tag = out[0];
        android.util.Log.d("SecretStream", "Decrypted tag: 0x" + String.format("%02x", tag));
        
        // Rest is the actual message (everything after the tag)
        byte[] m = Arrays.copyOfRange(out, 1, (int)mlen_max);

        // XOR inonce with MAC
        for (int i = 0; i < 8; i++) {
            state.nonce[4 + i] ^= storedMac[i];
        }

        // Increment counter
        incrementCounter(state);

        // Rekey if needed
        if ((tag & TAG_REKEY) != 0 || isCounterZero(state)) {
            android.util.Log.d("SecretStream", "Rekeying...");
            rekey(state);
        }

        return new PullResult(m, tag);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString().trim();
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

        // XOR with ChaCha20 stream (counter = 0)
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
