/*
 * Portions of this software are derived from libsodium.
 * Source: https://github.com/jedisct1/libsodium
 * Copyright (c) 2013-2024 Frank Denis <j at pureftpd dot org>
 * 
 * Based on crypto_secretstream_xchacha20poly1305.c
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

        // Derive subkey using HChaCha20
        Core.HCaCha20(state.k, header, key, null);
        
        // Reset counter to 1
        counterReset(state);
        
        // Copy nonce from header[16..23]
        System.arraycopy(header, 16, state.nonce, 4, 8);

        // Clear padding
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
        // Check minimum size
        if (inlen < ABYTES) {
            android.util.Log.e("SecretStream", "Input too short: " + inlen + " bytes");
            return null;
        }

        // mlen = length without MAC (includes encrypted tag byte)
        long mlen = inlen - 16;
        
        android.util.Log.d("SecretStream", "Input length: " + inlen);
        android.util.Log.d("SecretStream", "Message+tag length: " + mlen);
        
        // Compute Poly1305 MAC
        Poly1305.State poly1305State = new Poly1305.State();
        byte[] block = new byte[64];
        byte[] slen = new byte[8];
        byte[] mac = new byte[16];

        // Generate Poly1305 key using ChaCha20 with counter=0
        Arrays.fill(block, (byte) 0);
        ChaCha20.streamIETF(block, 64, state.nonce, state.k);
        
        // Debug: Show the Poly1305 key
        android.util.Log.d("SecretStream", "Poly1305 key: " + bytesToHex(Arrays.copyOf(block, 32)));
        
        Poly1305.init(poly1305State, block);
        
        // Process additional data if present
        if (ad != null && adlen > 0) {
            Poly1305.update(poly1305State, ad, 0, adlen);
            int padlen = (16 - (adlen & 15)) & 15;
            if (padlen > 0) {
                Poly1305.update(poly1305State, PAD0, 0, padlen);
            }
        }

        // Authenticate the ciphertext directly (all mlen bytes)
        // This is different from what I had before - we authenticate ALL the ciphertext
        Poly1305.update(poly1305State, in, 0, (int) mlen);
        
        android.util.Log.d("SecretStream", "Authenticating " + mlen + " bytes of ciphertext (including tag)");
        android.util.Log.d("SecretStream", "First 32 bytes: " + bytesToHex(Arrays.copyOfRange(in, 0, Math.min(32, (int) mlen))));

        // Padding
        int padlen = (int) ((16 - (mlen & 15)) & 15);
        android.util.Log.d("SecretStream", "Ciphertext length: " + mlen + ", padding: " + padlen);
        if (padlen > 0) {
            Poly1305.update(poly1305State, PAD0, 0, padlen);
        }

        // Lengths
        store64_le(slen, 0, ad != null ? adlen : 0);
        Poly1305.update(poly1305State, slen, 0, 8);
        android.util.Log.d("SecretStream", "AD length: " + bytesToHex(slen));
        
        store64_le(slen, 0, mlen);
        Poly1305.update(poly1305State, slen, 0, 8);
        android.util.Log.d("SecretStream", "Ciphertext length: " + bytesToHex(slen));

        // Finalize MAC
        Poly1305.finalizeMAC(poly1305State, mac);

        // Get stored MAC
        byte[] storedMac = Arrays.copyOfRange(in, (int) mlen, (int) mlen + 16);

        // Debug
        android.util.Log.d("SecretStream", "Computed MAC: " + bytesToHex(mac));
        android.util.Log.d("SecretStream", "Stored MAC:   " + bytesToHex(storedMac));

        // Verify MAC
        if (!constantTimeCompare(mac, storedMac)) {
            android.util.Log.e("SecretStream", "MAC verification FAILED!");
            
            // Debug: Let's check what we're authenticating
            android.util.Log.d("SecretStream", "Nonce: " + bytesToHex(state.nonce));
            android.util.Log.d("SecretStream", "Key (first 16): " + bytesToHex(Arrays.copyOf(state.k, 16)));
            android.util.Log.d("SecretStream", "Encrypted tag: 0x" + String.format("%02x", in[0]));
            
            return null;
        }
        
        android.util.Log.d("SecretStream", "MAC verification SUCCESS!");

        // Decrypt using counter=1
        byte[] out = new byte[(int) mlen];
        ChaCha20.streamIETFXorIC(out, in, (int) mlen, state.nonce, 1, state.k);

        // Extract tag
        byte tag = out[0];
        android.util.Log.d("SecretStream", "Decrypted tag: 0x" + String.format("%02x", tag));
        
        // Extract message
        byte[] m = new byte[(int) mlen - 1];
        System.arraycopy(out, 1, m, 0, (int) mlen - 1);

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

    private void counterReset(State state) {
        state.nonce[0] = 1;
        for (int i = 1; i < 4; i++) {
            state.nonce[i] = 0;
        }
    }

    private void rekey(State state) {
        byte[] newKeyAndInonce = new byte[40];

        System.arraycopy(state.k, 0, newKeyAndInonce, 0, 32);
        System.arraycopy(state.nonce, 4, newKeyAndInonce, 32, 8);

        ChaCha20.streamIETFXorIC(newKeyAndInonce, newKeyAndInonce, 40, state.nonce, 0, state.k);

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
