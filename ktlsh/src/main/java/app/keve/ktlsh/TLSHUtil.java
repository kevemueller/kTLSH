/*
 * Copyright 2020 Keve Müller
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.keve.ktlsh;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.ServiceLoader;

import app.keve.ktlsh.impl.TLSH;
import app.keve.ktlsh.spi.KProvider;
import app.keve.ktlsh.spi.TMProvider;

public final class TLSHUtil {
    private TLSHUtil() {
    }

    /**
     * Obtain the name of the K provider.
     * 
     * @return the name of the K provider.
     */
    public static String providerNameK() {
        return KProvider.NAME;
    }

    /**
     * Obtain the name of the TM provider.
     * 
     * @return the name of the TM provider.
     */
    public static String providerNameTM() {
        return TMProvider.NAME;
    }

    /**
     * Dynamically register the K and TM providers.
     */
    public static void registerProviders() {
        ServiceLoader<Provider> sl = ServiceLoader.load(java.security.Provider.class);
        for (Provider p : sl) {
            if (p.getName().equals(KProvider.NAME) || p.getName().equals(TMProvider.NAME)) {
                Security.addProvider(p);
            }
        }
    }

    /**
     * Convert a sequence of hex characters to a buffer of bytes.
     * 
     * @param hex the hex string
     * @return the byte buffer
     */
    public static byte[] hexToBytes(final CharSequence hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Lookup table for lower case hex characters.
     */
    private static final byte[] HEX_LC = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    /**
     * Lookup table for upper case hex characters.
     */
    private static final byte[] HEX_UC = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    /**
     * Convert a byte buffer to lower case hex character string.
     * 
     * @param bytes the buffer
     * @return the hex string
     */
    public static String bytesToHex(final byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_LC[v >>> 4];
            hexChars[j * 2 + 1] = HEX_LC[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * Convert a byte buffer to upper case hex character string.
     * 
     * @param bytes the buffer
     * @return the hex string
     */
    public static String bytesToHEX(final byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_UC[v >>> 4];
            hexChars[j * 2 + 1] = HEX_UC[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * Encode the buffer representation of the TLSH hash.
     * 
     * @param hash the TLSH hash in buffer representation.
     * @return the TLSH hash in hexadecimal string representation.
     */
    public static String encoded(final byte[] hash) {
        return bytesToHEX(hash);
    }

    /**
     * Encode the buffer representation of the TLSH hash with version prefix.
     * 
     * @param hash the TLSH hash in buffer representation.
     * @return the TLSH hash in hexadecimal string representation with version
     *         prefix.
     */
    public static String encodedT1(final byte[] hash) {
        return "T1" + bytesToHEX(hash);
    }

    /**
     * Score two TLSH hashes in buffer representation.
     * 
     * @param hash1   the TLSH hash in buffer representation.
     * @param hash2   the TLSH hash in buffer representation.
     * @param lenDiff true, if the length difference should be scored.
     * @return the score value.
     */
    public static int score(final byte[] hash1, final byte[] hash2, final boolean lenDiff) {
        return TLSH.of(hash1).score(TLSH.of(hash2), lenDiff);
    }
}
