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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.junit.jupiter.api.Test;

/**
 * Test class for the Usage example in Readme.md.
 * 
 * @author keve
 *
 */
public final class TestUsage {

    /** Expected score. */
    private static final int EXPECTED_SCORE = 165;

    static {
        TLSHUtil.registerProvider();
    }

    /**
     * Test case for the Usage example in Readme.md.
     * 
     * @throws NoSuchProviderException if the provider is not found
     * @throws NoSuchAlgorithmException if the hash algorithm is not found
     */
    @Test
    public void testUsage() throws NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest tlshDigest = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameK());
        tlshDigest.update("Hello world!".getBytes());
        final byte[] hash1 = tlshDigest.digest();
        final String encoded1 = TLSHUtil.encoded(hash1);
        final byte[] hash2 = tlshDigest.digest("Goodbye Cruel World".getBytes());
        final String encoded2 = TLSHUtil.encoded(hash2);
        final int score = TLSHUtil.score(hash1, hash2, false);

        assertEquals("DD6000030030000C000000000C300CC00000C000030000000000F00030F0C00300CCC0", encoded1);
        assertEquals("F87000008008000822B80080002C82A000808002800C003020000B2830202008A83A22", encoded2);
        assertEquals(EXPECTED_SCORE, score);
    }

}
