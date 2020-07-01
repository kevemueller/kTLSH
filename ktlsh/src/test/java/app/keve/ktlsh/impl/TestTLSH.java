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
package app.keve.ktlsh.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;

import app.keve.ktlsh.testutil.TestUtil;

/**
 * Test TLSH related methods.
 * 
 * @author keve
 *
 */
public class TestTLSH extends AbstractImplTest {
    /** 0b01010101. */
    private static final int BITS_55 = 0x55;
    /** 0b10101010b. */
    private static final int BITS_AA = 0xAA;
    /** 0b11111111b. */
    private static final int BITS_FF = 0xFF;

    /**
     * Test generating TLSH instance of garbage.
     */
    @Test
    public void testOfGarbage() {
        assertThrows(IllegalArgumentException.class, () -> TLSH.of(new byte[3]));
    }

    /**
     * Test TLSH.toString().
     */
    @Test
    public void testToString() {
        final TLSH tlsh = TLSH.of(new byte[32 + 2 + 1]);
        final String tlshString = tlsh.toString();
        assertNotNull(tlshString);
    }

    /**
     * Test TLSH.equals() and TLSH.hashCode().
     */
    @Test
    public void testEquals() throws NoSuchAlgorithmException {
        final byte[] buf = new byte[32 + 2 + 1];
        TestUtil.rnd().nextBytes(buf);
        final TLSH tlsh1 = TLSH.of(buf);
        final TLSH tlsh2 = TLSH.of(buf);
        assertEquals(tlsh1, tlsh1);
        assertEquals(tlsh1, tlsh2);
        assertEquals(tlsh1.hashCode(), tlsh2.hashCode());
        assertNotEquals(tlsh1, "Hello World!");
    }

    /**
     * Test TLSHDigest.of() bad windowLength.
     */
    @Test
    public void testDigestOfBadWindow() {
        assertThrows(IllegalArgumentException.class, () -> TLSHDigest.of(-1, 128, 1));
    }

    /**
     * Test TLSHDigest.toString().
     */
    @Test
    public void testDigestToString() {
        final TLSHDigest digest = TLSHDigest.of(4, 128, 1);
        digest.update((byte) 64);
        final String digestDetails = digest.toString();
        assertNotNull(digestDetails);
    }

    /**
     * Test TLSHDigest.getLag() for all algorithms.
     */
    @Test
    public void testLag() {
        final int[] windowSizes = {4, 5, 6, 7, 8};
        final int[] buckets = {128, 256};
        final int[] checksums = {1, 3};

        for (int windowSize : windowSizes) {
            for (int bucket : buckets) {
                for (int checksum : checksums) {
                    final TLSHDigest digest = TLSHDigest.of(windowSize, bucket, checksum);
                    digest.update((byte) BITS_AA); // l2
                    digest.update((byte) BITS_55); // l1
                    digest.update((byte) BITS_FF); // l0
                    final int[] lag = ((AbstractTLSHDigest) digest).getLag();
                    assertEquals(BITS_AA, lag[2]);
                    assertEquals(BITS_55, lag[1]);
                    assertEquals(BITS_FF, lag[0]);

                    final String digestStateEmpty = digest.toString();
                    assertNotNull(digestStateEmpty);
                    for (byte i = 0; i < 16; i++) {
                        digest.update(i);
                    }
                    final String digestStateNotEmpty = digest.toString();
                    assertNotNull(digestStateNotEmpty);
                }
            }
        }
    }
}
