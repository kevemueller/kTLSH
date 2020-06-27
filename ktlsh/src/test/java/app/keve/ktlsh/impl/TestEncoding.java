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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.trendmicro.tlsh.Tlsh;
import com.trendmicro.tlsh.TlshCreator;

import app.keve.ktlsh.TLSHUtil;
import app.keve.ktlsh.testutil.Util;

/**
 * Test the packing and unpacking of TLSH hashes.
 * 
 * @author keve
 *
 */
public final class TestEncoding {
    /** KiB multiplier. */
    private static final int KIB = 1024;

    private static final class SampleData {
        /** random byte buffer. */
        public final byte[] buf;
        /** TM TLSH hash of the byte buffer. */
        public final Tlsh hash;
        /** TM TLSH encoded hash of the byte buffer. */
        public final String expectedEncodedHash;

        private SampleData(final byte[] buf, final Tlsh hash, final String expectedEncodedHash) {
            this.buf = buf;
            this.hash = hash;
            this.expectedEncodedHash = expectedEncodedHash;
        }

        public static SampleData of(final byte[] buf, final Tlsh hash, final String expectedEncodedHash) {
            return new SampleData(buf, hash, expectedEncodedHash);
        }
    }

    /** Random sample byte buffers with reference implementation hash results. */
    private static final SampleData[] SAMPLE_DATA;
    /** Curated list of hash metadata values. */
    private static final List<TLSH> SAMPLE_TLSH;

    static {
        TLSHUtil.registerProvider();
        try {
            final SecureRandom rnd = Util.rnd();
            SAMPLE_DATA = new SampleData[256];
            final TlshCreator tmTLSH = new TlshCreator();
            for (int i = 0; i < SAMPLE_DATA.length; i++) {
                final byte[] buf = new byte[16 * KIB + rnd.nextInt(64 * KIB)];
                rnd.nextBytes(buf);
                tmTLSH.update(buf);
                final Tlsh hash = tmTLSH.getHash();
                SAMPLE_DATA[i] = SampleData.of(buf, hash, hash.getEncoded());
                tmTLSH.reset();
            }
            final int[][] checksums = new int[][] {{0}, {0x55}, {0xAA}, {0xFF}, {0, 0, 0}, {0xFF, 0xFF, 0xFF},
                    {0xAA, 0x55, 0xAA}, {0x55, 0xAA, 0x55}};
            final Supplier<Stream<int[]>> sChecksum = () -> Stream.of(checksums);
            final Supplier<Stream<Integer>> sLvalue = () -> Stream.of(0, 1, 128 - 1, 128, 255);
            final Supplier<Stream<Integer>> sQ1 = () -> IntStream.range(0, 16).boxed();
            final Supplier<Stream<Integer>> sQ2 = () -> IntStream.range(0, 16).boxed();
            final int[] codes = new int[32];
            final Stream<TLSH> st = sChecksum.get()
                    .flatMap(checksum -> sLvalue.get().flatMap(lvalue -> sQ1.get().flatMap(q1 -> sQ2.get().map(q2 -> {
                        return TLSH.of(checksum, lvalue, q1, q2, codes);
                    }))));
            SAMPLE_TLSH = st.collect(Collectors.toList()); // size: 10240 elements

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Test for random sample data.
     * 
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException if the provider cannot be found
     */
    @Test
    public void testSampleData() throws NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest md = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameK());
        for (SampleData sd : SAMPLE_DATA) {
            final byte[] kHash = md.digest(sd.buf);
            md.reset();

            final TLSH kTLSHfromBuf = TLSH.of(kHash);
            final TLSH kTLSHfromHex = TLSH.of(TLSHUtil.hexToBytes(sd.expectedEncodedHash));
            final TLSH kTLSHfromParam = TLSH.of(TMTestUtil.getChecksum(sd.hash), TMTestUtil.getLvalue(sd.hash),
                    TMTestUtil.getQ1ratio(sd.hash), TMTestUtil.getQ2ratio(sd.hash), TMTestUtil.getCodes(sd.hash));

            assertEquals(sd.expectedEncodedHash, TLSHUtil.encoded(kHash));
            assertEquals(sd.expectedEncodedHash, TLSHUtil.encoded(kTLSHfromBuf.pack()));
            assertEquals(kTLSHfromBuf, kTLSHfromHex);
            assertEquals(kTLSHfromBuf, kTLSHfromParam);
        }
    }

    /**
     * Test for a curated list of hashes.
     * 
     * @param tlsh the hash
     */
    @ParameterizedTest(name = "{index}")
    @MethodSource("sampleTLSH")
    public void testSampleHash(final TLSH tlsh) {
        final byte[] tlshBuf = tlsh.pack();
        final TLSH tlshFromBuf = TLSH.of(tlshBuf);
        assertEquals(tlsh, tlshFromBuf);
        final String tlshHex = TLSHUtil.encoded(tlshBuf);
        final Tlsh tmTlsh = Tlsh.fromTlshStr(tlshHex);
        assertArrayEquals(TMTestUtil.getChecksum(tmTlsh), tlshFromBuf.checksum);
        assertEquals(TMTestUtil.getLvalue(tmTlsh), tlshFromBuf.lValue);
        assertEquals(TMTestUtil.getQ1ratio(tmTlsh), tlshFromBuf.q1);
        assertEquals(TMTestUtil.getQ2ratio(tmTlsh), tlshFromBuf.q2);
        assertArrayEquals(TMTestUtil.getCodes(tmTlsh), tlshFromBuf.body);

        final byte[] buf2 = TLSHUtil.hexToBytes(tlshHex);
        assertArrayEquals(tlshBuf, buf2);
    }

    /**
     * Obtain curated list of TLSH samples.
     * 
     * @return the samples.
     */
    public static List<TLSH> sampleTLSH() {
        return SAMPLE_TLSH;
    }

}
