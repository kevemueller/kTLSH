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

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.trendmicro.tlsh.BucketOption;
import com.trendmicro.tlsh.ChecksumOption;
import com.trendmicro.tlsh.Tlsh;
import com.trendmicro.tlsh.TlshCreator;

import app.keve.ktlsh.TLSHUtil;
import app.keve.ktlsh.testutil.TestUtil;

/**
 * Test digester operation between TM and K implementations.
 * 
 * @author keve
 *
 */
public final class TestDigest extends AbstractImplTest {
    /** 64KiB length. */
    private static final int MEDIUM_LENGTH_64KIB = 65536;

    /** 32KiB length. */
    private static final int MEDIUM_LENGTH_32KIB = 32768;

    /** 2KiB length. */
    private static final int MEDIUM_LENGTH_2KIB = 2048;

    /** Base directory of the unit test data. */
    private static final String BASE = "/tlsh/Testing/";

    /** The source of randomness. */
    private final SecureRandom rnd;

    /** Construct the test instance. */
    public TestDigest() throws NoSuchAlgorithmException {
        rnd = TestUtil.rnd();
    }

    /**
     * Factory for arguments of buckets x checksum.
     * 
     * @return all possible combinations of bucket x checksum.
     */
    public static Stream<Arguments> bc() {
        return Stream.of(Arguments.of(128, 1), Arguments.of(128, 3), Arguments.of(256, 1), Arguments.of(256, 3));
    }

    /**
     * Test matching state on incremental update.
     * 
     * @param buckets  the number of buckets.
     * @param checksum the number of checksum bytes.
     */
    @ParameterizedTest
    @MethodSource("bc")
    public void testUpdate(final int buckets, final int checksum) {
        final TLSHDigest kd = TLSHDigest.of(5, buckets, checksum);
        final TlshCreator td = new TlshCreator(128 == buckets ? BucketOption.BUCKETS_128 : BucketOption.BUCKETS_256,
                1 == checksum ? ChecksumOption.CHECKSUM_1B : ChecksumOption.CHECKSUM_3B);

        for (byte i = 1; i < 8; i++) {
            kd.update(i);
            td.update(new byte[] {i});

            TMTestUtil.assertEqualState(td, kd);
        }
    }

    /**
     * Test matching state on full update.
     * 
     * @param buckets  the number of buckets.
     * @param checksum the number of checksum bytes.
     */
    @ParameterizedTest
    @MethodSource("bc")
    public void testDigestFull(final int buckets, final int checksum) {
        final TLSHDigest kd = TLSHDigest.of(5, buckets, checksum);
        final TlshCreator td = new TlshCreator(128 == buckets ? BucketOption.BUCKETS_128 : BucketOption.BUCKETS_256,
                1 == checksum ? ChecksumOption.CHECKSUM_1B : ChecksumOption.CHECKSUM_3B);

        final byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        kd.update(buf);
        td.update(buf);

        TMTestUtil.assertEqualState(td, kd);

        final TLSH kTLSH = kd.digest();
        final Tlsh tTLSH = td.getHash();

        TMTestUtil.assertEqualState(tTLSH, kTLSH);

        final String kHash = TLSHUtil.encoded(kTLSH.pack());
        final String tHash = tTLSH.toString();

        LOGGER.info(kHash);
        LOGGER.info(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Incremental updates with single byte.
     * 
     * @param buckets  the number of buckets.
     * @param checksum the number of checksum bytes.
     */
    @ParameterizedTest
    @MethodSource("bc")
    public void testDigest1(final int buckets, final int checksum) {
        final TLSHDigest kd = TLSHDigest.of(5, buckets, checksum);
        final TlshCreator td = new TlshCreator(128 == buckets ? BucketOption.BUCKETS_128 : BucketOption.BUCKETS_256,
                1 == checksum ? ChecksumOption.CHECKSUM_1B : ChecksumOption.CHECKSUM_3B);

        final byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        for (byte b : buf) {
            kd.update(b);
            td.update(new byte[] {b});
        }

        TMTestUtil.assertEqualState(td, kd);

        final TLSH kTLSH = kd.digest();
        final Tlsh tTLSH = td.getHash();

        TMTestUtil.assertEqualState(tTLSH, kTLSH);

        final String kHash = TLSHUtil.encoded(kTLSH.pack());
        final String tHash = tTLSH.toString();

        LOGGER.info(kHash);
        LOGGER.info(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Incremental updates with smaller than windowsize buffers.
     * 
     * @param buckets  the number of buckets.
     * @param checksum the number of checksum bytes.
     */
    @ParameterizedTest
    @MethodSource("bc")
    public void testDigestSmall(final int buckets, final int checksum) {
        final TLSHDigest kd = TLSHDigest.of(5, buckets, checksum);
        final TlshCreator td = new TlshCreator(128 == buckets ? BucketOption.BUCKETS_128 : BucketOption.BUCKETS_256,
                1 == checksum ? ChecksumOption.CHECKSUM_1B : ChecksumOption.CHECKSUM_3B);

        final byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        final ByteBuffer bb = ByteBuffer.wrap(buf);
        while (bb.hasRemaining()) {
            final byte[] iu = new byte[Math.min(bb.remaining(), rnd.nextInt(4))];
            bb.get(iu);
            kd.update(iu);
            td.update(iu);
        }

        TMTestUtil.assertEqualState(td, kd);

        final TLSH kTLSH = kd.digest();
        final Tlsh tTLSH = td.getHash();

        TMTestUtil.assertEqualState(tTLSH, kTLSH);

        final String kHash = TLSHUtil.encoded(kTLSH.pack());
        final String tHash = tTLSH.toString();
        LOGGER.info(kHash);
        LOGGER.info(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Incremental updates with medium sized buffers.
     * 
     * @param buckets  the number of buckets.
     * @param checksum the number of checksum bytes.
     */
    @ParameterizedTest
    @MethodSource("bc")
    public void testDigestMedium(final int buckets, final int checksum) {
        final TLSHDigest kd = TLSHDigest.of(5, buckets, checksum);
        final TlshCreator td = new TlshCreator(128 == buckets ? BucketOption.BUCKETS_128 : BucketOption.BUCKETS_256,
                1 == checksum ? ChecksumOption.CHECKSUM_1B : ChecksumOption.CHECKSUM_3B);

        final byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        final ByteBuffer bb = ByteBuffer.wrap(buf);
        while (bb.hasRemaining()) {
            final byte[] iu = new byte[Math.min(bb.remaining(), rnd.nextInt(MEDIUM_LENGTH_2KIB))];
            bb.get(iu);
            kd.update(iu);
            td.update(iu);
        }

        TMTestUtil.assertEqualState(td, kd);

        final TLSH kTLSH = kd.digest();
        final Tlsh tTLSH = td.getHash();

        TMTestUtil.assertEqualState(tTLSH, kTLSH);

        final String kHash = TLSHUtil.encoded(kTLSH.pack());
        final String tHash = tTLSH.toString();
        LOGGER.info(kHash);
        LOGGER.info(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Test hashing a resource.
     * 
     * @throws IOException if an I/O error occurs
     */
    @Test
    public void testResource() throws IOException {
        final String resource = "example_data/021106_yossivassa.txt";
        final String expectedEncoded = "1FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE";
        final byte[] buf;
        try (InputStream in = getClass().getResourceAsStream(BASE + resource)) {
            buf = in.readAllBytes();
        }

        final TLSHDigest kd = TLSHDigest.of();
        final TlshCreator td = new TlshCreator();
        kd.update(buf);
        td.update(buf);

        TMTestUtil.assertEqualState(td, kd);

        final TLSH kTLSH = kd.digest();
        final Tlsh tTLSH = td.getHash();

        TMTestUtil.assertEqualState(tTLSH, kTLSH);

        final String kHash = TLSHUtil.encoded(kTLSH.pack());
        final String tHash = tTLSH.toString();
        LOGGER.info(kHash);
        LOGGER.info(tHash);

        assertEquals(expectedEncoded, tHash);
        assertEquals(expectedEncoded, kHash);
    }
}
