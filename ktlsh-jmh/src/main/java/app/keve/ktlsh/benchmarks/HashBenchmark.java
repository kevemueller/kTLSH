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
package app.keve.ktlsh.benchmarks;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import app.keve.ktlsh.TLSHUtil;

/**
 * Hash benchmarks.
 * 
 * @author keve
 *
 */
@Fork(1)
@Warmup(time = 2)
@Measurement(iterations = 2)
public class HashBenchmark {
    /** The algorithm name. */
    private static final String TLSH_ALGNAME = "TLSH";
    /** The KiB multiplier. */
    private static final int KIB = 1024;
    static {
        TLSHUtil.registerProviders();
    }

    /**
     * The state class of the benchmarks holding the buffers.
     * 
     * @author keve
     *
     */
    @State(Scope.Benchmark)
    public static class MyState {
        /** small 32KiB buffer. */
        private byte[] smallBuf32KiB;
        /** large 16MiB buffer. */
        private byte[] largeBuf16MiB;
        /** huge 1GiB buffer. */
        private byte[] hugeBuf1GiB;

        /**
         * Initialise the state class members.
         * 
         * @throws NoSuchAlgorithmException if TLSH algorithm cannot be found.
         */
        @Setup
        public void init() throws NoSuchAlgorithmException {
            final SecureRandom rnd = Util.rnd();
            smallBuf32KiB = new byte[32 * KIB];
            largeBuf16MiB = new byte[16 * KIB * KIB];
            hugeBuf1GiB = new byte[1 * KIB * KIB * KIB];
            rnd.nextBytes(getSmallBuf32KiB());
            rnd.nextBytes(getLargeBuf16MiB());
            rnd.nextBytes(getHugeBuf1GiB());
        }

        /**
         * Getter for small buffer.
         * 
         * @return the buffer
         */
        public byte[] getSmallBuf32KiB() {
            return smallBuf32KiB;
        }

        /**
         * Getter for large buffer.
         * 
         * @return the buffer
         */
        public byte[] getLargeBuf16MiB() {
            return largeBuf16MiB;
        }

        /**
         * Getter for huge buffer.
         * 
         * @return the buffer
         */
        public byte[] getHugeBuf1GiB() {
            return hugeBuf1GiB;
        }
    }

    private void test(final MessageDigest md, final byte[] buf) {
        final byte[] hash = md.digest(buf);
        TLSHUtil.encoded(hash);
    }

    /**
     * Benchmark hash with TM implementation, 32KiB buffer.
     * 
     * @param state the state
     * @throws GeneralSecurityException algorithms are not found
     */
    @Benchmark
    @OperationsPerInvocation(32)
    public void testTMSmall32KiB(final MyState state) throws GeneralSecurityException {
        final MessageDigest md = MessageDigest.getInstance(TLSH_ALGNAME, TLSHUtil.providerNameTM());
        test(md, state.getSmallBuf32KiB());
    }

    /**
     * Benchmark hash with K implementation, 32KiB buffer.
     * 
     * @param state the state
     * @throws GeneralSecurityException algorithms are not found
     */
    @Benchmark
    @OperationsPerInvocation(32)
    public void testKSmall32KiB(final MyState state) throws GeneralSecurityException {
        final MessageDigest md = MessageDigest.getInstance(TLSH_ALGNAME, TLSHUtil.providerNameK());
        test(md, state.getSmallBuf32KiB());
    }

    /**
     * Benchmark MD5 hash, 32KiB buffer.
     * 
     * @param state the state
     * @throws GeneralSecurityException algorithms are not found
     */
    @Benchmark
    @OperationsPerInvocation(32)
    public void testMD5Small32KiB(final MyState state) throws GeneralSecurityException {
        final MessageDigest md = MessageDigest.getInstance("MD5");
        test(md, state.getSmallBuf32KiB());
    }

    /**
     * Benchmark hash with TM implementation, 16MiB buffer.
     * 
     * @param state the state
     * @throws GeneralSecurityException algorithms are not found
     */
    @Benchmark
    @OperationsPerInvocation(16 * KIB)
    public void testTMLarge16MiB(final MyState state) throws GeneralSecurityException {
        final MessageDigest md = MessageDigest.getInstance(TLSH_ALGNAME, TLSHUtil.providerNameTM());
        test(md, state.getLargeBuf16MiB());
    }

    /**
     * Benchmark hash with K implementation, 16MiB buffer.
     * 
     * @param state the state
     * @throws GeneralSecurityException algorithms are not found
     */
    @Benchmark
    @OperationsPerInvocation(16 * KIB)
    public void testKLarge16MiB(final MyState state) throws GeneralSecurityException {
        final MessageDigest md = MessageDigest.getInstance(TLSH_ALGNAME, TLSHUtil.providerNameK());
        test(md, state.getLargeBuf16MiB());
    }

    /**
     * Benchmark MD5 hash, 16MiB buffer.
     * 
     * @param state the state
     * @throws GeneralSecurityException algorithms are not found
     */
    @Benchmark
    @OperationsPerInvocation(16 * KIB)
    public void testMD5Large16MiB(final MyState state) throws GeneralSecurityException {
        final MessageDigest md = MessageDigest.getInstance("MD5");
        test(md, state.getLargeBuf16MiB());
    }
}
