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
package app.keve.ktlsh.spi;

import java.nio.ByteBuffer;
import java.security.MessageDigestSpi;

import app.keve.ktlsh.impl.TLSH;
import app.keve.ktlsh.impl.TLSHDigest;
import app.keve.ktlsh.impl.TLSHDigest5;

/**
 * The Service Provider for the kTLSH implementation.
 * 
 * @author keve
 *
 */
public final class TLSHMessageDigestSpiK extends MessageDigestSpi {
    /** The underlying TLSH digester implementation. */
    private final TLSHDigest impl;
    /** The precomputed length of the digest buffer. */
    private final int digestLength;

    TLSHMessageDigestSpiK() {
        this(TLSHDigest5.WINDOW_LENGTH, 128, 1);
    }

    TLSHMessageDigestSpiK(final int windowLength, final int bucketCount, final int checksumLength) {
        impl = TLSHDigest.of(windowLength, bucketCount, checksumLength);
        final int l = bucketCount / 2 + checksumLength * 2 + 4;
        this.digestLength = l / 2;
    }

    @Override
    protected int engineGetDigestLength() {
        return digestLength;
    }

    @Override
    protected void engineUpdate(final byte input) {
        impl.update(input);
    }

    @Override
    protected void engineUpdate(final byte[] input, final int offset, final int len) {
        impl.update(input, offset, len);
    }

    @Override
    protected void engineUpdate(final ByteBuffer buf) {
        impl.update(buf);
    }

    @Override
    protected byte[] engineDigest() {
        final TLSH hash = impl.digest();
        impl.reset();
        return hash.pack();
    }

    @Override
    protected void engineReset() {
        impl.reset();
    }
}
