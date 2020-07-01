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

import java.nio.ByteBuffer;

/**
 * The base interface for TLSH digesters.
 * 
 * @author keve
 *
 */
public interface TLSHDigest {

    /**
     * Update the digester with given byte.
     * 
     * @param b the byte
     */
    default void update(final byte b) {
        update(ByteBuffer.wrap(new byte[] {b}));
    }

    /**
     * Update the digester with given bytes.
     * 
     * @param buf the bytes
     */
    default void update(final byte[] buf) {
        update(ByteBuffer.wrap(buf));
    }

    /**
     * Update the digester with given bytes.
     * 
     * @param buf    the byte buffer
     * @param offset offset to read from
     * @param length number of bytes to read
     */
    default void update(final byte[] buf, final int offset, final int length) {
        update(ByteBuffer.wrap(buf, offset, length));
    }

    /**
     * Update the digester with given bytes.
     * 
     * @param buf the bytes
     */
    void update(ByteBuffer buf);

    /**
     * Reset the digester instance.
     */
    void reset();

    /**
     * Finish the TLSH computation and return the hash.
     * 
     * @return the hash
     */
    TLSH digest();

    /**
     * Return the default TLSHDigest instance with 5 bytes window, 128 buckets and 1
     * checksum byte.
     * 
     * @return the instance.
     */
    static TLSHDigest of() {
        return of(TLSHDigest5.WINDOW_LENGTH, 128, 1);
    }

    /**
     * Return an TLSHDigest instance for given configuration.
     * 
     * @param windowLength   the window length ([4-8])
     * @param bucketCount    the bucket count (128|256)
     * @param checkSumLength the number of checksum bytes (1|3)
     * @return the instance
     */
    static TLSHDigest of(final int windowLength, final int bucketCount, final int checkSumLength) {
        switch (windowLength) {
        case TLSHDigest4.WINDOW_LENGTH:
            return new TLSHDigest4(bucketCount, checkSumLength);
        case TLSHDigest5.WINDOW_LENGTH:
            if (1 == checkSumLength) {
                return new TLSHDigest5c1(bucketCount);
            } else {
                return new TLSHDigest5(bucketCount, checkSumLength);
            }
        case TLSHDigest6.WINDOW_LENGTH:
            return new TLSHDigest6(bucketCount, checkSumLength);
        case TLSHDigest7.WINDOW_LENGTH:
            return new TLSHDigest7(bucketCount, checkSumLength);
        case TLSHDigest8.WINDOW_LENGTH:
            return new TLSHDigest8(bucketCount, checkSumLength);
        default:
            throw new IllegalArgumentException();
        }
    }
}
