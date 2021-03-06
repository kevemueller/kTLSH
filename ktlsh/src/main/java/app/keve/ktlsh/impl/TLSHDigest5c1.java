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
 * A TLSH digester for window size of 5 bytes and single checksum byte. This is
 * the default TLSH algorithm case.
 * 
 * @author keve
 *
 */
public final class TLSHDigest5c1 extends AbstractTLSHDigest {
    /**
     * The supported window length.
     */
    private static final int WINDOW_LENGTH = 5;

    /**
     * Hold the lag window of 4 bytes.
     */
    private int lag;

    /**
     * Construct the instance with window length 5 and 1 checksum byte.
     * 
     * @param bucketCount the number of buckets (128|256)
     */
    public TLSHDigest5c1(final int bucketCount) {
        super(WINDOW_LENGTH, bucketCount, 1);
    }

    @Override
    public void update(final ByteBuffer buf) {
        while (count < windowLength - 1 && buf.hasRemaining()) {
            final int l0 = buf.get() & 0xFF;
            count++;
            lag <<= 8;
            lag |= l0;
            if (!buf.hasRemaining()) {
                return;
            }
        }
        int l1 = lag & 0xFF;
        int l2 = lag >>> 8 & 0xFF;
        int l3 = lag >>> 16 & 0xFF;
        int l4 = lag >>> 24 & 0xFF;
        while (buf.hasRemaining()) {
            final int l0 = buf.get() & 0xFF;
            count++;

            checksum[0] = sMapping(T0, l0, l1, checksum[0]);

            aBucket[sMapping(T2, l0, l1, l2)]++;
            aBucket[sMapping(T3, l0, l1, l3)]++;
            aBucket[sMapping(T5, l0, l2, l3)]++;

            aBucket[sMapping(T7, l0, l2, l4)]++;
            aBucket[sMapping(T11, l0, l1, l4)]++;
            aBucket[sMapping(T13, l0, l3, l4)]++;

            l4 = l3;
            l3 = l2;
            l2 = l1;
            l1 = l0;
        }
        lag = l4 << 24 | l3 << 16 | l2 << 8 | l1;
    }

    @Override
    protected int[] getLag() {
        return new int[] {lag & 0xFF, lag >>> 8 & 0xFF, lag >>> 16 & 0xFF, lag >>> 24 & 0xFF};
    }

}
