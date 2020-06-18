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
 * A TLSH digester for window size of 7 bytes.
 * 
 * @author keve
 *
 */
public final class TLSHDigest7 extends AbstractTLSHDigest {
    /**
     * The supported window length.
     */
    public static final int WINDOW_LENGTH = 7;

    /**
     * Hold the lag window of 6 bytes.
     */
    private long lag;

    /**
     * Construct the instance with window length 7.
     * 
     * @param bucketCount    the number of buckets (128|256)
     * @param checkSumLength the number of checksum bytes (1|3)
     */
    public TLSHDigest7(final int bucketCount, final int checkSumLength) {
        super(WINDOW_LENGTH, bucketCount, checkSumLength);
    }

    @Override
    @SuppressWarnings("checkstyle:MagicNumber")
    public void update(final ByteBuffer buf) {
        int l1 = (int) (lag & 0xFF);
        int l2 = (int) (lag >>> 8 & 0xFF);
        int l3 = (int) (lag >>> 16 & 0xFF);
        int l4 = (int) (lag >>> 24 & 0xFF);
        int l5 = (int) (lag >>> 32 & 0xFF);
        int l6 = (int) (lag >>> 40 & 0xFF);
        while (buf.hasRemaining()) {
            final int l0 = buf.get() & 0xFF;
            count++;
            if (count >= windowLength) {
                switch (checkSumLength) {
                case 1:
                    checksum[0] = sMapping(1 /* T[0] */, l0, l1, checksum[0]);
                    break;
                case 3:
                    checksum[0] = sMapping(1 /* T[0] */, l0, l1, checksum[0]);
                    checksum[1] = bMapping(checksum[0], l0, l1, checksum[1]);
                    checksum[2] = bMapping(checksum[1], l0, l1, checksum[2]);
                    break;
                default:
                    checksum[0] = sMapping(1 /* T[0] */, l0, l1, checksum[0]);
                    for (int k = 1; k < checksum.length; k++) {
                        checksum[k] = bMapping(checksum[k - 1], l0, l1, checksum[k]);
                    }
                    break;
                }

                aBucket[sMapping(49 /* T[2] */, l0, l1, l2)]++;
                aBucket[sMapping(12 /* T[3] */, l0, l1, l3)]++;
                aBucket[sMapping(178 /* T[5] */, l0, l2, l3)]++;

                aBucket[sMapping(166 /* T[7] */, l0, l2, l4)]++;
                aBucket[sMapping(84 /* T[11] */, l0, l1, l4)]++;
                aBucket[sMapping(230 /* T[13] */, l0, l3, l4)]++;

                aBucket[sMapping(197 /* T[17] */, l0, l1, l5)]++;
                aBucket[sMapping(181 /* T[19] */, l0, l2, l5)]++;
                aBucket[sMapping(80 /* T[23] */, l0, l3, l5)]++;
                aBucket[sMapping(142 /* T[29] */, l0, l4, l5)]++;

                aBucket[sMapping(200 /* T[31] */, l0, l1, l6)]++;
                aBucket[sMapping(253 /* T[37] */, l0, l2, l6)]++;
                aBucket[sMapping(101 /* T[41] */, l0, l3, l6)]++;
                aBucket[sMapping(18 /* T[43] */, l0, l4, l6)]++;
                aBucket[sMapping(222 /* T[47] */, l0, l5, l6)]++;
            }
            l6 = l5;
            l5 = l4;
            l4 = l3;
            l3 = l2;
            l2 = l1;
            l1 = l0;
        }
        lag = l6 << 40 | l5 << 32 | l4 << 24 | l3 << 16 | l2 << 8 | l1;
    }

    @Override
    protected int[] getLag() {
        return new int[] {(int) (lag & 0xFF), (int) (lag >>> 8 & 0xFF), (int) (lag >>> 16 & 0xFF),
                (int) (lag >>> 24 & 0xFF), (int) (lag >>> 32 & 0xFF), (int) (lag >>> 40 & 0xFF)};
    }
}
