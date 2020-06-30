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

import java.util.Arrays;

/**
 * Base implementation of the TLSH digester.
 * 
 * @author keve
 *
 */
public abstract class AbstractTLSHDigest implements TLSHDigest {
    /** The Pearson default hash of 0. */
    protected static final int T0 = 1 /* T[0] */;
    /** The Pearson default hash of 2. */
    protected static final int T2 = 49 /* T[2] */;
    /** The Pearson default hash of 3. */
    protected static final int T3 = 12 /* T[3] */;
    /** The Pearson default hash of 5. */
    protected static final int T5 = 178 /* T[5] */;
    /** The Pearson default hash of 7. */
    protected static final int T7 = 166 /* T[7] */;
    /** The Pearson default hash of 11. */
    protected static final int T11 = 84 /* T[11] */;
    /** The Pearson default hash of 13. */
    protected static final int T13 = 230 /* T[13] */;
    /** The Pearson default hash of 17. */
    protected static final int T17 = 197 /* T[17] */;
    /** The Pearson default hash of 19. */
    protected static final int T19 = 181 /* T[19] */;
    /** The Pearson default hash of 23. */
    protected static final int T23 = 80 /* T[23] */;
    /** The Pearson default hash of 29. */
    protected static final int T29 = 142 /* T[29] */;
    /** The Pearson default hash of 31. */
    protected static final int T31 = 200 /* T[31] */;
    /** The Pearson default hash of 37. */
    protected static final int T37 = 253 /* T[37] */;
    /** The Pearson default hash of 41. */
    protected static final int T41 = 101 /* T[41] */;
    /** The Pearson default hash of 43. */
    protected static final int T43 = 18 /* T[43] */;
    /** The Pearson default hash of 47. */
    protected static final int T47 = 222 /* T[47] */;
    /** The Pearson default hash of 53. */
    protected static final int T53 = 237 /* T[53] */;
    /** The Pearson default hash of 59. */
    protected static final int T59 = 214 /* T[59] */;
    /** The Pearson default hash of 61. */
    protected static final int T61 = 227 /* T[61] */;
    /** The Pearson default hash of 67. */
    protected static final int T67 = 22 /* T[67] */;
    /** The Pearson default hash of 71. */
    protected static final int T71 = 175 /* T[71] */;
    /** The Pearson default hash of 73. */
    protected static final int T73 = 5 /* T[73] */;

    /** the window length [4-8]. */
    protected final int windowLength;
    /** the bucket count (128|256). */
    protected final int bucketCount;
    /** the number of checksum bytes (1|3). */
    protected final int checkSumLength;
    /** the buckets to accumulate the histogram in. */
    protected final long[] aBucket;
    /** the checksum bytes. */
    protected final int[] checksum;
    /** the number of bytes processed so far. */
    protected long count;

    protected AbstractTLSHDigest(final int windowLength, final int bucketCount, final int checkSumLength) {
        this.windowLength = windowLength;
        this.bucketCount = bucketCount;
        this.checkSumLength = checkSumLength;
        aBucket = new long[256];
        checksum = new int[checkSumLength];
        count = 0;
    }

    @Override
    public final void reset() {
        count = 0;
        Arrays.fill(aBucket, 0);
        Arrays.fill(checksum, 0);
    }

    @Override
    public final TLSH digest() {
        // findQuartiles
        final long[] bucketCopy = Arrays.copyOf(aBucket, bucketCount);
        Arrays.sort(bucketCopy);
        final int quartile = bucketCount / 4;
        final int p1 = quartile - 1;
        final long q1 = bucketCopy[p1];
        final long q2 = bucketCopy[p1 + quartile];
        final long q3 = bucketCopy[p1 + 2 * quartile];

        // compress buckets
        final int codeSize = bucketCount / 4;
        final int[] code = new int[codeSize];
        for (int i = 0; i < codeSize; i++) {
            int h = 0;
            for (int j = 0; j < 4; j++) {
                final long k = aBucket[4 * i + j];
                if (q3 < k) {
                    h += 3 << j * 2;
                } else if (q2 < k) {
                    h += 2 << j * 2;
                } else if (q1 < k) {
                    h += 1 << j * 2;
                }
            }
            code[i] = h;
        }
        return TLSH.of(checksum.clone(), count, q1, q2, q3, code);
    }

    protected final int bMapping(final int salt, final int i, final int j, final int k) {
        return Pearson.T[Pearson.T[Pearson.T[Pearson.T[salt] ^ i] ^ j] ^ k];

    }

    protected final int sMapping(final int h, final int i, final int j, final int k) {
        return Pearson.T[Pearson.T[Pearson.T[h ^ i] ^ j] ^ k];
    }

    /**
     * Obtain the lag window as an array.
     * 
     * @return the lag window array.
     */
    protected abstract int[] getLag();

    @Override
    public final String toString() {
        final StringBuffer stringBuffer = new StringBuffer(64);
        stringBuffer.append("aBucket=\n");
        for (int i = 0; i < aBucket.length; i++) {
            if (aBucket[i] > 0) {
                stringBuffer.append(i).append(':').append(aBucket[i]).append('\n');
            }
        }
        stringBuffer.append('\n');
        final int[] lag = getLag();
        stringBuffer.append("lag=").append(Arrays.toString(lag)).append('\n');

        stringBuffer.append("count=").append(count).append('\n');
        stringBuffer.append("checksum=").append(Arrays.toString(checksum)).append('\n');
        return stringBuffer.toString();
    }

}
