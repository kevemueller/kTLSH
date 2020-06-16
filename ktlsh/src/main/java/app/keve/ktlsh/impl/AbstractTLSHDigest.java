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

public abstract class AbstractTLSHDigest implements TLSHDigest {
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
        long[] bucketCopy = Arrays.copyOf(aBucket, bucketCount);
        Arrays.sort(bucketCopy);
        int quartile = bucketCount / 4;
        final int p1 = quartile - 1;
        long q1 = bucketCopy[p1];
        long q2 = bucketCopy[p1 + quartile];
        long q3 = bucketCopy[p1 + 2 * quartile];

        // compress buckets
        int codeSize = bucketCount / 4;
        int[] code = new int[codeSize];
        for (int i = 0; i < codeSize; i++) {
            int h = 0;
            for (int j = 0; j < 4; j++) {
                long k = aBucket[4 * i + j];
                if (q3 < k) {
                    h += 3 << (j * 2);
                } else if (q2 < k) {
                    h += 2 << (j * 2);
                } else if (q1 < k) {
                    h += 1 << (j * 2);
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
     * @return the lag window array.
     */
    protected abstract int[] getLag();

    @Override
    public final String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("aBucket=\n");
        for (int i = 0; i < aBucket.length; i++) {
            if (aBucket[i] > 0) {
                sb.append(i).append(":").append(aBucket[i]).append('\n');
            }
        }
        sb.append('\n');
        int[] lag = getLag();
        sb.append("lag=").append(Arrays.toString(lag)).append('\n');

        sb.append("count=").append(count).append('\n');
        sb.append("checksum=").append(Arrays.toString(checksum)).append('\n');
        return sb.toString();
    }

}
