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
import java.util.Arrays;
import java.util.Objects;

/**
 * The representation of the TLSH hash as a value type.
 * 
 * @author keve
 *
 */
public final class TLSH {
    /**
     * The scaling multiplier for difference scoring.
     */
    private static final int DIFF_SCALE = 12;

    /**
     * The scaling multiplier for difference scoring of bits.
     */
    private static final int DIFF_SCALE6 = 6;

    // NOTE: we cannot compute this array in Java as java does not have a
    // Math.log(float)!
    /**
     * Lookup table for the logs of the length value.
     */
    private static final long[] TOPVAL = {1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110,
            1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907,
            11998, 13198, 14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564,
            50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183, 130002, 143002, 157302, 173032,
            190335, 209369, 230306, 253337, 278670, 306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356,
            657091, 722800, 795081, 874589, 962048, 1058252, 1164078, 1280486, 1408534, 1549388, 1704327, 1874759,
            2062236, 2268459, 2495305, 2744836, 3019320, 3321252, 3653374, 4018711, 4420582, 4862641, 5348905, 5883796,
            6472176, 7119394, 7831333, 8614467, 9475909, 10423501, 11465851, 12612437, 13873681, 15261050, 16787154,
            18465870, 20312458, 22343706, 24578077, 27035886, 29739474, 32713425, 35984770, 39583245, 43541573,
            47895730, 52685306, 57953837, 63749221, 70124148, 77136564, 84850228, 93335252, 102668779, 112935659,
            124229227, 136652151, 150317384, 165349128, 181884040, 200072456, 220079703, 242087671, 266296456,
            292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559, 570830240, 627913311,
            690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880, 1223623232, 1345985727, 1480584256,
            1628642751, 1791507135, 1970657856, 2167723648L, 2384496256L, 2622945920L, 2885240448L, 3173764736L,
            3491141248L, 3840255616L, 4224281216L};

    /**
     * The checksum bytes.
     */
    public final int[] checksum;
    /**
     * The encoded length value.
     */
    public final int lValue;
    /**
     * The q1 ratio.
     */
    public final int q1;
    /**
     * The q2 ratio.
     */
    public final int q2;
    /**
     * The buckets.
     */
    public final int[] body;

    private TLSH(final int[] checksum, final int lValue, final int q1, final int q2, final int[] body) {
        assert 1 == checksum.length || 3 == checksum.length;
        this.checksum = checksum;
        this.lValue = lValue;
        this.q1 = q1;
        this.q2 = q2;
        assert 32 == body.length || 64 == body.length;
        this.body = body;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(body);
        result = prime * result + Arrays.hashCode(checksum);
        result = prime * result + Objects.hash(lValue, q1, q2);
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TLSH)) {
            return false;
        }
        final TLSH other = (TLSH) obj;
        return Arrays.equals(body, other.body) && Arrays.equals(checksum, other.checksum) && lValue == other.lValue
                && q1 == other.q1 && q2 == other.q2;
    }

    @Override
    public String toString() {
        final int maxLen = 10;
        final StringBuilder builder = new StringBuilder();
        builder.append("TLSH [checksum=");
        builder.append(
                checksum != null ? Arrays.toString(Arrays.copyOf(checksum, Math.min(checksum.length, maxLen))) : null);
        builder.append(", lValue=");
        builder.append(lValue);
        builder.append(", q1=");
        builder.append(q1);
        builder.append(", q2=");
        builder.append(q2);
        builder.append(", body[").append(body.length).append("]=");
        builder.append(body != null ? Arrays.toString(Arrays.copyOf(body, Math.min(body.length, maxLen))) : null);
        builder.append("]");
        return builder.toString();
    }

    /**
     * Score the difference of the the hash with a given other hash.
     * 
     * @param other   the other hash
     * @param lenDiff true, if the length difference should be scored
     * @return the score
     */
    public int score(final TLSH other, final boolean lenDiff) {
        if (checksum.length != other.checksum.length || body.length != other.body.length) {
            throw new IllegalArgumentException();
        }
        int score = 0;

        score += scoreChecksum(checksum, other.checksum);
        if (lenDiff) {
            score += scoreLValue(lValue, other.lValue);
        }
        score += scoreQ(q1, other.q1);
        score += scoreQ(q2, other.q2);
        score += scoreBody(body, other.body);

        return score;
    }

    private static int swapNibble(final int x) {
        return (x & 0x0F) << 4 | (x & 0xF0) >> 4;
    }

    private static int modDiff(final int x, final int y, final int range) {
        int dl = 0;
        int dr = 0;
        if (y > x) {
            dl = y - x;
            dr = x + range - y;
        } else {
            dl = x - y;
            dr = y + range - x;
        }
        return dl > dr ? dr : dl;
    }

    private static int scoreBody(final int[] body1, final int[] body2) {
        int diff = 0;

        for (int i = 0; i < body1.length; i++) {
            diff += DiffTable.BIT_PAIRS_DIFF_TABLE[body1[i]][body2[i]];
        }

        return diff;
    }

    private static int scoreChecksum(final int[] checksum2, final int[] checksum3) {
        return Arrays.equals(checksum2, checksum3) ? 0 : 1;
    }

    private static int scoreQ(final int q2, final int q3) {
        final int q1diff = modDiff(q2, q3, 16);

        return q1diff <= 1 ? q1diff : (q1diff - 1) * DIFF_SCALE;
    }

    private static int scoreLValue(final int lValue2, final int lValue3) {
        final int ldiff = modDiff(lValue2, lValue3, 256);
        switch (ldiff) {
        case 0:
            return 0;
        case 1:
            return 1;
        default:
            return DIFF_SCALE * ldiff;
        }
    }

    private static final class DiffTable {
        /**
         * Difference lookup table.
         */
        private static final int[][] BIT_PAIRS_DIFF_TABLE = generateTable();

        private static int[][] generateTable() {
            final int[][] result = new int[256][256];
            for (int i = 0; i < 256; i++) {
                for (int j = 0; j < 256; j++) {
                    int x = i;
                    int y = j;
                    int d;
                    int diff = 0;
                    d = Math.abs(x % 4 - y % 4);
                    diff += d == 3 ? DIFF_SCALE6 : d;
                    x /= 4;
                    y /= 4;
                    d = Math.abs(x % 4 - y % 4);
                    diff += d == 3 ? DIFF_SCALE6 : d;
                    x /= 4;
                    y /= 4;
                    d = Math.abs(x % 4 - y % 4);
                    diff += d == 3 ? DIFF_SCALE6 : d;
                    x /= 4;
                    y /= 4;
                    d = Math.abs(x % 4 - y % 4);
                    diff += d == 3 ? DIFF_SCALE6 : d;
                    result[i][j] = diff;
                }
            }
            return result;
        }
    }

    /**
     * Pack the TLSH instance in the network format.
     * 
     * @return the byte array representation of the hash.
     */
    public byte[] pack() {
        final ByteBuffer buf = ByteBuffer.allocate(checksum.length + 2 + body.length);
        for (int i = 0; i < checksum.length; i++) {
            buf.put((byte) swapNibble(checksum[i]));
        }
        buf.put((byte) swapNibble(lValue));
        buf.put((byte) (q1 << 4 | q2));
        for (int i = body.length - 1; i >= 0; i--) {
            buf.put((byte) body[i]);
        }
        buf.flip();
        if (buf.hasArray() && 0 == buf.arrayOffset()) {
            return buf.array();
        } else {
            final byte[] hash = new byte[buf.remaining()];
            buf.get(hash);
            return hash;
        }
    }

    private static int lCapturing(final long len) {
        final int x = Arrays.binarySearch(TOPVAL, len);
        return x >= 0 ? x : -x - 1;
    }

    /**
     * Create an instance from the packed byte buffer.
     * 
     * @param hash the packed byte buffer
     * @return the hash instance.
     */
    public static TLSH of(final byte[] hash) {
        final int bucketCount;
        final int checksumLength;
        switch (hash.length) {
        case 32 + 2 + 1:
            bucketCount = 128;
            checksumLength = 1;
            break;
        case 32 + 2 + 3:
            bucketCount = 128;
            checksumLength = 3;
            break;
        case 64 + 2 + 1:
            bucketCount = 256;
            checksumLength = 1;
            break;
        case 64 + 2 + 3:
            bucketCount = 256;
            checksumLength = 3;
            break;
        default:
            throw new IllegalArgumentException();
        }

        final ByteBuffer buf = ByteBuffer.wrap(hash);

        final int[] checksum = new int[checksumLength];
        for (int i = 0; i < checksum.length; i++) {
            checksum[i] = swapNibble(buf.get() & 0xFF);
        }
        final int lValue = swapNibble(buf.get() & 0xFF);
        final int qRatio = buf.get() & 0xFF;
        final int q1Ratio = qRatio >> 4;
        final int q2Ratio = qRatio & 0x0F;
        final int[] codes = new int[bucketCount / 8 * 2];
        for (int i = 0; i < codes.length; i++) {
            codes[codes.length - 1 - i] = buf.get() & 0xFF;
        }
        return new TLSH(checksum, lValue, q1Ratio, q2Ratio, codes);
    }

    /**
     * Create an instance with the provided parameters.
     * 
     * @param checksum the checksum bytes
     * @param lValue   the encoded length
     * @param q1       the q1 ratio
     * @param q2       the q2 ratio
     * @param codes    the buckets
     * @return the hash instance.
     */
    public static TLSH of(final int[] checksum, final int lValue, final int q1, final int q2, final int[] codes) {
        return new TLSH(checksum, lValue, q1, q2, codes);
    }

    /**
     * Create an instance with the provided parameters.
     * 
     * @param checksum the checksum bytes
     * @param count    the number of bytes digested
     * @param q1       the 1st quartile
     * @param q2       the 2nd quartile
     * @param q3       the 3rd quartile
     * @param code     the buckets
     * @return the hash instance.
     */
    public static TLSH of(final int[] checksum, final long count, final long q1, final long q2, final long q3,
            final int[] code) {
        final int lvalue = lCapturing(count);
        final int q1ratio = (int) (q1 * 100.0f / q3) & 0x0F;
        final int q2ratio = (int) (q2 * 100.0f / q3) & 0x0F;

        return TLSH.of(checksum, lvalue, q1ratio, q2ratio, code);
    }
}
