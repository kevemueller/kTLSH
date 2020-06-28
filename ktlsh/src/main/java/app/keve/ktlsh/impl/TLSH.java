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
     * Lookup table for the logs of the length value. The last entry saturates the
     * logLength at 255.
     * 
     * <p>
     * 7 -> 25L means 25 is the highest number for which the log is 7. <br>
     * Generally speaking for the closed interval [ TOPVAL(n-1)+1 .. TOPVAL(n) ] the
     * logLength is n.
     */
    static final long[] TOPVAL = {/* 0 */ 1, /* 1 */ 2, /* 2 */ 3, /* 3 */ 5, /* 4 */ 7, /* 5 */ 11, /* 6 */ 17,
            /* 7 */ 25, /* 8 */ 38, /* 9 */ 57, /* 10 */ 86, /* 11 */ 129, /* 12 */ 194, /* 13 */ 291, /* 14 */ 437,
            /* 15 */ 656, /* 16 */ 854, /* 17 */ 1110, /* 18 */ 1443, /* 19 */ 1876, /* 20 */ 2439, /* 21 */ 3171,
            /* 22 */ 3475, /* 23 */ 3823, /* 24 */ 4205, /* 25 */ 4626, /* 26 */ 5088, /* 27 */ 5597, /* 28 */ 6157,
            /* 29 */ 6772, /* 30 */ 7450, /* 31 */ 8195, /* 32 */ 9014, /* 33 */ 9916, /* 34 */ 10907, /* 35 */ 11998,
            /* 36 */ 13198, /* 37 */ 14518, /* 38 */ 15970, /* 39 */ 17567, /* 40 */ 19323, /* 41 */ 21256,
            /* 42 */ 23382, /* 43 */ 25720, /* 44 */ 28292, /* 45 */ 31121, /* 46 */ 34233, /* 47 */ 37656,
            /* 48 */ 41422, /* 49 */ 45564, /* 50 */ 50121, /* 51 */ 55133, /* 52 */ 60646, /* 53 */ 66711,
            /* 54 */ 73382, /* 55 */ 80721, /* 56 */ 88793, /* 57 */ 97672, /* 58 */ 107439, /* 59 */ 118183,
            /* 60 */ 130002, /* 61 */ 143002, /* 62 */ 157302, /* 63 */ 173032, /* 64 */ 190335, /* 65 */ 209369,
            /* 66 */ 230306, /* 67 */ 253337, /* 68 */ 278670, /* 69 */ 306538, /* 70 */ 337191, /* 71 */ 370911,
            /* 72 */ 408002, /* 73 */ 448802, /* 74 */ 493682, /* 75 */ 543050, /* 76 */ 597356, /* 77 */ 657091,
            /* 78 */ 722800, /* 79 */ 795081, /* 80 */ 874589, /* 81 */ 962048, /* 82 */ 1058252, /* 83 */ 1164078,
            /* 84 */ 1280486, /* 85 */ 1408534, /* 86 */ 1549388, /* 87 */ 1704327, /* 88 */ 1874759, /* 89 */ 2062236,
            /* 90 */ 2268459, /* 91 */ 2495305, /* 92 */ 2744836, /* 93 */ 3019320, /* 94 */ 3321252, /* 95 */ 3653374,
            /* 96 */ 4018711, /* 97 */ 4420582, /* 98 */ 4862641, /* 99 */ 5348905, /* 100 */ 5883796,
            /* 101 */ 6472176, /* 102 */ 7119394, /* 103 */ 7831333, /* 104 */ 8614467, /* 105 */ 9475909,
            /* 106 */ 10423501, /* 107 */ 11465851, /* 108 */ 12612437, /* 109 */ 13873681, /* 110 */ 15261050,
            /* 111 */ 16787154, /* 112 */ 18465870, /* 113 */ 20312458, /* 114 */ 22343706, /* 115 */ 24578077,
            /* 116 */ 27035886, /* 117 */ 29739474, /* 118 */ 32713425, /* 119 */ 35984770, /* 120 */ 39583245,
            /* 121 */ 43541573, /* 122 */ 47895730, /* 123 */ 52685306, /* 124 */ 57953837, /* 125 */ 63749221,
            /* 126 */ 70124148, /* 127 */ 77136564, /* 128 */ 84850228, /* 129 */ 93335252, /* 130 */ 102668779,
            /* 131 */ 112935659, /* 132 */ 124229227, /* 133 */ 136652151, /* 134 */ 150317384, /* 135 */ 165349128,
            /* 136 */ 181884040, /* 137 */ 200072456, /* 138 */ 220079703, /* 139 */ 242087671, /* 140 */ 266296456,
            /* 141 */ 292926096, /* 142 */ 322218735, /* 143 */ 354440623, /* 144 */ 389884688, /* 145 */ 428873168,
            /* 146 */ 471760495, /* 147 */ 518936559, /* 148 */ 570830240, /* 149 */ 627913311, /* 150 */ 690704607,
            /* 151 */ 759775136, /* 152 */ 835752671, /* 153 */ 919327967, /* 154 */ 1011260767, /* 155 */ 1112386880,
            /* 156 */ 1223623232, /* 157 */ 1345985727, /* 158 */ 1480584256, /* 159 */ 1628642751,
            /* 160 */ 1791507135, /* 161 */ 1970657856, /* 162 */ 2167723648L, /* 163 */ 2384496256L,
            /* 164 */ 2622945920L, /* 165 */ 2885240448L, /* 166 */ 3173764736L, /* 167 */ 3491141248L,
            /* 168 */ 3840255616L, /* 169 */ 4224281216L, /* 170 */ 4646709504L, /* 171 */ 5111380735L,
            /* 172 */ 5622519040L, /* 173 */ 6184770816L, /* 174 */ 6803248384L, /* 175 */ 7483572991L,
            /* 176 */ 8231930623L, /* 177 */ 9055123968L, /* 178 */ 9960636928L, /* 179 */ 10956701183L,
            /* 180 */ 12052370943L, /* 181 */ 13257608703L, /* 182 */ 14583370240L, /* 183 */ 16041708032L,
            /* 184 */ 17645878271L, /* 185 */ 19410467839L, /* 186 */ 21351515136L, /* 187 */ 23486667775L,
            /* 188 */ 25835334655L, /* 189 */ 28418870271L, /* 190 */ 31260756991L, /* 191 */ 34386835455L,
            /* 192 */ 37825517567L, /* 193 */ 41608071168L, /* 194 */ 45768882175L, /* 195 */ 50345768959L,
            /* 196 */ 55380346880L, /* 197 */ 60918384640L, /* 198 */ 67010226176L, /* 199 */ 73711251455L,
            /* 200 */ 81082380287L, /* 201 */ 89190617088L, /* 202 */ 98109681663L, /* 203 */ 107920658432L,
            /* 204 */ 118712725503L, /* 205 */ 130584006656L, /* 206 */ 143642402816L, /* 207 */ 158006648832L,
            /* 208 */ 173807329279L, /* 209 */ 191188066303L, /* 210 */ 210306867200L, /* 211 */ 231337566208L,
            /* 212 */ 254471331839L, /* 213 */ 279918460927L, /* 214 */ 307910328319L, /* 215 */ 338701369343L,
            /* 216 */ 372571521024L, /* 217 */ 409827917823L, /* 218 */ 450810724351L, /* 219 */ 495891791872L,
            /* 220 */ 545481015295L, /* 221 */ 600029102079L, /* 222 */ 660032028671L, /* 223 */ 726035300351L,
            /* 224 */ 798638833663L, /* 225 */ 878502772736L, /* 226 */ 966353059839L, /* 227 */ 1062988382207L,
            /* 228 */ 1169287217151L, /* 229 */ 1286216024063L, /* 230 */ 1414837633024L, /* 231 */ 1556321468416L,
            /* 232 */ 1711953739776L, /* 233 */ 1883149107199L, /* 234 */ 2071464050688L, /* 235 */ 2278610567167L,
            /* 236 */ 2506471636992L, /* 237 */ 2757119049728L, /* 238 */ 3032831098880L, /* 239 */ 3336114143231L,
            /* 240 */ 3669725675520L, /* 241 */ 4036698439680L, /* 242 */ 4440368349184L, /* 243 */ 4884405157887L,
            /* 244 */ 5372846014464L, /* 245 */ 5910131113984L, /* 246 */ 6501144199168L, /* 247 */ 7151258697727L,
            /* 248 */ 7866384908288L, /* 249 */ 8653023477760L, /* 250 */ 9518326480895L, /* 251 */ 10470159810560L,
            /* 252 */ 11517175529472L, /* 253 */ 12668893659136L, /* 254 */ 13935783182336L,
            /* 255 */ /* 15329425519609L */ Long.MAX_VALUE};

    /**
     * The scaling multiplier for difference scoring.
     */
    private static final int DIFF_SCALE = 12;

    /**
     * The scaling multiplier for difference scoring of bits.
     */
    private static final int DIFF_SCALE6 = 6;

    /** The length threshold for step 1. */
    private static final int LEN_STEP_1 = 656;
    /** The log(1.5) constant used in CPP reference implementation for step 1. */
    private static final double LOG_1_5 = 0.4054651D;

    /** The length threshold for step 2. */
    private static final int LEN_STEP_2 = 3199;
    /** The adjustment for step 2. */
    private static final double LEN_ADJ_2 = 8.72777D;
    /** The log(1.3) constant used in CPP reference implementation for step 2. */
    private static final double LOG_1_3 = 0.26236426D;

    /** The adjustment for step 3. */
    private static final double LEN_ADJ_3 = 62.5472D;
    /** The log(1.1) constant used in CPP reference implementation for step 3. */
    private static final double LOG_1_1 = 0.095310180D;

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

    private static int scoreBody(final int[] bodyA, final int[] bodyB) {
        if (bodyA.length != bodyB.length) {
            throw new IllegalArgumentException(
                    String.format("Number of body bytes differ %d != %d", bodyA.length, bodyB.length));
        }

        int diff = 0;
        for (int i = 0; i < bodyA.length; i++) {
            diff += DiffTable.BIT_PAIRS_DIFF_TABLE[bodyA[i]][bodyB[i]];
        }
        return diff;
    }

    private static int scoreChecksum(final int[] checksumA, final int[] checksumB) {
        if (checksumA.length != checksumB.length) {
            throw new IllegalArgumentException(
                    String.format("Number of checksum bytes differ %d != %d", checksumA.length, checksumB.length));
        }
        return Arrays.equals(checksumA, checksumB) ? 0 : 1;
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

    /**
     * Capture the log(length) in a single byte value.
     * 
     * @param len the length
     * @return the byte value
     */
    public static int lCapturing(final long len) {
        final int x = Arrays.binarySearch(TOPVAL, len);
        return x >= 0 ? x : -x - 1;
    }

    /**
     * Capture the log(length) in a single byte value.
     * 
     * <p>
     * Math.log based implementation.
     * 
     * @param len the length
     * @return the byte value
     */
    public static int lCapturingLog(final long len) {
        if (len <= 0) {
            return 0;
        }
        double d = (float) Math.log((float) len);
        if (len <= LEN_STEP_1) {
            d = d / LOG_1_5;
        } else if (len <= LEN_STEP_2) {
            d = d / LOG_1_3 - LEN_ADJ_2;
        } else {
            d = d / LOG_1_1 - LEN_ADJ_3;
        }
//        return (int) Math.floor(d) & 0xFF;
        return Math.min((int) Math.floor(d), 255);
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
