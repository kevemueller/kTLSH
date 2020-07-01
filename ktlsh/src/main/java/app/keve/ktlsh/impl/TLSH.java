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
            /* 15 */ 656, /* 16 */ 854, /* 17 */ 1_110, /* 18 */ 1443, /* 19 */ 1876, /* 20 */ 2439, /* 21 */ 3171,
            /* 22 */ 3475, /* 23 */ 3823, /* 24 */ 4205, /* 25 */ 4626, /* 26 */ 5088, /* 27 */ 5597, /* 28 */ 6157,
            /* 29 */ 6772, /* 30 */ 7450, /* 31 */ 8195, /* 32 */ 9014, /* 33 */ 9916, /* 34 */ 10_907, /* 35 */ 11_998,
            /* 36 */ 13_198, /* 37 */ 14_518, /* 38 */ 15_970, /* 39 */ 17_567, /* 40 */ 19_323, /* 41 */ 21_256,
            /* 42 */ 23_382, /* 43 */ 25_720, /* 44 */ 28_292, /* 45 */ 31_121, /* 46 */ 34_233, /* 47 */ 37_656,
            /* 48 */ 41_422, /* 49 */ 45_564, /* 50 */ 50_121, /* 51 */ 55_133, /* 52 */ 60_646, /* 53 */ 66_711,
            /* 54 */ 73_382, /* 55 */ 80_721, /* 56 */ 88_793, /* 57 */ 97_672, /* 58 */ 107_439, /* 59 */ 118_183,
            /* 60 */ 130_002, /* 61 */ 143_002, /* 62 */ 157_302, /* 63 */ 173_032, /* 64 */ 190_335, /* 65 */ 209_369,
            /* 66 */ 230_306, /* 67 */ 253_337, /* 68 */ 278_670, /* 69 */ 306_538, /* 70 */ 337_191, /* 71 */ 370_911,
            /* 72 */ 408_002, /* 73 */ 448_802, /* 74 */ 493_682, /* 75 */ 543_050, /* 76 */ 597_356, /* 77 */ 657_091,
            /* 78 */ 722_800, /* 79 */ 795_081, /* 80 */ 874_589, /* 81 */ 962_048, /* 82 */ 1_058_252,
            /* 83 */ 1_164_078, /* 84 */ 1_280_486, /* 85 */ 1_408_534, /* 86 */ 1_549_388, /* 87 */ 1_704_327,
            /* 88 */ 1_874_759, /* 89 */ 2_062_236, /* 90 */ 2_268_459, /* 91 */ 2_495_305, /* 92 */ 2_744_836,
            /* 93 */ 3_019_320, /* 94 */ 3_321_252, /* 95 */ 3_653_374, /* 96 */ 4_018_711, /* 97 */ 4_420_582,
            /* 98 */ 4_862_641, /* 99 */ 5_348_905, /* 100 */ 5_883_796, /* 101 */ 6_472_176, /* 102 */ 7_119_394,
            /* 103 */ 7_831_333, /* 104 */ 8_614_467, /* 105 */ 9_475_909, /* 106 */ 10_423_501, /* 107 */ 11_465_851,
            /* 108 */ 12_612_437, /* 109 */ 13_873_681, /* 110 */ 15_261_050, /* 111 */ 16_787_154,
            /* 112 */ 18_465_870, /* 113 */ 20_312_458, /* 114 */ 22_343_706, /* 115 */ 24_578_077,
            /* 116 */ 27_035_886, /* 117 */ 29_739_474, /* 118 */ 32_713_425, /* 119 */ 35_984_770,
            /* 120 */ 39_583_245, /* 121 */ 43_541_573, /* 122 */ 47_895_730, /* 123 */ 52_685_306,
            /* 124 */ 57_953_837, /* 125 */ 63_749_221, /* 126 */ 70_124_148, /* 127 */ 77_136_564,
            /* 128 */ 84_850_228, /* 129 */ 93_335_252, /* 130 */ 102_668_779, /* 131 */ 112_935_659,
            /* 132 */ 124_229_227, /* 133 */ 136_652_151, /* 134 */ 150_317_384, /* 135 */ 165_349_128,
            /* 136 */ 181_884_040, /* 137 */ 200_072_456, /* 138 */ 220_079_703, /* 139 */ 242_087_671,
            /* 140 */ 266_296_456, /* 141 */ 292_926_096, /* 142 */ 322_218_735, /* 143 */ 354_440_623,
            /* 144 */ 389_884_688, /* 145 */ 428_873_168, /* 146 */ 471_760_495, /* 147 */ 518_936_559,
            /* 148 */ 570_830_240, /* 149 */ 627_913_311, /* 150 */ 690_704_607, /* 151 */ 759_775_136,
            /* 152 */ 835_752_671, /* 153 */ 919_327_967, /* 154 */ 1_011_260_767, /* 155 */ 1_112_386_880,
            /* 156 */ 1_223_623_232, /* 157 */ 1_345_985_727, /* 158 */ 1_480_584_256, /* 159 */ 1_628_642_751,
            /* 160 */ 1_791_507_135, /* 161 */ 1_970_657_856, /* 162 */ 2_167_723_648L, /* 163 */ 2_384_496_256L,
            /* 164 */ 2_622_945_920L, /* 165 */ 2_885_240_448L, /* 166 */ 3_173_764_736L, /* 167 */ 3_491_141_248L,
            /* 168 */ 3_840_255_616L, /* 169 */ 4_224_281_216L, /* 170 */ 4_646_709_504L, /* 171 */ 5_111_380_735L,
            /* 172 */ 5_622_519_040L, /* 173 */ 6_184_770_816L, /* 174 */ 6_803_248_384L, /* 175 */ 7_483_572_991L,
            /* 176 */ 8_231_930_623L, /* 177 */ 9_055_123_968L, /* 178 */ 9_960_636_928L, /* 179 */ 10_956_701_183L,
            /* 180 */ 12_052_370_943L, /* 181 */ 13_257_608_703L, /* 182 */ 14_583_370_240L, /* 183 */ 16_041_708_032L,
            /* 184 */ 17_645_878_271L, /* 185 */ 19_410_467_839L, /* 186 */ 21_351_515_136L, /* 187 */ 23_486_667_775L,
            /* 188 */ 25_835_334_655L, /* 189 */ 28_418_870_271L, /* 190 */ 31_260_756_991L, /* 191 */ 34_386_835_455L,
            /* 192 */ 37_825_517_567L, /* 193 */ 41_608_071_168L, /* 194 */ 45_768_882_175L, /* 195 */ 50_345_768_959L,
            /* 196 */ 55_380_346_880L, /* 197 */ 60_918_384_640L, /* 198 */ 67_010_226_176L, /* 199 */ 73_711_251_455L,
            /* 200 */ 81_082_380_287L, /* 201 */ 89_190_617_088L, /* 202 */ 98_109_681_663L, /* 203 */ 107_920_658_432L,
            /* 204 */ 118_712_725_503L, /* 205 */ 130_584_006_656L, /* 206 */ 143_642_402_816L,
            /* 207 */ 158_006_648_832L, /* 208 */ 173_807_329_279L, /* 209 */ 191_188_066_303L,
            /* 210 */ 210_306_867_200L, /* 211 */ 231_337_566_208L, /* 212 */ 254_471_331_839L,
            /* 213 */ 279_918_460_927L, /* 214 */ 307_910_328_319L, /* 215 */ 338_701_369_343L,
            /* 216 */ 372_571_521_024L, /* 217 */ 409_827_917_823L, /* 218 */ 450_810_724_351L,
            /* 219 */ 495_891_791_872L, /* 220 */ 545_481_015_295L, /* 221 */ 600_029_102_079L,
            /* 222 */ 660_032_028_671L, /* 223 */ 726_035_300_351L, /* 224 */ 798_638_833_663L,
            /* 225 */ 878_502_772_736L, /* 226 */ 966_353_059_839L, /* 227 */ 1_062_988_382_207L,
            /* 228 */ 1_169_287_217_151L, /* 229 */ 1_286_216_024_063L, /* 230 */ 1_414_837_633_024L,
            /* 231 */ 1_556_321_468_416L, /* 232 */ 1_711_953_739_776L, /* 233 */ 1_883_149_107_199L,
            /* 234 */ 2_071_464_050_688L, /* 235 */ 2_278_610_567_167L, /* 236 */ 2_506_471_636_992L,
            /* 237 */ 2_757_119_049_728L, /* 238 */ 3_032_831_098_880L, /* 239 */ 3_336_114_143_231L,
            /* 240 */ 3_669_725_675_520L, /* 241 */ 4_036_698_439_680L, /* 242 */ 4_440_368_349_184L,
            /* 243 */ 4_884_405_157_887L, /* 244 */ 5_372_846_014_464L, /* 245 */ 5_910_131_113_984L,
            /* 246 */ 6_501_144_199_168L, /* 247 */ 7_151_258_697_727L, /* 248 */ 7_866_384_908_288L,
            /* 249 */ 8_653_023_477_760L, /* 250 */ 9_518_326_480_895L, /* 251 */ 10_470_159_810_560L,
            /* 252 */ 11_517_175_529_472L, /* 253 */ 12_668_893_659_136L, /* 254 */ 13_935_783_182_336L,
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
    private static final double LOG_1_5 = 0.405_465_100D;

    /** The length threshold for step 2. */
    private static final int LEN_STEP_2 = 3199;
    /** The adjustment for step 2. */
    private static final double LEN_ADJ_2 = 8.727_770D;
    /** The log(1.3) constant used in CPP reference implementation for step 2. */
    private static final double LOG_1_3 = 0.262_364_260D;

    /** The adjustment for step 3. */
    private static final double LEN_ADJ_3 = 62.547_200D;
    /** The log(1.1) constant used in CPP reference implementation for step 3. */
    private static final double LOG_1_1 = 0.095_310_180D;

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
        final StringBuilder builder = new StringBuilder(64);
        builder.append("TLSH [checksum=");
        builder.append(
                null == checksum ? null : Arrays.toString(Arrays.copyOf(checksum, Math.min(checksum.length, maxLen))));
        builder.append(", lValue=").append(lValue);
        builder.append(", q1=").append(q1);
        builder.append(", q2=").append(q2);
        builder.append(", body[").append(body.length).append("]=");
        builder.append(null == body ? null : Arrays.toString(Arrays.copyOf(body, Math.min(body.length, maxLen))));
        builder.append(']');
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

    /**
     * Diff table in embedded class to avoid immediate instantiation.
     * 
     * @author keve
     *
     */
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
        for (final int c : checksum) {
            buf.put((byte) swapNibble(c));
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
            throw new IllegalArgumentException(
                    String.format("Illegal hash buffer length: %d, must be one of 35,37,67,69", hash.length));
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
