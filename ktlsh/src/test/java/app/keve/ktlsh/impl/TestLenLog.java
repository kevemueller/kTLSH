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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Test the conversion of the length to log(length).
 * 
 * @author keve
 *
 */
@SuppressWarnings("checkstyle:MagicNumber")
public final class TestLenLog {
    /** The topval array used in CPP reference implementation. */
    private static final long[] TOPVAL_REFERENCE = {1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854,
            1110, 1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907,
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

    /** Natural logarithm of 1.5. */
    private static final double LOG_1_5 = 0.4054651;
    /** Natural logarithm of 1.3. */
    private static final double LOG_1_3 = 0.26236426;
    /** Natural logarithm of 1.1. */
    private static final double LOG_1_1 = 0.095310180;

    /**
     * Compare the lookup based and the log calculation based algorithms for all
     * positive values of Long. Print the length thresholds causing an increase in
     * the log value.
     * 
     * <p>
     * Runs long...
     */
    @Test
    @Disabled
    public void testLen() {
        int last = -1;
        for (long l = 0; l < Long.MAX_VALUE; l++) {
            final int lenLog = TLSH.lCapturingLog(l);
            final int lCapture = TLSH.lCapturing(l);
            if (lCapture != last) {
                System.out.printf("%d - %d\n", last, l - 1);
                last = lCapture;
            }
            assertEquals(lCapture, lenLog, String.format("Mismatch at %d", l));
        }
    }

    /**
     * Compare the lookup based and the log calculation based algorithms for
     * specific values of Long.
     */
    @Test
    public void testLenSpecific() {
        for (int i = 0; i < 256; i++) {
            for (int j : new int[] {-5, -1, 0, +1, +5}) {
                final long len = TLSH.TOPVAL[i] + j;
                final int lenLog = TLSH.lCapturingLog(len);
                final int lCapture = TLSH.lCapturing(len);
                assertEquals(lCapture, lenLog, String.format("Mismatch at %d ([%d]%d)", len, i, j));
            }
        }
    }

    /**
     * Compare the lookup based and the naive log calculation based algorithms for
     * specific values of Long.
     */
    @Test
    @Disabled("Used to show mismatch in Java reference implementation")
    public void testLenSpecificNaive() {
        for (int i = 0; i < 256; i++) {
            for (int j : new int[] {-5, -1, 0, +1, +5}) {
                final long len = TLSH.TOPVAL[i] + j;
                final int lenLog = lCapturingNaive((int) len);
                final int lCapture = TLSH.lCapturing(len);
                assertEquals(lCapture, lenLog, String.format("Mismatch at %d ([%d]%d)", len, i, j));
            }
        }
    }

    /**
     * Find the location of the threshold by using a directed search based on the
     * mathematical reorganization of the log function. Compare the array with the
     * entries used by the lookup code.
     * 
     */
    @Test
    public void testInvLen() {
        final long[] topval = new long[256];
        for (int i = 1; i <= 256; i++) {
            long len;
            if (i <= 15) {
                len = (long) Math.pow(Math.E, 0.405465 * i);
            } else if (i <= 22) {
                len = (long) (9.87351 * Math.pow(Math.E, 0.262364 * i));
            } else {
                len = (long) (388.147 * Math.pow(Math.E, 0.0953102 * i));
            }
            while (i <= TLSH.lCapturingLog(len)) {
                len--;
            }
            if (i < 256) {
                System.out.printf(", /* %d  */ %d%s", i - 1, len, len > Integer.MAX_VALUE ? "L" : "");
            } else {
                System.out.printf(", /* %d  */ /* %dL */ Long.MAX_VALUE", i - 1, len);
                len = Long.MAX_VALUE;
            }
            topval[i - 1] = len;
        }
        System.out.println();
        assertArrayEquals(TLSH.TOPVAL, topval);
    }

    /**
     * Compare the lookup codes entries with the reference implementation's entries.
     * 
     */
    @Test
    public void testTopValReference() {
        final long[] tlshTopVal = Arrays.copyOf(TLSH.TOPVAL, TOPVAL_REFERENCE.length);
        assertArrayEquals(TOPVAL_REFERENCE, tlshTopVal);
    }

    /**
     * Test that TOPVAL entries are indeed threshold steps.
     */
    @Test
    public void testTopVal() {
        for (int i = 0; i < 255; i++) {
            final int lm = TLSH.lCapturingLog(TLSH.TOPVAL[i]);
            final int ll = TLSH.lCapturingLog(TLSH.TOPVAL[i] + 1);
            assertEquals(lm + 1, ll, String.format("Mismatch at %d", i));
        }
    }

    /**
     * Compute length portion of TLSH. Naïve implementation.
     * 
     * @param len the length
     * @return the log
     */
    private int lCapturingNaive(final int len) {
        final int i;
        if (len <= 656) {
            i = (int) Math.floor(Math.log(len) / LOG_1_5);
        } else if (len <= 3199) {
            i = (int) Math.floor(Math.log(len) / LOG_1_3 - 8.72777);
        } else {
            i = (int) Math.floor(Math.log(len) / LOG_1_1 - 62.5472);
        }

        return i & 0xFF;
    }

}
