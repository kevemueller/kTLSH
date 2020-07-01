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

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.trendmicro.tlsh.Tlsh;
import com.trendmicro.tlsh.TlshCreator;

/**
 * Utility class to access internals of the TM implementation classes for
 * testing/debugging purposes.
 * 
 * @author keve
 *
 */
public final class TMTestUtil {
    /** Internal fields of TlshCreator. */
    private static Map<String, Field> tlshCreatorFields;
    /** Internal fields of Tlsh. */
    private static Map<String, Field> tlshFields;
    static {
        tlshCreatorFields = new HashMap<>();
        for (final Field f : TlshCreator.class.getDeclaredFields()) {
            f.setAccessible(true);
            tlshCreatorFields.put(f.getName(), f);
        }
        tlshFields = new HashMap<>();
        for (final Field f : Tlsh.class.getDeclaredFields()) {
            f.setAccessible(true);
            tlshFields.put(f.getName(), f);
        }
    }

    private TMTestUtil() {
    }

    @SuppressWarnings("unchecked")
    private static <T> T get(final Tlsh tlsh, final String name) {
        try {
            return (T) tlshFields.get(name).get(tlsh);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T get(final TlshCreator tlsh, final String name) {
        try {
            return (T) tlshCreatorFields.get(name).get(tlsh);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * get Tlsh.checksum.
     * 
     * @param tlsh the tlsh instance
     * @return the value of the checksum field.
     */
    public static int[] getChecksum(final Tlsh tlsh) {
        return get(tlsh, "checksum");
    }

    /**
     * get TlshCreator.checksum.
     * 
     * @param tlsh the TlshCreator instance
     * @return the value of the checksumArray field.
     */
    public static int getChecksum(final TlshCreator tlsh) {
        return get(tlsh, "checksum");
    }

    /**
     * get Tlsh.Lvalue.
     * 
     * @param tlsh the tlsh instance
     * @return the value of the Lvalue field.
     */
    public static int getLvalue(final Tlsh tlsh) {
        return get(tlsh, "Lvalue");
    }

    /**
     * get Tlsh.Q1ratio.
     * 
     * @param tlsh the tlsh instance
     * @return the value of the Q1ratio field.
     */
    public static int getQ1ratio(final Tlsh tlsh) {
        return get(tlsh, "Q1ratio");
    }

    /**
     * get Tlsh.Q2ratio.
     * 
     * @param tlsh the tlsh instance
     * @return the value of the Q2ratio field.
     */
    public static int getQ2ratio(final Tlsh tlsh) {
        return get(tlsh, "Q2ratio");
    }

    /**
     * get Tlsh.codes.
     * 
     * @param tlsh the tlsh instance
     * @return the value of the codes field.
     */
    public static int[] getCodes(final Tlsh tlsh) {
        return get(tlsh, "codes");
    }

    /**
     * get TlshCreator.a_bucket.
     * 
     * @param tlsh the TlshCreator instance
     * @return the value of the a_bucket field.
     */
    public static long[] getABucket(final TlshCreator tlsh) {
        return get(tlsh, "a_bucket");
    }

    /**
     * get TlshCreator.slide_window.
     * 
     * @param tlsh the TlshCreator instance
     * @return the value of the slide_window field.
     */
    public static int[] getSlideWindow(final TlshCreator tlsh) {
        return get(tlsh, "slide_window");
    }

    /**
     * get TlshCreator.checksumArray.
     * 
     * @param tlsh the TlshCreator instance
     * @return the value of the checksumArray field.
     */
    public static int[] getChecksumArray(final TlshCreator tlsh) {
        return get(tlsh, "checksumArray");
    }

    /**
     * get TlshCreator.data_len.
     * 
     * @param tlsh the TlshCreator instance
     * @return the value of the data_len field.
     */
    public static int getDataLen(final TlshCreator tlsh) {
        return get(tlsh, "data_len");
    }

    private static void dump(final PrintStream out, final Collection<Field> fields, final Object c) {
        try {
            for (final Field f : fields) {
                if (f.getType().isArray()) {
                    final Object a = f.get(c);
                    if (a instanceof long[]) {
                        final long[] la = (long[]) a;
                        out.printf("%s[%d]=\n", f.getName(), la.length);
                        for (int i = 0; i < la.length; i++) {
                            if (la[i] > 0) {
                                out.printf("%d:%d\n", i, la[i]);
                            }
                        }
                    } else if (a instanceof int[]) {
                        final int[] ia = (int[]) a;
                        out.printf("%s[%d]=%s\n", f.getName(), ia.length, Arrays.toString(ia));
                    } else {
                        out.printf("%s=%s\n", f.getName(), Arrays.toString((Object[]) a));
                    }
                } else {
                    out.printf("%s=%s\n", f.getName(), f.get(c));
                }
            }
        } catch (final IllegalAccessException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Dump the fields of a TlshCreator instance.
     * 
     * @param c the TlshCreator instance.
     */
    public static void dump(final TlshCreator c) {
        dump(System.out, tlshCreatorFields.values(), c);
    }

    /**
     * Dump the fields of a Tlsh instance.
     * 
     * @param tTLSH the Tlsh instance.
     */
    public static void dump(final Tlsh tTLSH) {
        dump(System.out, tlshFields.values(), tTLSH);
    }

    /**
     * Assert that the internal states of reference implementation and K
     * implementation are equal.
     * 
     * @param tlsh the TlshCreator instance of the reference implementation
     * @param kd   the TLSHDigest of the K implementation
     */
    public static void assertEqualState(final TlshCreator tlsh, final TLSHDigest kd) {
        final AbstractTLSHDigest akd = (AbstractTLSHDigest) kd;
        assertArrayEquals(getABucket(tlsh), akd.aBucket);
        if (1 == akd.checkSumLength) {
            assertEquals(getChecksum(tlsh), akd.checksum[0]);
        } else {
            assertArrayEquals(getChecksumArray(tlsh), akd.checksum);
        }
        final int dataLen = getDataLen(tlsh);
        assertEquals(dataLen, akd.count);
        final int[] lag = akd.getLag();
        final int[] slideWindow = getSlideWindow(tlsh);

        final int[] lagWindow = new int[slideWindow.length - 1];
        final int j = dataLen % slideWindow.length;
        for (int i = 1; i < slideWindow.length; i++) {
            final int ji = (j - i + slideWindow.length) % slideWindow.length;
            lagWindow[i - 1] = slideWindow[ji];
        }
        assertArrayEquals(lagWindow, lag);
    }

    /**
     * Assert that the internal states of reference implementation and K
     * implementation are equal.
     * 
     * @param tTLSH the Tlsh instance of the reference implementation
     * @param kTLSH the TLSH instance of the K implementation
     */
    public static void assertEqualState(final Tlsh tTLSH, final TLSH kTLSH) {
        assertArrayEquals(getChecksum(tTLSH), kTLSH.checksum);
        assertEquals(getLvalue(tTLSH), kTLSH.lValue);
        assertEquals(getQ1ratio(tTLSH), kTLSH.q1);
        assertEquals(getQ2ratio(tTLSH), kTLSH.q2);
        assertArrayEquals(getCodes(tTLSH), kTLSH.body);
    }

}
