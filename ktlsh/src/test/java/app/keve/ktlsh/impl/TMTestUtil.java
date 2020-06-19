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

    private static void dump(final Collection<Field> fields, final Object c) {
        try {
            for (final Field f : fields) {
                if (f.getType().isArray()) {
                    final Object a = f.get(c);
                    if (a instanceof long[]) {
                        final long[] la = (long[]) a;
                        System.out.printf("%s[%d]=\n", f.getName(), la.length);
                        for (int i = 0; i < la.length; i++) {
                            if (la[i] > 0) {
                                System.out.printf("%d:%d\n", i, la[i]);
                            }
                        }
                    } else if (a instanceof int[]) {
                        final int[] ia = (int[]) a;
                        System.out.printf("%s[%d]=%s\n", f.getName(), ia.length, Arrays.toString(ia));
                    } else {
                        System.out.printf("%s=%s\n", f.getName(), Arrays.toString((Object[]) a));
                    }
                } else {
                    System.out.printf("%s=%s\n", f.getName(), f.get(c));
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
        dump(tlshCreatorFields.values(), c);
    }

    /**
     * Dump the fields of a Tlsh instance.
     * 
     * @param tTLSH the Tlsh instance.
     */
    public static void dump(final Tlsh tTLSH) {
        dump(tlshFields.values(), tTLSH);
    }

}
