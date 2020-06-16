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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.trendmicro.tlsh.Tlsh;
import com.trendmicro.tlsh.TlshCreator;

import app.keve.ktlsh.TLSHUtil;

public final class TestDigest {
    /** 64KiB length. */
    private static final int MEDIUM_LENGTH_64KIB = 65536;

    /** 32KiB length. */
    private static final int MEDIUM_LENGTH_32KIB = 32768;

    /** 2KiB length. */
    private static final int MEDIUM_LENGTH_2KIB = 2048;

    /** Base directory of the unit test data. */
    private static final String BASE = "/tlsh/Testing/";

    /** Internal fields of TlshCreator. */
    private static List<Field> tlshCreatorFields;
    /** Internal fields of Tlsh. */
    private static List<Field> tlshFields;
    static {
        tlshCreatorFields = new ArrayList<Field>();
        for (Field f : TlshCreator.class.getDeclaredFields()) {
            f.setAccessible(true);
            tlshCreatorFields.add(f);
        }
        tlshFields = new ArrayList<Field>();
        for (Field f : Tlsh.class.getDeclaredFields()) {
            f.setAccessible(true);
            tlshFields.add(f);
        }
    }

    private void dump(final List<Field> fields, final Object c)
            throws IllegalArgumentException, IllegalAccessException {
        for (Field f : fields) {
            if (f.getType().isArray()) {
                Object a = f.get(c);
                if (a instanceof long[]) {
                    long[] la = (long[]) a;
                    System.out.printf("%s[%d]=\n", f.getName(), la.length);
                    for (int i = 0; i < la.length; i++) {
                        if (la[i] > 0) {
                            System.out.printf("%d:%d\n", i, la[i]);
                        }
                    }
                } else if (a instanceof int[]) {
                    int[] ia = (int[]) a;
                    System.out.printf("%s[%d]=%s\n", f.getName(), ia.length, Arrays.toString(ia));
                } else {
                    System.out.printf("%s=%s\n", f.getName(), Arrays.toString((Object[]) a));
                }
            } else {
                System.out.printf("%s=%s\n", f.getName(), f.get(c));
            }
        }
    }

    private void dump(final TlshCreator c) throws IllegalArgumentException, IllegalAccessException {
        dump(tlshCreatorFields, c);
    }

    private void dump(final Tlsh tTLSH) throws IllegalArgumentException, IllegalAccessException {
        dump(tlshFields, tTLSH);
    }

    /**
     * Test matching state on incremental update.
     * 
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     */
    @Test
    public void testUpdate() throws IllegalArgumentException, IllegalAccessException {
        TLSHDigest kd = TLSHDigest.of();
        TlshCreator td = new TlshCreator();

        for (byte i = 1; i < 8; i++) {
            kd.update(i);
            System.out.println(kd);

            td.update(new byte[] {i});
            dump(td);

            System.out.println("---");
        }
    }

    /**
     * Test matching state on full update.
     * 
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testDigestFull() throws IllegalArgumentException, IllegalAccessException, NoSuchAlgorithmException {
        TLSHDigest kd = TLSHDigest.of();
        TlshCreator td = new TlshCreator();
        SecureRandom rnd = SecureRandom.getInstance("NativePRNGNonBlocking");

        byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        kd.update(buf);
        td.update(buf);

        System.out.println(kd);
        dump(td);

        TLSH kTLSH = kd.digest();
        Tlsh tTLSH = td.getHash();
        System.out.println(kTLSH);
        dump(tTLSH);

        String kHash = TLSHUtil.encoded(kTLSH.pack());
        String tHash = tTLSH.toString();
        System.out.println(kHash);
        System.out.println(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Incremental updates with single byte.
     * 
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testDigest1() throws IllegalArgumentException, IllegalAccessException, NoSuchAlgorithmException {
        TLSHDigest kd = TLSHDigest.of();
        TlshCreator td = new TlshCreator();
        SecureRandom rnd = SecureRandom.getInstance("NativePRNGNonBlocking");

        byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        for (int i = 0; i < buf.length; i++) {
            kd.update(buf[i]);
            td.update(new byte[] {buf[i]});
        }

        System.out.println(kd);
        dump(td);

        TLSH kTLSH = kd.digest();
        Tlsh tTLSH = td.getHash();
        System.out.println(kTLSH);
        dump(tTLSH);

        String kHash = TLSHUtil.encoded(kTLSH.pack());
        String tHash = tTLSH.toString();
        System.out.println(kHash);
        System.out.println(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Incremental updates with smaller than windowsize buffers.
     * 
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testDigestSmall() throws IllegalArgumentException, IllegalAccessException, NoSuchAlgorithmException {
        TLSHDigest kd = TLSHDigest.of();
        TlshCreator td = new TlshCreator();
        SecureRandom rnd = SecureRandom.getInstance("NativePRNGNonBlocking");

        byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        ByteBuffer bb = ByteBuffer.wrap(buf);
        while (bb.hasRemaining()) {
            byte[] iu = new byte[Math.min(bb.remaining(), rnd.nextInt(4))];
            bb.get(iu);
            kd.update(iu);
            td.update(iu);
        }

        System.out.println(kd);
        dump(td);

        TLSH kTLSH = kd.digest();
        Tlsh tTLSH = td.getHash();
        System.out.println(kTLSH);
        dump(tTLSH);

        String kHash = TLSHUtil.encoded(kTLSH.pack());
        String tHash = tTLSH.toString();
        System.out.println(kHash);
        System.out.println(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Incremental updates with medium sized buffers.
     * 
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testDigestMedium() throws IllegalArgumentException, IllegalAccessException, NoSuchAlgorithmException {
        TLSHDigest kd = TLSHDigest.of();
        TlshCreator td = new TlshCreator();
        SecureRandom rnd = SecureRandom.getInstance("NativePRNGNonBlocking");

        byte[] buf = new byte[MEDIUM_LENGTH_32KIB + rnd.nextInt(MEDIUM_LENGTH_64KIB)];
        rnd.nextBytes(buf);

        ByteBuffer bb = ByteBuffer.wrap(buf);
        while (bb.hasRemaining()) {
            byte[] iu = new byte[Math.min(bb.remaining(), rnd.nextInt(MEDIUM_LENGTH_2KIB))];
            bb.get(iu);
            kd.update(iu);
            td.update(iu);
        }

        System.out.println(kd);
        dump(td);

        TLSH kTLSH = kd.digest();
        Tlsh tTLSH = td.getHash();
        System.out.println(kTLSH);
        dump(tTLSH);

        String kHash = TLSHUtil.encoded(kTLSH.pack());
        String tHash = tTLSH.toString();
        System.out.println(kHash);
        System.out.println(tHash);

        assertEquals(kHash, tHash);
    }

    /**
     * Test hashing a resource.
     * 
     * @throws IOException
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     */
    @Test
    public void testResource() throws IOException, IllegalArgumentException, IllegalAccessException {
        String resource = "example_data/021106_yossivassa.txt";
        String expectedEncoded = "1FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE";
        InputStream in = getClass().getResourceAsStream(BASE + resource);
        byte[] buf = in.readAllBytes();

        TLSHDigest kd = TLSHDigest.of();
        TlshCreator td = new TlshCreator();
        kd.update(buf);
        td.update(buf);

        System.out.println(kd);
        dump(td);

        TLSH kTLSH = kd.digest();
        Tlsh tTLSH = td.getHash();
        System.out.println(kTLSH);
        dump(tTLSH);

        String kHash = TLSHUtil.encoded(kTLSH.pack());
        String tHash = tTLSH.toString();
        System.out.println(kHash);
        System.out.println(tHash);

        assertEquals(expectedEncoded, tHash);
        assertEquals(expectedEncoded, kHash);
    }
}
