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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

public class TestPearson {
    /**
     * Test Pearson default instance.
     */
    @Test
    public void testDefaultInstance() {
        Pearson p = Pearson.defaultInstance();
        assertEquals(256, IntStream.of(p.t).distinct().count());
        for (int i = 0; i < 256; i++) {
            assertEquals(Pearson.T[i], p.hash(i));
        }
    }

    /**
     * Test Pearson default instance hashing 1 byte.
     */
    @Test
    public void testHashByte() {
        Pearson p = Pearson.defaultInstance();
        assertEquals(256, IntStream.of(p.t).distinct().count());
        for (int i = 0; i < 256; i++) {
            assertEquals(Pearson.T[i], p.hash(new byte[] {(byte) i}));
        }
    }

    /**
     * Test Pearson random instance.
     */
    @Test
    public void testRandomInstance() {
        Pearson p = Pearson.randomInstance();
        System.out.println(p);
        assertEquals(256, IntStream.of(p.t).distinct().count());
    }

    /**
     * Test Pearson equals.
     */
    @Test
    public void testEquals() {
        assertEquals(Pearson.defaultInstance(), Pearson.of(Pearson.T));
        Pearson p = Pearson.randomInstance();
        assertFalse(Pearson.defaultInstance().equals(p));
        assertEquals(p, Pearson.of(p.t));
    }

    /**
     * Test Pearson providing erroneous permutation.
     */
    @Test
    public void testBadPermutation() {
        List<Integer> l = IntStream.range(0, 256).boxed().collect(Collectors.toList());
        Collections.shuffle(l);
        int[] t = new int[256];
        int i = 0;
        for (Iterator<Integer> it = l.iterator(); it.hasNext();) {
            t[i++] = it.next();
        }

        t[128] = t[0];

        assertThrows(IllegalArgumentException.class, () -> Pearson.of(t));
    }

    /**
     * Test Pearson providing erroneous permutation value.
     */
    @Test
    public void testBadRange() {
        List<Integer> l = IntStream.range(0, 256).boxed().collect(Collectors.toList());
        Collections.shuffle(l);
        int[] t = new int[256];
        int i = 0;
        for (Iterator<Integer> it = l.iterator(); it.hasNext();) {
            t[i++] = it.next();
        }

        t[128] = -t[128];
        assertThrows(IllegalArgumentException.class, () -> Pearson.of(t));

        t[128] = -t[128];
        t[255] = 256;
        assertThrows(IllegalArgumentException.class, () -> Pearson.of(t));

    }

}
