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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Implementation of Pearson's hash function. Follows original publication:
 * https://web.archive.org/web/20120704025921/http://cs.mwsu.edu/~griffin/courses/2133/downloads/Spring11/p677-pearson.pdf
 *
 */
public final class Pearson {
    /** Pearson's sample random table from aforementioned publication. */
    public static final int[] T = {1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14, 197, 213,
            181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103, 141, 253, 255, 50, 77, 101,
            81, 18, 45, 96, 31, 222, 25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235, 97, 234,
            57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248, 174, 169, 211, 58, 66, 154, 106, 195, 245,
            171, 17, 187, 182, 179, 0, 243, 132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
            119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10, 138, 30, 48, 183, 156, 35, 61, 26,
            143, 74, 251, 94, 129, 162, 63, 152, 170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
            125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123, 118, 73, 2, 157, 46, 116, 9, 145,
            134, 228, 207, 212, 202, 215, 69, 229, 27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39,
            203, 233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76, 140, 36, 210, 172, 41, 54,
            159, 8, 185, 232, 113, 196, 231, 47, 146, 120, 51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71,
            109, 184, 209};

    /** The permutation to use for hashing. */
    public final int[] t;
    /** The pre-computed hashCode of the permutation array. */
    private final int hashCode;

    private Pearson(final int[] t) {
        this.t = t;
        hashCode = Arrays.hashCode(t);
    }

    /**
     * Hash a byte buffer.
     * 
     * @param buf the buffer to hash
     * @return the unsigned byte hash value
     */
    public int hash(final byte[] buf) {
        int h = 0;
        for (int i = 0; i < buf.length; i++) {
            h = t[h ^ (buf[i] & 0xFF)];
        }
        return h;
    }

    /**
     * Hash a single byte.
     * 
     * @param i the byte to hash
     * @return the unsigned byte hash value
     */
    public int hash(final int i) {
        return t[i];
    }

    /**
     * Hash a two bytes.
     * 
     * @param i the first byte to hash
     * @param j the second byte.
     * @return the unsigned byte hash value
     */
    public int hash(final int i, final int j) {
        return t[t[i] ^ j];
    }

    /**
     * Hash a three bytes.
     * 
     * @param i the first byte to hash
     * @param j the second byte.
     * @param k the third byte.
     * @return the unsigned byte hash value
     */
    public int hash(final int i, final int j, final int k) {
        return t[t[t[i] ^ j] ^ k];
    }

    /**
     * Hash a sequence of bytes.
     * 
     * @param buf the bytes to hash
     * @return the unsigned byte hash value
     */
    public int hash(final int... buf) {
        int h = 0;
        for (int i = 0; i < buf.length; i++) {
            h = t[h ^ buf[i]];
        }
        return h;
    }

    /**
     * Obtain a Pearson hash instance for the default permutation.
     * 
     * @return the instance.
     */
    public static Pearson defaultInstance() {
        return Pearson.of(T);
    }

    /**
     * Obtain a Pearson hash instance for a random permutation.
     * 
     * @return the instance.
     */
    public static Pearson randomInstance() {
        int[] t = new int[256];
        List<Integer> l = IntStream.range(0, 256).boxed().collect(Collectors.toList());
        Collections.shuffle(l);
        int i = 0;
        for (Iterator<Integer> it = l.iterator(); it.hasNext();) {
            t[i++] = it.next();
        }

        return Pearson.of(t);
    }

    /**
     * Obtain a Pearson hash instance the given permutation.
     * 
     * @param t the permutation
     * @return the instance.
     */
    public static Pearson of(final int[] t) {
        if (256 != t.length || 256 != IntStream.of(t).distinct().count()) {
            throw new IllegalArgumentException("Bad permutation!");
        }
        for (int i = 0; i < t.length; i++) {
            if (t[i] < 0 || t[i] >= 256) {
                throw new IllegalArgumentException("Bad value " + t[i] + ".");
            }
        }
        return new Pearson(t.clone());
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Pearson)) {
            return false;
        }
        Pearson other = (Pearson) obj;
        return hashCode == other.hashCode && Arrays.equals(t, other.t);
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer("Pearson");
        sb.append(Arrays.toString(t));
        return sb.toString();
    }
}
