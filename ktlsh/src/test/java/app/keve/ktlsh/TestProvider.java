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
package app.keve.ktlsh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import app.keve.ktlsh.impl.TLSHDigest4;
import app.keve.ktlsh.impl.TLSHDigest5;
import app.keve.ktlsh.impl.TLSHDigest6;
import app.keve.ktlsh.impl.TLSHDigest7;
import app.keve.ktlsh.impl.TLSHDigest8;
import app.keve.ktlsh.testutil.Util;

/**
 * The registering and retrieving the providers.
 * 
 * @author keve
 *
 */
public final class TestProvider {
    /** The default TLSH algorithm name. */
    private static final String TLSH = "TLSH";
    /** 64KiB medium size buffer length. */
    private static final int MEDIUM_SIZE = 65536;

    static {
        Util.registerProvider();
    }

    /**
     * Test obtaining the provider.
     */
    @Test
    public void testProvider() {
        final Provider p = Security.getProvider(TLSHUtil.providerNameK());
        assertNotNull(p);

        System.out.println("KeveAppProvider provider name is " + p.getName());
        System.out.println("KeveAppProvider provider info is " + p.getInfo());
    }

    /**
     * Test obtaining the default instance from both providers.
     */
    @Test
    public void testInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest mdTLSH = MessageDigest.getInstance(TLSH, TLSHUtil.providerNameK());
        assertNotNull(mdTLSH);

        System.out.println("TLSH provider " + mdTLSH.getProvider());
        System.out.println("TLSH algname " + mdTLSH.getAlgorithm());
        System.out.println("TLSH length " + mdTLSH.getDigestLength());

        mdTLSH = MessageDigest.getInstance(TLSH, Util.providerNameTM());
        assertNotNull(mdTLSH);

        System.out.println("TLSH provider " + mdTLSH.getProvider());
        System.out.println("TLSH algname " + mdTLSH.getAlgorithm());
        System.out.println("TLSH length " + mdTLSH.getDigestLength());

    }

    /**
     * Test obtaining all common instances from both providers (window size 5).
     */
    @Test
    public void testAllInstances() throws NoSuchAlgorithmException, NoSuchProviderException {
        final int[] buckets = {128, 256};
        final int[] checksum = {1, 3};
        final String[] provider = {TLSHUtil.providerNameK(), Util.providerNameTM()};

        for (int i = 0; i < buckets.length; i++) {
            for (int j = 0; j < checksum.length; j++) {
                for (int k = 0; k < provider.length; k++) {
                    final String algorithm = String.format("TLSH-%d-%d", buckets[i], checksum[j]);
                    final MessageDigest md = MessageDigest.getInstance(algorithm, provider[k]);
                    assertNotNull(md);
                    assertEquals(algorithm, md.getAlgorithm());
                    assertEquals(provider[k], md.getProvider().getName());
                    assertEquals(checksum[j] + 2 + buckets[i] / 8 * 2, md.getDigestLength());
                }
            }
        }
    }

    /**
     * Test obtaining all instances from K provider (all window sizes).
     */
    @Test
    public void testWindowSize() throws NoSuchAlgorithmException, NoSuchProviderException {
        final int[] buckets = {128, 256};
        final int[] checksum = {1, 3};
        final int[] windowSize = {TLSHDigest4.WINDOW_LENGTH, TLSHDigest5.WINDOW_LENGTH, TLSHDigest6.WINDOW_LENGTH,
                TLSHDigest7.WINDOW_LENGTH, TLSHDigest8.WINDOW_LENGTH};

        for (int i = 0; i < buckets.length; i++) {
            for (int j = 0; j < checksum.length; j++) {
                for (int k = 0; k < windowSize.length; k++) {
                    final String algorithm = String.format("TLSH-%d-%d/%d", buckets[i], checksum[j], windowSize[k]);
                    final MessageDigest md = MessageDigest.getInstance(algorithm, TLSHUtil.providerNameK());
                    assertNotNull(md);
                    assertEquals(algorithm, md.getAlgorithm());
                    assertEquals(TLSHUtil.providerNameK(), md.getProvider().getName());
                    assertEquals(checksum[j] + 2 + buckets[i] / 8 * 2, md.getDigestLength());
                }
            }
        }
    }

    /**
     * Test calculating hash by both providers.
     * 
     * @param provider the provider name.
     */
    @ParameterizedTest
    @ValueSource(strings = {"KProvider", "TMProvider"})
    public void testHash(final String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdTLSH = MessageDigest.getInstance(TLSH, provider);
        assertNotNull(mdTLSH);

        final SecureRandom rnd = Util.rnd();
        final byte[] buf = new byte[rnd.nextInt(MEDIUM_SIZE)];
        rnd.nextBytes(buf);
        final byte[] hash1 = mdTLSH.digest(buf);
        assertNotNull(hash1);

        final byte[] hash2 = mdTLSH.digest(buf);
        assertNotNull(hash2);

        assertArrayEquals(hash1, hash2);

        assertEquals(mdTLSH.getDigestLength(), hash1.length);
    }

    /**
     * Test calculating hash of trivial input.
     * 
     * @param provider the provider name.
     */
    @ParameterizedTest
    @ValueSource(strings = {"KProvider", "TMProvider"})
    public void testHashTrivial(final String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdTLSH = MessageDigest.getInstance(TLSH, provider);
        assertNotNull(mdTLSH);

        final byte[] buf = new byte[128];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (byte) i;
        }
        final byte[] hash1 = mdTLSH.digest(buf);
        assertNotNull(hash1);

        System.out.println(TLSHUtil.encoded(hash1));

        final byte[] hash2 = mdTLSH.digest(buf);
        assertNotNull(hash2);

        assertArrayEquals(hash1, hash2);

        assertEquals(mdTLSH.getDigestLength(), hash1.length);
    }
}
