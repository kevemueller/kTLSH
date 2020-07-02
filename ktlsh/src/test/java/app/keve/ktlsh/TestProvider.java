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
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import app.keve.ktlsh.impl.TLSH;
import app.keve.ktlsh.impl.TLSHDigest4;
import app.keve.ktlsh.impl.TLSHDigest5;
import app.keve.ktlsh.impl.TLSHDigest6;
import app.keve.ktlsh.impl.TLSHDigest7;
import app.keve.ktlsh.impl.TLSHDigest8;
import app.keve.ktlsh.testutil.TestUtil;

/**
 * The registering and retrieving the providers.
 * 
 * @author keve
 *
 */
public final class TestProvider extends AbstractTest {
    /** Random bits. */
    private static final int AA = 0xAA;
    /** The default TLSH algorithm name. */
    private static final String ALG_TLSH = "TLSH";
    /** 64KiB medium size buffer length. */
    private static final int MEDIUM_SIZE = 65536;

    /**
     * Reference hashes for all algorithms with all window sizes
     * (128|256)-(1|3)/(4|5|6|7|8).
     */

    private static final Map<String, String> REFERENCE_HASHES = Map.ofEntries(
            Map.entry("TLSH-48-1/4", "FF538CC197800AA3252C438C3C9606"),
            Map.entry("TLSH-48-1/5", "5753EBC1EB720DA7180E03483C6B66"),
            Map.entry("TLSH-48-1/6", "7853BBC0EE140D9B2D1E83042C1BAA"),
            Map.entry("TLSH-48-1/7", "7853D341B6280CC71E0CC20DB82F98"),
            Map.entry("TLSH-48-1/8", "9553B743747108831AAEC67E789FE5"),
            Map.entry("TLSH-128-1/4", "FF532B40C3043D53F028D4D680987105058C5A5D47A301C197800FA3252C438C3CD707"),
            Map.entry("TLSH-128-1/5", "57532B8997453D416035B5D9D01F120B4D4CFA884F5B01C1EF764DA71C1E074D3D7B66"),
            Map.entry("TLSH-128-1/6", "78532341852A7E422121F4D6652F210E444C9A144E7B00C0EE191D9B2E1E87556C5BAA"),
            Map.entry("TLSH-128-1/7", "7853C8008525AFA93172F9C1153F500F95BC52144E7B0041B6784CD71F1CD21DBC6F99"),
            Map.entry("TLSH-128-1/8", "9553F715890DFE6832BBFA897E7B240B91BDD5648E290143747108431A59C66D385FE5"),
            Map.entry("TLSH-128-3/4", "FFE371532B40C3043D53F028D4D680987105058C5A5D47A301C197800FA3252C438C3CD707"),
            Map.entry("TLSH-128-3/5", "573D60532B8997453D416035B5D9D01F120B4D4CFA884F5B01C1EF764DA71C1E074D3D7B66"),
            Map.entry("TLSH-128-3/6", "78AB12532341852A7E422121F4D6652F210E444C9A144E7B00C0EE191D9B2E1E87556C5BAA"),
            Map.entry("TLSH-128-3/7", "78AB1253C8008525AFA93172F9C1153F500F95BC52144E7B0041B6784CD71F1CD21DBC6F99"),
            Map.entry("TLSH-128-3/8", "95085D53F715890DFE6832BBFA897E7B240B91BDD5648E290143747108431A59C66D385FE5"),
            Map.entry("TLSH-256-1/4",
                    "FF532B00194C396B20D0B505D048029D24E0C84030CC3018045908108D30C06CC0465340C3"
                            + "043D53F028D4D680987105058C5A5D47A301C197800FA3252C438C3CD707"),
            Map.entry("TLSH-256-1/5",
                    "57532B05955D1EA730E17241C08C074C3DD1CF5C53CC580C1E2D3064CCF0E05DD8C1528997"
                            + "453D416035B5D9D01F120B4D4CFA884F5B01C1EF764DA71C1E074D3D7B66"),
            Map.entry("TLSH-256-1/6",
                    "78532305818E984330A03281804E121C3ED189CC4699886C351D30B18EF4A0298445614185"
                            + "2A7E422121F4D6652F210E444C9A144E7B00C0EE191D9B2E1E87556C5BAA"),
            Map.entry("TLSH-256-1/7",
                    "7853C8048D8AD99730E132D09049022D3BD2DDCC610DDD6C313C32F6CEF8B038D441610095"
                            + "25AFA93172F9D1557F501F95BD56144E7B0041B6785DD71F5DD25DBC6F99"),
            Map.entry("TLSH-256-1/8",
                    "9553B700898BE8D3345535C1884E051D36C5ABCC941A8D6C593D32B6CFE4607DC811321589"
                            + "0DFE6832BBFA897E7B240B91BDD5648E290143747108431A59C66D785FE5"),
            Map.entry("TLSH-256-3/4",
                    "FFE371532B00194C396B20D0B505D048029D24E0C84030CC3018045908108D30C06CC04653"
                            + "40C3043D53F028D4D680987105058C5A5D47A301C197800FA3252C438C3CD707"),
            Map.entry("TLSH-256-3/5",
                    "573D60532B05955D1EA730E17241C08C074C3DD1CF5C53CC580C1E2D3064CCF0E05DD8C152"
                            + "8997453D416035B5D9D01F120B4D4CFA884F5B01C1EF764DA71C1E074D3D7B66"),
            Map.entry("TLSH-256-3/6",
                    "78AB12532305818E984330A03281804E121C3ED189CC4699886C351D30B18EF4A029844561"
                            + "41852A7E422121F4D6652F210E444C9A144E7B00C0EE191D9B2E1E87556C5BAA"),
            Map.entry("TLSH-256-3/7",
                    "78AB1253C8048D8AD99730E132D09049022D3BD2DDCC610DDD6C313C32F6CEF8B038D44161"
                            + "009525AFA93172F9D1557F501F95BD56144E7B0041B6785DD71F5DD25DBC6F99"),
            Map.entry("TLSH-256-3/8", "95085D53B700898BE8D3345535C1884E051D36C5ABCC941A8D6C593D32B6CFE4607DC81132"
                    + "15890DFE6832BBFA897E7B240B91BDD5648E290143747108431A59C66D785FE5"));

    static {
        TestUtil.registerProvider();
    }

    /**
     * Test obtaining the provider.
     * 
     */
    @Test
    public void testProvider() {
        final Provider p = Security.getProvider(TLSHUtil.providerNameK());
        assertNotNull(p);

        LOGGER.info("KProvider provider name is {}", p.getName());
        LOGGER.info("KProvider provider info is {}", p.getInfo());
        assertEquals(TLSHUtil.providerNameK(), p.getName());
    }

    /**
     * Test obtaining the default instance from both providers.
     */
    @Test
    public void testInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest mdTLSH = MessageDigest.getInstance(ALG_TLSH, TLSHUtil.providerNameK());
        assertNotNull(mdTLSH);

        LOGGER.info("TLSH provider K {}", mdTLSH.getProvider());
        LOGGER.info("TLSH algname K {}", mdTLSH.getAlgorithm());
        LOGGER.info("TLSH length K {}", mdTLSH.getDigestLength());
        assertEquals(TLSHUtil.providerNameK(), mdTLSH.getProvider().getName());
        assertEquals(ALG_TLSH, mdTLSH.getAlgorithm());

        mdTLSH = MessageDigest.getInstance(ALG_TLSH, TestUtil.providerNameTM());
        assertNotNull(mdTLSH);

        LOGGER.info("TLSH provider TM {}", mdTLSH.getProvider());
        LOGGER.info("TLSH algname TM {}", mdTLSH.getAlgorithm());
        LOGGER.info("TLSH length TM {}", mdTLSH.getDigestLength());
        assertEquals(TestUtil.providerNameTM(), mdTLSH.getProvider().getName());
        assertEquals(ALG_TLSH, mdTLSH.getAlgorithm());
    }

    /**
     * Test obtaining all common instances from both providers (window size 5).
     */
    @Test
    public void testAllInstances() throws NoSuchAlgorithmException, NoSuchProviderException {
        final int[] buckets = {128, 256};
        final int[] checksums = {1, 3};
        final String[] providers = {TLSHUtil.providerNameK(), TestUtil.providerNameTM()};

        for (int bucket : buckets) {
            for (int checksum : checksums) {
                for (String provider : providers) {
                    final String algorithm = String.format("TLSH-%d-%d", bucket, checksum);
                    final MessageDigest md = MessageDigest.getInstance(algorithm, provider);
                    assertNotNull(md);
                    assertEquals(algorithm, md.getAlgorithm());
                    assertEquals(provider, md.getProvider().getName());
                    assertEquals(checksum + 2 + bucket / 8 * 2, md.getDigestLength());
                }
            }
        }
    }

    /**
     * Test obtaining all instances from K provider (all window sizes).
     */
    @Test
    public void testWindowSize() throws NoSuchAlgorithmException, NoSuchProviderException {
        final int[] buckets = {TLSH.BUCKET_48, TLSH.BUCKET_128, TLSH.BUCKET_256};
        final int[] checksums = {1, 3};
        final int[] windowSizes = {TLSHDigest4.WINDOW_LENGTH, TLSHDigest5.WINDOW_LENGTH, TLSHDigest6.WINDOW_LENGTH,
                TLSHDigest7.WINDOW_LENGTH, TLSHDigest8.WINDOW_LENGTH};

        for (int bucket : buckets) {
            for (int checksum : checksums) {
                if (48 == bucket && 3 == checksum) {
                    continue;
                }
                for (int windowSize : windowSizes) {
                    final String algorithm = String.format("TLSH-%d-%d/%d", bucket, checksum, windowSize);
                    final MessageDigest md = MessageDigest.getInstance(algorithm, TLSHUtil.providerNameK());
                    assertNotNull(md);
                    assertEquals(algorithm, md.getAlgorithm());
                    assertEquals(TLSHUtil.providerNameK(), md.getProvider().getName());
                    assertEquals(checksum + 2 + bucket / 8 * 2, md.getDigestLength());
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
        final MessageDigest mdTLSH = MessageDigest.getInstance(ALG_TLSH, provider);
        assertNotNull(mdTLSH);

        final SecureRandom rnd = TestUtil.rnd();
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
        final MessageDigest mdTLSH = MessageDigest.getInstance(ALG_TLSH, provider);
        assertNotNull(mdTLSH);

        final byte[] buf = new byte[128];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (byte) i;
        }
        final byte[] hash1 = mdTLSH.digest(buf);
        assertNotNull(hash1);

        LOGGER.info(TLSHUtil.encoded(hash1));

        final byte[] hash2 = mdTLSH.digest(buf);
        assertNotNull(hash2);

        assertArrayEquals(hash1, hash2);

        assertEquals(mdTLSH.getDigestLength(), hash1.length);
    }

    /**
     * Test obtaining all instances from K provider (all window sizes) and hash
     * reference input.
     */
    @Test
    public void testWindowSizeReference() throws NoSuchAlgorithmException, NoSuchProviderException {
        final int[] buckets = {48, 128, 256};
        final int[] checksums = {1, 3};
        final int[] windowSizes = {TLSHDigest4.WINDOW_LENGTH, TLSHDigest5.WINDOW_LENGTH, TLSHDigest6.WINDOW_LENGTH,
                TLSHDigest7.WINDOW_LENGTH, TLSHDigest8.WINDOW_LENGTH};

        final byte[] referenceInput = new byte[MEDIUM_SIZE];
        for (int i = 0; i < referenceInput.length; i++) {
            referenceInput[i] = (byte) (i ^ AA);
        }

        for (int bucket : buckets) {
            for (int checksum : checksums) {
                if (48 == bucket && 3 == checksum) {
                    continue;
                }
                for (int windowSize : windowSizes) {
                    final String algorithm = String.format("TLSH-%d-%d/%d", bucket, checksum, windowSize);
                    final MessageDigest md = MessageDigest.getInstance(algorithm, TLSHUtil.providerNameK());
                    final byte[] kHash = md.digest(referenceInput);

                    if (48 != bucket && TLSHDigest5.WINDOW_LENGTH == windowSize) {
                        final MessageDigest td = MessageDigest.getInstance(algorithm, TestUtil.providerNameTM());
                        final byte[] tmHash = td.digest(referenceInput);
                        assertArrayEquals(tmHash, kHash, "@" + algorithm);
                    }
                    assertEquals(REFERENCE_HASHES.get(algorithm), TLSHUtil.encoded(kHash));
//                    System.out.println("Map.entry(\"" + algorithm + "\",\"" + TLSHUtil.encoded(kHash) + "\"),");

                    // also check the conversion from hash to TLSH instance.
                    assertEquals(0, TLSHUtil.score(kHash, kHash, true));
                }
            }
        }
    }

}
