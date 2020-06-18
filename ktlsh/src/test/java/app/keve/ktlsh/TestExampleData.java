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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test hashing and scoring based on reference testing data and expected
 * results.
 * 
 * @author keve
 *
 */
public final class TestExampleData {
    /** Base directory of the unit test data. */
    private static final String BASE = "/tlsh/Testing/";

    /** The prefix of the test file resources. */
    private static final String PATH_PREFIX = "../Testing/";

    /** TLSH provider name. */
    private final String provider;

    static {
        TLSHUtil.registerProviders();
    }

    /** Construct test class instance, assign provider to be used. */
    public TestExampleData() {
//      this.provider = TLSHUtil.providerNameTM();
        this.provider = TLSHUtil.providerNameK();
    }

    /**
     * Test the hashes in the csv file.
     * 
     * @param resourceName the name of the resource.
     * @param expectedHash the expected hash of the stream content.
     * @throws IOException              if an I/O error occurs
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException  if the provider is not registered
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("exampleLines")
    public void testCsv(final String resourceName, final String expectedHash)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest md = MessageDigest.getInstance("TLSH", provider);
        final InputStream resource = resourceStream(resourceName);
        final byte[] buf = resource.readAllBytes();
        final byte[] hash = md.digest(buf);
        final String encodedHash = TLSHUtil.encoded(hash);
        assertEquals(expectedHash, encodedHash);
    }

    private String formatAlg(final String bits, final String check) {
        return String.format("TLSH-%s-%s", bits, check);
    }

    /**
     * Test the hashes in the expLen files.
     * 
     * @param resourceGroup the resource group
     * @param bits          the number of buckets
     * @param check         the checksum bytes.
     * @param resourceName  the name of the resource
     * @param expectedHash  the expected hash of the stream content.
     * @throws IOException              if an I/O error occurs
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException  if the provider is not registered
     */
    @ParameterizedTest(name = "{1}-{2} {3}")
    @MethodSource("expLen")
    public void testExpLen(final String resourceGroup, final String bits, final String check, final String resourceName,
            final String expectedHash) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdx = MessageDigest.getInstance(formatAlg(bits, check), provider);
        final InputStream resource = resourceStream(resourceName);
        final byte[] buf = resource.readAllBytes();
        final byte[] hash = mdx.digest(buf);
        final String encodedHash = "128".equals(bits) && "1".equals(check) ? TLSHUtil.encodedT1(hash)
                : TLSHUtil.encoded(hash);
        assertEquals(expectedHash, encodedHash);
    }

    private int getScore(final MessageDigest mdx, final InputStream resource1, final InputStream resource2,
            final boolean lenDiff) throws IOException {
        final byte[] buf1 = resource1.readAllBytes();
        final byte[] hash1 = mdx.digest(buf1);
        final byte[] buf2 = resource2.readAllBytes();
        final byte[] hash2 = mdx.digest(buf2);
        return TLSHUtil.score(hash1, hash2, lenDiff);
    }

    /**
     * Test the scores in the expLenScore files.
     * 
     * @param resourceGroup the resource group
     * @param bits          the number of buckets
     * @param check         the checksum bytes.
     * @param resource1Name the name of the first resource
     * @param resource2Name the name of the second resource
     * @param expectedScore the expected score of the stream content hashes.
     * @throws IOException              if an I/O error occurs
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException  if the provider is not registered
     */
    @ParameterizedTest(name = "{1}-{2} {3}")
    @MethodSource("expLenScore")
    public void testExpLenScore(final String resourceGroup, final String bits, final String check,
            final String resource1Name, final String resource2Name, final int expectedScore)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdx = MessageDigest.getInstance(formatAlg(bits, check), provider);
        final InputStream resource1 = resourceStream(resource1Name);
        final InputStream resource2 = resourceStream(resource2Name);
        final int score = getScore(mdx, resource1, resource2, true);
        assertEquals(expectedScore, score);
    }

    /**
     * Test the scores in the expLenXRefScore files.
     * 
     * @param resourceGroup the resource group
     * @param bits          the number of buckets
     * @param check         the checksum bytes.
     * @param resource1Name the name of the first resource
     * @param resource2Name the name of the second resource
     * @param expectedScore the expected score of the stream content hashes.
     * @throws IOException              if an I/O error occurs
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException  if the provider is not registered
     */
    @ParameterizedTest(name = "{1}-{2} {3}<>{5}")
    @MethodSource("expLenXrefScore")
    public void testExpLenXrefScore(final String resourceGroup, final String bits, final String check,
            final String resource1Name, final String resource2Name, final int expectedScore)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdx = MessageDigest.getInstance(formatAlg(bits, check), provider);
        final InputStream resource1 = resourceStream(resource1Name);
        final InputStream resource2 = resourceStream(resource2Name);
        final int score = getScore(mdx, resource1, resource2, true);
        assertEquals(expectedScore, score);
    }

    /**
     * Test the scores in the expXLenScore files.
     * 
     * @param resourceGroup the resource group
     * @param bits          the number of buckets
     * @param check         the checksum bytes.
     * @param resource1Name the name of the first resource
     * @param resource2Name the name of the second resource
     * @param expectedScore the expected score of the stream content hashes.
     * @throws IOException              if an I/O error occurs
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException  if the provider is not registered
     */
    @ParameterizedTest(name = "{1}-{2} {3}")
    @MethodSource("expXLenScore")
    public void testExpXLenScore(final String resourceGroup, final String bits, final String check,
            final String resource1Name, final String resource2Name, final int expectedScore)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdx = MessageDigest.getInstance(formatAlg(bits, check), provider);
        final InputStream resource1 = resourceStream(resource1Name);
        final InputStream resource2 = resourceStream(resource2Name);
        final int score = getScore(mdx, resource1, resource2, false);
        assertEquals(expectedScore, score);
    }

    /**
     * Test the scores in the expXLenXrefScore files.
     * 
     * @param resourceGroup the resource group
     * @param bits          the number of buckets
     * @param check         the checksum bytes.
     * @param resource1Name the name of the first resource
     * @param resource2Name the name of the second resource
     * @param expectedScore the expected score of the stream content hashes.
     * @throws IOException              if an I/O error occurs
     * @throws NoSuchAlgorithmException if the TLSH algorithm is not registered
     * @throws NoSuchProviderException  if the provider is not registered
     */
    @ParameterizedTest(name = "{1}-{2} {3}")
    @MethodSource("expXLenXrefScore")
    public void testExpXLenXrefScore(final String resourceGroup, final String bits, final String check,
            final String resource1Name, final String resource2Name, final int expectedScore)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest mdx = MessageDigest.getInstance(formatAlg(bits, check), provider);
        final InputStream resource1 = resourceStream(resource1Name);
        final InputStream resource2 = resourceStream(resource2Name);
        final int score = getScore(mdx, resource1, resource2, false);
        assertEquals(expectedScore, score);
    }

    /**
     * Provide the lines of the csv test description.
     * 
     * @return the stream of arguments.
     */
    static Stream<Arguments> exampleLines() {
        final Class<?> clazz = TestExampleData.class;
        final InputStream rs = clazz.getResourceAsStream(BASE + "example_data_col_swap.csv");
        final Stream<String> lines = new BufferedReader(new InputStreamReader(rs, StandardCharsets.UTF_8)).lines();
        return lines.map(l -> {
            final int x = l.indexOf(',');
            final String resourceName = l.substring(0, x);
            final String expectedHash = l.substring(x + 1);
            return Arguments.of(resourceName, expectedHash);
        });
    }

    private InputStream resourceStream(final String resourceName) {
        return getClass().getResourceAsStream(BASE + resourceName);
    }

    /**
     * Provide the lines of the
     * example_data.&lt;&lt;bits&gt;&gt;.&lt;&lt;checksum&gt;&gt;.len_out_EXP tests.
     * 
     * @return the stream of arguments.
     */
    static Stream<Arguments> expLen() {
        final Stream<String> bits = Stream.of("128", "256");
        final Stream<Arguments> ret = bits.flatMap(b -> Stream.of("1", "3").flatMap(c -> {
            final String name = String.format("example_data.%s.%s.len.out_EXP", b, c);
            final Class<?> clazz = TestExampleData.class;
            final InputStream rs = clazz.getResourceAsStream(BASE + "exp/" + name);
            final Stream<Arguments> lines = new BufferedReader(new InputStreamReader(rs, StandardCharsets.UTF_8))
                    .lines().map(l -> {
                        final int x = l.indexOf("\t");
                        final String expectedHash = l.substring(0, x);
                        String resourceName = l.substring(x + 1);
                        if (resourceName.startsWith(PATH_PREFIX)) {
                            resourceName = resourceName.substring(PATH_PREFIX.length());
                        }
                        return Arguments.of(name, b, c, resourceName, expectedHash);
                    });
            return lines;
        }));
        return ret;
    }

    private static Stream<Arguments> score(final String f) {
        final Stream<String> bits = Stream.of("128", "256");
        final Stream<Arguments> ret = bits.flatMap(b -> Stream.of("1", "3").flatMap(c -> {
            final String name = String.format(f, b, c);
            final Class<?> clazz = TestExampleData.class;
            final InputStream rs = clazz.getResourceAsStream(BASE + "exp/" + name);
            final Stream<Arguments> lines = new BufferedReader(new InputStreamReader(rs, StandardCharsets.UTF_8))
                    .lines().map(l -> {
                        final int x1 = l.indexOf('\t');
                        final int x2 = l.indexOf('\t', x1 + 1);
                        String resourceName1 = l.substring(0, x1);
                        String resourceName2 = l.substring(x1 + 1, x2);
                        final int expectedScore = Integer.valueOf(l.substring(x2 + 1));
                        if (resourceName1.startsWith(PATH_PREFIX)) {
                            resourceName1 = resourceName1.substring(PATH_PREFIX.length());
                        }
                        if (resourceName2.startsWith(PATH_PREFIX)) {
                            resourceName2 = resourceName2.substring(PATH_PREFIX.length());
                        }
                        return Arguments.of(name, b, c, resourceName1, resourceName2, expectedScore);
                    });
            return lines;
        }));
        return ret;
    }

    /**
     * Provide the lines of the
     * example_data.&lt;&lt;bits&gt;&gt;.&lt;&lt;checksum&gt;&gt;.len.scores_EXP
     * tests.
     * 
     * @return the stream of arguments.
     */
    static Stream<Arguments> expLenScore() {
        return score("example_data.%s.%s.len.scores_EXP");
    }

    /**
     * Provide the lines of the
     * example_data.&lt;&lt;bits&gt;&gt;.&lt;&lt;checksum&gt;&gt;.xlen.scores_EXP
     * tests.
     * 
     * @return the stream of arguments.
     */
    static Stream<Arguments> expLenXrefScore() {
        return score("example_data.%s.%s.len.xref.scores_EXP");
    }

    /**
     * Provide the lines of the
     * example_data.&lt;&lt;bits&gt;&gt;.&lt;&lt;checksum&gt;&gt;.xlen.scores_EXP
     * tests.
     * 
     * @return the stream of arguments.
     */
    static Stream<Arguments> expXLenScore() {
        return score("example_data.%s.%s.xlen.scores_EXP");
    }

    /**
     * Provide the lines of the
     * example_data.&lt;&lt;bits&gt;&gt;.&lt;&lt;checksum&gt;&gt;.xlen.scores_EXP
     * tests.
     * 
     * @return the stream of arguments.
     */
    static Stream<Arguments> expXLenXrefScore() {
        return score("example_data.%s.%s.xlen.xref.scores_EXP");
    }

}
