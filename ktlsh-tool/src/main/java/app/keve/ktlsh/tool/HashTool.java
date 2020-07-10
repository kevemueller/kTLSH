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
package app.keve.ktlsh.tool;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import app.keve.ktlsh.TLSHUtil;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * CLI tool to obtain and check hashes on filesystem objects.
 * 
 * @author keve
 *
 */
@Command(name = "tlshsum", mixinStandardHelpOptions = true, version = "tlsh 1.0.2", description = "Calculate, check or cross-ref"
        + " TLSH and common hash algorithms of input or filesystem objects.", customSynopsis = {
                HashTool.TOOL_NAME + " [-aorstmM] [<paths>...] (calculate hashes)",
                HashTool.INDENTED_NAME + " -c [-a] [<paths>...]    (check hashes)",
                HashTool.INDENTED_NAME + " -x [-rmM] [<paths>...]  (cross-ref hashes)",
                HashTool.INDENTED_NAME + " -h                      (help)",
                HashTool.INDENTED_NAME + " -V                      (version)"})
public final class HashTool implements Callable<Integer> {
    /** The name of the tool for usage help purposes. */
    public static final String TOOL_NAME = "TLSHTool";
    /** The name of the tool for usage help purposes (indented). */
    public static final String INDENTED_NAME = "       " + TOOL_NAME;

    /** sums file pattern GNU style. */
    private static final Pattern GNU_LINE_PATTERN = Pattern.compile("([0-9a-fA-F]+)\\s+\\*?(.*)");
    /** sums file pattern BSD style. */
    private static final Pattern BSD_LINE_PATTERN = Pattern
            .compile("([a-zA-Z0-9/-]+)\\s+\\((.*)\\)\\s+=\\s+([0-9a-fA-F]+)");
    /** Default minimum file size (0). */
    private static final String DEFAULT_MIN_SIZE = "0";
    /** Default maximum file size (Long.MAX_VALUE). */
    private static final String DEFAULT_MAX_SIZE = "9223372036854775807";

    static class ToolMode {
        /** check mode flag. */
        @Option(names = {"-c", "--check"}, required = true, description = "Read hash values from files and check them.")
        private boolean check;
        /** xref mode flag. */
        @Option(names = {"-x", "--xref"}, required = true, description = "Cross-ref hash values.")
        private boolean xref;
    }

    /** usage mode (hash==null, check or xref. */
    @ArgGroup(exclusive = true)
    private ToolMode mode;

    /** Recursive mode. */
    @Option(names = {"-r", "--recursive"}, description = "Recurse into subdirectories.")
    private boolean recursive;

    /** The algorithm. */
    @Option(names = {"-a",
            "--algorithm"}, defaultValue = "TLSH", completionCandidates = AlgorithmCandidates.class, description = "Algorithm "
                    + "names to compute, like ${COMPLETION-CANDIDATES}.")
    private List<String> algorithms;

    /** Minimal size. */
    @Option(description = "Minimum size threshold for hashing (inclusive). Accepts unit suffixes.", names = {"-m",
            "--minimal-size"}, defaultValue = DEFAULT_MIN_SIZE, converter = SizeConverter.class)
    private long minSize;

    /** Maximal size. */
    @Option(description = "Maximum size for hashing (exclusive). Accepts unit suffixes.", names = {"-M",
            "--maximal-size"}, defaultValue = DEFAULT_MAX_SIZE, converter = SizeConverter.class)
    private long maxSize;

    /** BSD style. */
    @Option(names = {"-t", "--tag"}, description = "Create BSD style output.")
    private boolean tag;

    /** Output file name. */
    @Option(names = {"-o",
            "--output"}, description = "Write here instead of stdout.", converter = OutputConverter.class, defaultValue = "-")
    private BufferedWriter output;

    /** Optional string input argument. */
    @Option(names = {"-s", "--string"}, description = "String input(s) to hash")
    private List<String> strings = List.of();

    /** Optional file paramaters. */
    @Parameters(description = "The path(s) whose hash should be calculated or the hashsum files that should be checked."
            + " If not specified, STDIN is used.")
    private List<Path> paths = List.of();

    /** The hash printing style. */
    private Consumer<Triple> printHash;

    /** The lock for output. */
    private final Object outputLock;

    /** The lock for stderr. */
    private final Object errLock;

    private HashTool() {
        outputLock = new Object();
        errLock = new Object();
        TLSHUtil.registerProvider();
    }

    /**
     * CLI entry point.
     * 
     * @param args CL args
     * @throws IOException when an I/O error occurs.
     */
    public static void main(final String... args) throws IOException {
        final int exitCode = new CommandLine(new HashTool()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws IOException {
        printHash = tag ? this::printHashBSD : this::printHashGNU;
        try {
            if (null == mode) {
                return hash();
            } else if (mode.check) {
                return check();
            } else if (mode.xref) {
                return xref();
            } else {
                System.err.println("Unknown mode!");
                return 1;
            }
        } finally {
            output.close(); // potentially no System.out after this point.
        }
    }

    private int check() throws IOException {
        final Map<Integer, String> algByDigestLength = new HashMap<Integer, String>();
        final Map<String, MessageDigest> algs = obtainDigest(algorithms);
        for (Entry<String, MessageDigest> alg : algs.entrySet()) {
            algByDigestLength.put(alg.getValue().getDigestLength(), alg.getKey());
        }
        releaseDigest(algs);

        for (final Path p : paths) {
            Files.lines(p).parallel().forEach(l -> doLine(l, algByDigestLength));
        }
        if (paths.isEmpty()) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                reader.lines().parallel().forEach(l -> doLine(l, algByDigestLength));
            }
        }

        return 1;
    }

    private int hash() throws IOException {
        final Map<String, MessageDigest> md = obtainDigest(algorithms);
        try {

            strings.stream().filter(s -> s.length() >= minSize && s.length() < maxSize).flatMap(this::doString)
                    .forEach(printHash);

            paths.parallelStream().flatMap(this::doParameter).forEach(printHash);

            if (strings.isEmpty() && paths.isEmpty()) {
                doInputStream("-", System.in).forEach(printHash);
            }
        } finally {
            releaseDigest(md);
        }
        return 0;
    }

    private int xref() {
        if (1 != algorithms.size()) {
            System.err.println("Must have exactly one algorithm, not " + algorithms.size());
            return 1;

        }
        System.err.println(Instant.now());
        final Stream<Triple> inputStrings = strings.stream().filter(s -> s.length() >= minSize && s.length() < maxSize)
                .flatMap(this::doString);
        final Stream<Triple> inputFiles = paths.parallelStream().flatMap(this::doParameter);

        final Deque<Triple> inputs = Stream.concat(inputStrings, inputFiles)
                .collect(Collectors.toCollection(LinkedList::new));
        System.err.println(Instant.now());
        final Collection<Entry<Triple, Triple>> xref = new ArrayList<Entry<Triple, Triple>>();
        while (!inputs.isEmpty()) {
            final Triple first = inputs.poll();
            for (Triple t : inputs) {
                xref.add(Map.entry(first, t));
            }
        }
        System.err.println(Instant.now());
        xref.parallelStream().forEach(me -> {
            final int score = TLSHUtil.score(me.getKey().hash, me.getValue().hash, true);
            printScore(me.getKey(), me.getValue(), score);
            printScore(me.getValue(), me.getKey(), score);
        });
        System.err.println(Instant.now());
        return 1;
    }

    /*
     * check mode
     */

    private void doLine(final String l, final Map<Integer, String> algByDigestLength) {
        final Matcher m = GNU_LINE_PATTERN.matcher(l);
        if (m.matches()) {
            final String expectedHashString = m.group(1);
            final String alg = algByDigestLength.get(expectedHashString.length() / 2);
            final String name = m.group(2);
            if (null == alg) {
                System.err.println("No algorithm for digest length of " + expectedHashString.length() * 4 + " bits.");
            } else {
                doCheck(alg, expectedHashString, name);
            }
        } else {
            final Matcher m2 = BSD_LINE_PATTERN.matcher(l);
            if (m2.matches()) {
                final String alg = m2.group(1);
                final String name = m2.group(2);
                final String expectedHashString = m2.group(3);
                doCheck(alg, expectedHashString, name);
            } else {
                System.err.println("nada: " + l);
            }
        }
    }

    private void doCheck(final String alg, final String expectedHashString, final String name) {
        final byte[] expectedHash = TLSHUtil.hexToBytes(expectedHashString);
        final MessageDigest md = obtainDigest(alg);
        try {
            final byte[] actualHash;
            if ('`' == name.charAt(0) && '`' == name.charAt(name.length() - 1)) {
                actualHash = md.digest(name.substring(1, name.length() - 1).getBytes());
            } else {
                try (InputStream in = new DigestInputStream(Files.newInputStream(Path.of(name)), md)) {
                    in.transferTo(OutputStream.nullOutputStream());
                    actualHash = md.digest();
                } catch (IOException e) {
                    System.err.println("I/O error " + e);
                    return;
                }
            }
            final int idx = Arrays.mismatch(expectedHash, actualHash);
            if (-1 == idx) {
                System.out.println("Match for " + name);
            } else {
                System.err.printf("Mismatch @%d for %s expected %s, but got %s.\n", idx, name, expectedHashString,
                        TLSHUtil.bytesToHEX(actualHash));
            }
        } finally {
            releaseDigest(alg, md);
        }

    }

    /*
     * hash mode.
     */

    private Stream<Triple> doParameter(final Path p) {
        try {
            final BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class);
            if (attrs.isRegularFile() && attrs.size() >= minSize && attrs.size() < maxSize) {
                return doFile(p);
            } else if (attrs.isDirectory()) {
                return Files.walk(p, recursive ? Integer.MAX_VALUE : 1).parallel().filter(fp -> {
                    try {
                        final BasicFileAttributes fpa = Files.readAttributes(fp, BasicFileAttributes.class);
                        if (fpa.isDirectory()) {
                            return false;
                        } else if (fpa.isRegularFile() && fpa.size() >= minSize && fpa.size() < maxSize) {
                            return true;
                        } else {
                            System.err.printf("Skipped: %s [%d]\n", fp, fpa.size());
                            return false;
                        }
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }).flatMap(this::doFile);
            } else {
                System.err.printf("Skipped: %s [%d]\n", p, attrs.size());
            }
        } catch (NoSuchFileException e) {
            System.err.printf("File not found: %s\n", p);
        } catch (IOException e) {
            System.err.printf("I/O error: %s (%s)\n", p, e);
        }
        return Stream.of();
    }

    private static final class Triple {
        /** The algorithm name. */
        private final String algorithm;
        /** The file name. */
        private final String name;
        /** The computed hash. */
        private final byte[] hash;

        private Triple(final String algorithm, final String name, final byte[] hash) {
            this.algorithm = algorithm;
            this.name = name;
            this.hash = hash;
        }
    }

    private Stream<Triple> doString(final String s) {
        final Map<String, MessageDigest> md = obtainDigest(algorithms);
        try {
            final List<Triple> result = new ArrayList<Triple>();
            final byte[] sBytes = s.getBytes();
            for (Entry<String, MessageDigest> mdE : md.entrySet()) {
                result.add(new Triple(mdE.getKey(), "`" + s + "`", mdE.getValue().digest(sBytes)));
            }
            return result.stream();
        } finally {
            releaseDigest(md);
        }
    }

    private Stream<Triple> doFile(final Path p) {
        final Map<String, MessageDigest> md = obtainDigest(algorithms);
        try (InputStream fileStream = Files.newInputStream(p)) {
            return doInputStream(p.toString(), fileStream);
        } catch (NoSuchFileException e) {
            System.err.printf("File not found: %s\n", p);
        } catch (IOException e) {
            System.err.printf("I/O error: %s (%s)\n", p, e);
        } finally {
            releaseDigest(md);
        }
        return Stream.of();
    }

    private Stream<Triple> doInputStream(final String name, final InputStream in1) {
        final Map<String, MessageDigest> md = obtainDigest(algorithms);
        try {
            InputStream in = in1;
            for (Entry<String, MessageDigest> mdE : md.entrySet()) {
                in = new DigestInputStream(in, mdE.getValue());
            }
            in.transferTo(OutputStream.nullOutputStream());
            final List<Triple> result = new ArrayList<Triple>();
            for (Entry<String, MessageDigest> mdE : md.entrySet()) {
                result.add(new Triple(mdE.getKey(), name, mdE.getValue().digest()));
            }
            return result.stream();
        } catch (IOException e) {
            System.err.printf("I/O error: %s (%s)\n", name, e);
        } finally {
            releaseDigest(md);
        }
        return Stream.of();
    }

    /*
     * xref mode.
     */

    /*
     * utility functions.
     */

    private void printHashBSD(final Triple triple) {
        synchronized (outputLock) {
            try {
                output.write(triple.algorithm);
                output.write(" (");
                output.write(triple.name);
                output.write(") = ");
                output.write(TLSHUtil.encoded(triple.hash));
                output.newLine();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    private void printHashGNU(final Triple triple) {
        synchronized (outputLock) {
            try {
                output.write(TLSHUtil.encoded(triple.hash));
                output.write(' ');
                output.write(' ');
                output.write(triple.name);
                output.newLine();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    private void printScore(final Triple a, final Triple b, final int score) {
        synchronized (outputLock) {
            try {
                output.write(a.name);
                output.write('\t');
                output.write(b.name);
                output.write('\t');
                output.write(Integer.toString(score));
                output.newLine();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    private Map<String, MessageDigest> obtainDigest(final List<String> names) {
        final Map<String, MessageDigest> dm = new HashMap<>();
        names.forEach(n -> dm.put(n, obtainDigest(n)));
        return dm;
    }

    private MessageDigest obtainDigest(final String name) {
        try {
            final MessageDigest md = MessageDigest.getInstance(name);
            return md;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void releaseDigest(final Map<String, MessageDigest> digests) {
        digests.entrySet().forEach(e -> releaseDigest(e.getKey(), e.getValue()));
    }

    private void releaseDigest(final String name, final MessageDigest md) {
    }

    /*
     * picocli helpers
     */

    private static class SizeConverter implements ITypeConverter<Long> {
        /**
         * Pattern for acceptable input for size value. Positive double value with
         * optional K or SI unit.
         */
        private static final Pattern P = Pattern
                .compile("([+]?\\d+([.]\\d*)?|[.]\\d+)\\s*(([kMGTPEZY]?B)|([KMGTPEZY]iB))?");

        /** Multiplier for K. */
        private static final int K_MULTIPLIER = 1000;
        /** Sizes for K. */
        private static final String K_SIZES = "BkMGTPEZY";
        /** Multiplier for SI. */
        private static final int SI_MULTIPLIER = 1024;
        /** Sizes for SI. */
        private static final String SI_SIZES = "_KMGTPEZY";

        @Override
        public Long convert(final String value) throws Exception {
            if (DEFAULT_MIN_SIZE.equals(value)) {
                return 0L;
            } else if (DEFAULT_MAX_SIZE.equals(value)) {
                return Long.MAX_VALUE;
            }
            final Matcher m = P.matcher(value);
            if (m.matches()) {
                double number = Double.parseDouble(m.group(1));
                final String mK = m.group(4);
                final String mSI = m.group(5);
                if (null != mK) {
                    int idx = K_SIZES.indexOf(mK.charAt(0));
                    while (idx > 0) {
                        number *= K_MULTIPLIER;
                        idx--;
                    }
                    return (long) number;
                } else if (null != mSI) {
                    int idx = SI_SIZES.indexOf(mSI.charAt(0));
                    while (idx > 0) {
                        number *= SI_MULTIPLIER;
                        idx--;
                    }
                    return (long) number;
                } else {
                    return (long) number;
                }
            } else {
                throw new IllegalArgumentException("Cannot parse " + value + " as a size.");
            }
        }
    }

    private static class OutputConverter implements ITypeConverter<BufferedWriter> {
        @Override
        public BufferedWriter convert(final String value) throws Exception {
            if ("-".equals(value)) {
                return new BufferedWriter(new OutputStreamWriter(System.out));
            } else {
                return Files.newBufferedWriter(Path.of(value));
            }
        }
    }

    static class AlgorithmCandidates extends ArrayList<String> {
        /** default. */
        private static final long serialVersionUID = 1L;

        /** pattern to grab the aliases. */
        private static final Pattern ALIAS = Pattern.compile(".*aliases:\\s*\\[(.*)\\].*", Pattern.DOTALL);

        AlgorithmCandidates() {
            for (Provider provider : Security.getProviders()) {
                for (Provider.Service service : provider.getServices()) {
                    if ("MessageDigest".equals(service.getType())) {
                        final String alg = service.getAlgorithm();
                        final Matcher m = ALIAS.matcher(service.toString());
                        if (m.matches()) {
                            final String[] aliases = m.group(1).split(",\\s*");
                            add(alg + "=" + String.join("=", aliases));
                        } else {
                            add(alg);
                        }
                    }
                }

            }
        }
    }

}
