# kTLSH
A fresh look at implementing TLSH in Java.

[![Apache License, Version 2.0, January 2004](https://img.shields.io/github/license/kevemueller/kTLSH.svg?label=License)](http://www.apache.org/licenses/)
[![Maven Central](https://img.shields.io/maven-central/v/app.keve.ktlsh/ktlsh.svg?label=Maven%20Central)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22app.keve.ktlsh%22%20AND%20a%3A%22ktlsh%22)
![Java CI with Maven](https://github.com/kevemueller/kTLSH/workflows/Java%20CI%20with%20Maven/badge.svg)

## Purpose
This source implements the [TLSH - Trend Locality Sensitive Hash](https://github.com/trendmicro/tlsh) method in Java language.

While there are already Java implementations of the method, the current one was written with specific design goals in mind.
- Specification compliant and unit tested
- Java look-and-feel compliant
- Performant

## Usage
The module is built with maven. Details on the maven build are at the [kTLSH site](https://ktlsh.keve.app/). There are also [API docs](https://ktlsh.keve.app/apidocs/). 

Usage follows the pattern used by the other hash methods available in Java.

```
MessageDigest tlshDigest = MessageDigest.getInstance("TLSH");

tlshDigest.update("Hello world!".getBytes());
final byte[] hash1 = tlshDigest.digest();
final String encoded1 = TLSHUtil.encoded(hash1);

final byte[] hash2 = tlshDigest.digest("Goodbye Cruel World".getBytes());
final String encoded2 = TLSHUtil.encoded(hash2);

final int score = TLSHUtil.score(hash1, hash2, false);
```

All published TLSH algorithm variants are supported using the following name selector `TLSH-(48|128|256)-(1|3)/[4-8]`, where `48`, `128` or `256` is the number of buckets, `1` or `3`  is the number of checksum bytes and the optional `/4` to `/8` suffix is the window size. The window size defaults to 5 bytes and may be omitted. Note that with 48 buckets only 1 checksum byte is specified. 
That is the full list of algorithms is:

| 4B window       | 5B window                                   | 6B window      | 7B window      | 8B window      |
| --------------- | ------------------------------------------- | -------------- | -------------- | -------------- |
| `TLSH-48-1/4`   | `TLSH-48-1/5` aka `TLSH-48-1`               | `TLSH-48-1/6`  | `TLSH-48-1/7`  | `TLSH-48-1/8`  |
| `TLSH-128-1/4`  | `TLSH-128-1/5` aka `TLSH-128-1` aka `TLSH`  | `TLSH-128-1/6` | `TLSH-128-1/7` | `TLSH-128-1/8` | 
| `TLSH-128-3/4`  | `TLSH-128-3/5` aka `TLSH-128-3`             | `TLSH-128-3/6` | `TLSH-128-3/7` | `TLSH-128-3/8` |
| `TLSH-256-1/4`  | `TLSH-256-1/5` aka `TLSH-256-1`             | `TLSH-256-1/6` | `TLSH-256-1/7` | `TLSH-256-1/8` | 
| `TLSH-256-3/4`  | `TLSH-256-3/5` aka `TLSH-256-3`             | `TLSH-256-3/6` | `TLSH-256-3/7` | `TLSH-256-3/8` |

The module only exports the `TLSHUtil` utility class. It contains the  `score` utility function that computes the score difference between the provided two hashes as well as formatters for the hexadecimal representation of the TLSH hash number.

## Compliance with the design goals
### Specification compliant and unit tested
The source code follows in relevant parts the choices made in the C reference implementation of the algorithm. The hashes obtained and scores calculated are unit tested against the published test data and expected results of the C reference implementation. All tests pass.

### Java look-and-feel compliant
The module exposes the TLSH algorithm the standard way by defining a MessageDigest service provider. This ensures that the TLSH hash can be computed by the library clients the same way as any other hash would be computed. 

The code is following Java source code coding guidelines as published by Sun and checked by checkstyle.

The algorithm is implemented using Java runtime features wherever possible, the code is written to be easy to read and follow.

### Performant
The implementation was tuned with care to perform even on large and very large input streams. For this purpose a separate [JMH](https://openjdk.java.net/projects/code-tools/jmh/) benchmark sub-module was created.
Performance optimisation was performed only when it did not conflict with previous design goals.
Performance was defined as raw hash bandwidth as well as stress on the Java GC (i.e. no unnecessary creation of objects).

The output of the benchmark harness is as follows

```
Benchmark                         Mode  Cnt       Score   Error  Units
HashBenchmark.testKLarge16MiB    thrpt    2  114142.230          ops/s
HashBenchmark.testKSmall32KiB    thrpt    2  115001.934          ops/s
HashBenchmark.testTMLarge16MiB   thrpt    2   92331.462          ops/s
HashBenchmark.testTMSmall32KiB   thrpt    2   94514.575          ops/s
HashBenchmark.testMD5Large16MiB  thrpt    2  507247.038          ops/s
HashBenchmark.testMD5Small32KiB  thrpt    2  497034.176          ops/s
```
The results show that the implementation is approximately 24% faster on large datasets and approximately. 22% faster on small datasets compared to the reference Java port. Preliminary comparison on large datasets of the C++ implementation show that the C++ implementation is comparable in speed to the reference Java implementation, i.e. slower than this Java implementation.

As a comparison the performance of the MD5 hash on the same datasets is also obtained.

All numbers are scaled to KiB/s hashing bandwidth, i.e. the implementation hashes 112MiB/s on the developers MacBook Pro.

Further increase in performance is currently being investigated.

## Other implementations
The reference implementation of the algorithm including a reference port to Java language can be found in the [authors' repository](https://github.com/trendmicro/tlsh).

Another implementation can be found under [https://github.com/idealista/tlsh](https://github.com/idealista/tlsh).

## Notable differences
### Match with the C++ reference implementation
This implementation follows the original C++ reference implementation and not the Java reference implementation.

### Arbitrary input size
This implementation will compute hashes for all input sizes between 0 and Long.MAX_VALUE, i.e. 8EiB. The C++ reference implementation will only produce a hash if a minimum of 50 bytes and a minimum level of entropy was fed into the digester. Also the C++ implementation has an upper bound of 2GiB.

## Feedback
The author is happy for any feedback and suggestion.
