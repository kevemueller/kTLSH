# kTLSH
A fresh look at implementing TLSH in Java.

## Purpose
This source implements the [TLSH - Trend Locality Sensitive Hash](https://github.com/trendmicro/tlsh) method in Java language.

While there are already Java implementations of the method, the current one was written with specific design goals in mind.
- Specfication compliant and unit tested
- Java look-and-feel compliant
- Performant

## Usage
The module is built with maven.

Usage follows the pattern used by the other hash methods available in Java.

```
MessageDigest tlshDigest = MessageDigest.getInstance("TLSH");
tlshDigest.update("Hello world!");
byte[] hash = tlshDigest.digest();
```

All published TLSH algorithm variants are supported using the following name selector `TLSH-(128|256)-(1|3)/[4-8]`, where `128` or `256` is the number of buckets, `1` or `3`  is the number of checksum bytes and the optional `/4` to `/8` suffix is the window size.

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
The results show that the implementation is approx. 24% faster on large datasets and approx. 22% faster on small datasets compared to the reference Java port.

As a comparison the performance of the MD5 hash on the same datasets is also obtained.

All numbers are scaled to KiB/s hashing bandwith, i.e. the implementation hashes 112MiB/s on the developers MacBook Pro.

Further increase in performance is currently being investigated.

## Other implementations
The reference implementation of the algorithm including a reference port to Java language can be found in the [authors' repository](https://github.com/trendmicro/tlsh).

Another implementation can be found under [https://github.com/idealista/tlsh](https://github.com/idealista/tlsh).


## Feedback
The author is happy for any feedback and suggestion.
