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
package app.keve.ktlsh.spi;

import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import app.keve.ktlsh.impl.TLSH;
import app.keve.ktlsh.impl.TLSHDigest4;
import app.keve.ktlsh.impl.TLSHDigest5;
import app.keve.ktlsh.impl.TLSHDigest6;
import app.keve.ktlsh.impl.TLSHDigest7;
import app.keve.ktlsh.impl.TLSHDigest8;

/**
 * The provider for the K set of algorithms to compute TLSH.
 * 
 * @author keve
 *
 */
public final class KProvider extends Provider {
    /** The canonical name of the provider. */
    public static final String NAME = "KProvider";
    /** The MessageDigest type string. */
    private static final String MESSAGE_DIGEST = "MessageDigest";
    /** The SPI class. */
    private static final String MESSAGE_DIGEST_SPI = "app.keve.ktlsh.spi.TLSHMessageDigestSpiK";
    /** Version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Initialise the K provider with the known algorithms.
     */
    public KProvider() {
        super(NAME, "1.0.1",
                "Implementation of the TLSH - Trend Locality Sensitive Hash MessageDigest using app.keve.ktlsh.");

        final int[] buckets = {TLSH.BUCKET_48, TLSH.BUCKET_128, TLSH.BUCKET_256};
        final int[] checksums = {1, 3};
        final int[] windowSizes = {TLSHDigest4.WINDOW_LENGTH, TLSHDigest5.WINDOW_LENGTH, TLSHDigest6.WINDOW_LENGTH,
                TLSHDigest7.WINDOW_LENGTH, TLSHDigest8.WINDOW_LENGTH};
        for (int bucket : buckets) {
            for (int checksum : checksums) {
                if (TLSH.BUCKET_48 == bucket && 3 == checksum) {
                    continue; // no 3 byte checksum with 48 buckets
                }
                for (int windowSize : windowSizes) {
                    final String fullName = String.format("TLSH-%d-%d/%d", bucket, checksum, windowSize);
                    if (TLSHDigest5.WINDOW_LENGTH == windowSize) {
                        final String shortName = String.format("TLSH-%d-%d", bucket, checksum);
                        if (1 == checksum && 128 == bucket) {
                            putService(new ProviderService(this, MESSAGE_DIGEST, fullName, MESSAGE_DIGEST_SPI, "TLSH",
                                    shortName));

                        } else {
                            putService(
                                    new ProviderService(this, MESSAGE_DIGEST, fullName, MESSAGE_DIGEST_SPI, shortName));
                        }
                    } else {
                        putService(new ProviderService(this, MESSAGE_DIGEST, fullName, MESSAGE_DIGEST_SPI));
                    }
                }
            }
        }
    }

    /**
     * Provider.Service for TLSH MesageDigest.
     * 
     * @author keve
     *
     */
    private static final class ProviderService extends Provider.Service {
        /** Regexp pattern for implemented algorithms. */
        private static final Pattern ALG_PATTERN = Pattern.compile("TLSH-(48|128|256)-(1|3)/([4-8])");

        ProviderService(final Provider p, final String type, final String algo, final String cn,
                final String... aliases) {
            super(p, type, algo, cn, List.of(aliases), null);
        }

        @Override
        public MessageDigestSpi newInstance(final Object ctrParamObj) throws NoSuchAlgorithmException {
            // We are only creating MessageDigest instances of this factory.
            assert MESSAGE_DIGEST.equals(getType());
//            try {
            final Matcher matcher = ALG_PATTERN.matcher(getAlgorithm());
            if (matcher.matches()) {
                final int bucketCount = Integer.valueOf(matcher.group(1));
                final int checksumCount = Integer.valueOf(matcher.group(2));
                final int windowSize = Integer.valueOf(matcher.group(3));
                return new TLSHMessageDigestSpiK(windowSize, bucketCount, checksumCount);
            }
//            } catch (final Exception ex) {
//                throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + " using " + NAME,
//                        ex);
//            }
            // this line is very hard to reach, it would mean we have a mistake in
            // constructing fullName in KProvider constructor
            // or Java code calls us with bogus parameters.
            throw new ProviderException(
                    String.format("No impl for %s %s in %s", getType(), getAlgorithm(), getClass().getName()));
        }
    }
}
