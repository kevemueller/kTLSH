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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

        final int[] buckets = {128, 256};
        final int[] checksum = {1, 3};
        final int[] windowSize = {TLSHDigest4.WINDOW_LENGTH, TLSHDigest5.WINDOW_LENGTH, TLSHDigest6.WINDOW_LENGTH,
                TLSHDigest7.WINDOW_LENGTH, TLSHDigest8.WINDOW_LENGTH};
        for (int i = 0; i < buckets.length; i++) {
            for (int j = 0; j < checksum.length; j++) {
                for (int k = 0; k < windowSize.length; k++) {
                    final String fullName = String.format("TLSH-%d-%d/%d", buckets[i], checksum[j], windowSize[k]);
                    if (TLSHDigest5.WINDOW_LENGTH == windowSize[k]) {
                        final String shortName = String.format("TLSH-%d-%d", buckets[i], checksum[j]);
                        if (1 == checksum[j] && 128 == buckets[i]) {
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

    private static final class ProviderService extends Provider.Service {
        /** Regex pattern for implemented algorithms. */
        private static final Pattern ALG_PATTERN = Pattern.compile("TLSH-(128|256)-(1|3)/([4-8])");

        ProviderService(final Provider p, final String type, final String algo, final String cn,
                final String... aliases) {
            super(p, type, algo, cn, List.of(aliases), null);
        }

        @SuppressWarnings("checkstyle:IllegalCatch")
        @Override
        public Object newInstance(final Object ctrParamObj) throws NoSuchAlgorithmException {
            final String type = getType();
            final String algo = getAlgorithm();
            try {
                if (MESSAGE_DIGEST.equals(type)) {
                    final Matcher matcher = ALG_PATTERN.matcher(algo);
                    if (matcher.matches()) {
                        final int bucketCount = Integer.valueOf(matcher.group(1));
                        final int checksumCount = Integer.valueOf(matcher.group(2));
                        final int windowSize = Integer.valueOf(matcher.group(3));
                        return new TLSHMessageDigestSpiK(windowSize, bucketCount, checksumCount);
                    }
                }
            } catch (final Exception ex) {
                throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + " using " + NAME,
                        ex);
            }
            throw new ProviderException("No impl for " + algo + " " + type);
        }
    }
}
