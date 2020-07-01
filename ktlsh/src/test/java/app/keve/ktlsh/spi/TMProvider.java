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

import com.trendmicro.tlsh.BucketOption;
import com.trendmicro.tlsh.ChecksumOption;

/**
 * The provider for the TM set of algorithms to compute TLSH.
 * 
 * @author keve
 *
 */
public final class TMProvider extends Provider {
    /** The canonical name of the provider. */
    public static final String NAME = "TMProvider";

    /** The MessageDigest name. */
    private static final String MESSAGE_DIGEST = "MessageDigest";

    /** The SPI class name. */
    private static final String MESSAGE_DIGEST_SPI = "app.keve.ktlsh.spi.TLSHMessageDigestSpi";
    /** Version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Initialise the TM provider with the known algorithms.
     */
    public TMProvider() {
        super(NAME, "3.7.1",
                "Implementation of the TLSH - Trend Locality Sensitive Hash MessageDigest using com.trendmicro.tlsh.");

        putService(new ProviderService(this, MESSAGE_DIGEST, "TLSH-128-1/5", MESSAGE_DIGEST_SPI, "TLSH-128-1", "TLSH"));
        putService(new ProviderService(this, MESSAGE_DIGEST, "TLSH-128-3/5", MESSAGE_DIGEST_SPI, "TLSH-128-3"));
        putService(new ProviderService(this, MESSAGE_DIGEST, "TLSH-256-1/5", MESSAGE_DIGEST_SPI, "TLSH-256-1"));
        putService(new ProviderService(this, MESSAGE_DIGEST, "TLSH-256-3/5", MESSAGE_DIGEST_SPI, "TLSH-256-3"));
    }

    private static final class ProviderService extends Provider.Service {
        /** Regex pattern for implemented algorithms. */
        private static final Pattern ALG_PATTERN = Pattern.compile("TLSH-(128|256)-(1|3)/5");

        ProviderService(final Provider p, final String type, final String algo, final String cn,
                final String... aliases) {
            super(p, type, algo, cn, List.of(aliases), null);
        }

        @Override
        public MessageDigestSpi newInstance(final Object ctrParamObj) throws NoSuchAlgorithmException {
            // We are only creating MessageDigest instances of this factory.
            assert MESSAGE_DIGEST.equals(getType());
//           try {
            final Matcher matcher = ALG_PATTERN.matcher(getAlgorithm());
            if (matcher.matches()) {
                final BucketOption bucketOption = BucketOption.valueOf("BUCKETS_" + matcher.group(1));
                final ChecksumOption checksumOption = ChecksumOption.valueOf("CHECKSUM_" + matcher.group(2) + "B");
                return new TLSHMessageDigestSpiTM(bucketOption, checksumOption);
            }
//                } catch (final Exception ex) {
//                throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + " using TMProvider",
//                        ex);
//            }
            throw new ProviderException(
                    String.format("No impl for %s %s in %s", getType(), getAlgorithm(), getClass().getName()));
        }
    }
}
