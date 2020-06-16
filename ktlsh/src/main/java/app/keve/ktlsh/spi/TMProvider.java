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

import com.trendmicro.tlsh.BucketOption;
import com.trendmicro.tlsh.ChecksumOption;

public final class TMProvider extends Provider {
    /** The canonical name of the provider. */
    public static final String NAME = "TMProvider";
    /** Version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Initialise the TM provider with the known algorithms.
     */
    public TMProvider() {
        super(NAME, "3.7.1",
                "Implementation of the TLSH - Trend Locality Sensitive Hash MessageDigest using com.trendmicro.tlsh.");

        putService(new ProviderService(this, "MessageDigest", "TLSH-128-1/5", "app.keve.ktlsh.spi.TLSHMessageDigestSpi",
                "TLSH-128-1", "TLSH"));
        putService(new ProviderService(this, "MessageDigest", "TLSH-128-3/5", "app.keve.ktlsh.spi.TLSHMessageDigestSpi",
                "TLSH-128-3"));
        putService(new ProviderService(this, "MessageDigest", "TLSH-256-1/5", "app.keve.ktlsh.spi.TLSHMessageDigestSpi",
                "TLSH-256-1"));
        putService(new ProviderService(this, "MessageDigest", "TLSH-256-3/5", "app.keve.ktlsh.spi.TLSHMessageDigestSpi",
                "TLSH-256-3"));
    }

    private static final class ProviderService extends Provider.Service {
        /** Regex pattern for implemented algorithms. */
        private static final Pattern ALG_PATTERN = Pattern.compile("TLSH-(128|256)-(1|3)/5");

        ProviderService(final Provider p, final String type, final String algo, final String cn,
                final String... aliases) {
            super(p, type, algo, cn, List.of(aliases), null);
        }

        @Override
        public Object newInstance(final Object ctrParamObj) throws NoSuchAlgorithmException {
            String type = getType();
            String algo = getAlgorithm();
            try {
                if (type.equals("MessageDigest")) {
                    Matcher matcher = ALG_PATTERN.matcher(algo);
                    if (matcher.matches()) {
                        BucketOption bucketOption = BucketOption.valueOf("BUCKETS_" + matcher.group(1));
                        ChecksumOption checksumOption = ChecksumOption.valueOf("CHECKSUM_" + matcher.group(2) + "B");
                        return new TLSHMessageDigestSpiTM(bucketOption, checksumOption);
                    }
                }
            } catch (Exception ex) {
                throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + " using TMProvider",
                        ex);
            }
            throw new ProviderException("No impl for " + algo + " " + type);
        }
    }
}
