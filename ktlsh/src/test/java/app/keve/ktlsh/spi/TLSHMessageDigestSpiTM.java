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

import com.trendmicro.tlsh.BucketOption;
import com.trendmicro.tlsh.ChecksumOption;
import com.trendmicro.tlsh.Tlsh;
import com.trendmicro.tlsh.TlshCreator;

import app.keve.ktlsh.TLSHUtil;

/**
 * The Service Provider for the TM TLSH implementation.
 * 
 * @author keve
 *
 */
public final class TLSHMessageDigestSpiTM extends MessageDigestSpi {
    /** The underlying TlshCreator r implementation. */
    private final TlshCreator impl;
    /** The pre-computed length of the digest buffer. */
    private final int digestLength;

    TLSHMessageDigestSpiTM() {
        this(BucketOption.BUCKETS_128, ChecksumOption.CHECKSUM_1B);
    }

    TLSHMessageDigestSpiTM(final BucketOption bucketOption, final ChecksumOption checksumOption) {
        impl = new TlshCreator(bucketOption, checksumOption);
        final int l = bucketOption.getBucketCount() / 2 + checksumOption.getChecksumLength() * 2 + 4;
        this.digestLength = l / 2;
    }

    @Override
    protected int engineGetDigestLength() {
        return digestLength;
    }

    @Override
    protected void engineUpdate(final byte input) {
        impl.update(new byte[] {input});
    }

    @Override
    protected void engineUpdate(final byte[] input, final int offset, final int len) {
        impl.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        final Tlsh hash = impl.getHash(true);
        impl.reset();
        return TLSHUtil.hexToBytes(hash.getEncoded());
    }

    @Override
    protected void engineReset() {
        impl.reset();
    }
}
