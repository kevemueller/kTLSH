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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Test hashing a large (4GiB) file.
 * 
 * @author keve
 *
 */
public class TestLargeFile {

    static {
        TLSHUtil.registerProvider();
    }

    /**
     * Test digesting a large (>4G) file.
     * 
     * @throws GeneralSecurityException if the algorithm or provider are not
     *                                  registered
     * @throws IOException              if an I/O error occurs
     */
    @Test
    @Disabled
    public void testLargeFile() throws GeneralSecurityException, IOException {
        final MessageDigest md = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameK());
        final Path p = Path.of("/Users/keve/Documents/set/Win10_1809Oct_EnglishInternational_x64.iso");
        try (InputStream in = Files.newInputStream(p); DigestInputStream din = new DigestInputStream(in, md)) {
            din.transferTo(OutputStream.nullOutputStream());
        }
        final byte[] hash = md.digest();
        System.out.println(TLSHUtil.encoded(hash));
    }
}
