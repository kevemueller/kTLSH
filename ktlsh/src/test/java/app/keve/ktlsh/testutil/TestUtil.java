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
package app.keve.ktlsh.testutil;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import app.keve.ktlsh.TLSHUtil;
import app.keve.ktlsh.spi.TMProvider;

/**
 * Utility functions for tests.
 * 
 * @author keve
 *
 */
public final class TestUtil {
    private TestUtil() {
    }

    /**
     * Register K provider as well as TM provider.
     */
    public static void registerProvider() {
        TLSHUtil.registerProvider();
        Security.addProvider(new TMProvider());
    }

    /**
     * Return the name of the TM provider.
     * 
     * @return the name
     */
    public static String providerNameTM() {
        return TMProvider.NAME;
    }

    /**
     * Get a SecureRandom instance.
     * 
     * @return the instance
     * @throws NoSuchAlgorithmException if none can be found
     */
    public static SecureRandom rnd() throws NoSuchAlgorithmException {
        final String os = System.getProperty("os.name").toLowerCase();
        return os.contains("win") ? SecureRandom.getInstanceStrong()
                : SecureRandom.getInstance("NativePRNGNonBlocking");
    }
}
