/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package app.keve.ktlsh;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@Fork(1)
@Warmup(time = 2)
@Measurement(iterations = 2, time = 5, timeUnit = TimeUnit.SECONDS)
public class HashBenchmark {
	static {
		TLSHUtil.registerProviders();
	}

	@State(Scope.Benchmark)
	public static class MyState {
		byte[] SMALL_BUF;
		byte[] LARGE_BUF;
		byte[] HUGE_BUF;

		@Setup
		public void init() throws NoSuchAlgorithmException {
			SecureRandom rnd = SecureRandom.getInstance("NativePRNGNonBlocking");
			SMALL_BUF = new byte[32 * 1024];
			LARGE_BUF = new byte[16 * 1024 * 1024];
			HUGE_BUF = new byte[1 * 1024 * 1024];
			rnd.nextBytes(SMALL_BUF);
			rnd.nextBytes(LARGE_BUF);
			rnd.nextBytes(HUGE_BUF);
		}
	}

	private void test(MessageDigest md, byte[] buf) {
		byte[] hash = md.digest(buf);
		TLSHUtil.encoded(hash);
	}

	@Benchmark
	@OperationsPerInvocation(32)
	public void testTMSmall32KiB(final MyState state) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameTM());
		test(md, state.SMALL_BUF);
	}

	@Benchmark
	@OperationsPerInvocation(32)
	public void testKSmall32KiB(final MyState state) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameK());
		test(md, state.SMALL_BUF);
	}

	@Benchmark
	@OperationsPerInvocation(32)
	public void testMD5Small32KiB(final MyState state) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		test(md, state.SMALL_BUF);
	}

	@Benchmark
	@OperationsPerInvocation(16 * 1024)
	public void testTMLarge16MiB(final MyState state) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameTM());
		test(md, state.LARGE_BUF);
	}

	@Benchmark
	@OperationsPerInvocation(16 * 1024)
	public void testKLarge16MiB(final MyState state) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("TLSH", TLSHUtil.providerNameK());
		test(md, state.LARGE_BUF);
	}

	@Benchmark
	@OperationsPerInvocation(16 * 1024)
	public void testMD5Large16MiB(final MyState state) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		test(md, state.LARGE_BUF);
	}
}
