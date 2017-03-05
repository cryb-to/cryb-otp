/*-
 * Copyright (c) 2017 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "cryb/otp-impl.h"

/* gcc's <cstdint> is broken */
#include <stdint.h>
#include <cstring>
#include <iostream>
#include <vector>

#include <cryb/coverage.h>

CRYB_DISABLE_COVERAGE;

class test {
public:
	virtual const char *name() = 0;
	virtual int run() = 0;
};

#define TEST(lib) \
	class test_##lib : public test {				\
	public:								\
		virtual const char *name() {				\
			return (#lib);					\
		}							\
		virtual int run() {					\
			return (std::strcmp(cryb_##lib##_version(),	\
			    PACKAGE_VERSION) == 0);			\
		}							\
	};

#if WITH_OTP_LIB
#include <cryb/otp.h>
TEST(otp)
#endif

#undef TEST

int
main(int argc, char *argv[])
{
	std::vector<test *> tests;
	int ret;

#define TEST(lib) tests.push_back(new test_##lib())

#if WITH_CRYB_OTP
	TEST(otp);
#endif

#undef TEST


	ret = 0;
	if (tests.empty()) {
		std::cout << "1..1" << std::endl <<
		    "ok 1 - dummy" << std::endl;
	} else {
		std::cout << "1.." << tests.size() << std::endl;
		for (int i = 0; i < tests.size(); ++i) {
			if (!tests[i]->run()) {
				std::cout << "not ";
				ret = 1;
			}
			std::cout << "ok " << (i + 1) << " - " <<
			    tests[i]->name() << std::endl;
		}
	}
	return (ret);
}
