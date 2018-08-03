/*-
 * Copyright (c) 2013-2018 The University of Oslo
 * Copyright (c) 2016-2018 Dag-Erling Smørgrav
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

#include "cryb/impl.h"

#include <stddef.h>
#include <stdint.h>

#include <cryb/assert.h>
#include <cryb/oath.h>
#include <cryb/otp.h>

#include "cryb_otp_impl.h"

/*
 * Check whether a given response is correct for the given keyfile.
 */
int
otp_verify(oath_key *key, unsigned long response)
{
	uint64_t prev;
	int ret;

	switch (key->mode) {
	case om_hotp:
		prev = key->counter;
		ret = oath_hotp_match(key, response, HOTP_WINDOW);
		assertf(key->counter >= prev, "counter went backwads");
		if (ret > 0) {
			assertf(key->counter > prev, "counter did not advance");
			ret = key->counter - prev - 1;
		}
		break;
	case om_totp:
		prev = key->lastused;
		ret = oath_totp_match(key, response, TOTP_WINDOW);
		assertf(key->lastused >= prev, "lastused went backwards");
		if (ret > 0) {
			assertf(key->lastused > prev, "lastused did not advance");
			ret = key->lastused - prev / key->timestep;
		}
		break;
	default:
		ret = -1;
	}
	/* oath_*_ret() return -1 on error, 0 on failure, 1 on success */
	return (ret);
}
