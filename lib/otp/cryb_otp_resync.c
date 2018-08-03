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
 * Resynchronize a desynchronized event-mode key.
 *
 * XXX review carefully for off-by-one errors, and write unit tests
 */

static int
otp_resync_recursive(oath_key *key, unsigned long *response,
    unsigned int n, unsigned int w)
{
	uint64_t first, prev, last;
	int ret;

	first = key->counter;
	last = first + w;
	while (w > 0) {
		prev = key->counter;
		ret = oath_hotp_match(key, response[0], last - key->counter);
		if (ret < 1)
			return (ret);
		assertf(key->counter > prev, "counter did not advance");
		w -= key->counter - prev;
		if (n == 1)
			return (key->counter - prev);
		prev = key->counter;
		ret = otp_resync_recursive(key, response + 1, n - 1, w);
		if (ret > 0)
			return (ret);
		key->counter = prev;
	}
	return (0);
}

int
otp_resync(oath_key *key, unsigned long *response, unsigned int n)
{
	unsigned int i, w;
	int ret;

	/* only applicable to RFC 4226 HOTP for now */
	/* note: n == 1 is identical to otp_verify() */
	if (key->mode != om_hotp || n < 1)
		return (-1);

	/* compute window size based on number of responses */
	for (i = 0, w = 1; i < n; ++i)
		w = w * (HOTP_WINDOW + 1);

	/* recursive search within window */
	ret = otp_resync_recursive(key, response, n, w);

	/* ... */

	return (ret);
}
