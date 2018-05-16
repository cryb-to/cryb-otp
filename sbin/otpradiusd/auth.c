/*-
 * Copyright (c) 2018 The University of Oslo
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

#include <sys/socket.h>

#include <arpa/inet.h>

#include <err.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <cryb/md5.h>
#include <cryb/memset_s.h>

#include "otpradiusd.h"

const char *rad_secret;
size_t rad_secret_len;

void
auth_encode(const uint8_t *nonce, const uint8_t *pt,
    uint8_t *ct, size_t len)
{
	md5_ctx ctx, sctx;
	uint8_t stream[16];
	const uint8_t *key;
	unsigned int i;

	// assert(len % 16 == 0);
	md5_init(&ctx);
	md5_update(&ctx, rad_secret, rad_secret_len);
	sctx = ctx;
	key = nonce;
	while (len >= 16) {
		ctx = sctx;
		md5_update(&ctx, key, 16);
		md5_final(&ctx, stream);
		for (i = 0; i < 16; ++i)
			ct[i] = pt[i] ^ stream[i];
		key = ct;
		ct += 16;
		pt += 16;
		len -= 16;
	}
	memset_s(&sctx, sizeof sctx, 0, sizeof sctx);
}

void
auth_decode(const uint8_t *nonce, const uint8_t *ct,
    uint8_t *pt, size_t len)
{
	md5_ctx ctx, sctx;
	uint8_t stream[16];
	const uint8_t *key;
	unsigned int i;

	// assert(len % 16 == 0);
	md5_init(&ctx);
	md5_update(&ctx, rad_secret, rad_secret_len);
	sctx = ctx;
	key = nonce;
	while (len >= 16) {
		ctx = sctx;
		md5_update(&ctx, key, 16);
		md5_final(&ctx, stream);
		for (i = 0; i < 16; ++i)
			pt[i] = ct[i] ^ stream[i];
		key = ct;
		pt += 16;
		ct += 16;
		len -= 16;
	}
	memset_s(&sctx, sizeof sctx, 0, sizeof sctx);
}