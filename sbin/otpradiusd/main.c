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

#include "cryb/impl.h"

#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cryb/oath.h>
#include <cryb/otp.h>

#include "otpradiusd.h"

void
print_hex(const void *data, size_t len, size_t off)
{
	const uint8_t *bytes = data;
	size_t beg, end, pos;

	beg = off;
	off -= off % 16;
	end = ((beg + len + 15) / 16) * 16;
	pos = off;
	while (pos < end) {
		if (pos % 16 == 0)
			fprintf(stderr, "%08zu |", pos);
		else if (pos % 8 == 0)
			fprintf(stderr, " .");
		else if (pos % 4 == 0)
			fprintf(stderr, " ");
		if (pos >= beg && pos < beg + len) {
#if 0
			if (*bytes > 32 && *bytes < 127)
				fprintf(stderr, "  %c", *bytes);
			else
#endif
				fprintf(stderr, " %02x", *bytes);
			bytes++;
		} else {
			fprintf(stderr, "   ");
		}
		pos++;
		if (pos % 16 == 0)
			fprintf(stderr, " |\n");
	}
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: otpradiusd [-46d] [-l host[:port]] [-s secret]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *laddrv[argc];
	unsigned int i, laddrc;
	int ipv, opt;

	ipv = 0;
	laddrc = 0;
	while ((opt = getopt(argc, argv, "46dl:s:")) != -1)
		switch (opt) {
		case '4':
		case '6':
			ipv |= 1 << (opt - '0');
			break;
		case 'd':
			/* nothing */
			break;
		case 'l':
			laddrv[laddrc++] = optarg;
			break;
		case 's':
			rad_secret = optarg;
			rad_secret_len = strlen(optarg);
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();

	if (ipv == 0)
		ipv = 1 << 4 | 1 << 6;
	if (laddrc == 0)
		laddrv[laddrc++] = "*:radius";
	for (i = 0; i < laddrc; i++)
		if (add_listener(laddrv[i], ipv) < 0)
			exit(1);

	dispatch();

	exit(0);
}
