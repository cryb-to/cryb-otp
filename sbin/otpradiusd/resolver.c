/*-
 * Copyright (c) 2016-2018 Dag-Erling Smørgrav
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

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cryb/ctype.h>

#include "otpradiusd.h"

/*
 * Parse an address spec of the form:
 *
 * addr-spec := <host-spec> [ ':' <port-spec> ]
 * host-spec := '*' | <host-name> | <ipv4-addr> |  '[' <ipv6-addr> ']'
 * port-spec := <service-name> | <port-number>
 *
 * then call getaddrinfo(3) with the appropriate parameters.  Input
 * validation is fairly lax; we trust getaddrinfo(3) to take up the slack.
 *
 * Derived from fetch_resolve() in FreeBSD's libfetch.
 */
int
resolve(const char *addr, const char *port, struct addrinfo **res)
{
	char hbuf[256];
	struct addrinfo hints;
	const char *hb, *he, *sep;
	const char *host, *service;
	int len;

	*res = NULL;

	/* first, check for a bracketed IPv6 address */
	if (*addr == '[') {
		hb = addr + 1;
		for (he = hb; *he != ']'; ++he) {
			if (!is_xdigit(*he) && *he != ':') {
				errno = EINVAL;
				return (EAI_SYSTEM);
			}
			sep = he;
		}
	} else {
		hb = addr;
		sep = strchrnul(hb, ':');
		he = sep;
	}

	/* see if we need to copy the host name */
	if (he == hb || (*hb == '*' && he - hb == 1)) {
		host = NULL;
	} else if (*he != '\0') {
		len = snprintf(hbuf, sizeof hbuf, "%.*s", (int)(he - hb), hb);
		if (len < 0)
			return (EAI_SYSTEM);
		if ((size_t)len >= sizeof hbuf) {
			errno = ENAMETOOLONG;
			return (EAI_SYSTEM);
		}
		host = hbuf;
	} else {
		host = hb;
	}

	/* was it followed by a service name? */
	if (*sep == '\0' && port != NULL) {
		service = port;
	} else if (*sep != '\0') {
		service = sep + 1;
	} else {
		service = NULL;
	}

	/* resolve */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
	return (getaddrinfo(host, service, &hints, res));
}
