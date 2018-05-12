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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cryb/ctype.h>

#include "otpradiusd.h"

#ifndef INFTIM
#define INFTIM -1
#endif

typedef struct rad_listener rad_listener;

struct rad_listener {
	char			 laddrstr[1024];
	struct sockaddr_storage	 laddr;
	socklen_t		 laddrlen;
	int			 sd;
};

static rad_listener *listeners;
static unsigned int nls, szls;

static int
open_and_bind(struct addrinfo *ai)
{
	int one, sd;

	if ((sd = socket(ai->ai_family, SOCK_DGRAM | SOCK_NONBLOCK, 0)) < 0)
		return (-1);
	one = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0 ||
	    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) < 0 ||
	    bind(sd, ai->ai_addr, ai->ai_addrlen) < 0) {
		close(sd);
		return (-1);
	}
	return (sd);
}

int
add_listener(const char *addrstr, int ipv)
{
	char hbuf[256], sbuf[8];
	struct addrinfo *ai, *res;
	rad_listener *l, *newls;
	int gai_err, serrno;
	int ip4, ip6;
	int n, sd;

	ip4 = !!(ipv & 1 << 4);
	ip6 = !!(ipv & 1 << 6);
	n = 0;

	/* attempt DNS lookup */
	if ((gai_err = resolve(addrstr, "radius", &res)) != 0) {
		if (gai_err == EAI_SYSTEM)
			warn("%s", addrstr);
		else
			warnx("%s: %s", addrstr, gai_strerror(gai_err));
		return (-1);
	}

	/* iterate of results, if any */
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		/* skip if not a desired address family */
		if (!(ip4 && ai->ai_family == AF_INET) &&
		    !(ip6 && ai->ai_family == AF_INET6))
			continue;
		/* pretty-print the address */
		hbuf[0] = '*'; sbuf[0] = '*'; hbuf[1] = sbuf[1] = '\0';
		getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    hbuf, sizeof hbuf, sbuf, sizeof sbuf,
		    NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
		/* try to open and bind */
		if ((sd = open_and_bind(ai)) < 0) {
			warn("%s:%s", hbuf, sbuf);
			continue;
		}
		/* resize list if necessary */
		if (nls == szls) {
			if (szls == 0)
				szls = 4;
			szls *= 2;
			newls = realloc(listeners, szls * sizeof *newls);
			if (newls == NULL)
				goto syserr;
			memset(newls + nls, 0, (szls - nls) * sizeof *newls);
			listeners = newls;
		}
		/* insert and increment */
		l = &listeners[nls++];
		// assert(ai->ai_addrlen <= sizeof l->laddr);
		snprintf(l->laddrstr, sizeof l->laddrstr, "%s:%s", hbuf, sbuf);
		memcpy(&l->laddr, ai->ai_addr, ai->ai_addrlen);
		l->laddrlen = ai->ai_addrlen;
		l->sd = sd;
		warnx("listener added for %s", l->laddrstr);
		n++;
	}
	if (n == 0)
		warnx("%s: no address found", addrstr);
	return (n);
syserr:
	serrno = errno;
	warn("%s", addrstr);
	close(sd);
	freeaddrinfo(res);
	errno = serrno;
	return (-1);
}

int
receive(const rad_listener *l, struct rad_transaction *rx)
{
	char hbuf[256], sbuf[8];
	ssize_t rcvdlen;

	memset(rx, 0, sizeof *rx);
	rx->caddrlen = sizeof rx->caddr;
	rcvdlen = recvfrom(l->sd, &rx->request, sizeof rx->request, 0,
	    (struct sockaddr *)&rx->caddr, &rx->caddrlen);
	fprintf(stderr, "message received on %s", l->laddrstr);
	hbuf[0] = '*'; sbuf[0] = '*'; hbuf[1] = sbuf[1] = '\0';
	getnameinfo((struct sockaddr *)&rx->caddr, rx->caddrlen,
	    hbuf, sizeof hbuf, sbuf, sizeof sbuf,
	    NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
	fprintf(stderr, " from %s:%s\n", hbuf, sbuf);
	print_hex(&rx->request, (size_t)rcvdlen, 0);
	if (rcvdlen < 0)
		return (-1);
	rx->reqlen = (size_t)rcvdlen;
	return (0);
}

int
reply(const rad_listener *l, const struct rad_transaction *rx)
{
	char hbuf[256], sbuf[8];
	ssize_t sentlen;

	do {
		fprintf(stderr, "sending message on %s", l->laddrstr);
		hbuf[0] = '*'; sbuf[0] = '*'; hbuf[1] = sbuf[1] = '\0';
		getnameinfo((const struct sockaddr *)&rx->caddr, rx->caddrlen,
		    hbuf, sizeof hbuf, sbuf, sizeof sbuf,
		    NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
		fprintf(stderr, " to %s:%s\n", hbuf, sbuf);
		print_hex(&rx->response, rx->rsplen, 0);
		sentlen = sendto(l->sd, &rx->response, rx->rsplen, 0,
		    (const struct sockaddr *)&rx->caddr, rx->caddrlen);
		if (sentlen < 0)
			return (-1);
	} while ((size_t)sentlen != rx->rsplen);
	return (0);
}

int
dispatch(void)
{
	struct rad_transaction rx;
	struct pollfd pfd[nls];
	unsigned int i;
	int n;

	memset(pfd, 0, sizeof pfd);
	for (i = 0; i < nls; ++i) {
		pfd[i].fd = listeners[i].sd;
		pfd[i].events = POLLIN | POLLERR;
	}
	for (;;) {
		if ((n = poll(pfd, nls, INFTIM)) < 0)
			return (-1);
		for (i = 0; i < nls; ++i) {
			if (pfd[i].revents & POLLERR) {
				warnx("%s: unspecified error",
				    listeners[i].laddrstr);
				close(listeners[i].sd);
				listeners[i].sd = pfd[i].fd = -1;
				pfd[i].events = 0;
			} else if (pfd[i].revents & POLLIN) {
				memset(&rx, 0, sizeof rx);
				if (receive(&listeners[i], &rx) < 0) {
					warn("%s", listeners[i].laddrstr);
					continue;
				}
				if (rad_handle(&rx) > 0 &&
				    reply(&listeners[i], &rx) < 0) {
					warn("%s", listeners[i].laddrstr);
				}
			}
		}
	}
}
