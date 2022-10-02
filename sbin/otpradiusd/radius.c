/*-
 * Copyright (c) 2018 The University of Oslo
 * Copyright (c) 2019-2022 Dag-Erling Smørgrav
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
#include <string.h>

#include <cryb/assert.h>
#include <cryb/md5.h>

#include "otpradiusd.h"

#define DEBUG_PRINTF 1

static struct rad_msg_def {
	const char		*name;
} rad_msg_def[rmc_max] = {
	[rmc_unknown] = {
		.name = "Unknown-Message",
	},
	[rmc_access_request] = {
		.name = "Access-Request",
	},
	[rmc_access_accept] = {
		.name = "Access-Accept",
	},
	[rmc_access_reject] = {
		.name = "Access-Reject",
	},
	[rmc_accounting_request] = {
		.name = "Accounting-Request",
	},
	[rmc_accounting_response] = {
		.name = "Accounting-Response",
	},
	[rmc_access_challenge] = {
		.name = "Access-Challenge",
	},
	[rmc_status_server] = {
		.name = "Status-Server",
	},
	[rmc_status_client] = {
		.name = "Status-Client",
	},
};

#define rad_msg_name(rmc)						\
	(((rmc) < rmc_max && rad_msg_def[(rmc)].name) ?			\
	    rad_msg_def[(rmc)].name : rad_msg_def[0].name)

typedef enum rad_attr_type {
	rat_unknown,
	rat_text,
	rat_string,
	rat_address,
	rat_integer,
	rat_time,
	rat_max
} rad_attr_type;

static struct rad_attr_def {
	const char		*name;
	rad_attr_type		 type;
	/* min / max lengths of value */
#define RAT_MIN_LENGTH 1
	size_t			 min;
#define RAT_MAX_LENGTH 253
	size_t			 max;
} rad_attr_def[rac_max] = {
	[rac_unknown_attr] = {
		.name = "Unknown-Attribute",
		.type = rat_unknown,
		.min = 0,
		.max = 0,
	},
	[rac_user_name] = {
		.name = "User-Name",
		.type = rat_string,
		.min = RAT_MIN_LENGTH,
		.max = RAT_MAX_LENGTH,
	},
	[rac_user_password] = {
		.name = "User-Password",
		.type = rat_string,
		.min = RAT_MIN_LENGTH,
		.max = 128,
	},
	[rac_chap_password] = {
		.name = "CHAP-Password",
	},
	[rac_nas_ip_address] = {
		.name = "NAS-IP-Address",
	},
	[rac_nas_port] = {
		.name = "NAS-Port",
	},
	[rac_service_type] = {
		.name = "Service-Type",
	},
	[rac_framed_protocol] = {
		.name = "Framed-Protocol",
	},
	[rac_framed_ip_address] = {
		.name = "Framed-IP-Address",
	},
	[rac_framed_ip_netmask] = {
		.name = "Framed-IP-Netmask",
	},
	[rac_framed_routing] = {
		.name = "Framed-Routing",
	},
	[rac_filter_id] = {
		.name = "Filter-Id",
	},
	[rac_framed_mtu] = {
		.name = "Framed-MTU",
	},
	[rac_framed_compression] = {
		.name = "Framed-Compression",
	},
	[rac_login_ip_host] = {
		.name = "Login-IP-Host",
	},
	[rac_login_service] = {
		.name = "Login-Service",
	},
	[rac_login_tcp_port] = {
		.name = "Login-TCP-Port",
	},
	[rac_reply_message] = {
		.name = "Reply-Message",
	},
	[rac_callback_number] = {
		.name = "Callback-Number",
	},
	[rac_callback_id] = {
		.name = "Callback-Id",
	},
	[rac_framed_route] = {
		.name = "Framed-Route",
	},
	[rac_framed_ipx_network] = {
		.name = "Framed-IPX-Network",
	},
	[rac_state] = {
		.name = "State",
	},
	[rac_class] = {
		.name = "Class",
	},
	[rac_vendor_specific] = {
		.name = "Vendor-Specific",
	},
	[rac_session_timeout] = {
		.name = "Session-Timeout",
	},
	[rac_idle_timeout] = {
		.name = "Idle-Timeout",
	},
	[rac_termination_action] = {
		.name = "Termination-Action",
	},
	[rac_called_station_id] = {
		.name = "Called-Station-Id",
	},
	[rac_calling_station_id] = {
		.name = "Calling-Station-Id",
		.type = rat_string,
		.min = RAT_MIN_LENGTH,
		.max = RAT_MAX_LENGTH,
	},
	[rac_nas_identifier] = {
		.name = "NAS-Identifier",
		.type = rat_string,
		.min = RAT_MIN_LENGTH,
		.max = RAT_MAX_LENGTH,
	},
	[rac_proxy_state] = {
		.name = "Proxy-State",
	},
	[rac_login_lat_service] = {
		.name = "Login-LAT-Service",
	},
	[rac_login_lat_node] = {
		.name = "Login-LAT-Node",
	},
	[rac_login_lat_group] = {
		.name = "Login-LAT-Group",
	},
	[rac_framed_appletalk_link] = {
		.name = "Framed-AppleTalk-Link",
	},
	[rac_framed_appletalk_network] = {
		.name = "Framed-AppleTalk-Network",
	},
	[rac_framed_appletalk_zone] = {
		.name = "Framed-AppleTalk-Zone",
	},
	[rac_acct_status_type] = {
		.name = "Acct-Status-Type",
	},
	[rac_acct_delay_time] = {
		.name = "Acct-Delay-Time",
	},
	[rac_acct_input_octets] = {
		.name = "Acct-Input-Octets",
	},
	[rac_acct_output_octets] = {
		.name = "Acct-Output-Octets",
	},
	[rac_acct_session_id] = {
		.name = "Acct-Session-Id",
	},
	[rac_acct_authentic] = {
		.name = "Acct-Authentic",
	},
	[rac_acct_session_time] = {
		.name = "Acct-Session-Time",
	},
	[rac_acct_input_packets] = {
		.name = "Acct-Input-Packets",
	},
	[rac_acct_output_packets] = {
		.name = "Acct-Output-Packets",
	},
	[rac_acct_terminate_cause] = {
		.name = "Acct-Terminate-Cause",
	},
	[rac_acct_multi_session_id] = {
		.name = "Acct-Multi-Session-Id",
	},
	[rac_acct_link_count] = {
		.name = "Acct-Link-Count",
	},
	[rac_chap_challenge] = {
		.name = "CHAP-Challenge",
	},
	[rac_nas_port_type] = {
		.name = "NAS-Port-Type",
	},
	[rac_port_limit] = {
		.name = "Port-Limit",
	},
	[rac_login_lat_port] = {
		.name = "Login-LAT-Port",
	},
};

#define rad_attr_name(rac)						\
	(((rac) < rac_max && rad_attr_def[(rac)].name) ?		\
	    rad_attr_def[(rac)].name : rad_attr_def[0].name)

static int
rad_decode_str(const rad_attribute *ra, const uint8_t **str, size_t *len)
{
	rad_attr_code rac;

	rac = ra->code;
	if (rac >= rac_max || rad_attr_def[rac].name == NULL) {
		warnx("unknown attribute 0x%02x", ra->code);
		return (-1);
	}
	assert(rad_attr_def[rac].type == rat_string);
	if ((int)ra->length < 3 || (int)ra->length > MAX_RADATTR_LEN) {
		warnx("invalid attribute length");
		return (-1);
	}
	*str = ra->value;
	*len = ra->length - 2;
	return (0);
}

#if DEBUG_PRINTF
static void
mxu(md5_ctx *context, const void *data, unsigned int len)
{
	const unsigned char *bytes = data;

	fprintf(stderr, "md5");
	for (unsigned int i = 0; i < len; ++i)
		fprintf(stderr, " %02x", bytes[i]);
	fprintf(stderr, "\n");
	md5_update(context, data, len);
}
#undef md5_update
#define md5_update mxu
#endif

static int
handle_access_request(rad_transaction *rx)
{
	uint8_t password[MAX_RADPASS_LEN];
	rad_message *req, *rsp;
	rad_attribute *ra;
	uint8_t *nextra, *end;
	const uint8_t *user, *pass;
	size_t userlen, passlen;

	req = &rx->request;
	rsp = &rx->response;
	nextra = req->attributes;
	end = (uint8_t *)&rx->request + rx->reqlen;
	user = pass = NULL;
	userlen = passlen = 0;
	assert(req->code == rmc_access_request);
	while (nextra + MIN_RADATTR_LEN < end) {
		ra = (rad_attribute *)nextra;
		if ((int)ra->length < MIN_RADATTR_LEN ||
		    (int)ra->length > MAX_RADATTR_LEN ||
		    (int)ra->length > end - nextra) {
			warnx("invalid attribute length %u", ra->length);
			return (0);
		}
		switch ((rad_attr_code)ra->code) {
		case rac_user_name:
			if (user != NULL) {
				warnx("duplicate User-Name attribute");
				return (0);
			}
			if (rad_decode_str(ra, &user, &userlen) != 0)
				return (0);
			break;
		case rac_user_password:
			if (pass != NULL) {
				warnx("duplicate User-Password attribute");
				return (0);
			}
			if (rad_decode_str(ra, &pass, &passlen) != 0)
				return (0);
			if (passlen < MIN_RADPASS_LEN ||
			    passlen > MAX_RADPASS_LEN ||
			    passlen % 16 != 0) {
				warnx("invalid User-Password length %zu",
				    passlen);
				return (0);
			}
			break;
		default:
			warnx("ignoring %s attribute",
			    rad_attr_name(ra->code));
		}
		nextra += ra->length;
	}
	if (nextra != end) {
		warnx("trailing garbage in request");
		return (0);
	}
	if (user == NULL) {
		warnx("mssing User-Name attribute");
		return (0);
	}
#if DEBUG_PRINTF
	fprintf(stderr, "user: \"");
	for (unsigned int i = 0; i < userlen; ++i) {
		int ch = user[i];
		if (ch >= 32 && ch < 127 && ch != '"')
			fprintf(stderr, "%c", ch);
		else
			fprintf(stderr, "\\x%02x", ch);
	}
	fprintf(stderr, "\"\n");
#endif
	if (pass == NULL) {
		warnx("missing User-Password attribute");
		return (0);
	}
	auth_decode(req->authenticator, pass, password, passlen);
	while (password[passlen - 1] == '\0')
		passlen--;
#if DEBUG_PRINTF
	fprintf(stderr, "pass: \"");
	for (unsigned int i = 0; i < passlen; ++i) {
		int ch = password[i];
		if (ch >= 32 && ch < 127 && ch != '"')
			fprintf(stderr, "%c", ch);
		else
			fprintf(stderr, "\\x%02x", ch);
	}
	fprintf(stderr, "\"\n");
#endif

	/*
	 * TODO:
	 *
	 * Create concept of keystore in libcryb-otp
	 * Configure / open keystore at start of otpradiusd
	 * On receipt of request, request key from keystore
	 * Verify request
	 * Report outcome to keystore
	 * Report outcome to client
	 */
	static int coin;
	if ((coin = !coin)) {
		/* accept */
		ra = (rad_attribute *)&rsp->attributes;
		ra->code = rac_reply_message;
		strcpy((char *)ra->value, "hello!");
		ra->length = 2 + strlen((const char *)ra->value);
		rsp->code = rmc_access_accept;
		rsp->length = htons(20 + ra->length);
	} else {
		/* reject */
		ra = (rad_attribute *)&rsp->attributes;
		ra->code = rac_reply_message;
		strcpy((char *)ra->value, "denied");
		ra->length = 2 + strlen((const char *)ra->value);
		rsp->code = rmc_access_reject;
		rsp->length = htons(20 + ra->length);
	}
	return (1);
}

void
authenticate_response(rad_message *rsp, size_t rsplen)
{
	md5_ctx ctx;

	md5_init(&ctx);
	md5_update(&ctx, rsp, rsplen);
	md5_update(&ctx, rad_secret, rad_secret_len);
	md5_final(&ctx, rsp->authenticator);
}

int
rad_handle(rad_transaction *rx)
{
	rad_message *req, *rsp;
	rad_msg_code rmc;
	int ret;

	req = &rx->request;
	rsp = &rx->response;
	if (rx->reqlen != ntohs(req->length)) {
		warnx("length mismatch: %zu != %u",
		    rx->reqlen, ntohs(req->length));
		return (0);
	}
	if (rx->reqlen < MIN_RADPKT_LEN || rx->reqlen > MAX_RADPKT_LEN) {
		warnx("invalid length: %zu", rx->reqlen);
		return (0);
	}
	rmc = req->code;
	if (rmc >= rmc_max || rad_attr_def[rmc].name == NULL) {
		warnx("unknown message 0x%02x", req->code);
		return (-1);
	}
	warnx("request 0x%02x (%s) ident 0x%02x", rmc,
	    rad_msg_name(rmc), req->identifier);
	memset(rsp, 0, sizeof *rsp);
	rsp->identifier = req->identifier;
	memcpy(rsp->authenticator, req->authenticator, 16);
	switch (rmc) {
	case rmc_access_request:
		ret = handle_access_request(rx);
		break;
	}
	if (ret > 0) {
		rx->rsplen = ntohs(rsp->length);
		if (rsp->code == rmc_access_accept ||
		    rsp->code == rmc_access_reject ||
		    rsp->code == rmc_access_challenge) {
			authenticate_response(rsp, rx->rsplen);
		}
	}
	print_hex(rsp, rx->rsplen, 0);
	return (ret);
}
