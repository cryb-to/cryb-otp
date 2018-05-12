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

#ifndef OTPRADIUSD_H_INCLUDED
#define OTPRADIUSD_H_INCLUDED

typedef struct rad_attribute	rad_attribute;
typedef struct rad_message	rad_message;
typedef struct rad_transaction	rad_transaction;

struct addrinfo;

typedef enum rad_msg_code {
	rmc_unknown			 =  0,
	rmc_access_request		 =  1,
	rmc_access_accept		 =  2,
	rmc_access_reject		 =  3,
	rmc_accounting_request		 =  4,
	rmc_accounting_response		 =  5,
	rmc_access_challenge		 = 11,
	rmc_status_server		 = 12,
	rmc_status_client		 = 13,

	rmc_max
} rad_msg_code;

typedef enum rad_attr_code {
	rac_unknown_attr		 =  0,
	rac_user_name			 =  1,
	rac_user_password		 =  2,
	rac_chap_password		 =  3,
	rac_nas_ip_address		 =  4,
	rac_nas_port			 =  5,
	rac_service_type		 =  6,
	rac_framed_protocol		 =  7,
	rac_framed_ip_address		 =  8,
	rac_framed_ip_netmask		 =  9,
	rac_framed_routing		 = 10,
	rac_filter_id			 = 11,
	rac_framed_mtu			 = 12,
	rac_framed_compression		 = 13,
	rac_login_ip_host		 = 14,
	rac_login_service		 = 15,
	rac_login_tcp_port		 = 16,
	/* unassigned			 = 17, */
	rac_reply_message		 = 18,
	rac_callback_number		 = 19,
	rac_callback_id			 = 20,
	/* unassigned			 = 21, */
	rac_framed_route		 = 22,
	rac_framed_ipx_network		 = 23,
	rac_state			 = 24,
	rac_class			 = 25,
	rac_vendor_specific		 = 26,
	rac_session_timeout		 = 27,
	rac_idle_timeout		 = 28,
	rac_termination_action		 = 29,
	rac_called_station_id		 = 30,
	rac_calling_station_id		 = 31,
	rac_nas_identifier		 = 32,
	rac_proxy_state			 = 33,
	rac_login_lat_service		 = 34,
	rac_login_lat_node		 = 35,
	rac_login_lat_group		 = 36,
	rac_framed_appletalk_link	 = 37,
	rac_framed_appletalk_network	 = 38,
	rac_framed_appletalk_zone	 = 39,
	/* reserved for accounting	 = 40...59, */
	rac_chap_challenge		 = 60,
	rac_nas_port_type		 = 61,
	rac_port_limit			 = 62,
	rac_login_lat_port		 = 63,

	rac_max
} rad_attr_code;

#define MIN_RADPASS_LEN		  16
#define MAX_RADPASS_LEN		 128

#define MIN_RADATTR_LEN		   3
#define MAX_RADATTR_LEN		 255

struct rad_attribute {
	uint8_t			 code;
	uint8_t			 length;
	uint8_t			 value[MAX_RADATTR_LEN - 2];
};

#define MIN_RADPKT_LEN	  20
#define MAX_RADPKT_LEN	4096

struct rad_message {
	uint8_t			 code;
	uint8_t			 identifier;
	uint16_t		 length;
	uint8_t			 authenticator[16];
	uint8_t			 attributes[MAX_RADPKT_LEN - 20];
};

struct rad_transaction {
	struct sockaddr_storage	 caddr;
	socklen_t		 caddrlen;
	rad_message		 request;
	size_t			 reqlen;
	rad_message		 response;
	size_t			 rsplen;
};

int add_listener(const char *, int);
int resolve(const char *, const char *, struct addrinfo **);
int dispatch(void);
int rad_handle(rad_transaction *);

extern const char *rad_secret;
extern size_t rad_secret_len;

void print_hex(const void *, size_t, size_t);

void auth_encode(const uint8_t *, const uint8_t *, uint8_t *, size_t);
void auth_decode(const uint8_t *, const uint8_t *, uint8_t *, size_t);

#endif
