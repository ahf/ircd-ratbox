/*
 * resolver.c: dns resolving daemon for ircd-ratbox
 * Based on many things ripped from ratbox-services
 * and ircd-ratbox itself and who knows what else
 *
 * Copyright (C) 2003-2005 Lee Hardy <leeh@leeh.co.uk>
 * Copyright (C) 2003-2008 ircd-ratbox development team
 * Copyright (C) 2005-2008 Aaron Sethman <androsyn@ratbox.org>
 *
 * $Id: resolver.c 26497 2009-04-28 21:19:11Z jilles $
 */

#define READBUF_SIZE    16384

#include "setup.h"
#include <ratbox_lib.h>
#include "res.h"
#include "reslib.h"

#define MAXPARA 10
#define REQIDLEN 10

#define REQREV 0
#define REQFWD 1

#define REVIPV4 0
#define REVIPV6 1
#define REVIPV6INT 2
#define FWDHOST 4

#define EmptyString(x) (!(x) || (*(x) == '\0'))

static int do_rehash;
static rb_helper *res_helper;

static char readBuf[READBUF_SIZE];
static void resolve_ip(char **parv);
static void resolve_host(char **parv);
static void report_nameservers(void);

#ifdef RB_IPV6
struct in6_addr ipv6_addr;
#endif
struct in_addr ipv4_addr;


struct dns_request
{
	struct DNSQuery query;
	char reqid[REQIDLEN];
	struct rb_sockaddr_storage addr;
	int reqtype;
	int revfwd;
};


#ifndef WINDOWS
static void
dummy_handler(int sig)
{
	return;
}

static void
rehash(int sig)
{
	do_rehash = 1;
}
#endif

static void
setup_signals(void)
{
#ifndef WINDOWS
	struct sigaction act;

	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGPIPE);
	sigaddset(&act.sa_mask, SIGALRM);
#ifdef SIGTRAP
	sigaddset(&act.sa_mask, SIGTRAP);
#endif

#ifdef SIGWINCH
	sigaddset(&act.sa_mask, SIGWINCH);
	sigaction(SIGWINCH, &act, 0);
#endif
	sigaction(SIGPIPE, &act, 0);
#ifdef SIGTRAP
	sigaction(SIGTRAP, &act, 0);
#endif

	act.sa_handler = dummy_handler;
	sigaction(SIGALRM, &act, 0);

	act.sa_handler = rehash;
	sigaddset(&act.sa_mask, SIGHUP);
	sigaction(SIGHUP, &act, 0);
#endif
}

static void
error_cb(rb_helper *helper)
{
	exit(1);
}


static void
send_answer(void *vptr, struct DNSReply *reply)
{
	struct dns_request *req = (struct dns_request *)vptr;
	char response[64];
	int result = 0;
	int aftype = 0;
	strcpy(response, "FAILED");
	if(reply != NULL)
	{
		switch (req->revfwd)
		{
		case REQREV:
			{
				if(req->reqtype == REVIPV4)
				{
					struct sockaddr_in *ip, *ip_fwd;
					ip = (struct sockaddr_in *)&req->addr;
					ip_fwd = (struct sockaddr_in *)&reply->addr;
					aftype = 4;
					if(ip->sin_addr.s_addr != ip_fwd->sin_addr.s_addr)
					{
						result = 0;
						break;
					}
				}
#ifdef RB_IPV6
				else if(req->reqtype == REVIPV6)
				{
					struct sockaddr_in6 *ip, *ip_fwd;
					ip = (struct sockaddr_in6 *)&req->addr;
					ip_fwd = (struct sockaddr_in6 *)&reply->addr;
					aftype = 6;
					if(memcmp
					   (&ip->sin6_addr, &ip_fwd->sin6_addr,
					    sizeof(struct in6_addr)) != 0)
					{
						result = 0;
						break;
					}
				}
#endif
				else
				{
					/* uhh wut? */
					result = 0;
					break;
				}

				if(strlen(reply->h_name) < 63)
				{
					strcpy(response, reply->h_name);
					result = 1;
				}
				else
				{
					strcpy(response, "HOSTTOOLONG");
					result = 0;
				}
				break;
			}

		case REQFWD:
			{
#ifdef RB_IPV6
				if(GET_SS_FAMILY(&reply->addr) == AF_INET6)
				{
					char tmpres[65];
					rb_inet_ntop_sock((struct sockaddr *)&reply->addr,
						     tmpres, sizeof(tmpres) - 1);
					aftype = 6;
					if(*tmpres == ':')
					{
						strcpy(response, "0");
						strcat(response, tmpres);
					}
					else
						strcpy(response, tmpres);
					result = 1;
					break;
				}
				else
#endif
				if(GET_SS_FAMILY(&reply->addr) == AF_INET)
				{
					result = 1;
					aftype = 4;
					rb_inet_ntop_sock((struct sockaddr *)&reply->addr,
						     response, sizeof(response));
					break;
				}
				else
					break;
			}
		default:
			{
				exit(1);
			}
		}

	}

	rb_helper_write(res_helper, "R %s %d %d %s\n", req->reqid, result, aftype, response);
	rb_free(req);
}

static void
set_bind(char **parv)
{
	char *ipv4 = parv[2];
#ifdef RB_IPV6
	char *ipv6 = parv[3];
#endif
	if(!strcmp(ipv4, "0"))
		ipv4_addr.s_addr = INADDR_ANY;
	else
		rb_inet_pton(AF_INET, ipv4, &ipv4_addr);
#ifdef RB_IPV6
	if(!strcmp(ipv6, "0"))
		memcpy(&ipv6_addr, &in6addr_any, sizeof(&ipv6_addr));
	else
		rb_inet_pton(AF_INET6, ipv6, &ipv6_addr);
#endif
}



/*
request protocol:

INPUTS:

IPTYPE:    4, 5,  6, ipv4, ipv6.int/arpa, ipv6 respectively
requestid: identifier of the request
 

RESIP  requestid IPTYPE IP 
RESHST requestid IPTYPE hostname

OUTPUTS:
ERR error string = daemon failed and is going to shutdown
otherwise

FWD requestid PASS/FAIL hostname or reason for failure
REV requestid PASS/FAIL IP or reason
  
*/


static void
parse_request(rb_helper *helper)
{
	int len;
	static char *parv[MAXPARA + 1];
	int parc;
	while((len = rb_helper_read(helper, readBuf, sizeof(readBuf))) > 0)
	{
		parc = rb_string_to_array(readBuf, parv, MAXPARA);
		switch (*parv[0])
		{
		case 'I':
			if(parc != 4)
				abort();
			resolve_ip(parv);
			break;
		case 'H':
			if(parc != 4)
				abort();
			resolve_host(parv);
			break;
		case 'B':
			if(parc != 4)
				abort();
			set_bind(parv);
			break;
		case 'R':
			restart_resolver();
			report_nameservers();
			break;
		default:
			break;
		}
	}
}


static void
resolve_host(char **parv)
{
	struct dns_request *req;
	char *requestid = parv[1];
	char *iptype = parv[2];
	char *rec = parv[3];
	int flags;

	req = rb_malloc(sizeof(struct dns_request));
	strcpy(req->reqid, requestid);

	req->revfwd = REQFWD;
	req->reqtype = FWDHOST;

	switch (*iptype)
	{
	case 6:
		flags = T_AAAA;
		break;
	default:
		flags = T_A;
		break;
	}

	req->query.ptr = req;
	req->query.callback = send_answer;
	gethost_byname_type(rec, &req->query, flags);
}

static void
resolve_ip(char **parv)
{
	char *requestid = parv[1];
	char *iptype = parv[2];
	char *rec = parv[3];
	int aftype;
	struct dns_request *req;
	if(strlen(requestid) >= REQIDLEN)
		exit(3);

	req = rb_malloc(sizeof(struct dns_request));
	req->revfwd = REQREV;
	strcpy(req->reqid, requestid);

	if(!rb_inet_pton_sock(rec, (struct sockaddr *)&req->addr))
		exit(6);

	aftype = GET_SS_FAMILY(&req->addr);
	switch (*iptype)
	{
	case '4':
		req->reqtype = REVIPV4;
		if(aftype != AF_INET)
			exit(6);
		break;
	case '6':
		req->reqtype = REVIPV6;
		if(aftype != AF_INET6)
			exit(6);
		break;
	default:
		exit(7);
	}
	req->query.ptr = req;
	req->query.callback = send_answer;
	gethost_byaddr(&req->addr, &req->query);
}

extern int irc_nscount;
extern struct rb_sockaddr_storage irc_nsaddr_list[];

static void
report_nameservers(void)
{
	int i;
	char ipaddr[HOSTIPLEN + 1];
	char buf[512];
	buf[0] = '\0';
	for(i = 0; i < irc_nscount; i++)
	{
		if(!rb_inet_ntop_sock
		   ((struct sockaddr *)&(irc_nsaddr_list[i]), ipaddr, sizeof(ipaddr)))
		{
			rb_strlcpy(ipaddr, "?", sizeof(ipaddr));
		}
		rb_snprintf_append(buf, sizeof(buf), "%s ", ipaddr);
	}
	rb_helper_write(res_helper, "A %s", buf);

}

static void
check_rehash(void *unused)
{
	if(do_rehash)
	{
		restart_resolver();
		do_rehash = 0;
		report_nameservers();
	}
}


int
main(int argc, char **argv)
{
	res_helper = rb_helper_child(parse_request, error_cb, NULL, NULL, NULL, 256, 1024, 256, 256);	/* XXX fix me */

	if(res_helper == NULL)
	{
		fprintf(stderr,
			"This is ircd-ratbox resolver.  You know you aren't supposed to run me directly?\n");
		fprintf(stderr,
			"You get an Id tag for this: $Id: resolver.c 26497 2009-04-28 21:19:11Z jilles $\n");
		fprintf(stderr, "Have a nice life\n");
		exit(1);
	}
	rb_set_time();
	setup_signals();
	init_resolver();
	rb_init_prng(NULL, RB_PRNG_DEFAULT);
	rb_event_add("check_rehash", check_rehash, NULL, 5);
	report_nameservers();
	rb_helper_loop(res_helper, 0);
	return 1;
}
