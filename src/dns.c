/*
 *  dns.c: An interface to the resolver daemon
 *  Copyright (C) 2005 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 *  $Id: dns.c 26606 2009-06-22 03:32:44Z androsyn $
 */

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "ircd_defs.h"
#include "parse.h"
#include "dns.h"
#include "match.h"
#include "s_log.h"
#include "s_conf.h"
#include "client.h"
#include "send.h"
#include "numeric.h"

#define IDTABLE 0xffff

#define DNS_HOST 	((char)'H')
#define DNS_REVERSE 	((char)'I')

static void submit_dns(const char, int id, int aftype, const char *addr);
static int start_resolver(void);
static void parse_dns_reply(rb_helper *helper);
static void restart_resolver_cb(rb_helper *helper);

static rb_helper *dns_helper;

struct dnsreq
{
	DNSCB *callback;
	void *data;
};

static struct dnsreq querytable[IDTABLE];
static uint16_t id = 1;

static uint16_t
assign_dns_id(void)
{
	while(1)
	{
		if(id < IDTABLE - 1)
			id++;
		else
			id = 1;
		if(querytable[id].callback == NULL)
			break;
	}
	return (id);
}

static inline void
check_resolver(void)
{
	if(dns_helper == NULL)
		restart_resolver();
}

static void
failed_resolver(uint16_t xid)
{
	struct dnsreq *req;

	req = &querytable[xid];
	if(req->callback == NULL)
		return;

	req->callback("FAILED", 0, 0, req->data);
	req->callback = NULL;
	req->data = NULL;
}

void
cancel_lookup(uint16_t xid)
{
	querytable[xid].callback = NULL;
	querytable[xid].data = NULL;
}

uint16_t
lookup_hostname(const char *hostname, int aftype, DNSCB * callback, void *data)
{
	struct dnsreq *req;
	int aft;
	uint16_t nid;
	check_resolver();
	nid = assign_dns_id();
	req = &querytable[nid];

	req->callback = callback;
	req->data = data;

#ifdef RB_IPV6
	if(aftype == AF_INET6)
		aft = 6;
	else
#endif
		aft = 4;

	submit_dns(DNS_HOST, nid, aft, hostname);
	return (id);
}

uint16_t
lookup_ip(const char *addr, int aftype, DNSCB * callback, void *data)
{
	struct dnsreq *req;
	int aft;
	uint16_t nid;
	check_resolver();

	nid = assign_dns_id();
	req = &querytable[nid];

	req->callback = callback;
	req->data = data;

#ifdef RB_IPV6
	if(aftype == AF_INET6)
		aft = 6;
	else
#endif
		aft = 4;

	submit_dns(DNS_REVERSE, nid, aft, addr);
	return (nid);
}


static void
results_callback(const char *callid, const char *status, const char *aftype, const char *results)
{
	struct dnsreq *req;
	uint16_t nid;
	int st;
	int aft;
	nid = strtol(callid, NULL, 16);
	req = &querytable[nid];
	st = atoi(status);
	aft = atoi(aftype);
	if(req->callback == NULL)
	{
		/* got cancelled..oh well */
		req->data = NULL;
		return;
	}
#ifdef RB_IPV6
	if(aft == 6)
		aft = AF_INET6;
	else
#endif
		aft = AF_INET;

	req->callback(results, st, aft, req->data);
	req->callback = NULL;
	req->data = NULL;
}


static char *resolver_path;

static int
start_resolver(void)
{
	char fullpath[PATH_MAX + 1];
#ifdef _WIN32
	const char *suffix = ".exe";
#else
	const char *suffix = "";
#endif
	if(resolver_path == NULL)
	{
		rb_snprintf(fullpath, sizeof(fullpath), "%s/resolver%s", LIBEXEC_DIR, suffix);

		if(access(fullpath, X_OK) == -1)
		{
			rb_snprintf(fullpath, sizeof(fullpath), "%s/libexec/ircd-ratbox/resolver%s",
				    ConfigFileEntry.dpath, suffix);
			if(access(fullpath, X_OK) == -1)
			{
				ilog(L_MAIN,
				     "Unable to execute resolver in %s or %s/libexec/ircd-ratbox",
				     LIBEXEC_DIR, ConfigFileEntry.dpath);
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Unable to execute resolver in %s or %s/libexec/ircd-ratbox",
						     LIBEXEC_DIR, ConfigFileEntry.dpath);
				return 1;
			}

		}

		resolver_path = rb_strdup(fullpath);
	}

	dns_helper =
		rb_helper_start("resolver", resolver_path, parse_dns_reply, restart_resolver_cb);

	if(dns_helper == NULL)
	{
		ilog(L_MAIN, "Unable to start resolver helper: %m");
		sendto_realops_flags(UMODE_ALL, L_ALL, "Unable to start resolver helper: %m");
		return 1;
	}
	ilog(L_MAIN, "resolver helper started");
	sendto_realops_flags(UMODE_ALL, L_ALL, "resolver helper started");
	rb_helper_run(dns_helper);
	return 0;
}

static rb_dlink_list nameservers;

static void
parse_nameservers(char **parv, int parc)
{
	rb_dlink_node *ptr, *next;
	char *server;
	int i;

	RB_DLINK_FOREACH_SAFE(ptr, next, nameservers.head)
	{
		rb_free(ptr->data);
		rb_dlinkDestroy(ptr, &nameservers);
	}

	for(i = 2; i < parc; i++)
	{
		server = rb_strdup(parv[i]);
		rb_dlinkAddTailAlloc(server, &nameservers);
	}
}

void
report_dns_servers(struct Client *source_p)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, nameservers.head)
	{
		sendto_one_numeric(source_p, RPL_STATSDEBUG, "A %s", (char *)ptr->data);
	}
}


static void
parse_dns_reply(rb_helper *helper)
{
	int len, parc;
	static char dnsBuf[READBUF_SIZE];

	char *parv[MAXPARA + 1];
	while((len = rb_helper_read(helper, dnsBuf, sizeof(dnsBuf))) > 0)
	{
		parc = string_to_array(dnsBuf, parv);	/* we shouldn't be using this here, but oh well */

		if(*parv[1] == 'R')
		{
			if(parc != 6)
			{
				ilog(L_MAIN,
				     "Resolver sent a result with wrong number of arguments");
				restart_resolver();
				return;
			}
			results_callback(parv[2], parv[3], parv[4], parv[5]);
		}
		else if(*parv[1] == 'A')
		{
			parse_nameservers(parv, parc);
		}
		else
		{
			ilog(L_MAIN, "Resolver sent an unknown command..restarting resolver");
			restart_resolver();
			return;
		}
	}
}

static void
submit_dns(char type, int nid, int aftype, const char *addr)
{
	if(dns_helper == NULL)
	{
		failed_resolver(nid);
		return;
	}
	rb_helper_write(dns_helper, "%c %x %d %s", type, nid, aftype, addr);
}

void
rehash_dns_vhost(void)
{
	const char *v6 = "0";
	const char *v4 = "0";
#ifdef RB_IPV6
	if(!EmptyString(ServerInfo.vhost6_dns))
		v6 = ServerInfo.vhost6_dns;
#endif
	if(!EmptyString(ServerInfo.vhost_dns))
		v4 = ServerInfo.vhost_dns;
	rb_helper_write(dns_helper, "B 0 %s %s", v4, v6);
}

void
init_resolver(void)
{
	if(start_resolver())
	{
		ilog(L_MAIN, "Unable to start resolver helper: %m");
		exit(0);
	}
}


static void
restart_resolver_cb(rb_helper *helper)
{
	ilog(L_MAIN, "resolver - restart_resolver_cb called, resolver helper died?");
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "resolver - restart_resolver_cb called, resolver helper died?");
	if(helper != NULL)
	{
		rb_helper_close(helper);
		dns_helper = NULL;
	}
	start_resolver();
	rehash_dns_vhost();
}

void
restart_resolver(void)
{
	restart_resolver_cb(dns_helper);
}

void
rehash_resolver(void)
{
	rb_helper_write(dns_helper, "R");
}
