/*
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 * s_newconf.h: code for dealing with conf stuff
 *
 * Copyright (C) 2004 Lee Hardy <lee@leeh.co.uk>
 * Copyright (C) 2004-2005 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: s_newconf.h 26443 2009-02-05 23:14:55Z jilles $
 */

#ifndef INCLUDED_s_newconf_h
#define INCLUDED_s_newconf_h

#ifdef USE_CHALLENGE
#include <openssl/rsa.h>
#endif

struct ConfItem;

extern rb_dlink_list cluster_conf_list;
extern rb_dlink_list shared_conf_list;
extern rb_dlink_list oper_conf_list;
extern rb_dlink_list hubleaf_conf_list;
extern rb_dlink_list server_conf_list;
extern rb_dlink_list xline_conf_list;
extern rb_dlink_list resv_conf_list;
extern rb_dlink_list tgchange_list;

extern rb_patricia_tree_t *tgchange_tree;

void init_s_newconf(void);
void clear_s_newconf(void);
void clear_s_newconf_bans(void);

#define FREE_TARGET(x) ((x)->localClient->targinfo[0])
#define USED_TARGETS(x) ((x)->localClient->targinfo[1])

typedef struct
{
	char *ip;
	time_t expiry;
	rb_patricia_node_t *pnode;
	rb_dlink_node node;
} tgchange;

void add_tgchange(const char *host);
tgchange *find_tgchange(const char *host);

/* shared/cluster/hub/leaf confs */
struct remote_conf
{
	char *username;
	char *host;
	char *server;
	int flags;
	rb_dlink_node node;
};

/* flags used in shared/cluster */
#define SHARED_TKLINE	0x0001
#define SHARED_PKLINE	0x0002
#define SHARED_UNKLINE	0x0004
#define SHARED_LOCOPS	0x0008
#define SHARED_TXLINE	0x0010
#define SHARED_PXLINE	0x0020
#define SHARED_UNXLINE	0x0040
#define SHARED_TRESV	0x0800
#define SHARED_PRESV	0x0100
#define SHARED_UNRESV	0x0200

#define SHARED_ALL	(SHARED_TKLINE | SHARED_PKLINE | SHARED_UNKLINE |\
			SHARED_PXLINE | SHARED_TXLINE | SHARED_UNXLINE |\
			SHARED_TRESV | SHARED_PRESV | SHARED_UNRESV)
#define CLUSTER_ALL	(SHARED_ALL | SHARED_LOCOPS)

/* flags used in hub/leaf */
#define CONF_HUB	0x0001
#define CONF_LEAF	0x0002

struct oper_conf
{
	char *name;
	char *username;
	char *host;
	char *passwd;

	int flags;
	int umodes;

#ifdef USE_CHALLENGE
	char *rsa_pubkey_file;
	RSA *rsa_pubkey;
#endif
};

struct remote_conf *make_remote_conf(void);
void free_remote_conf(struct remote_conf *);

int find_shared_conf(const char *username, const char *host, const char *server, int flags);
void cluster_generic(struct Client *, const char *, int cltype, const char *format, ...);

#define OPER_ENCRYPTED	0x00001
#define OPER_KLINE	0x00002
#define OPER_UNKLINE	0x00004
#define OPER_LOCKILL	0x00008
#define OPER_GLOBKILL	0x00010
#define OPER_REMOTE	0x00020
#define OPER_GLINE	0x00040
#define OPER_XLINE	0x00080
#define OPER_RESV	0x00100
#define OPER_NICKS	0x00200
#define OPER_REHASH	0x00400
#define OPER_DIE	0x00800
#define OPER_ADMIN	0x01000
#define OPER_HADMIN	0x02000
#define OPER_OPERWALL	0x04000
#define OPER_INVIS	0x08000
#define OPER_SPY	0x10000
#define OPER_REMOTEBAN	0x20000
#define OPER_NEEDSSL	0x40000

#define OPER_FLAGS	(OPER_KLINE|OPER_UNKLINE|OPER_LOCKILL|OPER_GLOBKILL|\
			 OPER_REMOTE|OPER_GLINE|OPER_XLINE|OPER_RESV|\
			 OPER_NICKS|OPER_REHASH|OPER_DIE|OPER_ADMIN|\
			 OPER_HADMIN|OPER_OPERWALL|OPER_INVIS|OPER_SPY|\
			 OPER_REMOTEBAN)

#define IsOperConfEncrypted(x)	((x)->flags & OPER_ENCRYPTED)
#define IsOperConfNeedSSL(x)	((x)->flags & OPER_NEEDSSL)

#define IsOperGlobalKill(x)     ((x)->operflags & OPER_GLOBKILL)
#define IsOperLocalKill(x)      ((x)->operflags & OPER_LOCKILL)
#define IsOperRemote(x)         ((x)->operflags & OPER_REMOTE)
#define IsOperUnkline(x)        ((x)->operflags & OPER_UNKLINE)
#define IsOperGline(x)          ((x)->operflags & OPER_GLINE)
#define IsOperN(x)              ((x)->operflags & OPER_NICKS)
#define IsOperK(x)              ((x)->operflags & OPER_KLINE)
#define IsOperXline(x)          ((x)->operflags & OPER_XLINE)
#define IsOperResv(x)           ((x)->operflags & OPER_RESV)
#define IsOperDie(x)            ((x)->operflags & OPER_DIE)
#define IsOperRehash(x)         ((x)->operflags & OPER_REHASH)
#define IsOperHiddenAdmin(x)    ((x)->operflags & OPER_HADMIN)
#define IsOperAdmin(x)          (((x)->operflags & OPER_ADMIN) || \
					((x)->operflags & OPER_HADMIN))
#define IsOperOperwall(x)       ((x)->operflags & OPER_OPERWALL)
#define IsOperSpy(x)            ((x)->operflags & OPER_SPY)
#define IsOperInvis(x)          ((x)->operflags & OPER_INVIS)
#define IsOperRemoteBan(x)	((x)->operflags & OPER_REMOTEBAN)

struct oper_conf *make_oper_conf(void);
void free_oper_conf(struct oper_conf *);
void clear_oper_conf(void);

struct oper_conf *find_oper_conf(const char *username, const char *host,
				 const char *locip, const char *oname);

const char *get_oper_privs(int flags);

struct server_conf
{
	char *name;
	char *host;
	char *passwd;
	char *spasswd;
	int port;
	int flags;
	int servers;
	time_t hold;

	struct rb_sockaddr_storage ipnum;
	struct rb_sockaddr_storage my_ipnum;

	char *class_name;
	struct Class *class;
	uint16_t dns_query;
	rb_dlink_node node;

};

#define SERVER_ILLEGAL		0x0001
#define SERVER_VHOSTED		0x0002
#define SERVER_ENCRYPTED	0x0004
#define SERVER_COMPRESSED	0x0008
#define SERVER_TB		0x0010
#define SERVER_AUTOCONN		0x0020
#define SERVER_SSL		0x0040

#define ServerConfIllegal(x)	((x)->flags & SERVER_ILLEGAL)
#define ServerConfVhosted(x)	((x)->flags & SERVER_VHOSTED)
#define ServerConfEncrypted(x)	((x)->flags & SERVER_ENCRYPTED)
#define ServerConfCompressed(x)	((x)->flags & SERVER_COMPRESSED)
#define ServerConfTb(x)		((x)->flags & SERVER_TB)
#define ServerConfAutoconn(x)	((x)->flags & SERVER_AUTOCONN)
#define ServerConfSSL(x)	((x)->flags & SERVER_SSL)


struct server_conf *make_server_conf(void);
void free_server_conf(struct server_conf *);
void clear_server_conf(void);
void add_server_conf(struct server_conf *);

struct server_conf *find_server_conf(const char *name);

void attach_server_conf(struct Client *, struct server_conf *);
void detach_server_conf(struct Client *);
void set_server_conf_autoconn(struct Client *source_p, const char *name, int newval);
void disable_server_conf_autoconn(const char *name);


struct ConfItem *find_xline(const char *, int);
struct ConfItem *find_nick_resv(const char *name);
struct ConfItem *find_xline_mask(const char *);
struct ConfItem *find_nick_resv_mask(const char *name);

int valid_wild_card_simple(const char *);
int clean_resv_nick(const char *);
time_t valid_temp_time(const char *p);

struct nd_entry
{
	char name[NICKLEN + 1];
	time_t expire;
	unsigned int hashv;

	rb_dlink_node hnode;	/* node in hash */
	rb_dlink_node lnode;	/* node in ll */
};

void add_nd_entry(const char *name);
void free_nd_entry(struct nd_entry *);
unsigned long get_nd_count(void);

#endif
