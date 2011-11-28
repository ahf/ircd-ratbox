/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_conf.h: A header for the configuration functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
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
 *  $Id: s_conf.h 27293 2011-11-01 21:24:10Z jilles $
 */

#ifndef INCLUDED_s_conf_h
#define INCLUDED_s_conf_h

#ifdef USE_CHALLENGE
#include <openssl/rsa.h>
#endif


struct Client;
struct DNSReply;
struct hostent;

struct ConfItem
{
	unsigned int status;	/* If CONF_ILLEGAL, delete when no clients */
	unsigned int flags;
	int clients;		/* Number of *LOCAL* clients using this */

	union
	{
		char *name;	/* IRC name, nick, server name, or original u@h */
		const char *oper;
	} info;

	char *host;		/* host part of user@host */
	char *passwd;		/* doubles as kline reason *ugh* */
	char *spasswd;		/* Password to send. */
	char *user;		/* user part of user@host */
	int port;
	time_t hold;		/* Hold action until this time (calendar time) */
	struct Class *c_class;	/* Class of connection */
	rb_patricia_node_t *pnode;
};

#define CONF_ILLEGAL            0x80000000
#define CONF_SKIPUSER		0x0001	/* skip username checks (ie, *@x) */
#define CONF_CLIENT             0x0002
#define CONF_KILL               0x0040
#define CONF_XLINE		0x0080
#define CONF_RESV_CHANNEL	0x0100
#define CONF_RESV_NICK		0x0200
#define CONF_GLINE             0x10000
#define CONF_DLINE             0x20000
#define CONF_EXEMPTDLINE      0x100000

#define IsIllegal(x)    ((x)->status & CONF_ILLEGAL)

/* aConfItem->flags */

/* Generic flags... */
/* access flags... */
#define CONF_FLAGS_NO_TILDE             0x00000001
#define CONF_FLAGS_NEED_IDENTD          0x00000002
#define CONF_FLAGS_EXEMPTKLINE          0x00000004
#define CONF_FLAGS_NOLIMIT              0x00000008
#define CONF_FLAGS_SPOOF_IP             0x00000010
#define CONF_FLAGS_SPOOF_NOTICE		0x00000020
#define CONF_FLAGS_REDIR                0x00000040
#define CONF_FLAGS_EXEMPTGLINE          0x00000080
#define CONF_FLAGS_EXEMPTRESV		0x00000100	/* exempt from resvs */
#define CONF_FLAGS_EXEMPTFLOOD          0x00000200
#define CONF_FLAGS_EXEMPTSPAMBOT	0x00000400
#define CONF_FLAGS_EXEMPTSHIDE		0x00000800
#define CONF_FLAGS_EXEMPTJUPE		0x00001000	/* exempt from resv generating warnings */
#define CONF_FLAGS_NEED_SSL		0x00002000
#define CONF_FLAGS_EXEMPTDNSBL		0x00080000
/* server flags */
#define CONF_FLAGS_ENCRYPTED            0x00004000
#define CONF_FLAGS_COMPRESSED           0x00008000
#define CONF_FLAGS_TEMPORARY            0x00010000
#define CONF_FLAGS_TB			0x00020000
#define CONF_FLAGS_LOCKED		0x00040000

/* Macros for struct ConfItem */
#define IsConfBan(x)		((x)->status & (CONF_KILL|CONF_XLINE|CONF_DLINE|\
						CONF_RESV_CHANNEL|CONF_RESV_NICK))

#define IsNoTilde(x)            ((x)->flags & CONF_FLAGS_NO_TILDE)
#define IsNeedIdentd(x)         ((x)->flags & CONF_FLAGS_NEED_IDENTD)
#define IsConfExemptKline(x)    ((x)->flags & CONF_FLAGS_EXEMPTKLINE)
#define IsConfExemptLimits(x)   ((x)->flags & CONF_FLAGS_NOLIMIT)
#define IsConfExemptGline(x)    ((x)->flags & CONF_FLAGS_EXEMPTGLINE)
#define IsConfExemptFlood(x)    ((x)->flags & CONF_FLAGS_EXEMPTFLOOD)
#define IsConfExemptSpambot(x)	((x)->flags & CONF_FLAGS_EXEMPTSPAMBOT)
#define IsConfExemptShide(x)	((x)->flags & CONF_FLAGS_EXEMPTSHIDE)
#define IsConfExemptJupe(x)	((x)->flags & CONF_FLAGS_EXEMPTJUPE)
#define IsConfExemptResv(x)	((x)->flags & CONF_FLAGS_EXEMPTRESV)
#define IsConfDoSpoofIp(x)      ((x)->flags & CONF_FLAGS_SPOOF_IP)
#define IsConfSpoofNotice(x)    ((x)->flags & CONF_FLAGS_SPOOF_NOTICE)
#define IsConfEncrypted(x)      ((x)->flags & CONF_FLAGS_ENCRYPTED)
#define IsConfCompressed(x)     ((x)->flags & CONF_FLAGS_COMPRESSED)
#define IsConfTburst(x)		((x)->flags & CONF_FLAGS_TB)
#define IsConfLocked(x)		((x)->flags & CONF_FLAGS_LOCKED)
#define IsConfSSLNeeded(x)	((x)->flags & CONF_FLAGS_NEED_SSL)
#define IsConfExemptDNSBL(x)	((x)->flags & CONF_FLAGS_EXEMPTDNSBL)

/* flag definitions for opers now in client.h */

struct config_file_entry
{
	const char *dpath;	/* DPATH if set from command line */
	const char *configfile;

	char *egdpool_path;

	char *default_operstring;
	char *default_adminstring;
	char *kline_reason;

	char *fname_userlog;
	char *fname_fuserlog;
	char *fname_operlog;
	char *fname_foperlog;
	char *fname_serverlog;
	char *fname_killlog;
	char *fname_glinelog;
	char *fname_klinelog;
	char *fname_operspylog;
	char *fname_ioerrorlog;

	unsigned char compression_level;
	int disable_fake_channels;
	int dots_in_ident;
	int failed_oper_notice;
	int anti_nick_flood;
	int anti_spam_exit_message_time;
	int max_accept;
	int max_monitor;
	int max_nick_time;
	int max_nick_changes;
	int ts_max_delta;
	int ts_warn_delta;
	int dline_with_reason;
	int kline_with_reason;
	int kline_delay;
	int warn_no_nline;
	int nick_delay;
	int non_redundant_klines;
	int stats_e_disabled;
	int stats_c_oper_only;
	int stats_y_oper_only;
	int stats_h_oper_only;
	int stats_o_oper_only;
	int stats_k_oper_only;
	int stats_i_oper_only;
	int stats_P_oper_only;
	int map_oper_only;
	int operspy_admin_only;
	int pace_wait;
	int pace_wait_simple;
	int short_motd;
	int default_invisible;
	int no_oper_flood;
	int glines;
	int gline_time;
	int gline_min_cidr;
	int gline_min_cidr6;
	int hide_server;
	int hide_error_messages;
	int client_exit;
	int oper_only_umodes;
	int oper_umodes;
	int max_targets;
	int caller_id_wait;
	int min_nonwildcard;
	int min_nonwildcard_simple;
	int default_floodcount;
	int client_flood;
	int use_egd;
	int ping_cookie;
	int tkline_expire_notices;
	int use_whois_actually;
	int disable_auth;
	int connect_timeout;
	int post_registration_delay;
	int burst_away;
	int reject_after_count;
	int reject_duration;
	int throttle_count;
	int throttle_duration;
	int target_change;
	int collision_fnc;
	int hide_spoof_ips;
	int global_cidr_ipv4_bitlen;
	int global_cidr_ipv4_count;
	int global_cidr_ipv6_bitlen;
	int global_cidr_ipv6_count;
	int global_cidr;
#ifdef RB_IPV6
	int fallback_to_ip6_int;
#endif
};

struct config_channel_entry
{
	int use_except;
	int use_invex;
	int use_knock;
	int use_sslonly;
	int knock_delay;
	int knock_delay_channel;
	int max_bans;
	int max_chans_per_user;
	int no_create_on_split;
	int no_join_on_split;
	int quiet_on_ban;
	int default_split_server_count;
	int default_split_user_count;
	int no_oper_resvs;
	int burst_topicwho;
	int invite_ops_only;
	int topiclen;
	int only_ascii_channels;
	int resv_forcepart;
};

struct config_server_hide
{
	int flatten_links;
	int links_delay;
	int links_disabled;
	int hidden;
	int disable_hidden;
};

struct server_info
{
	char *name;
	char sid[4];
	char *description;
	char *network_name;
	int hub;
	int default_max_clients;
	struct sockaddr_in ip;
#ifdef RB_IPV6
	struct sockaddr_in6 ip6;
#endif
	int specific_ipv4_vhost;
#ifdef RB_IPV6
	int specific_ipv6_vhost;
#endif
	char *ssl_private_key;
	char *ssl_ca_cert;
	char *ssl_cert;
	char *ssl_dh_params;
	int ssld_count;
	char *vhost_dns;
#ifdef RB_IPV6
	char *vhost6_dns;
#endif
	char *bandb_path;
};

struct admin_info
{
	char *name;
	char *description;
	char *email;
};

/* All variables are GLOBAL */
extern int specific_ipv4_vhost;	/* used in s_bsd.c */
extern int specific_ipv6_vhost;
extern struct config_file_entry ConfigFileEntry;	/* defined in ircd.c */
extern struct config_channel_entry ConfigChannel;	/* defined in channel.c */
extern struct config_server_hide ConfigServerHide;	/* defined in s_conf.c */
extern struct server_info ServerInfo;	/* defined in ircd.c */
extern struct admin_info AdminInfo;	/* defined in ircd.c */
/* End GLOBAL section */

#ifdef ENABLE_SERVICES
extern rb_dlink_list service_list;
#endif

typedef enum temp_list
{
	TEMP_MIN,
	TEMP_HOUR,
	TEMP_DAY,
	TEMP_WEEK,
	LAST_TEMP_TYPE
} temp_list;

extern rb_dlink_list temp_klines[LAST_TEMP_TYPE];
extern rb_dlink_list temp_dlines[LAST_TEMP_TYPE];

void init_s_conf(void);

struct ConfItem *make_conf(void);
void free_conf(struct ConfItem *);

int attach_conf(struct Client *, struct ConfItem *);
int check_client(struct Client *client_p, struct Client *source_p, const char *);

int detach_conf(struct Client *);

struct ConfItem *conf_connect_allowed(struct sockaddr *addr, int);

struct ConfItem *find_tkline(const char *, const char *, struct sockaddr *);

void get_printable_conf(struct ConfItem *,
			const char **, const char **, const char **, const char **, int *,
			const char **);
void get_printable_kline(struct Client *, struct ConfItem *, const char **, const char **,
			 const char **, const char **);

void yyerror(const char *);
int conf_yy_fatal_error(const char *);
int conf_fgets(char *, int, FILE *);

const char *make_ban_reason(const char *reason, const char *oper_reason);

void add_temp_kline(struct ConfItem *);
void add_temp_dline(struct ConfItem *);
void report_temp_klines(struct Client *);
void show_temp_klines(struct Client *, rb_dlink_list *);

void rehash(int);
void rehash_bans(int);

int conf_add_server(struct ConfItem *, int);
void conf_add_class_to_conf(struct ConfItem *, const char *);
void conf_add_me(struct ConfItem *);
void conf_add_class(struct ConfItem *, int);
void conf_add_d_conf(struct ConfItem *);
void flush_expired_ips(void *);

const char *get_oper_name(struct Client *client_p);
const char *get_class_name(struct ConfItem *aconf);
void set_default_conf(void);


#define NOT_AUTHORISED  (-1)
#define I_SOCKET_ERROR    (-2)
#define I_LINE_FULL     (-3)
#define BANNED_CLIENT   (-4)
#define TOO_MANY_LOCAL	(-6)
#define TOO_MANY_GLOBAL (-7)
#define TOO_MANY_IDENT	(-8)
#define TOO_MANY_GLOBAL_CIDR (-9)

#endif /* INCLUDED_s_conf_h */
