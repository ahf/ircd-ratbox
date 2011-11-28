/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_conf.c: Configuration file functions.
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
 *  $Id: s_conf.c 27293 2011-11-01 21:24:10Z jilles $
 */

#include "stdinc.h"
#include "struct.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_stats.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "match.h"
#include "ratbox_lib.h"
#include "ircd.h"
#include "listener.h"
#include "hostmask.h"
#include "hook.h"
#include "modules.h"
#include "numeric.h"
#include "s_log.h"
#include "send.h"
#include "s_gline.h"
#include "reject.h"
#include "cache.h"
#include "dns.h"
#include "operhash.h"
#include "bandbi.h"
#include "newconf.h"
#include "blacklist.h"

struct config_server_hide ConfigServerHide;

extern char linebuf[];

static rb_bh *confitem_heap = NULL;

rb_dlink_list temp_klines[LAST_TEMP_TYPE];
rb_dlink_list temp_dlines[LAST_TEMP_TYPE];

#ifdef ENABLE_SERVICES
rb_dlink_list service_list;
#endif

/* internally defined functions */
static void clear_out_old_conf(void);

static void expire_temp_kd(void *list);
static void reorganise_temp_kd(void *list);

extern char yytext[];

static int verify_access(struct Client *client_p, const char *username);
static int attach_iline(struct Client *, struct ConfItem *);

void
init_s_conf(void)
{
	confitem_heap = rb_bh_create(sizeof(struct ConfItem), CONFITEM_HEAP_SIZE, "confitem_heap");

	rb_event_addish("expire_temp_klines", expire_temp_kd, &temp_klines[TEMP_MIN], 60);
	rb_event_addish("expire_temp_dlines", expire_temp_kd, &temp_dlines[TEMP_MIN], 60);

	rb_event_addish("expire_temp_klines_hour", reorganise_temp_kd,
			&temp_klines[TEMP_HOUR], 3600);
	rb_event_addish("expire_temp_dlines_hour", reorganise_temp_kd,
			&temp_dlines[TEMP_HOUR], 3600);
	rb_event_addish("expire_temp_klines_day", reorganise_temp_kd,
			&temp_klines[TEMP_DAY], 86400);
	rb_event_addish("expire_temp_dlines_day", reorganise_temp_kd,
			&temp_dlines[TEMP_DAY], 86400);
	rb_event_addish("expire_temp_klines_week", reorganise_temp_kd,
			&temp_klines[TEMP_WEEK], 604800);
	rb_event_addish("expire_temp_dlines_week", reorganise_temp_kd,
			&temp_dlines[TEMP_WEEK], 604800);
}

/*
 * make_conf
 *
 * inputs	- none
 * output	- pointer to new conf entry
 * side effects	- none
 */
struct ConfItem *
make_conf()
{
	struct ConfItem *aconf;

	aconf = rb_bh_alloc(confitem_heap);
	aconf->status = CONF_ILLEGAL;
	return (aconf);
}

/*
 * free_conf
 *
 * inputs	- pointer to conf to free
 * output	- none
 * side effects	- crucial password fields are zeroed, conf is freed
 */
void
free_conf(struct ConfItem *aconf)
{
	s_assert(aconf != NULL);
	if(aconf == NULL)
		return;

	/* security.. */
	if(aconf->passwd)
		memset(aconf->passwd, 0, strlen(aconf->passwd));
	if(aconf->spasswd)
		memset(aconf->spasswd, 0, strlen(aconf->spasswd));

	rb_free(aconf->passwd);
	rb_free(aconf->spasswd);
	rb_free(aconf->user);
	rb_free(aconf->host);

	if(IsConfBan(aconf))
		operhash_delete(aconf->info.oper);
	else
		rb_free(aconf->info.name);

	rb_bh_free(confitem_heap, aconf);
}

/*
 * check_client
 *
 * inputs	- pointer to client
 * output	- 0 = Success
 * 		  NOT_AUTHORISED (-1) = Access denied (no I line match)
 * 		  I_SOCKET_ERROR   (-2) = Bad socket.
 * 		  I_LINE_FULL    (-3) = I-line is full
 *		  TOO_MANY       (-4) = Too many connections from hostname
 * 		  BANNED_CLIENT  (-5) = K-lined
 * side effects - Ordinary client access check.
 *		  Look for conf lines which have the same
 * 		  status as the flags passed.
 */
int
check_client(struct Client *client_p, struct Client *source_p, const char *username)
{
	int i;

	if((i = verify_access(source_p, username)))
	{
		ilog(L_FUSER, "Access denied: %s[%s]", source_p->name, source_p->sockhost);
	}

	switch (i)
	{
	case I_SOCKET_ERROR:
		exit_client(client_p, source_p, &me, "Socket Error");
		break;

	case TOO_MANY_LOCAL:
		sendto_realops_flags(UMODE_FULL, L_ALL,
				     "Too many local connections for %s!%s%s@%s",
				     source_p->name, IsGotId(source_p) ? "" : "~",
				     source_p->username, show_ip(NULL,
								 source_p) ? source_p->sockhost :
				     source_p->host);

		ilog(L_FUSER, "Too many local connections from %s!%s%s@%s",
		     source_p->name, IsGotId(source_p) ? "" : "~",
		     source_p->username, source_p->sockhost);

		ServerStats.is_ref++;
		exit_client(client_p, source_p, &me, "Too many host connections (local)");
		break;

	case TOO_MANY_GLOBAL:
		sendto_realops_flags(UMODE_FULL, L_ALL,
				     "Too many global connections for %s!%s%s@%s",
				     source_p->name, IsGotId(source_p) ? "" : "~",
				     source_p->username, show_ip(NULL,
								 source_p) ? source_p->sockhost :
				     source_p->host);
		ilog(L_FUSER, "Too many global connections from %s!%s%s@%s", source_p->name,
		     IsGotId(source_p) ? "" : "~", source_p->username, source_p->sockhost);

		ServerStats.is_ref++;
		exit_client(client_p, source_p, &me, "Too many host connections (global)");
		break;

	case TOO_MANY_GLOBAL_CIDR:
		sendto_realops_flags(UMODE_FULL, L_ALL,
				     "Too many global connections(cidr) for %s!%s%s@%s",
				     source_p->name, IsGotId(source_p) ? "" : "~",
				     source_p->username, show_ip(NULL,
								 source_p) ? source_p->sockhost :
				     source_p->host);
		ilog(L_FUSER, "Too many global connections(cidr) from %s!%s%s@%s", source_p->name,
		     IsGotId(source_p) ? "" : "~", source_p->username, source_p->sockhost);

		ServerStats.is_ref++;
		exit_client(client_p, source_p, &me, "Too many host connections (global cidr)");
		break;


	case TOO_MANY_IDENT:
		sendto_realops_flags(UMODE_FULL, L_ALL,
				     "Too many user connections for %s!%s%s@%s",
				     source_p->name, IsGotId(source_p) ? "" : "~",
				     source_p->username, show_ip(NULL,
								 source_p) ? source_p->sockhost :
				     source_p->host);
		ilog(L_FUSER, "Too many user connections from %s!%s%s@%s", source_p->name,
		     IsGotId(source_p) ? "" : "~", source_p->username, source_p->sockhost);

		ServerStats.is_ref++;
		exit_client(client_p, source_p, &me, "Too many user connections (global)");
		break;

	case I_LINE_FULL:
		sendto_realops_flags(UMODE_FULL, L_ALL,
				     "I-line is full for %s!%s%s@%s (%s).",
				     source_p->name, IsGotId(source_p) ? "" : "~",
				     source_p->username, source_p->host,
				     show_ip(NULL, source_p) ? source_p->sockhost : source_p->host);

		ilog(L_FUSER, "Too many connections from %s!%s%s@%s.",
		     source_p->name, IsGotId(source_p) ? "" : "~",
		     source_p->username, source_p->sockhost);

		ServerStats.is_ref++;
		exit_client(client_p, source_p, &me,
			    "No more connections allowed in your connection class");
		break;

	case NOT_AUTHORISED:
		{
			int port = -1;
#ifdef RB_IPV6
			if(GET_SS_FAMILY(&source_p->localClient->ip) == AF_INET6)
				port = ntohs(((struct sockaddr_in6 *)&source_p->
					      localClient->listener->addr)->sin6_port);
			else
#endif
				port = ntohs(((struct sockaddr_in *)&source_p->
					      localClient->listener->addr)->sin_port);

			ServerStats.is_ref++;
			/* jdc - lists server name & port connections are on */
			/*       a purely cosmetical change */

			sendto_realops_flags(UMODE_UNAUTH, L_ALL,
					     "Unauthorised client connection from "
					     "%s!%s%s@%s [%s] on [%s/%u].",
					     source_p->name, IsGotId(source_p) ? "" : "~",
					     source_p->username, source_p->host,
					     source_p->sockhost,
					     source_p->localClient->listener->name, port);

			ilog(L_FUSER,
			     "Unauthorised client connection from %s!%s%s@%s on [%s/%u].",
			     source_p->name, IsGotId(source_p) ? "" : "~",
			     source_p->username, source_p->sockhost,
			     source_p->localClient->listener->name, port);
			add_reject(client_p);
			exit_client(client_p, source_p, &me,
				    "You are not authorised to use this server");
			break;
		}
	case BANNED_CLIENT:
		add_reject(client_p);
		exit_client(client_p, client_p, &me, "*** Banned ");
		ServerStats.is_ref++;
		break;

	case 0:
	default:
		break;
	}
	return (i);
}

/*
 * verify_access
 *
 * inputs	- pointer to client to verify
 *		- pointer to proposed username
 * output	- 0 if success -'ve if not
 * side effect	- find the first (best) I line to attach.
 */
static int
verify_access(struct Client *client_p, const char *username)
{
	struct ConfItem *aconf;
	char non_ident[USERLEN + 1];

	if(IsGotId(client_p))
	{
		aconf = find_address_conf(client_p->host, client_p->sockhost,
					  client_p->username,
					  (struct sockaddr *)&client_p->localClient->ip,
					  GET_SS_FAMILY(&client_p->localClient->ip));
	}
	else
	{
		rb_strlcpy(non_ident, "~", sizeof(non_ident));
		rb_strlcat(non_ident, username, sizeof(non_ident));
		aconf = find_address_conf(client_p->host, client_p->sockhost,
					  non_ident,
					  (struct sockaddr *)&client_p->localClient->ip,
					  GET_SS_FAMILY(&client_p->localClient->ip));
	}

	if(aconf == NULL)
		return NOT_AUTHORISED;

	if(aconf->status & CONF_CLIENT)
	{
		if(aconf->flags & CONF_FLAGS_REDIR)
		{
			sendto_one(client_p, form_str(RPL_REDIR),
				   me.name, client_p->name,
				   aconf->info.name ? aconf->info.name : "", aconf->port);
			return (NOT_AUTHORISED);
		}

		/* Thanks for spoof idea amm */
		if(IsConfDoSpoofIp(aconf))
		{
			char *p;
			SetIPSpoof(client_p);	/*show_ip depends on this */
			if(IsConfSpoofNotice(aconf))
			{
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "%s spoofing: %s as %s",
						     client_p->name,
						     show_ip(NULL,
							     client_p) ? client_p->
						     host : aconf->info.name, aconf->info.name);
			}

			/* user@host spoof */
			if((p = strchr(aconf->info.name, '@')) != NULL)
			{
				char *host = p + 1;
				*p = '\0';

				rb_strlcpy(client_p->username, aconf->info.name,
					   sizeof(client_p->username));
				rb_strlcpy(client_p->host, host, sizeof(client_p->host));
				*p = '@';
			}
			else
				rb_strlcpy(client_p->host, aconf->info.name,
					   sizeof(client_p->host));
		}
		return (attach_iline(client_p, aconf));
	}
	else if(aconf->status & CONF_KILL)
	{
		if(ConfigFileEntry.kline_with_reason)
			sendto_one_notice(client_p, ":*** Banned %s", aconf->passwd);
		return (BANNED_CLIENT);
	}
	else if(aconf->status & CONF_GLINE)
	{
		sendto_one_notice(client_p, ":*** G-lined");

		if(ConfigFileEntry.kline_with_reason)
			sendto_one_notice(client_p, ":*** Banned %s", aconf->passwd);

		return (BANNED_CLIENT);
	}

	return NOT_AUTHORISED;
}


/*
 * add_ip_limit
 * 
 * Returns 1 if successful 0 if not
 *
 * This checks if the user has exceed the limits for their class
 * unless of course they are exempt..
 */

static int
add_ip_limit(struct Client *client_p, struct ConfItem *aconf)
{
	rb_patricia_node_t *pnode;
	int bitlen;
	/* If the limits are 0 don't do anything.. */
	if(ConfCidrAmount(aconf) == 0
	   || (ConfCidrIpv4Bitlen(aconf) == 0 && ConfCidrIpv6Bitlen(aconf) == 0))
		return -1;

	pnode = rb_match_ip(ConfIpLimits(aconf), (struct sockaddr *)&client_p->localClient->ip);

	if(GET_SS_FAMILY(&client_p->localClient->ip) == AF_INET)
		bitlen = ConfCidrIpv4Bitlen(aconf);
	else
		bitlen = ConfCidrIpv6Bitlen(aconf);

	if(pnode == NULL)
		pnode = make_and_lookup_ip(ConfIpLimits(aconf),
					   (struct sockaddr *)&client_p->localClient->ip, bitlen);

	s_assert(pnode != NULL);

	if(pnode != NULL)
	{
		if(((intptr_t)pnode->data) >= ConfCidrAmount(aconf) && !IsConfExemptLimits(aconf))
		{
			/* This should only happen if the limits are set to 0 */
			if((intptr_t)pnode->data == 0)
			{
				rb_patricia_remove(ConfIpLimits(aconf), pnode);
			}
			return (0);
		}

		pnode->data = (void *)(((intptr_t)pnode->data) + 1);
	}
	return 1;
}

static void
remove_ip_limit(struct Client *client_p, struct ConfItem *aconf)
{
	rb_patricia_node_t *pnode;

	/* If the limits are 0 don't do anything.. */
	if(ConfCidrAmount(aconf) == 0
	   || (ConfCidrIpv4Bitlen(aconf) == 0 && ConfCidrIpv6Bitlen(aconf) == 0))
		return;

	pnode = rb_match_ip(ConfIpLimits(aconf), (struct sockaddr *)&client_p->localClient->ip);
	if(pnode == NULL)
		return;

	pnode->data = (void *)(((intptr_t)pnode->data) - 1);
	if(((intptr_t)pnode->data) == 0)
	{
		rb_patricia_remove(ConfIpLimits(aconf), pnode);
	}

}

/*
 * attach_iline
 *
 * inputs	- client pointer
 *		- conf pointer
 * output	-
 * side effects	- do actual attach
 */
static int
attach_iline(struct Client *client_p, struct ConfItem *aconf)
{
	struct Client *target_p;
	rb_dlink_node *ptr;
	int local_count = 0;
	int global_count = 0;
	int ident_count = 0;
	int unidented = 0;

	if(IsConfExemptLimits(aconf))
		return (attach_conf(client_p, aconf));

	if(*client_p->username == '~')
		unidented = 1;

	/* find_hostname() returns the head of the list to search */
	RB_DLINK_FOREACH(ptr, find_hostname(client_p->host))
	{
		target_p = ptr->data;

		if(irccmp(client_p->host, target_p->host) != 0)
			continue;

		if(MyConnect(target_p))
			local_count++;

		global_count++;

		if(unidented)
		{
			if(*target_p->username == '~')
				ident_count++;
		}
		else if(irccmp(target_p->username, client_p->username) == 0)
			ident_count++;

		if(ConfMaxLocal(aconf) && local_count >= ConfMaxLocal(aconf))
			return (TOO_MANY_LOCAL);
		else if(ConfMaxGlobal(aconf) && global_count >= ConfMaxGlobal(aconf))
			return (TOO_MANY_GLOBAL);
		else if(ConfMaxIdent(aconf) && ident_count >= ConfMaxIdent(aconf))
			return (TOO_MANY_IDENT);
	}

	if(ConfigFileEntry.global_cidr && check_global_cidr_count(client_p) > 0)
		return (TOO_MANY_GLOBAL_CIDR);
	return (attach_conf(client_p, aconf));
}

/*
 * detach_conf
 *
 * inputs	- pointer to client to detach
 * output	- 0 for success, -1 for failure
 * side effects	- Disassociate configuration from the client.
 *		  Also removes a class from the list if marked for deleting.
 */
int
detach_conf(struct Client *client_p)
{
	struct ConfItem *aconf;

	aconf = client_p->localClient->att_conf;

	if(aconf != NULL)
	{
		if(ClassPtr(aconf))
		{
			remove_ip_limit(client_p, aconf);

			if(ConfCurrUsers(aconf) > 0)
				--ConfCurrUsers(aconf);

			if(ConfMaxUsers(aconf) == -1 && ConfCurrUsers(aconf) == 0)
			{
				free_class(ClassPtr(aconf));
				ClassPtr(aconf) = NULL;
			}

		}

		aconf->clients--;
		if(!aconf->clients && IsIllegal(aconf))
			free_conf(aconf);

		client_p->localClient->att_conf = NULL;
		return 0;
	}

	return -1;
}

/*
 * attach_conf
 * 
 * inputs	- client pointer
 * 		- conf pointer
 * output	-
 * side effects - Associate a specific configuration entry to a *local*
 *                client (this is the one which used in accepting the
 *                connection). Note, that this automatically changes the
 *                attachment if there was an old one...
 */
int
attach_conf(struct Client *client_p, struct ConfItem *aconf)
{
	if(IsIllegal(aconf))
		return (NOT_AUTHORISED);

	if(ClassPtr(aconf))
	{
		if(!add_ip_limit(client_p, aconf))
			return (TOO_MANY_LOCAL);
	}

	if((aconf->status & CONF_CLIENT) &&
	   ConfCurrUsers(aconf) >= ConfMaxUsers(aconf) && ConfMaxUsers(aconf) > 0)
	{
		if(!IsConfExemptLimits(aconf))
		{
			return (I_LINE_FULL);
		}
		else
		{
			sendto_one_notice(client_p,
					  ":*** I: line is full, but you have an >I: line!");
			SetExemptLimits(client_p);
		}

	}

	if(client_p->localClient->att_conf != NULL)
		detach_conf(client_p);

	client_p->localClient->att_conf = aconf;

	aconf->clients++;
	ConfCurrUsers(aconf)++;
	return (0);
}

/*
 * rehash
 *
 * Actual REHASH service routine. Called with sig == 0 if it has been called
 * as a result of an operator issuing this command, else assume it has been
 * called as a result of the server receiving a HUP signal.
 */
void
rehash(int sig)
{
	const char *filename;
	int r;
	int old_global_ipv4_cidr = ConfigFileEntry.global_cidr_ipv4_bitlen;
	int old_global_ipv6_cidr = ConfigFileEntry.global_cidr_ipv6_bitlen;
	char *old_bandb_path = LOCAL_COPY(ServerInfo.bandb_path);
	
	if(sig != 0)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Got signal SIGHUP, reloading ircd conf. file");
	}

	filename = ConfigFileEntry.configfile;

	r = read_config_file(filename);

	if(r > 0)
	{
		ilog(L_MAIN, "Config file %s has %d error(s) - aborting rehash", filename, r);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Config file %s has %d error(s) aborting rehash", filename, r);
		return;
	}

	r = check_valid_entries();

	if(r > 0)
	{
		ilog(L_MAIN, "Config file %s reports %d error(s) on second pass - aborting rehash",
		     filename, r);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Config file %s reports %d error(s) on second pass - aborting rehash",
				     filename, r);
		return;
	}

	clear_out_old_conf();
	load_conf_settings();

	if(ServerInfo.description != NULL)
		rb_strlcpy(me.info, ServerInfo.description, sizeof(me.info));
	else
		rb_strlcpy(me.info, "unknown", sizeof(me.info));
		
	if(ServerInfo.bandb_path == NULL)
		ServerInfo.bandb_path = rb_strdup(DBPATH);

	if(strcmp(old_bandb_path, ServerInfo.bandb_path))
		bandb_restart();

	open_logfiles(logFileName);
	if(old_global_ipv4_cidr != ConfigFileEntry.global_cidr_ipv4_bitlen ||
	   old_global_ipv6_cidr != ConfigFileEntry.global_cidr_ipv6_bitlen)
		rehash_global_cidr_tree();

	rehash_dns_vhost();
	return;
}

void
rehash_bans(int sig)
{
	if(sig != 0)
		sendto_realops_flags(UMODE_ALL, L_ALL, "Got signal SIGUSR2, reloading ban confs");

	bandb_rehash_bans();
}

/*
 * set_default_conf()
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- Set default values here.
 *		  This is called **PRIOR** to parsing the
 *		  configuration file.  If you want to do some validation
 *		  of values later, put them in validate_conf().
 */

#define YES     1
#define NO      0
#define UNSET  -1

void
set_default_conf(void)
{
	/* ServerInfo.name is not rehashable */
	/* ServerInfo.name = ServerInfo.name; */
	ServerInfo.description = NULL;
	ServerInfo.network_name = rb_strdup(NETWORK_NAME_DEFAULT);
	ServerInfo.bandb_path = NULL;
	memset(&ServerInfo.ip, 0, sizeof(ServerInfo.ip));
	ServerInfo.specific_ipv4_vhost = 0;

#ifdef RB_IPV6
	memset(&ServerInfo.ip6, 0, sizeof(ServerInfo.ip6));
	ServerInfo.specific_ipv6_vhost = 0;
#endif
	ServerInfo.default_max_clients = MAXCONNECTIONS;
	ServerInfo.ssld_count = 1;


	/* Don't reset hub, as that will break lazylinks */
	/* ServerInfo.hub = NO; */
	AdminInfo.name = NULL;
	AdminInfo.email = NULL;
	AdminInfo.description = NULL;

	ConfigFileEntry.default_operstring = rb_strdup("is an IRC operator");
	ConfigFileEntry.default_adminstring = rb_strdup("is a Server Administrator");

	ConfigFileEntry.failed_oper_notice = YES;
	ConfigFileEntry.anti_nick_flood = NO;
	ConfigFileEntry.disable_fake_channels = NO;
	ConfigFileEntry.max_nick_time = 20;
	ConfigFileEntry.max_nick_changes = 5;
	ConfigFileEntry.max_accept = 20;
	ConfigFileEntry.max_monitor = 60;
	ConfigFileEntry.nick_delay = 900;	/* 15 minutes */
	ConfigFileEntry.target_change = YES;
	ConfigFileEntry.collision_fnc = NO;
	ConfigFileEntry.anti_spam_exit_message_time = 0;
	ConfigFileEntry.ts_warn_delta = TS_WARN_DELTA_DEFAULT;
	ConfigFileEntry.ts_max_delta = TS_MAX_DELTA_DEFAULT;
	ConfigFileEntry.client_exit = YES;
	ConfigFileEntry.dline_with_reason = YES;
	ConfigFileEntry.kline_with_reason = YES;
	ConfigFileEntry.kline_delay = 0;
	ConfigFileEntry.warn_no_nline = YES;
	ConfigFileEntry.non_redundant_klines = YES;
	ConfigFileEntry.stats_e_disabled = NO;
	ConfigFileEntry.stats_o_oper_only = NO;
	ConfigFileEntry.stats_k_oper_only = 1;	/* masked */
	ConfigFileEntry.stats_i_oper_only = 1;	/* masked */
	ConfigFileEntry.stats_P_oper_only = NO;
	ConfigFileEntry.stats_c_oper_only = NO;
	ConfigFileEntry.stats_y_oper_only = NO;
	ConfigFileEntry.stats_h_oper_only = NO;
	ConfigFileEntry.map_oper_only = YES;
	ConfigFileEntry.operspy_admin_only = NO;
	ConfigFileEntry.pace_wait = 10;
	ConfigFileEntry.caller_id_wait = 60;
	ConfigFileEntry.pace_wait_simple = 1;
	ConfigFileEntry.short_motd = NO;
	ConfigFileEntry.no_oper_flood = NO;
	ConfigFileEntry.post_registration_delay = 0;
	ConfigFileEntry.default_invisible = NO;
	ConfigFileEntry.fname_userlog = NULL;
	ConfigFileEntry.fname_fuserlog = NULL;
	ConfigFileEntry.fname_operlog = NULL;
	ConfigFileEntry.fname_foperlog = NULL;
	ConfigFileEntry.fname_serverlog = NULL;
	ConfigFileEntry.fname_glinelog = NULL;
	ConfigFileEntry.fname_klinelog = NULL;
	ConfigFileEntry.fname_operspylog = NULL;
	ConfigFileEntry.fname_ioerrorlog = NULL;
	ConfigFileEntry.glines = NO;
	ConfigFileEntry.use_egd = NO;
	ConfigFileEntry.gline_time = 12 * 3600;
	ConfigFileEntry.gline_min_cidr = 16;
	ConfigFileEntry.gline_min_cidr6 = 48;
	ConfigFileEntry.hide_error_messages = 1;
	ConfigFileEntry.dots_in_ident = 0;
	ConfigFileEntry.max_targets = MAX_TARGETS_DEFAULT;
	ConfigFileEntry.egdpool_path = NULL;
	ConfigFileEntry.use_whois_actually = YES;
	ConfigFileEntry.burst_away = NO;
	ConfigFileEntry.hide_spoof_ips = YES;
#ifdef HAVE_ZLIB
	ConfigFileEntry.compression_level = 4;
#endif

	ConfigFileEntry.oper_umodes = UMODE_LOCOPS | UMODE_SERVNOTICE |
		UMODE_OPERWALL | UMODE_WALLOP;
	ConfigFileEntry.oper_only_umodes = UMODE_DEBUG | UMODE_OPERSPY;

	ConfigChannel.use_except = YES;
	ConfigChannel.use_invex = YES;
	ConfigChannel.use_knock = YES;
	ConfigChannel.use_sslonly = NO;
	ConfigChannel.knock_delay = 300;
	ConfigChannel.knock_delay_channel = 60;
	ConfigChannel.max_chans_per_user = 15;
	ConfigChannel.max_bans = 25;
	ConfigChannel.only_ascii_channels = NO;
	ConfigChannel.burst_topicwho = YES;
	ConfigChannel.invite_ops_only = YES;

	ConfigChannel.default_split_user_count = 15000;
	ConfigChannel.default_split_server_count = 10;
	ConfigChannel.no_join_on_split = NO;
	ConfigChannel.no_create_on_split = YES;
	ConfigChannel.topiclen = DEFAULT_TOPICLEN;
	ConfigChannel.resv_forcepart = YES;

	ConfigServerHide.flatten_links = 0;
	ConfigServerHide.links_delay = 300;
	ConfigServerHide.hidden = 0;
	ConfigServerHide.disable_hidden = 0;

	ConfigFileEntry.min_nonwildcard = 4;
	ConfigFileEntry.min_nonwildcard_simple = 3;
	ConfigFileEntry.default_floodcount = 8;
	ConfigFileEntry.client_flood = CLIENT_FLOOD_DEFAULT;
	ConfigFileEntry.tkline_expire_notices = 0;

	ConfigFileEntry.reject_after_count = 5;
	ConfigFileEntry.reject_duration = 120;
	ConfigFileEntry.throttle_count = 4;
	ConfigFileEntry.throttle_duration = 60;
	ConfigFileEntry.global_cidr_ipv4_bitlen = 24;
	ConfigFileEntry.global_cidr_ipv4_count = 384;
	ConfigFileEntry.global_cidr_ipv6_bitlen = 64;
	ConfigFileEntry.global_cidr_ipv6_count = 128;
	ConfigFileEntry.global_cidr = YES;
}

#undef YES
#undef NO

/*
 * lookup_confhost - start DNS lookups of all hostnames in the conf
 * line and convert an IP addresses in a.b.c.d number for to IP#s.
 *
 */

/*
 * conf_connect_allowed
 *
 * inputs	- pointer to inaddr
 *		- int type ipv4 or ipv6
 * output	- ban info or NULL
 * side effects	- none
 */
struct ConfItem *
conf_connect_allowed(struct sockaddr *addr, int aftype)
{
	struct ConfItem *aconf = find_dline(addr);

	/* DLINE exempt also gets you out of static limits/pacing... */
	if(aconf && (aconf->status & CONF_EXEMPTDLINE))
		return NULL;

	if(aconf != NULL)
		return aconf;

	return NULL;
}

/* make_ban_reason()
 *
 * inputs	- reason, oper reason
 * outputs	-
 * side effects	- returns a single reason, combining the two fields if
 * 		  appropriate
 */
const char *
make_ban_reason(const char *reason, const char *oper_reason)
{
	static char buf[IRCD_BUFSIZE];

	if(!EmptyString(oper_reason))
	{
		snprintf(buf, sizeof(buf), "%s|%s", reason, oper_reason);
		return buf;
	}
	else
		return reason;
}

/* add_temp_kline()
 *
 * inputs        - pointer to struct ConfItem
 * output        - none
 * Side effects  - links in given struct ConfItem into 
 *                 temporary kline link list
 */
void
add_temp_kline(struct ConfItem *aconf)
{
	if(aconf->hold >= rb_time() + (10080 * 60))
	{
		rb_dlinkAddAlloc(aconf, &temp_klines[TEMP_WEEK]);
		aconf->port = TEMP_WEEK;
	}
	else if(aconf->hold >= rb_time() + (1440 * 60))
	{
		rb_dlinkAddAlloc(aconf, &temp_klines[TEMP_DAY]);
		aconf->port = TEMP_DAY;
	}
	else if(aconf->hold >= rb_time() + (60 * 60))
	{
		rb_dlinkAddAlloc(aconf, &temp_klines[TEMP_HOUR]);
		aconf->port = TEMP_HOUR;
	}
	else
	{
		rb_dlinkAddAlloc(aconf, &temp_klines[TEMP_MIN]);
		aconf->port = TEMP_MIN;
	}

	aconf->flags |= CONF_FLAGS_TEMPORARY;
	add_conf_by_address(aconf->host, CONF_KILL, aconf->user, aconf);
}

/* add_temp_dline()
 *
 * input	- pointer to struct ConfItem
 * output	- none
 * side effects - added to tdline link list and address hash
 */
void
add_temp_dline(struct ConfItem *aconf)
{
	if(aconf->hold >= rb_time() + (10080 * 60))
	{
		rb_dlinkAddAlloc(aconf, &temp_dlines[TEMP_WEEK]);
		aconf->port = TEMP_WEEK;
	}
	else if(aconf->hold >= rb_time() + (1440 * 60))
	{
		rb_dlinkAddAlloc(aconf, &temp_dlines[TEMP_DAY]);
		aconf->port = TEMP_DAY;
	}
	else if(aconf->hold >= rb_time() + (60 * 60))
	{
		rb_dlinkAddAlloc(aconf, &temp_dlines[TEMP_HOUR]);
		aconf->port = TEMP_HOUR;
	}
	else
	{
		rb_dlinkAddAlloc(aconf, &temp_dlines[TEMP_MIN]);
		aconf->port = TEMP_MIN;
	}

	aconf->flags |= CONF_FLAGS_TEMPORARY;
	add_dline(aconf);
}

/* expire_tkline()
 *
 * inputs       - list pointer
 * 		- type
 * output       - NONE
 * side effects - expire tklines and moves them between lists
 */
static void
expire_temp_kd(void *list)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	struct ConfItem *aconf;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, ((rb_dlink_list *)list)->head)
	{
		aconf = ptr->data;

		if(aconf->hold <= rb_time())
		{
			/* Alert opers that a TKline expired - Hwy */
			if(ConfigFileEntry.tkline_expire_notices)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Temporary K-line for [%s@%s] expired",
						     (aconf->user) ? aconf->user : "*",
						     (aconf->host) ? aconf->host : "*");

			if(aconf->status & CONF_DLINE)
				remove_dline(aconf);
			else
				delete_one_address_conf(aconf->host, aconf);
			rb_dlinkDestroy(ptr, list);
		}
	}
}

static void
reorganise_temp_kd(void *list)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr, *next_ptr;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, ((rb_dlink_list *)list)->head)
	{
		aconf = ptr->data;

		if(aconf->hold < (rb_time() + (60 * 60)))
		{
			rb_dlinkMoveNode(ptr, list, (aconf->status == CONF_KILL) ?
					 &temp_klines[TEMP_MIN] : &temp_dlines[TEMP_MIN]);
			aconf->port = TEMP_MIN;
		}
		else if(aconf->port > TEMP_HOUR)
		{
			if(aconf->hold < (rb_time() + (1440 * 60)))
			{
				rb_dlinkMoveNode(ptr, list, (aconf->status == CONF_KILL) ?
						 &temp_klines[TEMP_HOUR] : &temp_dlines[TEMP_HOUR]);
				aconf->port = TEMP_HOUR;
			}
			else if(aconf->port > TEMP_DAY &&
				(aconf->hold < (rb_time() + (10080 * 60))))
			{
				rb_dlinkMoveNode(ptr, list, (aconf->status == CONF_KILL) ?
						 &temp_klines[TEMP_DAY] : &temp_dlines[TEMP_DAY]);
				aconf->port = TEMP_DAY;
			}
		}
	}
}


/* const char* get_oper_name(struct Client *client_p)
 * Input: A client to find the active oper{} name for.
 * Output: The nick!user@host{oper} of the oper.
 *         "oper" is server name for remote opers
 * Side effects: None.
 */
const char *
get_oper_name(struct Client *client_p)
{
	/* +5 for !,@,{,} and null */
	static char buffer[NICKLEN + USERLEN + HOSTLEN + HOSTLEN + 5];

	if(MyOper(client_p))
	{
		rb_snprintf(buffer, sizeof(buffer), "%s!%s@%s{%s}",
			    client_p->name, client_p->username,
			    client_p->host, client_p->localClient->opername);
		return buffer;
	}

	rb_snprintf(buffer, sizeof(buffer), "%s!%s@%s{%s}",
		    client_p->name, client_p->username, client_p->host, client_p->servptr->name);
	return buffer;
}

/* returns class name */
const char *
get_class_name(struct ConfItem *aconf)
{
	static const char *zero = "default";

	if(aconf == NULL || aconf->c_class == NULL || EmptyString(ConfClassName(aconf)))
		return zero;

	return ConfClassName(aconf);
}

/*
 * get_printable_conf
 *
 * inputs        - struct ConfItem
 *
 * output         - name 
 *                - host
 *                - pass
 *                - user
 *                - port
 *
 * side effects        -
 * Examine the struct struct ConfItem, setting the values
 * of name, host, pass, user to values either
 * in aconf, or "<NULL>" port is set to aconf->port in all cases.
 */
void
get_printable_conf(struct ConfItem *aconf, const char **name, const char **host,
		   const char **pass, const char **user, int *port, const char **classname)
{
	static const char *null = "<NULL>";

	*name = EmptyString(aconf->info.name) ? null : aconf->info.name;
	*host = EmptyString(aconf->host) ? null : aconf->host;
	*pass = EmptyString(aconf->passwd) ? null : aconf->passwd;
	*user = EmptyString(aconf->user) ? null : aconf->user;
	*classname = get_class_name(aconf);
	*port = (int)aconf->port;
}

void
get_printable_kline(struct Client *source_p, struct ConfItem *aconf,
		    const char **host, const char **reason,
		    const char **user, const char **oper_reason)
{
	static const char *null = "<NULL>";

	*host = EmptyString(aconf->host) ? null : aconf->host;
	*reason = EmptyString(aconf->passwd) ? null : aconf->passwd;
	*user = EmptyString(aconf->user) ? null : aconf->user;

	if(EmptyString(aconf->spasswd) || !IsOper(source_p))
		*oper_reason = NULL;
	else
		*oper_reason = aconf->spasswd;
}

/*
 * clear_out_old_conf
 *
 * inputs       - none
 * output       - none
 * side effects - Clear out the old configuration
 */
static void
clear_out_old_conf(void)
{
	struct Class *cltmp;
	rb_dlink_node *ptr;
#ifdef ENABLE_SERVICES
	rb_dlink_node *next_ptr;
#endif

	/*
	 * don't delete the class table, rather mark all entries
	 * for deletion. The table is cleaned up by check_class. - avalon
	 */
	RB_DLINK_FOREACH(ptr, class_list.head)
	{
		cltmp = ptr->data;
		MaxUsers(cltmp) = -1;
	}

	clear_out_address_conf();
	remove_elines();
	clear_s_newconf();

	/* clean out module paths */
#ifndef STATIC_MODULES
	mod_clear_paths();
	mod_add_path(MODULE_DIR);
	mod_add_path(MODULE_DIR "/autoload");
#endif

	/* clean out ServerInfo */
	rb_free(ServerInfo.description);
	ServerInfo.description = NULL;
	rb_free(ServerInfo.network_name);
	ServerInfo.network_name = NULL;

	rb_free(ServerInfo.bandb_path);
	ServerInfo.bandb_path = NULL;
	
	/* clean out AdminInfo */
	rb_free(AdminInfo.name);
	AdminInfo.name = NULL;
	rb_free(AdminInfo.email);
	AdminInfo.email = NULL;
	rb_free(AdminInfo.description);
	AdminInfo.description = NULL;

	/* clean out log file names  */
	rb_free(ConfigFileEntry.fname_userlog);
	ConfigFileEntry.fname_userlog = NULL;
	rb_free(ConfigFileEntry.fname_fuserlog);
	ConfigFileEntry.fname_fuserlog = NULL;
	rb_free(ConfigFileEntry.fname_operlog);
	ConfigFileEntry.fname_operlog = NULL;
	rb_free(ConfigFileEntry.fname_foperlog);
	ConfigFileEntry.fname_foperlog = NULL;
	rb_free(ConfigFileEntry.fname_serverlog);
	ConfigFileEntry.fname_serverlog = NULL;
	rb_free(ConfigFileEntry.fname_killlog);
	ConfigFileEntry.fname_killlog = NULL;
	rb_free(ConfigFileEntry.fname_glinelog);
	ConfigFileEntry.fname_glinelog = NULL;
	rb_free(ConfigFileEntry.fname_klinelog);
	ConfigFileEntry.fname_klinelog = NULL;
	rb_free(ConfigFileEntry.fname_operspylog);
	ConfigFileEntry.fname_operspylog = NULL;
	rb_free(ConfigFileEntry.fname_ioerrorlog);
	ConfigFileEntry.fname_ioerrorlog = NULL;

	rb_free(ServerInfo.vhost_dns);
	ServerInfo.vhost_dns = NULL;
#ifdef IPV6
	rb_free(ServerInfo.vhost6_dns);
	ServerInfo.vhost6_dns = NULL;
#endif
	/* operator{} and class{} blocks are freed above */
	/* clean out listeners */
	close_listeners();

	/* auth{}, quarantine{}, shared{}, connect{}, kill{}, deny{}, exempt{}
	 * and gecos{} blocks are freed above too
	 */

	/* clean out general */
	rb_free(ConfigFileEntry.kline_reason);
	ConfigFileEntry.kline_reason = NULL;

	destroy_blacklists();

#ifdef ENABLE_SERVICES
	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, service_list.head)
	{
		rb_free(ptr->data);
		rb_dlinkDestroy(ptr, &service_list);
	}
#endif

	/* OK, that should be everything... */
}

/*
 * conf_add_class_to_conf
 * inputs       - pointer to config item
 * output       - NONE
 * side effects - Add a class pointer to a conf 
 */

void
conf_add_class_to_conf(struct ConfItem *aconf, const char *classname)
{
	if(EmptyString(classname))
	{
		ClassPtr(aconf) = default_class;
		return;
	}

	ClassPtr(aconf) = find_class(classname);

	if(ClassPtr(aconf) == default_class)
	{
		if(aconf->status == CONF_CLIENT)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Warning -- Using default class for missing class \"%s\" in auth{} for %s@%s",
					     classname, aconf->user, aconf->host);
		}

		return;
	}

	if(ConfMaxUsers(aconf) < 0)
	{
		ClassPtr(aconf) = default_class;
		return;
	}
}

/*
 * conf_add_d_conf
 * inputs       - pointer to config item
 * output       - NONE
 * side effects - Add a d/D line
 */
void
conf_add_d_conf(struct ConfItem *aconf)
{
	if(aconf->host == NULL)
		return;

	aconf->user = NULL;

	/* XXX - Should 'd' ever be in the old conf? For new conf we don't
	 *       need this anyway, so I will disable it for now... -A1kmm
	 */

	if(!add_dline(aconf))
	{
		ilog(L_MAIN, "Invalid Dline %s ignored", aconf->host);
		free_conf(aconf);
	}
}
