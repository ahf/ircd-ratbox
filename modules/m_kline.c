/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_kline.c: Bans/unbans a user.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2008 ircd-ratbox development team
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
 *  $Id: m_kline.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "hostmask.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "send.h"
#include "s_serv.h"
#include "parse.h"
#include "modules.h"
#include "operhash.h"
#include "bandbi.h"

static int mo_kline(struct Client *, struct Client *, int, const char **);
static int me_kline(struct Client *, struct Client *, int, const char **);
static int mo_adminkline(struct Client *, struct Client *, int, const char **);
static int mo_unkline(struct Client *, struct Client *, int, const char **);
static int me_unkline(struct Client *, struct Client *, int, const char **);

struct Message kline_msgtab = {
	"KLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_kline, 5}, {mo_kline, 3}}
};

struct Message adminkline_msgtab = {
	"ADMINKLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_adminkline, 3}}
};

struct Message unkline_msgtab = {
	"UNKLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_unkline, 3}, {mo_unkline, 2}}
};

mapi_clist_av2 kline_clist[] = { &kline_msgtab, &unkline_msgtab, &adminkline_msgtab, NULL };

DECLARE_MODULE_AV2(kline, NULL, NULL, kline_clist, NULL, NULL, "$Revision: 27173 $");

/* Local function prototypes */
static int find_user_host(struct Client *source_p, const char *userhost, char *user, char *host);
static int valid_user_host(struct Client *source_p, const char *user, const char *host);
static int valid_wild_card(struct Client *source_p, const char *user, const char *host);

static void set_kline(struct Client *source_p, const char *user, const char *host,
		      const char *lreason, int tkline_time, int admin);
static void apply_kline(struct Client *source_p, struct ConfItem *aconf,
			const char *reason, const char *oper_reason, const char *current_date,
			int perm);
static void apply_tkline(struct Client *source_p, struct ConfItem *aconf, const char *,
			 const char *, const char *, int);
static int already_placed_kline(struct Client *, const char *, const char *, int);

static int remove_temp_kline(struct Client *, const char *, const char *);
static void remove_perm_kline(struct Client *, const char *, const char *);

/* mo_kline()
 *
 *   parv[1] - temp time or user@host
 *   parv[2] - user@host, "ON", or reason
 *   parv[3] - "ON", reason, or server to target
 *   parv[4] - server to target, or reason
 *   parv[5] - reason
 */
static int
mo_kline(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	char def[] = "No Reason";
	char user[USERLEN + 2];
	char host[HOSTLEN + 2];
	char *reason = def;
	const char *target_server = NULL;
	int tkline_time = 0;
	int loc = 1;

	if(!IsOperK(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "kline");
		return 0;
	}

	if((tkline_time = valid_temp_time(parv[loc])) >= 0)
		loc++;
	/* we just set tkline_time to -1! */
	else
		tkline_time = 0;

	if(find_user_host(source_p, parv[loc], user, host) == 0)
		return 0;

	loc++;

	if(parc >= loc + 2 && !irccmp(parv[loc], "ON"))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return 0;
		}

		target_server = parv[loc + 1];
		loc += 2;
	}

	if(parc <= loc || EmptyString(parv[loc]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name, source_p->name, "KLINE");
		return 0;
	}
	reason = LOCAL_COPY(parv[loc]);

	if(target_server != NULL)
	{
		sendto_match_servs(source_p, target_server, CAP_ENCAP, NOCAPS,
				   "ENCAP %s KLINE %d %s %s :%s",
				   target_server, tkline_time, user, host, reason);

		/* If we are sending it somewhere that doesnt include us, stop */
		if(!match(target_server, me.name))
			return 0;
	}
	/* if we have cluster servers, send it to them.. */
	else if(rb_dlink_list_length(&cluster_conf_list) > 0)
		cluster_generic(source_p, "KLINE",
				(tkline_time > 0) ? SHARED_TKLINE : SHARED_PKLINE,
				"%lu %s %s :%s", tkline_time, user, host, reason);

	set_kline(source_p, user, host, parv[loc], tkline_time, 0);

	return 0;
}

static int
me_kline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	int tkline_time;

	/* <tkline_time> <user> <host> :<reason> */
	if(!IsClient(source_p))
		return 0;

	tkline_time = atoi(parv[1]);

	if(!find_shared_conf(source_p->username, source_p->host,
			     source_p->servptr->name,
			     (tkline_time > 0) ? SHARED_TKLINE : SHARED_PKLINE))
		return 0;

	set_kline(source_p, parv[2], parv[3], parv[4], tkline_time, 0);

	return 0;
}

/* mo_adminkline()
 *
 *   parv[1] - user@host
 *   parv[2] - reason
 */
static int
mo_adminkline(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	char user[USERLEN + 2];
	char host[HOSTLEN + 2];

	if(!IsOperK(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "kline");
		return 0;
	}

	if(!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
		return 0;
	}

	if(find_user_host(source_p, parv[1], user, host) == 0)
		return 0;

	set_kline(source_p, user, host, parv[2], 0, 1);

	return 0;
}


/* mo_unkline()
 *
 *   parv[1] - kline to remove
 *   parv[2] - optional "ON"
 *   parv[3] - optional target server
 */
static int
mo_unkline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *user;
	char *host;
	char splat[] = "*";
	char *h = LOCAL_COPY(parv[1]);

	if(!IsOperUnkline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "unkline");
		return 0;
	}

	if((host = strchr(h, '@')) || *h == '*' || strchr(h, '.') || strchr(h, ':'))
	{
		/* Explicit user@host mask given */

		if(host)	/* Found user@host */
		{
			*host++ = '\0';

			/* check for @host */
			if(*h)
				user = h;
			else
				user = splat;

			/* check for user@ */
			if(!*host)
				host = splat;
		}
		else
		{
			user = splat;	/* no @ found, assume its *@somehost */
			host = h;
		}
	}
	else
	{
		sendto_one_notice(source_p, ":Invalid parameters");
		return 0;
	}

	/* possible remote kline.. */
	if((parc > 3) && (irccmp(parv[2], "ON") == 0))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return 0;
		}

		sendto_match_servs(source_p, parv[3], CAP_ENCAP, NOCAPS,
				   "ENCAP %s UNKLINE %s %s", parv[3], user, host);

		if(match(parv[3], me.name) == 0)
			return 0;
	}
	else if(rb_dlink_list_length(&cluster_conf_list) > 0)
		cluster_generic(source_p, "UNKLINE", SHARED_UNKLINE, "%s %s", user, host);

	if(remove_temp_kline(source_p, user, host))
		return 0;

	remove_perm_kline(source_p, user, host);
	return 0;
}

static int
me_unkline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *user, *host;

	/* user host */
	if(!IsClient(source_p))
		return 0;

	user = parv[1];
	host = parv[2];

	if(!find_shared_conf(source_p->username, source_p->host,
			     source_p->servptr->name, SHARED_UNKLINE))
		return 0;

	if(remove_temp_kline(source_p, user, host))
		return 0;

	remove_perm_kline(source_p, user, host);
	return 0;
}

static void
set_kline(struct Client *source_p, const char *user, const char *host, const char *lreason,
	  int tkline_time, int admin)
{
	char buffer[IRCD_BUFSIZE];
	struct ConfItem *aconf;
	const char *current_date;
	char *reason;
	char *oper_reason;

	reason = LOCAL_COPY_N(lreason, REASONLEN);

	if(!valid_user_host(source_p, user, host) || !valid_wild_card(source_p, user, host))
		return;

	if(already_placed_kline(source_p, user, host, tkline_time))
		return;

	rb_set_time();
	current_date = smalldate(rb_time());
	aconf = make_conf();
	aconf->status = CONF_KILL;
	aconf->user = rb_strdup(user);
	aconf->host = rb_strdup(host);

	/* Look for an oper reason */
	if((oper_reason = strchr(reason, '|')) != NULL)
	{
		*oper_reason = '\0';
		oper_reason++;

		if(!EmptyString(oper_reason))
			aconf->spasswd = rb_strdup(oper_reason);
	}

	if(tkline_time > 0)
	{
		rb_snprintf(buffer, sizeof(buffer),
			    "Temporary K-line %d min. - %s (%s)",
			    (int)(tkline_time / 60), reason, current_date);
		aconf->passwd = rb_strdup(buffer);
		apply_tkline(source_p, aconf, reason, oper_reason, current_date, tkline_time);
	}
	else
	{
		rb_snprintf(buffer, sizeof(buffer), "%s (%s)", reason, current_date);
		aconf->passwd = rb_strdup(buffer);
		apply_kline(source_p, aconf, reason, oper_reason, current_date, admin);
	}

	if(ConfigFileEntry.kline_delay)
	{
		if(kline_queued == 0)
		{
			rb_event_addonce("check_klines", check_klines_event, NULL,
					 ConfigFileEntry.kline_delay);
			kline_queued = 1;
		}
	}
	else
		check_klines();
}

/* apply_kline()
 *
 * inputs	- 
 * output	- NONE
 * side effects	- kline as given, is added to the hashtable
 *		  and conf file
 */
static void
apply_kline(struct Client *source_p, struct ConfItem *aconf,
	    const char *reason, const char *oper_reason, const char *current_date, int locked)
{
	const char *oper = get_oper_name(source_p);

	aconf->info.oper = operhash_add(oper);
	aconf->hold = rb_time();
	if(locked)
		aconf->flags |= CONF_FLAGS_LOCKED;

	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s added K-Line for [%s@%s] [%s]",
			     aconf->info.oper, aconf->user, aconf->host, make_ban_reason(reason,
											 oper_reason));
	ilog(L_KLINE, "K %s 0 %s %s %s", aconf->info.oper, aconf->user, aconf->host,
	     make_ban_reason(reason, oper_reason));

	sendto_one_notice(source_p, ":Added %s [%s@%s]",
			  locked ? "Locked K-Line" : "K-Line", aconf->user, aconf->host);

	add_conf_by_address(aconf->host, CONF_KILL, aconf->user, aconf);
	bandb_add(BANDB_KLINE, source_p, aconf->user, aconf->host,
		  reason, EmptyString(oper_reason) ? NULL : oper_reason, locked);
}

/* apply_tkline()
 *
 * inputs	-
 * output	- NONE
 * side effects	- tkline as given is placed
 */
static void
apply_tkline(struct Client *source_p, struct ConfItem *aconf,
	     const char *reason, const char *oper_reason, const char *current_date, int tkline_time)
{
	const char *oper = get_oper_name(source_p);

	aconf->info.oper = operhash_add(oper);
	aconf->hold = rb_time() + tkline_time;
	add_temp_kline(aconf);

	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s added temporary %d min. K-Line for [%s@%s] [%s]",
			     aconf->info.oper, tkline_time / 60,
			     aconf->user, aconf->host, make_ban_reason(reason, oper_reason));
	ilog(L_KLINE, "K %s %d %s %s %s",
	     aconf->info.oper, tkline_time / 60, aconf->user, aconf->host,
	     make_ban_reason(reason, oper_reason));

	sendto_one_notice(source_p, ":Added temporary %d min. K-Line [%s@%s]",
			  tkline_time / 60, aconf->user, aconf->host);
}


static inline int
is_ip_number(const char *number)
{
	if(strlen(number) > 3)
		return 0;
	while(*number)
	{
		if(!IsDigit(*number++))
			return 0;
	}
	return 1;
}

static const char *
mangle_wildcard_to_cidr(const char *text)
{
	static char buf[20];
	static const char *splat = "*", *dot = ".";
	char *p, *q, *n1, *n2, *n3, *n4;

	q = LOCAL_COPY(text);

	n1 = rb_strtok_r(q, dot, &p);
	n2 = rb_strtok_r(NULL, dot, &p);
	n3 = rb_strtok_r(NULL, dot, &p);
	n4 = rb_strtok_r(NULL, dot, &p);

	if(n1 == NULL)
		return NULL;

	/* ain't gonna touch this with a ten foot pole.. */
	if(!strcmp(n1, splat) || !is_ip_number(n1))
		return NULL;

	if(n2 == NULL || !strcmp(n2, splat))
	{
		if(n3 == NULL || (!strcmp(n3, splat) && (n4 == NULL || !strcmp(n4, splat))))
		{
			rb_snprintf(buf, sizeof(buf), "%s.0.0.0/8", n1);
			return buf;
		}
	}

	if(!is_ip_number(n2))
		return NULL;

	if(n3 == NULL || !strcmp(n3, splat))
	{
		if(n4 == NULL || !strcmp(n4, splat))
		{
			rb_snprintf(buf, sizeof(buf), "%s.%s.0.0/16", n1, n2);
			return buf;
		}
	}

	if(!is_ip_number(n3))
		return NULL;

	if(n4 == NULL || !strcmp(n4, splat))
	{
		rb_snprintf(buf, sizeof(buf), "%s.%s.%s.0/24", n1, n2, n3);
		return buf;
	}

	return NULL;
}


/* find_user_host()
 * 
 * inputs	- client placing kline, user@host, user buffer, host buffer
 * output	- 0 if not ok to kline, 1 to kline i.e. if valid user host
 * side effects -
 */
static int
find_user_host(struct Client *source_p, const char *userhost, char *luser, char *lhost)
{
	char *hostp;
	const char *ptr;

	hostp = strchr(userhost, '@');

	if(hostp != NULL)	/* I'm a little user@host */
	{
		*(hostp++) = '\0';	/* short and squat */
		if(*userhost)
			rb_strlcpy(luser, userhost, USERLEN + 1);	/* here is my user */
		else
			strcpy(luser, "*");
		if(*hostp)
		{
			ptr = mangle_wildcard_to_cidr(hostp);
			if(ptr == NULL)
				ptr = hostp;
			rb_strlcpy(lhost, ptr, HOSTLEN + 1);	/* here is my host */
		}
		else
			strcpy(lhost, "*");
	}
	else
	{
		/* no '@', no '.', so its not a user@host or host, therefore
		 * its a nick, which support was removed for.
		 */
		if(strchr(userhost, '.') == NULL && strchr(userhost, ':') == NULL)
		{
			sendto_one_notice(source_p, ":K-Line must be a user@host or host");
			return 0;
		}

		luser[0] = '*';	/* no @ found, assume its *@somehost */
		luser[1] = '\0';
		ptr = mangle_wildcard_to_cidr(userhost);

		if(ptr == NULL)
			ptr = userhost;

		rb_strlcpy(lhost, ptr, HOSTLEN + 1);
	}

	return 1;
}

/* valid_user_host()
 *
 * inputs       - user buffer, host buffer
 * output	- 0 if invalid, 1 if valid
 * side effects -
 */
static int
valid_user_host(struct Client *source_p, const char *luser, const char *lhost)
{
	const char *p;

	for(p = luser; *p; p++)
	{
		if(!IsUserChar(*p) && !IsKWildChar(*p))
		{
			sendto_one_notice(source_p, ":Invalid K-Line");
			return 0;
		}
	}

	for(p = lhost; *p; p++)
	{
		if(!IsHostChar(*p) && !IsKWildChar(*p))
		{
			sendto_one_notice(source_p, ":Invalid K-Line");
			return 0;
		}
	}

	return 1;
}

/* valid_wild_card()
 * 
 * input        - user buffer, host buffer
 * output       - 0 if invalid, 1 if valid
 * side effects -
 */
static int
valid_wild_card(struct Client *source_p, const char *luser, const char *lhost)
{
	const char *p;
	char tmpch;
	int nonwild = 0;

	/* check there are enough non wildcard chars */
	p = luser;
	while((tmpch = *p++))
	{
		if(!IsKWildChar(tmpch))
		{
			/* found enough chars, return */
			if(++nonwild >= ConfigFileEntry.min_nonwildcard)
				return 1;
		}
	}

	/* try host, as user didnt contain enough */
	p = lhost;
	while((tmpch = *p++))
	{
		if(!IsKWildChar(tmpch))
			if(++nonwild >= ConfigFileEntry.min_nonwildcard)
				return 1;
	}

	sendto_one_notice(source_p,
			  ":Please include at least %d non-wildcard "
			  "characters with the user@host", ConfigFileEntry.min_nonwildcard);
	return 0;
}


/* already_placed_kline()
 *
 * inputs       - source to notify, user@host to check, tkline time
 * outputs      - 1 if a perm kline or a tkline when a tkline is being
 *                set exists, else 0
 * side effects - notifies source_p kline exists
 */
/* Note: This currently works if the new K-line is a special case of an
 *       existing K-line, but not the other way round. To do that we would
 *       have to walk the hash and check every existing K-line. -A1kmm.
 */
static int
already_placed_kline(struct Client *source_p, const char *luser, const char *lhost, int tkline)
{
	const char *reason;
	struct rb_sockaddr_storage iphost, *piphost;
	struct ConfItem *aconf;
	int t;
	if(ConfigFileEntry.non_redundant_klines)
	{
		if((t = parse_netmask(lhost, (struct sockaddr *)&iphost, NULL)) != HM_HOST)
		{
#ifdef RB_IPV6
			if(t == HM_IPV6)
				t = AF_INET6;
			else
#endif
				t = AF_INET;

			piphost = &iphost;
		}
		else
			piphost = NULL;

		if((aconf =
		    find_conf_by_address(lhost, NULL, (struct sockaddr *)piphost, CONF_KILL, t,
					 luser)))
		{
			/* setting a tkline, or existing one is perm */
			/* there is a possibility the hash will return a
			 * temporary kline, when a permanent one also
			 * exists.  It isn't worth fixing, so disable below --anfl
			 */
			/*if(tkline || ((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)) */
			{
				reason = aconf->passwd ? aconf->passwd : "<No Reason>";

				sendto_one_notice(source_p,
						  ":[%s@%s] already K-Lined by [%s@%s] - %s",
						  luser, lhost, aconf->user, aconf->host, reason);
				return 1;
			}
		}
	}

	return 0;
}

static void
remove_perm_kline(struct Client *source_p, const char *user, const char *host)
{
	struct AddressRec *arec;
	struct ConfItem *aconf;
	int i;

	/* dont need to be safe, as we're quitting once we've done anything */
	HOSTHASH_WALK(i, arec)
	{
		if((arec->type & ~CONF_SKIPUSER) == CONF_KILL)
		{
			aconf = arec->aconf;

			if(aconf->flags & CONF_FLAGS_TEMPORARY)
				continue;

			if((aconf->user && irccmp(user, aconf->user)) || irccmp(host, aconf->host))
				continue;

			if(IsConfLocked(aconf) && !IsOperAdmin(source_p))
			{
				sendto_one_notice(source_p, ":Cannot remove locked K-Line %s@%s",
						  user, host);
				return;
			}

			bandb_del(BANDB_KLINE, aconf->user, aconf->host);
			delete_one_address_conf(host, aconf);


			sendto_one_notice(source_p, ":K-Line for [%s@%s] is removed", user, host);
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "%s has removed the K-Line for: [%s@%s]",
					     get_oper_name(source_p), user, host);
			ilog(L_KLINE, "UK %s %s %s", get_oper_name(source_p), user, host);
			return;
		}

	}
	HOSTHASH_WALK_END;
	sendto_one_notice(source_p, ":No K-Line for %s@%s", user, host);
}

/* remove_temp_kline()
 *
 * inputs       - username, hostname to unkline
 * outputs      -
 * side effects - tries to unkline anything that matches
 */
static int
remove_temp_kline(struct Client *source_p, const char *user, const char *host)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	int i;

	for(i = 0; i < LAST_TEMP_TYPE; i++)
	{
		RB_DLINK_FOREACH(ptr, temp_klines[i].head)
		{
			aconf = ptr->data;

			if(aconf->user && irccmp(user, aconf->user))
				continue;

			if(irccmp(aconf->host, host))
				continue;

			rb_dlinkDestroy(ptr, &temp_klines[i]);
			delete_one_address_conf(aconf->host, aconf);

			sendto_one_notice(source_p,
					  ":Un-klined [%s@%s] from temporary k-lines", user, host);
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "%s has removed the temporary K-Line for: [%s@%s]",
					     get_oper_name(source_p), user, host);
			ilog(L_KLINE, "UK %s %s %s", get_oper_name(source_p), user, host);

			return YES;
		}
	}

	return NO;
}
