/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_resv.c: Reserves(jupes) a nickname or channel.
 *
 *  Copyright (C) 2001-2002 Hybrid Development Team
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
 *  $Id: m_resv.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "channel.h"
#include "ircd.h"
#include "numeric.h"
#include "s_serv.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "hash.h"
#include "s_log.h"
#include "match.h"
#include "operhash.h"
#include "bandbi.h"

static int mo_resv(struct Client *, struct Client *, int, const char **);
static int me_resv(struct Client *, struct Client *, int, const char **);
static int mo_adminresv(struct Client *, struct Client *, int, const char **);
static int mo_unresv(struct Client *, struct Client *, int, const char **);
static int me_unresv(struct Client *, struct Client *, int, const char **);

struct Message resv_msgtab = {
	"RESV", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_resv, 5}, {mo_resv, 3}}
};

struct Message adminresv_msgtab = {
	"ADMINRESV", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_adminresv, 3}}
};

struct Message unresv_msgtab = {
	"UNRESV", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_unresv, 2}, {mo_unresv, 2}}
};

mapi_clist_av2 resv_clist[] = { &resv_msgtab, &adminresv_msgtab, &unresv_msgtab, NULL };

DECLARE_MODULE_AV2(resv, NULL, NULL, resv_clist, NULL, NULL, "$Revision: 27173 $");

static void parse_resv(struct Client *source_p, const char *name,
		       const char *reason, int temp_time, int perm);

static void remove_resv(struct Client *source_p, const char *name);
static void resv_chan_forcepart(const char *name, const char *reason, int temp_time);

/*
 * mo_resv()
 *      parv[1] = channel/nick to forbid
 *      parv[2] = reason
 */
static int
mo_resv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *name;
	const char *reason;
	const char *target_server = NULL;
	int temp_time;
	int loc = 1;

	if(!IsOperResv(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "resv");
		return 0;
	}

	/* RESV [time] <name> [ON <server>] :<reason> */

	if((temp_time = valid_temp_time(parv[loc])) >= 0)
		loc++;
	/* we just set temp_time to -1! */
	else
		temp_time = 0;

	name = parv[loc];
	loc++;

	if((parc >= loc + 2) && (irccmp(parv[loc], "ON") == 0))
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
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "RESV");
		return 0;
	}

	reason = parv[loc];

	if(target_server)
	{
		sendto_match_servs(source_p, target_server, CAP_ENCAP, NOCAPS,
				   "ENCAP %s RESV %d %s 0 :%s",
				   target_server, temp_time, name, reason);

		if(match(target_server, me.name) == 0)
			return 0;
	}
	else if(rb_dlink_list_length(&cluster_conf_list) > 0)
		cluster_generic(source_p, "RESV",
				(temp_time > 0) ? SHARED_TRESV : SHARED_PRESV,
				"%d %s 0 :%s", temp_time, name, reason);

	parse_resv(source_p, name, reason, temp_time, 0);

	return 0;
}

static int
mo_adminresv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsOperResv(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "resv");
		return 0;
	}

	if(!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
		return 0;
	}

	parse_resv(source_p, parv[1], parv[2], 0, 1);

	return 0;
}


static int
me_resv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* time name 0 :reason */
	if(!IsClient(source_p))
		return 0;

	parse_resv(source_p, parv[2], parv[4], atoi(parv[1]), 0);

	return 0;
}

static void
notify_resv(struct Client *source_p, const char *name, const char *reason, int temp_time)
{
	if(temp_time)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s added temporary %d min. RESV for [%s] [%s]",
				     get_oper_name(source_p), temp_time / 60, name, reason);
		ilog(L_KLINE, "R %s %d %s %s",
		     get_oper_name(source_p), temp_time / 60, name, reason);
		sendto_one_notice(source_p, ":Added temporary %d min. RESV [%s]",
				  temp_time / 60, name);
	}
	else
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s added RESV for [%s] [%s]",
				     get_oper_name(source_p), name, reason);
		ilog(L_KLINE, "R %s 0 %s %s", get_oper_name(source_p), name, reason);
		sendto_one_notice(source_p, ":Added RESV for [%s] [%s]", name, reason);
	}
}


/* parse_resv()
 *
 * inputs       - source_p if error messages wanted
 * 		- thing to resv
 * 		- reason for resv
 * outputs	-
 * side effects - will parse the resv and create it if valid
 */
static void
parse_resv(struct Client *source_p, const char *name, const char *reason, int temp_time, int locked)
{
	struct ConfItem *aconf;
	const char *oper = get_oper_name(source_p);

	if(!MyClient(source_p) &&
	   !find_shared_conf(source_p->username, source_p->host,
			     source_p->servptr->name,
			     (temp_time > 0) ? SHARED_TRESV : SHARED_PRESV))
		return;

	if(IsChannelName(name))
	{
		const char *p;

		if(hash_find_resv(name))
		{
			sendto_one_notice(source_p,
					  ":A RESV has already been placed on channel: %s", name);
			return;
		}

		if(strlen(name) > CHANNELLEN)
		{
			sendto_one_notice(source_p, ":Invalid RESV length: %s", name);
			return;
		}

		for(p = name; *p; p++)
		{
			if(!IsChanChar(*p))
			{
				sendto_one_notice(source_p, ":Invalid character '%c' in resv", *p);
				return;
			}
		}

		aconf = make_conf();
		aconf->status = CONF_RESV_CHANNEL;
		aconf->port = 0;
		aconf->host = rb_strdup(name);
		aconf->passwd = rb_strdup(reason);
		aconf->info.oper = operhash_add(oper);
		if(locked)
			aconf->flags |= CONF_FLAGS_LOCKED;

		add_to_hash(HASH_RESV, aconf->host, aconf);

		notify_resv(source_p, aconf->host, aconf->passwd, temp_time);
		resv_chan_forcepart(aconf->host, aconf->passwd, temp_time);

		if(temp_time > 0)
		{
			aconf->flags |= CONF_FLAGS_TEMPORARY;
			aconf->hold = rb_time() + temp_time;
		}
		else
		{
			bandb_add(BANDB_RESV, source_p, aconf->host, NULL, aconf->passwd, NULL,
				  locked);
			aconf->hold = rb_time();
		}
	}
	else if(clean_resv_nick(name))
	{
		if(strlen(name) > NICKLEN * 2)
		{
			sendto_one_notice(source_p, ":Invalid RESV length: %s", name);
			return;
		}

		if(!valid_wild_card_simple(name))
		{
			sendto_one_notice(source_p,
					  ":Please include at least %d non-wildcard "
					  "characters with the resv",
					  ConfigFileEntry.min_nonwildcard_simple);
			return;
		}

		if(find_nick_resv_mask(name))
		{
			sendto_one_notice(source_p,
					  ":A RESV has already been placed on nick: %s", name);
			return;
		}

		aconf = make_conf();
		aconf->status = CONF_RESV_NICK;
		aconf->port = 0;
		aconf->host = rb_strdup(name);
		aconf->passwd = rb_strdup(reason);
		aconf->info.oper = operhash_add(oper);
		if(locked)
			aconf->flags |= CONF_FLAGS_LOCKED;

		rb_dlinkAddAlloc(aconf, &resv_conf_list);

		notify_resv(source_p, aconf->host, aconf->passwd, temp_time);

		if(temp_time > 0)
		{
			aconf->flags |= CONF_FLAGS_TEMPORARY;
			aconf->hold = rb_time() + temp_time;
		}
		else
		{
			bandb_add(BANDB_RESV, source_p, aconf->host, NULL, aconf->passwd, NULL,
				  locked);
			aconf->hold = rb_time();
		}

	}
	else
		sendto_one_notice(source_p, ":You have specified an invalid resv: [%s]", name);
}

/*
 * mo_unresv()
 *     parv[1] = channel/nick to unforbid
 */
static int
mo_unresv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsOperResv(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "resv");
		return 0;
	}

	if((parc == 4) && (irccmp(parv[2], "ON") == 0))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return 0;
		}

		sendto_match_servs(source_p, parv[3], CAP_ENCAP, NOCAPS,
				   "ENCAP %s UNRESV %s", parv[3], parv[1]);

		if(match(parv[3], me.name) == 0)
			return 0;
	}
	else if(rb_dlink_list_length(&cluster_conf_list) > 0)
		cluster_generic(source_p, "UNRESV", SHARED_UNRESV, "%s", parv[1]);

	remove_resv(source_p, parv[1]);
	return 0;
}

static int
me_unresv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *name;

	/* name */
	if(!IsClient(source_p))
		return 0;

	name = parv[1];

	if(!find_shared_conf(source_p->username, source_p->host,
			     source_p->servptr->name, SHARED_UNRESV))
		return 0;

	remove_resv(source_p, name);
	return 0;
}

static void
remove_resv(struct Client *source_p, const char *name)
{
	struct ConfItem *aconf = NULL;

	if(IsChannelName(name))
	{
		if((aconf = hash_find_resv(name)) == NULL)
		{
			sendto_one_notice(source_p, ":No RESV for %s", name);
			return;
		}

		if(IsConfLocked(aconf) && !IsOperAdmin(source_p))
		{
			sendto_one_notice(source_p, ":Cannot remove locked RESV %s", name);
			return;
		}

		/* schedule it to transaction log */
		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			bandb_del(BANDB_RESV, aconf->host, NULL);

		del_from_hash(HASH_RESV, name, aconf);
		free_conf(aconf);
	}
	else
	{
		rb_dlink_node *ptr;

		RB_DLINK_FOREACH(ptr, resv_conf_list.head)
		{
			aconf = ptr->data;

			if(irccmp(aconf->host, name))
				aconf = NULL;
			else
				break;
		}

		if(aconf == NULL)
		{
			sendto_one_notice(source_p, ":No RESV for %s", name);
			return;
		}

		if(IsConfLocked(aconf) && !IsOperAdmin(source_p))
		{
			sendto_one_notice(source_p, ":Cannot remove locked RESV %s", name);
			return;
		}

		/* schedule it to transaction log */
		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			bandb_del(BANDB_RESV, aconf->host, NULL);

		/* already have ptr from the loop above.. */
		rb_dlinkDestroy(ptr, &resv_conf_list);
		free_conf(aconf);
	}

	sendto_one_notice(source_p, ":RESV for [%s] is removed", name);
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s has removed the RESV for: [%s]", get_oper_name(source_p), name);
	ilog(L_KLINE, "UR %s %s", get_oper_name(source_p), name);
}

static void 
resv_chan_forcepart(const char *name, const char *reason, int temp_time)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	struct Channel *chptr;
	struct membership *msptr;
	struct Client *target_p;

	if(!ConfigChannel.resv_forcepart)
		return;

	/* for each user on our server in the channel list
	 * send them a PART, and notify opers.
	 */
	chptr = find_channel(name);
	if(chptr != NULL)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, chptr->locmembers.head)
		{
			msptr = ptr->data;
			target_p = msptr->client_p;

			if(IsExemptResv(target_p))
				continue;

			sendto_server(target_p, chptr, CAP_TS6, NOCAPS,
			              ":%s PART %s", target_p->id, chptr->chname);

			sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s PART %s :%s",
			                     target_p->name, target_p->username,
			                     target_p->host, chptr->chname, target_p->name);

			remove_user_from_channel(msptr);

			/* notify opers & user they were removed from the channel */
			sendto_realops_flags(UMODE_ALL, L_ALL,
			                     "Forced PART for %s!%s@%s from %s (%s)",
			                     target_p->name, target_p->username, 
			                     target_p->host, name, reason);

			if(temp_time > 0)
				sendto_one_notice(target_p, ":*** Channel %s is temporarily unavailable on this server.",
				           name);
			else
				sendto_one_notice(target_p, ":*** Channel %s is no longer available on this server.",
				           name);
		}
	}
}

