/* modules/m_xline.c
 * 
 *  Copyright (C) 2002-2003 Lee Hardy <lee@leeh.co.uk>
 *  Copyright (C) 2002-2008 ircd-ratbox development team
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
 * $Id: m_xline.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "send.h"
#include "client.h"
#include "class.h"
#include "ircd.h"
#include "numeric.h"
#include "s_log.h"
#include "s_serv.h"
#include "match.h"
#include "ratbox_lib.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "operhash.h"
#include "bandbi.h"

static int mo_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int mo_adminxline(struct Client *client_p, struct Client *source_p, int parc,
			 const char *parv[]);
static int mo_unxline(struct Client *client_p, struct Client *source_p, int parc,
		      const char *parv[]);
static int me_unxline(struct Client *client_p, struct Client *source_p, int parc,
		      const char *parv[]);

struct Message xline_msgtab = {
	"XLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_xline, 5}, {mo_xline, 3}}
};

struct Message adminxline_msgtab = {
	"ADMINXLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_adminxline, 3}}
};

struct Message unxline_msgtab = {
	"UNXLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_unxline, 2}, {mo_unxline, 2}}
};

mapi_clist_av2 xline_clist[] = { &xline_msgtab, &unxline_msgtab, NULL };

DECLARE_MODULE_AV2(xline, NULL, NULL, xline_clist, NULL, NULL, "$Revision: 27173 $");

static int valid_xline(struct Client *, const char *, const char *, int temp);
static void apply_xline(struct Client *client_p, const char *name,
			const char *reason, int temp_time, int perm);

static void remove_xline(struct Client *source_p, const char *gecos);


/* m_xline()
 *
 * parv[1] - thing to xline
 * parv[2] - optional type/reason
 * parv[3] - reason
 */
static int
mo_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct ConfItem *aconf;
	const char *name;
	const char *reason;
	const char *target_server = NULL;
	int temp_time;
	int loc = 1;

	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "xline");
		return 0;
	}

	if((temp_time = valid_temp_time(parv[loc])) >= 0)
		loc++;
	/* we just set temp_time to -1! */
	else
		temp_time = 0;

	name = parv[loc];
	loc++;

	/* XLINE <gecos> ON <server> :<reason> */
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
			   me.name, source_p->name, "XLINE");
		return 0;
	}

	reason = parv[loc];

	if(target_server != NULL)
	{
		sendto_match_servs(source_p, target_server, CAP_ENCAP, NOCAPS,
				   "ENCAP %s XLINE %d %s 2 :%s",
				   target_server, temp_time, name, reason);

		if(!match(target_server, me.name))
			return 0;
	}
	else if(rb_dlink_list_length(&cluster_conf_list) > 0)
		cluster_generic(source_p, "XLINE",
				(temp_time > 0) ? SHARED_TXLINE : SHARED_PXLINE,
				"%d %s 2 :%s", temp_time, name, reason);

	if((aconf = find_xline_mask(name)) != NULL)
	{
		sendto_one_notice(source_p, ":[%s] already X-Lined by [%s] - %s",
				  name, aconf->host, aconf->passwd);
		return 0;
	}

	if(!valid_xline(source_p, name, reason, temp_time))
		return 0;

	apply_xline(source_p, name, reason, temp_time, 0);

	return 0;
}

static int
me_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct ConfItem *aconf;
	const char *name, *reason;
	int temp_time;

	/* time name type :reason */
	if(!IsClient(source_p))
		return 0;

	temp_time = atoi(parv[1]);
	name = parv[2];
	reason = parv[4];

	if(!find_shared_conf(source_p->username, source_p->host,
			     source_p->servptr->name,
			     (temp_time > 0) ? SHARED_TXLINE : SHARED_PXLINE))
		return 0;

	if(!valid_xline(source_p, name, reason, temp_time))
		return 0;

	/* already xlined */
	if((aconf = find_xline_mask(name)) != NULL)
	{
		sendto_one_notice(source_p, ":[%s] already X-Lined by [%s] - %s",
				  name, aconf->host, aconf->passwd);
		return 0;
	}

	apply_xline(source_p, name, reason, temp_time, 0);
	return 0;
}

static int
mo_adminxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct ConfItem *aconf;

	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "xline");
		return 0;
	}

	if(!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
		return 0;
	}

	if((aconf = find_xline_mask(parv[1])) != NULL)
	{
		sendto_one_notice(source_p, ":[%s] already X-Lined by [%s] - %s",
				  parv[1], aconf->host, aconf->passwd);
		return 0;
	}

	if(!valid_xline(source_p, parv[1], parv[2], 0))
		return 0;

	apply_xline(source_p, parv[1], parv[2], 0, 1);
	return 0;
}

/* valid_xline()
 *
 * inputs	- client xlining, gecos, reason and whether to warn
 * outputs	-
 * side effects - checks the xline for validity, erroring if needed
 */
static int
valid_xline(struct Client *source_p, const char *gecos, const char *reason, int temp_time)
{
	if(EmptyString(reason))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   get_id(&me, source_p), get_id(source_p, source_p), "XLINE");
		return 0;
	}

	if(!valid_wild_card_simple(gecos))
	{
		sendto_one_notice(source_p,
				  ":Please include at least %d non-wildcard "
				  "characters with the xline",
				  ConfigFileEntry.min_nonwildcard_simple);
		return 0;
	}

	return 1;
}

/* check_xlines
 *
 * inputs       -
 * outputs      -
 * side effects - all clients will be checked for xlines
 */
static void
check_xlines(void)
{
	struct Client *client_p;
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
	{
		client_p = ptr->data;

		if(IsMe(client_p) || !IsClient(client_p))
			continue;

		if((aconf = find_xline(client_p->info, 1)) != NULL)
		{
			if(IsExemptKline(client_p))
			{
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "XLINE over-ruled for %s, client is kline_exempt",
						     get_client_name(client_p, HIDE_IP));
				continue;
			}

			sendto_realops_flags(UMODE_ALL, L_ALL, "XLINE active for %s",
					     get_client_name(client_p, HIDE_IP));

			(void)exit_client(client_p, client_p, &me, "Bad user info");
			continue;
		}
	}
}

void
apply_xline(struct Client *source_p, const char *name, const char *reason, int temp_time,
	    int locked)
{
	struct ConfItem *aconf;
	const char *oper = get_oper_name(source_p);

	aconf = make_conf();
	aconf->status = CONF_XLINE;
	aconf->host = rb_strdup(name);
	aconf->passwd = rb_strdup(reason);
	if(locked)
		aconf->flags |= CONF_FLAGS_LOCKED;

	collapse(aconf->host);

	aconf->info.oper = operhash_add(oper);

	if(temp_time > 0)
	{
		aconf->flags |= CONF_FLAGS_TEMPORARY;
		aconf->hold = rb_time() + temp_time;

		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s added temporary %d min. X-Line for [%s] [%s]",
				     aconf->info.oper, temp_time / 60, aconf->host, reason);
		ilog(L_KLINE, "X %s %d %s %s", aconf->info.oper, temp_time / 60, name, reason);
		sendto_one_notice(source_p, ":Added temporary %d min. X-Line [%s]",
				  temp_time / 60, aconf->host);
	}
	else
	{
		aconf->hold = rb_time();
		bandb_add(BANDB_XLINE, source_p, aconf->host, NULL, reason, NULL, locked);

		sendto_realops_flags(UMODE_ALL, L_ALL, "%s added X-Line for [%s] [%s]",
				     aconf->info.oper, aconf->host, aconf->passwd);
		sendto_one_notice(source_p, ":Added %s for [%s] [%s]",
				  locked ? "Locked X-Line" : "X-Line", aconf->host, aconf->passwd);
		ilog(L_KLINE, "X %s 0 %s %s", aconf->info.oper, name, reason);
	}

	rb_dlinkAddAlloc(aconf, &xline_conf_list);
	check_xlines();
}

/* mo_unxline()
 *
 * parv[1] - thing to unxline
 */
static int
mo_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "xline");
		return 0;
	}

	if(parc == 4 && !(irccmp(parv[2], "ON")))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return 0;
		}

		sendto_match_servs(source_p, parv[3], CAP_ENCAP, NOCAPS,
				   "ENCAP %s UNXLINE %s", parv[3], parv[1]);

		if(match(parv[3], me.name) == 0)
			return 0;
	}
	else if(rb_dlink_list_length(&cluster_conf_list))
		cluster_generic(source_p, "UNXLINE", SHARED_UNXLINE, "%s", parv[1]);

	remove_xline(source_p, parv[1]);
	return 0;
}

static int
me_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *name;

	/* name */
	if(!IsClient(source_p))
		return 0;

	name = parv[1];

	if(!find_shared_conf(source_p->username, source_p->host,
			     source_p->servptr->name, SHARED_UNXLINE))
		return 0;

	remove_xline(source_p, name);
	return 0;
}

static void
remove_xline(struct Client *source_p, const char *name)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, xline_conf_list.head)
	{
		aconf = ptr->data;

		if(irccmp(aconf->host, name))
			continue;

		if(IsConfLocked(aconf) && !IsOperAdmin(source_p))
		{
			sendto_one_notice(source_p, ":Cannot remove locked X-Line %s", name);
			return;
		}

		sendto_one_notice(source_p, ":X-Line for [%s] is removed", name);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s has removed the X-Line for: [%s]",
				     get_oper_name(source_p), name);
		ilog(L_KLINE, "UX %s %s", get_oper_name(source_p), name);


		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			bandb_del(BANDB_XLINE, aconf->host, NULL);

		free_conf(aconf);
		rb_dlinkDestroy(ptr, &xline_conf_list);
		return;
	}

	sendto_one_notice(source_p, ":No X-Line for %s", name);
}
