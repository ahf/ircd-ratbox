/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_dline.c: Bans/unbans a user.
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
 *  $Id: m_dline.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "match.h"
#include "reject.h"
#include "ircd.h"
#include "hostmask.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "operhash.h"
#include "bandbi.h"

static int mo_dline(struct Client *, struct Client *, int, const char **);
static int mo_admindline(struct Client *, struct Client *, int, const char **);
static int mo_undline(struct Client *, struct Client *, int, const char **);

struct Message dline_msgtab = {
	"DLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_dline, 2}}
};

struct Message admindline_msgtab = {
	"ADMINDLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_admindline, 3}}
};

struct Message undline_msgtab = {
	"UNDLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_undline, 2}}
};

mapi_clist_av2 dline_clist[] = { &dline_msgtab, &admindline_msgtab, &undline_msgtab, NULL };

DECLARE_MODULE_AV2(dline, NULL, NULL, dline_clist, NULL, NULL, "$Revision: 27173 $");

static int valid_dline(struct Client *source_p, const char *dlhost);
static int already_placed_dline(struct Client *source_p, const char *dlhost);
static void set_dline(struct Client *source_p, const char *dlhost,
		      const char *lreason, int tkline_time, int admin);
static void check_dlines(void);

/* mo_dline()
 * 
 *   parv[1] - dline to add
 *   parv[2] - reason
 */
static int
mo_dline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char def[] = "No Reason";
	const char *dlhost;
	const char *reason = def;
	int tdline_time = 0;
	int loc = 1;

	if(!IsOperK(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "kline");
		return 0;
	}

	if((tdline_time = valid_temp_time(parv[loc])) >= 0)
		loc++;


	if(parc < loc + 1)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name, source_p->name, "DLINE");
		return 0;
	}

	dlhost = parv[loc];
	loc++;

	if(!valid_dline(source_p, dlhost))
		return 0;

	/* reason */
	if((parc >= loc + 1) && !EmptyString(parv[loc]))
		reason = parv[loc];

	if(!already_placed_dline(source_p, dlhost))
		return 0;

	set_dline(source_p, dlhost, reason, tdline_time, 0);
	check_dlines();

	return 0;
}

static int
mo_admindline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
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


	if(!valid_dline(source_p, parv[1]))
		return 0;

	if(!already_placed_dline(source_p, parv[1]))
		return 0;

	set_dline(source_p, parv[1], parv[2], 0, 1);
	check_dlines();

	return 0;
}

/* mo_undline()
 *
 *      parv[1] = dline to remove
 */
static int
mo_undline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct rb_sockaddr_storage daddr;
	struct ConfItem *aconf;
	int b, ty;
	const char *cidr = parv[1];
	const char *host;
	if(!IsOperUnkline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "unkline");
		return 0;
	}

	if((ty = parse_netmask(cidr, (struct sockaddr *)&daddr, &b)) == HM_HOST)
	{
		sendto_one_notice(source_p, ":Invalid D-Line");
		return 0;
	}

	aconf = find_dline_exact((struct sockaddr *)&daddr, b);

	if(aconf == NULL)
	{
		sendto_one_notice(source_p, ":No D-Line for %s", cidr);
		return 0;
	}

	if(IsConfLocked(aconf) && !IsOperAdmin(source_p))
	{
		sendto_one_notice(source_p, ":Cannot remove locked D-Line %s", cidr);
		return 0;
	}

	host = LOCAL_COPY(aconf->host);
	remove_dline(aconf);

	if(!(aconf->flags & CONF_FLAGS_TEMPORARY))
	{
		bandb_del(BANDB_DLINE, host, NULL);

		sendto_one_notice(source_p, ":D-Line for [%s] is removed", host);
		sendto_realops_flags(UMODE_ALL, L_ALL, "%s has removed the D-Line for: [%s]",
				     get_oper_name(source_p), host);

	}
	else
	{
		rb_dlink_list *list;
		list = &temp_dlines[aconf->port];
		rb_dlinkFindDestroy(aconf, list);
		sendto_one_notice(source_p, ":Un-dlined [%s] from temporary D-lines", host);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s has removed the temporary D-Line for: [%s]",
				     get_oper_name(source_p), host);
		return 0;
	}

	ilog(L_KLINE, "UD %s %s", get_oper_name(source_p), host);

	return 0;
}

static int
valid_dline(struct Client *source_p, const char *dlhost)
{
	static char cidr_form_host[HOSTLEN + 1];
	int bits;

	rb_strlcpy(cidr_form_host, dlhost, sizeof(cidr_form_host));

	if(!parse_netmask(dlhost, NULL, &bits))
	{
		sendto_one_notice(source_p, ":Invalid D-Line");
		return 0;
	}

	if(IsOperAdmin(source_p))
	{
		if(bits < 8)
		{
			sendto_one_notice(source_p,
					  ":For safety, bitmasks less than 8 require db access.");
			return 0;
		}
	}
	else
	{
		if(bits < 16)
		{
			sendto_one_notice(source_p,
					  ":Dline bitmasks less than 16 are for admins only.");
			return 0;
		}
	}

	return 1;
}

static int
already_placed_dline(struct Client *source_p, const char *dlhost)
{
	if(ConfigFileEntry.non_redundant_klines)
	{
		struct ConfItem *aconf;
		struct rb_sockaddr_storage daddr;
		const char *creason;
		int t = AF_INET, ty, b;
		ty = parse_netmask(dlhost, (struct sockaddr *)&daddr, &b);
#ifdef RB_IPV6
		if(ty == HM_IPV6)
			t = AF_INET6;
		else
#endif
			t = AF_INET;

		if((aconf = find_dline((struct sockaddr *)&daddr)) != NULL)
		{
			int bx;
			parse_netmask(aconf->host, NULL, &bx);
			if(b >= bx)
			{
				creason = aconf->passwd ? aconf->passwd : "<No Reason>";
				if(IsConfExemptKline(aconf))
					sendto_one_notice(source_p,
							  ":[%s] is (E)d-lined by [%s] - %s",
							  dlhost, aconf->host, creason);
				else
					sendto_one_notice(source_p,
							  ":[%s] already D-lined by [%s] - %s",
							  dlhost, aconf->host, creason);
				return 0;
			}
		}
	}

	return 1;
}

static void
set_dline(struct Client *source_p, const char *dlhost, const char *lreason, int tdline_time,
	  int admin)
{
	struct ConfItem *aconf;
	char dlbuffer[IRCD_BUFSIZE];
	const char *current_date;
	const char *oper;
	char *reason;
	char *oper_reason;

	reason = LOCAL_COPY_N(lreason, REASONLEN);

	rb_set_time();
	current_date = smalldate(rb_time());

	aconf = make_conf();
	aconf->status = CONF_DLINE;
	aconf->host = rb_strdup(dlhost);

	oper = get_oper_name(source_p);
	aconf->info.oper = operhash_add(oper);

	if(admin)
		aconf->flags |= CONF_FLAGS_LOCKED;

	/* Look for an oper reason */
	if((oper_reason = strchr(reason, '|')) != NULL)
	{
		*oper_reason = '\0';
		oper_reason++;

		if(!EmptyString(oper_reason))
			aconf->spasswd = rb_strdup(oper_reason);
	}

	if(tdline_time > 0)
	{
		rb_snprintf(dlbuffer, sizeof(dlbuffer),
			    "Temporary D-line %d min. - %s (%s)",
			    (int)(tdline_time / 60), reason, current_date);
		aconf->passwd = rb_strdup(dlbuffer);
		aconf->hold = rb_time() + tdline_time;
		add_temp_dline(aconf);

		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s added temporary %d min. D-Line for [%s] [%s]",
				     aconf->info.oper, tdline_time / 60,
				     aconf->host, make_ban_reason(reason, oper_reason));
		ilog(L_KLINE, "D %s %d %s %s",
		     aconf->info.oper, tdline_time / 60, aconf->host, make_ban_reason(reason,
										      oper_reason));

		sendto_one_notice(source_p, ":Added temporary %d min. D-Line for [%s]",
				  tdline_time / 60, aconf->host);
	}
	else
	{
		rb_snprintf(dlbuffer, sizeof(dlbuffer), "%s (%s)", reason, current_date);
		aconf->passwd = rb_strdup(dlbuffer);
		add_dline(aconf);

		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s added D-Line for [%s] [%s]",
				     aconf->info.oper, aconf->host, make_ban_reason(reason,
										    oper_reason));
		ilog(L_KLINE, "D %s 0 %s %s", aconf->info.oper, aconf->host,
		     make_ban_reason(reason, oper_reason));

		sendto_one_notice(source_p, ":Added %s [%s]", admin ? "Admin D-Line" : "D-Line",
				  aconf->host);

		bandb_add(BANDB_DLINE, source_p, aconf->host, NULL,
			  reason, EmptyString(aconf->spasswd) ? NULL : aconf->spasswd, admin);
	}
}

/* check_dlines()
 *
 * inputs       -
 * outputs      -
 * side effects - all clients will be checked for dlines
 */
static void
check_dlines(void)
{
	struct Client *client_p;
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
	{
		client_p = ptr->data;

		if(IsMe(client_p))
			continue;

		if((aconf = find_dline((struct sockaddr *)&client_p->localClient->ip)) != NULL)
		{
			if(aconf->status & CONF_EXEMPTDLINE)
				continue;

			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "DLINE active for %s",
					     get_client_name(client_p, HIDE_IP));

			notify_banned_client(client_p, aconf, D_LINED);
			continue;
		}
	}

	/* dlines need to be checked against unknowns too */
	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, unknown_list.head)
	{
		client_p = ptr->data;

		if((aconf = find_dline((struct sockaddr *)&client_p->localClient->ip)) != NULL)
		{
			if(aconf->status & CONF_EXEMPTDLINE)
				continue;

			notify_banned_client(client_p, aconf, D_LINED);
		}
	}
}
