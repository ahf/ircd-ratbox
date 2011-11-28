/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_trace.c: Traces a path to a client/server.
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
 *  $Id: m_trace.c 27325 2011-11-12 22:57:45Z jilles $
 */

#include "stdinc.h"
#include "struct.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_conf.h"
#include "hook.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "channel.h"
#include "s_newconf.h"
#include "s_log.h"

static int m_trace(struct Client *, struct Client *, int, const char **);
static int mo_etrace(struct Client *, struct Client *, int, const char **);
static int me_etrace(struct Client *, struct Client *, int, const char **);
static int mo_chantrace(struct Client *, struct Client *, int, const char **);
static int mo_masktrace(struct Client *, struct Client *, int, const char **);

static void trace_spy(struct Client *, struct Client *);


struct Message chantrace_msgtab = {
	"CHANTRACE", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_chantrace, 2}}
};

struct Message masktrace_msgtab = {
	"MASKTRACE", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_masktrace, 2}}
};

struct Message etrace_msgtab = {
	"ETRACE", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_etrace, 0}, {mo_etrace, 0}}
};

struct Message trace_msgtab = {
	"TRACE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_trace, 0}, {m_trace, 0}, mg_ignore, mg_ignore, {m_trace, 0}}
};

static void do_etrace(struct Client *source_p, int ipv4, int ipv6);
static void do_etrace_full(struct Client *source_p);
static void do_single_etrace(struct Client *source_p, struct Client *target_p);
static void count_downlinks(struct Client *server_p, int *pservcount, int *pusercount);
static int report_this_status(struct Client *source_p, struct Client *target_p);

static const char *empty_sockhost = "255.255.255.255";
static const char *spoofed_sockhost = "0";

int doing_trace_hook;

mapi_clist_av2 trace_clist[] =
	{ &trace_msgtab, &etrace_msgtab, &chantrace_msgtab, &masktrace_msgtab, NULL };
mapi_hlist_av2 trace_hlist[] = {
	{"doing_trace", &doing_trace_hook},
	{NULL, NULL}
};

DECLARE_MODULE_AV2(trace, NULL, NULL, trace_clist, trace_hlist, NULL, "$Revision: 27325 $");


/*
 * m_trace
 *      parv[1] = servername
 */
static int
m_trace(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p = NULL;
	struct Class *cltmp;
	const char *tname;
	int doall = 0;
	int cnt = 0, wilds, dow;
	rb_dlink_node *ptr;

	if(parc > 1)
	{
		tname = parv[1];

		if(parc > 2)
		{
			if(hunt_server(client_p, source_p, ":%s TRACE %s :%s", 2, parc, parv) !=
			   HUNTED_ISME)
				return 0;
		}
	}
	else
		tname = me.name;

	/* if we have 3 parameters, then the command is directed at us.  So
	 * we shouldnt be forwarding it anywhere. --anfl
	 */
	if(parc < 3)
	{
		switch (hunt_server(client_p, source_p, ":%s TRACE :%s", 1, parc, parv))
		{
		case HUNTED_PASS:	/* note: gets here only if parv[1] exists */
			{
				struct Client *ac2ptr;

				if(MyClient(source_p))
					ac2ptr = find_named_client(tname);
				else
					ac2ptr = find_client(tname);

				if(ac2ptr == NULL)
				{
					RB_DLINK_FOREACH(ptr, global_client_list.head)
					{
						ac2ptr = ptr->data;

						if(match(tname, ac2ptr->name))
							break;
						else
							ac2ptr = NULL;
					}
				}

				/* giving this out with flattened links defeats the
				 * object --fl
				 */
				if(IsOper(source_p) || IsExemptShide(source_p) ||
				   !ConfigServerHide.flatten_links)
					sendto_one_numeric(source_p, RPL_TRACELINK,
							   form_str(RPL_TRACELINK),
							   ircd_version,
							   ac2ptr ? ac2ptr->name : tname,
							   ac2ptr ? ac2ptr->from->name : "EEK!");

				return 0;
			}

		case HUNTED_ISME:
			break;

		default:
			return 0;
		}
	}

	if(match(tname, me.name))
	{
		doall = 1;
	}
	/* if theyre tracing our SID, we need to move tname to our name so
	 * we dont give the sid in ENDOFTRACE
	 */
	else if(!MyClient(source_p) && !strcmp(tname, me.id))
	{
		doall = 1;
		tname = me.name;
	}

	wilds = (strpbrk(tname, "*?") != NULL);
	dow = wilds || doall;

	/* specific trace */
	if(dow == 0)
	{
		if(MyClient(source_p) || parc > 2)
			target_p = find_named_person(tname);
		else
			target_p = find_person(tname);

		/* tname could be pointing to an ID at this point, so reset
		 * it to target_p->name if we have a target --fl
		 */
		if(target_p != NULL)
		{
			report_this_status(source_p, target_p);
			tname = target_p->name;
		}

		trace_spy(source_p, target_p);

		sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), tname);
		return 0;
	}

	trace_spy(source_p, NULL);

	/* give non-opers a limited trace output of themselves (if local), 
	 * opers and servers (if no shide) --fl
	 */
	if(!IsOper(source_p))
	{
		SetCork(source_p);
		if(MyClient(source_p))
		{
			if(doall || (wilds && match(tname, source_p->name)))
				report_this_status(source_p, source_p);
		}

		RB_DLINK_FOREACH(ptr, oper_list.head)
		{
			target_p = ptr->data;

			if(!doall && wilds && (match(tname, target_p->name) == 0))
				continue;

			report_this_status(source_p, target_p);
		}

		if (IsExemptShide(source_p) || !ConfigServerHide.flatten_links)
		{
			RB_DLINK_FOREACH(ptr, serv_list.head)
			{
				target_p = ptr->data;

				if(!doall && wilds && !match(tname, target_p->name))
					continue;

				report_this_status(source_p, target_p);
			}
		}
		ClearCork(source_p);
		sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), tname);
		return 0;
	}

	/* source_p is opered */
	SetCork(source_p);
	/* report all direct connections */
	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		target_p = ptr->data;

		/* dont show invisible users to remote opers */
		if(IsInvisible(target_p) && dow && !MyConnect(source_p) && !IsOper(target_p))
			continue;

		if(!doall && wilds && !match(tname, target_p->name))
			continue;

		cnt = report_this_status(source_p, target_p);
	}

	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		if(!doall && wilds && !match(tname, target_p->name))
			continue;

		cnt = report_this_status(source_p, target_p);
	}

	if(MyConnect(source_p))
	{
		RB_DLINK_FOREACH(ptr, unknown_list.head)
		{
			target_p = ptr->data;

			if(!doall && wilds && !match(tname, target_p->name))
				continue;

			cnt = report_this_status(source_p, target_p);
		}
	}
	ClearCork(source_p);
	/*
	 * Add these lines to summarize the above which can get rather long
	 * and messy when done remotely - Avalon
	 */
	if(!cnt)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHSERVER, form_str(ERR_NOSUCHSERVER), tname);

		/* let the user have some idea that its at the end of the
		 * trace
		 */
		sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), tname);
		return 0;
	}

	if(doall)
	{
		SetCork(source_p);
		RB_DLINK_FOREACH(ptr, class_list.head)
		{
			cltmp = ptr->data;

			if(CurrUsers(cltmp) > 0)
				sendto_one_numeric(source_p, RPL_TRACECLASS,
						   form_str(RPL_TRACECLASS),
						   ClassName(cltmp), CurrUsers(cltmp));
		}
		ClearCork(source_p);
	}

	sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), tname);

	return 0;
}

/*
 * count_downlinks
 *
 * inputs	- pointer to server to count
 *		- pointers to server and user count
 * output	- NONE
 * side effects - server and user counts are added to given values
 */
static void
count_downlinks(struct Client *server_p, int *pservcount, int *pusercount)
{
	rb_dlink_node *ptr;

	(*pservcount)++;
	*pusercount += rb_dlink_list_length(&server_p->serv->users);
	RB_DLINK_FOREACH(ptr, server_p->serv->servers.head)
	{
		count_downlinks(ptr->data, pservcount, pusercount);
	}
}

/*
 * report_this_status
 *
 * inputs	- pointer to client to report to
 * 		- pointer to client to report about
 * output	- counter of number of hits
 * side effects - NONE
 */
static int
report_this_status(struct Client *source_p, struct Client *target_p)
{
	const char *name;
	const char *class_name;
	char ip[HOSTIPLEN];
	int cnt = 0;

	/* sanity check - should never happen */
	if(!MyConnect(target_p))
		return 0;

	rb_inet_ntop_sock((struct sockaddr *)&target_p->localClient->ip, ip, sizeof(ip));
	class_name = get_client_class(target_p);

	if(IsAnyServer(target_p))
		name = target_p->name;
	else
		name = get_client_name(target_p, HIDE_IP);

	switch (target_p->status)
	{
	case STAT_CONNECTING:
		sendto_one_numeric(source_p, RPL_TRACECONNECTING,
				   form_str(RPL_TRACECONNECTING), class_name, name);
		cnt++;
		break;

	case STAT_HANDSHAKE:
		sendto_one_numeric(source_p, RPL_TRACEHANDSHAKE,
				   form_str(RPL_TRACEHANDSHAKE), class_name, name);
		cnt++;
		break;

	case STAT_ME:
		break;

	case STAT_UNKNOWN:
		/* added time -Taner */
		sendto_one_numeric(source_p, RPL_TRACEUNKNOWN,
				   form_str(RPL_TRACEUNKNOWN),
				   class_name, name, ip,
				   rb_time() - target_p->localClient->firsttime);
		cnt++;
		break;

	case STAT_CLIENT:
		sendto_one_numeric(source_p,
				   IsOper(target_p) ? RPL_TRACEOPERATOR : RPL_TRACEUSER,
				   IsOper(target_p) ? form_str(RPL_TRACEOPERATOR) : form_str(RPL_TRACEUSER),
				   class_name, name,
				   show_ip(source_p, target_p) ? ip : empty_sockhost,
				   (unsigned long)(rb_time() - target_p->localClient->lasttime),
				   (unsigned long)(rb_time() - target_p->localClient->last));
		cnt++;
		break;


	case STAT_SERVER:
		{
			int usercount = 0;
			int servcount = 0;

			count_downlinks(target_p, &servcount, &usercount);

			sendto_one_numeric(source_p, RPL_TRACESERVER, form_str(RPL_TRACESERVER),
					   class_name, servcount, usercount, name,
					   *(target_p->serv->by) ? target_p->serv->by : "*", "*",
					   me.name,
					   (unsigned long)(rb_time() - target_p->localClient->lasttime));
			cnt++;

		}
		break;

	default:		/* ...we actually shouldn't come here... --msa */
		sendto_one_numeric(source_p, RPL_TRACENEWTYPE,
				   form_str(RPL_TRACENEWTYPE), name);
		cnt++;
		break;
	}

	return (cnt);
}

/* trace_spy()
 *
 * input        - pointer to client
 * output       - none
 * side effects - hook event doing_trace is called
 */
static void
trace_spy(struct Client *source_p, struct Client *target_p)
{
	hook_data_client hdata;

	hdata.client = source_p;
	hdata.target = target_p;

	call_hook(doing_trace_hook, &hdata);
}



/*
 * m_etrace
 *      parv[1] = options [or target]
 *	parv[2] = [target]
 */
static int
mo_etrace(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(parc > 1 && !EmptyString(parv[1]))
	{
		if(!irccmp(parv[1], "-full"))
			do_etrace_full(source_p);
#ifdef RB_IPV6
		else if(!irccmp(parv[1], "-v6"))
			do_etrace(source_p, 0, 1);
		else if(!irccmp(parv[1], "-v4"))
			do_etrace(source_p, 1, 0);
#endif
		else
		{
			struct Client *target_p = find_named_person(parv[1]);

			if(target_p)
			{
				if(!MyClient(target_p))
					sendto_one(target_p, ":%s ENCAP %s ETRACE %s",
						   get_id(source_p, target_p),
						   target_p->servptr->name,
						   get_id(target_p, target_p));
				else
					do_single_etrace(source_p, target_p);
			}
			else
				sendto_one_numeric(source_p, ERR_NOSUCHNICK,
						   form_str(ERR_NOSUCHNICK), parv[1]);
		}
	}
	else
		do_etrace(source_p, 1, 1);

	return 0;
}

static int
me_etrace(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	if(!IsOper(source_p) || parc < 2 || EmptyString(parv[1]))
		return 0;

	/* we cant etrace remote clients.. we shouldnt even get sent them */
	if((target_p = find_person(parv[1])) && MyClient(target_p))
		do_single_etrace(source_p, target_p);

	sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE),
			   target_p ? target_p->name : parv[1]);

	return 0;
}

static void
do_etrace(struct Client *source_p, int ipv4, int ipv6)
{
	struct Client *target_p;
	rb_dlink_node *ptr;

	SetCork(source_p);
	/* report all direct connections */
	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		target_p = ptr->data;

#ifdef RB_IPV6
		if((!ipv4 && GET_SS_FAMILY(&target_p->localClient->ip) == AF_INET) ||
		   (!ipv6 && GET_SS_FAMILY(&target_p->localClient->ip) == AF_INET6))
			continue;
#endif

		sendto_one(source_p, form_str(RPL_ETRACE),
			   me.name, source_p->name,
			   IsOper(target_p) ? "Oper" : "User",
			   get_client_class(target_p),
			   target_p->name, target_p->username, target_p->host,
			   show_ip(source_p, target_p) ? target_p->sockhost : empty_sockhost,
			   target_p->info);
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), me.name);
}

static void
do_etrace_full(struct Client *source_p)
{
	rb_dlink_node *ptr;
	SetCork(source_p);
	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		do_single_etrace(source_p, ptr->data);
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), me.name);
}

/*
 * do_single_etrace  - searches local clients and displays those matching
 *                     a pattern
 * input             - source client, target client
 * output	     - etrace results
 * side effects	     - etrace results are displayed
 */
static void
do_single_etrace(struct Client *source_p, struct Client *target_p)
{
	/* note, we hide fullcaps for spoofed users, as mirc can often
	 * advertise its internal ip address in the field --fl
	 */
	if(!show_ip(source_p, target_p))
		sendto_one(source_p, form_str(RPL_ETRACEFULL),
			   me.name, source_p->name,
			   IsOper(target_p) ? "Oper" : "User",
			   get_client_class(target_p),
			   target_p->name, target_p->username, target_p->host,
			   empty_sockhost, "<hidden> <hidden>", target_p->info);
	else
		sendto_one(source_p, form_str(RPL_ETRACEFULL),
			   me.name, source_p->name,
			   IsOper(target_p) ? "Oper" : "User",
			   get_client_class(target_p),
			   target_p->name, target_p->username,
			   target_p->host, target_p->sockhost,
			   target_p->localClient->fullcaps, target_p->info);
}

static int
mo_chantrace(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	const char *sockhost;
	const char *name;
	rb_dlink_node *ptr;
	int operspy = 0;

	name = parv[1];

	if(IsOperSpy(source_p) && parv[1][0] == '!')
	{
		name++;
		operspy = 1;
		if(EmptyString(name))
		{
			sendto_one_numeric(source_p, ERR_NEEDMOREPARAMS,
					   form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name,
					   "CHANTRACE");
			return 0;
		}
	}

	if((chptr = find_channel(name)) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), name);
		return 0;
	}

	/* dont report operspys for nonexistant channels. */
	if(operspy)
		report_operspy(source_p, "CHANTRACE", chptr->chname);

	if(!operspy && !IsMember(client_p, chptr))
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL, form_str(ERR_NOTONCHANNEL),
				   chptr->chname);
		return 0;
	}
	SetCork(source_p);
	RB_DLINK_FOREACH(ptr, chptr->members.head)
	{
		msptr = ptr->data;
		target_p = msptr->client_p;

		if(EmptyString(target_p->sockhost))
			sockhost = empty_sockhost;
		else if(!show_ip(source_p, target_p))
			sockhost = spoofed_sockhost;
		else
			sockhost = target_p->sockhost;

		sendto_one(source_p, form_str(RPL_ETRACE),
			   me.name, source_p->name, IsOper(target_p) ? "Oper" : "User",
			   /* class field -- pretend its server.. */
			   target_p->servptr->name,
			   target_p->name, target_p->username, target_p->host,
			   sockhost, target_p->info);
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), me.name);
	return 0;
}

static void
match_masktrace(struct Client *source_p, rb_dlink_list *list, const char *username,
		const char *hostname, const char *name, const char *gecos)
{
	struct Client *target_p;
	rb_dlink_node *ptr;
	const char *sockhost;
	RB_DLINK_FOREACH(ptr, list->head)
	{
		target_p = ptr->data;
		if(!IsClient(target_p))
			continue;

		if(EmptyString(target_p->sockhost))
			sockhost = empty_sockhost;
		else if(!show_ip(source_p, target_p))
			sockhost = spoofed_sockhost;
		else
			sockhost = target_p->sockhost;

		if(match(username, target_p->username) && (match(hostname, target_p->host) ||
							   match(hostname, sockhost)
							   || match_ips(hostname, sockhost)))
		{
			if(name != NULL && !match(name, target_p->name))
				continue;

			if(gecos != NULL && !match_esc(gecos, target_p->info))
				continue;

			sendto_one(source_p, form_str(RPL_ETRACE),
				   me.name, source_p->name, IsOper(target_p) ? "Oper" : "User",
				   /* class field -- pretend its server.. */
				   target_p->servptr->name,
				   target_p->name, target_p->username, target_p->host,
				   sockhost, target_p->info);
		}
	}
}

static int
mo_masktrace(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char *name, *username, *hostname, *gecos;
	const char *mask;
	int operspy = 0;

	mask = parv[1];
	name = LOCAL_COPY(parv[1]);
	collapse(name);


	if(IsOperSpy(source_p) && parv[1][0] == '!')
	{
		name++;
		mask++;
		operspy = 1;
	}

	if(parc > 2 && !EmptyString(parv[2]))
	{
		gecos = LOCAL_COPY(parv[2]);
		collapse_esc(gecos);
	}
	else
		gecos = NULL;


	if((hostname = strchr(name, '@')) == NULL)
	{
		sendto_one_notice(source_p, ":Invalid parameters");
		return 0;
	}

	*hostname++ = '\0';

	if((username = strchr(name, '!')) == NULL)
	{
		username = name;
		name = NULL;
	}
	else
		*username++ = '\0';

	if(EmptyString(username) || EmptyString(hostname))
	{
		sendto_one_notice(source_p, ":Invalid parameters");
		return 0;
	}
	SetCork(source_p);
	if(operspy)
	{
		char buf[512];
		rb_strlcpy(buf, mask, sizeof(buf));
		if(!EmptyString(gecos))
		{
			rb_strlcat(buf, " ", sizeof(buf));
			rb_strlcat(buf, gecos, sizeof(buf));
		}

		report_operspy(source_p, "MASKTRACE", buf);
		match_masktrace(source_p, &global_client_list, username, hostname, name, gecos);
	}
	else
		match_masktrace(source_p, &lclient_list, username, hostname, name, gecos);
	ClearCork(source_p);
	sendto_one_numeric(source_p, RPL_ENDOFTRACE, form_str(RPL_ENDOFTRACE), me.name);
	return 0;
}
