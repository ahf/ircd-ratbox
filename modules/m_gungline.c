/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_gungline.c: Votes towards removing a gline.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2009 ircd-ratbox development team
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
 *  $Id: m_gline.c 26421 2009-01-18 17:38:16Z jilles $
 */

#include "stdinc.h"
#include "struct.h"
#include "s_gline.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "hostmask.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "scache.h"
#include "send.h"
#include "s_serv.h"
#include "hash.h"
#include "parse.h"
#include "modules.h"
#include "s_log.h"
#include "hook.h"

static int mo_gungline(struct Client *, struct Client *, int, const char **);
static int me_gungline(struct Client *, struct Client *, int, const char **);

static void h_gungline_stats(hook_data_int *);

static int modinit(void);
static void moddeinit(void);

struct Message gungline_msgtab = {
	"GUNGLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_gungline, 4}, {mo_gungline, 3}}
};

mapi_clist_av2 gungline_clist[] = { &gungline_msgtab, NULL };

mapi_hfn_list_av2 gungline_hfnlist[] = {
	{"doing_stats", (hookfn) h_gungline_stats},
	{NULL, NULL}
};

DECLARE_MODULE_AV2(gungline, modinit, moddeinit, gungline_clist, NULL, gungline_hfnlist, "$Revision: 26421 $");

static int majority_ungline(struct Client *source_p, const char *user,
			  const char *host, const char *reason);

static int invalid_gline(struct Client *, const char *, char *);

static int remove_temp_gline(const char *, const char *);
static void expire_pending_gunglines(void *unused);
static struct ev_entry *pending_gungline_ev;
static void flush_pending_gunglines(void);

static rb_dlink_list pending_gunglines;

static int
modinit(void)
{
	pending_gungline_ev = rb_event_addish("expire_pending_gunglines", expire_pending_gunglines, NULL,
					   CLEANUP_GLINES_TIME);
	return 0;
}

static void
moddeinit(void)
{
	rb_event_delete(pending_gungline_ev);
	if (rb_dlink_list_length(&pending_gunglines) > 0)
		sendto_realops_flags(UMODE_ALL, L_ALL,
				"Discarding pending gunglines because of module unload");
	flush_pending_gunglines();
}

/* mo_gungline()
 *
 * inputs       - The usual for a m_ function
 * output       -
 * side effects - remove a gline if 3 opers agree
 */
static int
mo_gungline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *user = NULL;
	char *host = NULL;
	char *reason = NULL;
	char splat[] = "*";

	if(!ConfigFileEntry.glines)
	{
		sendto_one_notice(source_p, ":GUNGLINE disabled");
		return 0;
	}

	if(!IsOperUnkline(source_p) || !IsOperGline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "ungline");
		return 0;
	}

	host = strchr(parv[1], '@');

	/* specific user@host */
	if(host != NULL)
	{
		user = parv[1];
		*(host++) = '\0';

		/* gline for "@host", use *@host */
		if(*user == '\0')
			user = splat;
	}
	/* just a host? */
	else
	{
		/* ok, its not a host.. abort */
		if(strchr(parv[1], '.') == NULL)
		{
			sendto_one_notice(source_p, ":Invalid parameters");
			return 0;
		}

		user = splat;
		host = LOCAL_COPY(parv[1]);
	}

	reason = LOCAL_COPY(parv[2]);

	if(invalid_gline(source_p, user, reason))
		return 0;

	/* inform users about the gline before we call majority_ungline()
	 * so already voted comes below gline request --fl
	 */
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s!%s@%s on %s is requesting ungline for [%s@%s] [%s]",
			     source_p->name, source_p->username,
			     source_p->host, me.name, user, host, reason);
	ilog(L_GLINE, "RU %s %s %s %s %s %s %s",
	     source_p->name, source_p->username, source_p->host,
	     source_p->servptr->name, user, host, reason);

	/* If at least 3 opers agree this user should be G lined then do it */
	majority_ungline(source_p, user, host, reason);

	sendto_server(client_p, NULL, CAP_ENCAP | CAP_TS6, NOCAPS,
		      ":%s ENCAP * GUNGLINE %s %s :%s", source_p->id, user, host, reason);
	return 0;
}

/* mc_gungline()
 */
static int
me_gungline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *acptr;
	const char *user;
	const char *host;
	char *reason;

	if (!IsClient(source_p))
		return 0;

	acptr = source_p;

	user = parv[1];
	host = parv[2];
	reason = LOCAL_COPY(parv[3]);

	if(invalid_gline(acptr, user, reason))
		return 0;

	if(!ConfigFileEntry.glines)
		return 0;

	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s!%s@%s on %s is requesting ungline for [%s@%s] [%s]",
			     acptr->name, acptr->username, acptr->host,
			     acptr->servptr->name, user, host, reason);

	ilog(L_GLINE, "RU %s %s %s %s %s %s %s",
	     source_p->name, source_p->username, source_p->host,
	     source_p->servptr->name, user, host, reason);

	/* If at least 3 opers agree this user should be G lined then do it */
	majority_ungline(acptr, user, host, reason);

	return 0;
}


/* invalid_gline
 *
 * inputs	- pointer to source client, ident, host and reason
 * outputs	- 1 if invalid, 0 if valid
 * side effects -
 */
static int
invalid_gline(struct Client *source_p, const char *luser, char *lreason)
{
	if(strchr(luser, '!'))
	{
		sendto_one_notice(source_p, ":Invalid character '!' in gline");
		return 1;
	}

	if(strlen(lreason) > REASONLEN)
		lreason[REASONLEN] = '\0';

	return 0;
}

/*
 * remove_local_gline
 *
 * inputs	- pointer to oper nick/username/host/server,
 * 		  victim user/host and reason
 * output	- NONE
 * side effects	-
 */
static void
remove_local_gline(struct Client *source_p, const char *user, const char *host, const char *reason)
{
	if (!remove_temp_gline(user, host))
		return;
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s!%s@%s on %s has triggered ungline for [%s@%s] [%s]",
			     source_p->name, source_p->username,
			     source_p->host, source_p->servptr->name, user, host, reason);
	ilog(L_GLINE, "TU %s %s %s %s %s %s %s",
	     source_p->name, source_p->username, source_p->host,
	     source_p->servptr->name, user, host, reason);
}

/* majority_ungline()
 *
 * input	- client doing gline, user, host and reason of gline
 * output       - YES if there are 3 different opers/servers agree, else NO
 * side effects -
 */
static int
majority_ungline(struct Client *source_p, const char *user, const char *host, const char *reason)
{
	rb_dlink_node *pending_node;
	struct gline_pending *pending;

	/* to avoid desync.. --fl */
	expire_pending_gunglines(NULL);

	RB_DLINK_FOREACH(pending_node, pending_gunglines.head)
	{
		pending = pending_node->data;

		if((irccmp(pending->user, user) == 0) && (irccmp(pending->host, host) == 0))
		{
			/* check oper or server hasnt already voted */
			if(((irccmp(pending->oper_user1, source_p->username) == 0) &&
			    (irccmp(pending->oper_host1, source_p->host) == 0)))
			{
				sendto_realops_flags(UMODE_ALL, L_ALL, "oper has already voted");
				return NO;
			}
			else if(irccmp(pending->oper_server1, source_p->servptr->name) == 0)
			{
				sendto_realops_flags(UMODE_ALL, L_ALL, "server has already voted");
				return NO;
			}

			if(pending->oper_user2[0] != '\0')
			{
				/* if two other opers on two different servers have voted yes */
				if(((irccmp(pending->oper_user2, source_p->username) == 0) &&
				    (irccmp(pending->oper_host2, source_p->host) == 0)))
				{
					sendto_realops_flags(UMODE_ALL, L_ALL,
							     "oper has already voted");
					return NO;
				}
				else if(irccmp(pending->oper_server2, source_p->servptr->name) == 0)
				{
					sendto_realops_flags(UMODE_ALL, L_ALL,
							     "server has already voted");
					return NO;
				}

				/* trigger the gline using the original reason --fl */
				remove_local_gline(source_p, user, host, pending->reason1);

				expire_pending_gunglines(pending);
				return YES;
			}
			else
			{
				rb_strlcpy(pending->oper_nick2, source_p->name,
					   sizeof(pending->oper_nick2));
				rb_strlcpy(pending->oper_user2, source_p->username,
					   sizeof(pending->oper_user2));
				rb_strlcpy(pending->oper_host2, source_p->host,
					   sizeof(pending->oper_host2));
				pending->reason2 = rb_strdup(reason);
				pending->oper_server2 = scache_add(source_p->servptr->name);
				pending->last_gline_time = rb_time();
				pending->time_request2 = rb_time();
				return NO;
			}
		}
	}

	/* no pending ungline, create a new one */
	pending = (struct gline_pending *)rb_malloc(sizeof(struct gline_pending));

	rb_strlcpy(pending->oper_nick1, source_p->name, sizeof(pending->oper_nick1));
	rb_strlcpy(pending->oper_user1, source_p->username, sizeof(pending->oper_user1));
	rb_strlcpy(pending->oper_host1, source_p->host, sizeof(pending->oper_host1));

	pending->oper_server1 = scache_add(source_p->servptr->name);

	rb_strlcpy(pending->user, user, sizeof(pending->user));
	rb_strlcpy(pending->host, host, sizeof(pending->host));
	pending->reason1 = rb_strdup(reason);
	pending->reason2 = NULL;

	pending->last_gline_time = rb_time();
	pending->time_request1 = rb_time();

	rb_dlinkAddAlloc(pending, &pending_gunglines);

	return NO;
}

/* remove_temp_gline()
 *
 * inputs       - username, hostname to ungline
 * outputs      -
 * side effects - tries to ungline anything that matches
 */
static int
remove_temp_gline(const char *user, const char *host)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	struct rb_sockaddr_storage addr, caddr;
	int bits, cbits;
	int mtype, gtype;

	mtype = parse_netmask(host, (struct sockaddr *)&addr, &bits);

	RB_DLINK_FOREACH(ptr, glines.head)
	{
		aconf = ptr->data;

		gtype = parse_netmask(aconf->host, (struct sockaddr *)&caddr, &cbits);

		if(gtype != mtype || (user && irccmp(user, aconf->user)))
			continue;

		if(gtype == HM_HOST)
		{
			if(irccmp(aconf->host, host))
				continue;
		}
		else if(bits != cbits ||
			!comp_with_mask_sock((struct sockaddr *)&addr,
					     (struct sockaddr *)&caddr, bits))
			continue;

		rb_dlinkDestroy(ptr, &glines);
		delete_one_address_conf(aconf->host, aconf);
		return YES;
	}

	return NO;
}

static void
h_gungline_stats(hook_data_int * data)
{
	char statchar = (char)data->arg2;

	if(ConfigFileEntry.glines && statchar == 'g' && IsOper(data->client))
	{
		rb_dlink_node *pending_node;
		struct gline_pending *glp_ptr;
		char timebuffer[MAX_DATE_STRING];
		struct tm *tmptr;

		RB_DLINK_FOREACH(pending_node, pending_gunglines.head)
		{
			glp_ptr = pending_node->data;

			tmptr = gmtime(&glp_ptr->time_request1);
			strftime(timebuffer, MAX_DATE_STRING, "%Y/%m/%d %H:%M:%S", tmptr);

			sendto_one_notice(data->client,
					  ":1) %s!%s@%s on %s requested ungline at %s for %s@%s [%s]",
					  glp_ptr->oper_nick1,
					  glp_ptr->oper_user1, glp_ptr->oper_host1,
					  glp_ptr->oper_server1, timebuffer,
					  glp_ptr->user, glp_ptr->host, glp_ptr->reason1);

			if(glp_ptr->oper_nick2[0])
			{
				tmptr = gmtime(&glp_ptr->time_request2);
				strftime(timebuffer, MAX_DATE_STRING, "%Y/%m/%d %H:%M:%S", tmptr);
				sendto_one_notice(data->client,
						  ":2) %s!%s@%s on %s requested ungline at %s for %s@%s [%s]",
						  glp_ptr->oper_nick2,
						  glp_ptr->oper_user2, glp_ptr->oper_host2,
						  glp_ptr->oper_server2, timebuffer,
						  glp_ptr->user, glp_ptr->host, glp_ptr->reason2);
			}
		}

		if(rb_dlink_list_length(&pending_gunglines) > 0)
			sendto_one_notice(data->client, ":End of Pending G-line Removals");
	}
}
/*
 * expire_pending_gunglines
 * 
 * inputs       - NONE
 * output       - NONE
 * side effects -
 *
 * Go through the pending gungline list, expire any that haven't had
 * enough "votes" in the time period allowed
 */
static void
expire_pending_gunglines(void *vptr)
{
	rb_dlink_node *pending_node;
	rb_dlink_node *next_node;
	struct gline_pending *glp_ptr;

	RB_DLINK_FOREACH_SAFE(pending_node, next_node, pending_gunglines.head)
	{
		glp_ptr = pending_node->data;

		if((glp_ptr->last_gline_time + GLINE_PENDING_EXPIRE) <=
		    rb_time() || vptr == glp_ptr)

		{
			rb_free(glp_ptr->reason1);
			rb_free(glp_ptr->reason2);
			rb_free(glp_ptr);
			rb_dlinkDestroy(pending_node, &pending_gunglines);
		}
	}
}

static void
flush_pending_gunglines(void)
{
	rb_dlink_node *pending_node;
	rb_dlink_node *next_node;
	struct gline_pending *glp_ptr;

	RB_DLINK_FOREACH_SAFE(pending_node, next_node, pending_gunglines.head)
	{
		glp_ptr = pending_node->data;

		rb_free(glp_ptr->reason1);
		rb_free(glp_ptr->reason2);
		rb_free(glp_ptr);
		rb_dlinkDestroy(pending_node, &pending_gunglines);
	}
}
