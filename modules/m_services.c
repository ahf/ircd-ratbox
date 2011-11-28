/* modules/m_services.c
 *   Copyright (C) 2005 Lee Hardy <lee -at- leeh.co.uk>
 *   Copyright (C) 2005 ircd-ratbox development team
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
 * $Id: m_services.c 27325 2011-11-12 22:57:45Z jilles $
 */

#include "stdinc.h"

#ifdef ENABLE_SERVICES
#include "struct.h"
#include "send.h"
#include "client.h"
#include "channel.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "hash.h"
#include "parse.h"
#include "hook.h"
#include "modules.h"
#include "match.h"
#include "whowas.h"
#include "monitor.h"
#include "s_serv.h"

static int me_su(struct Client *, struct Client *, int, const char **);
static int me_login(struct Client *, struct Client *, int, const char **);
static int me_rsfnc(struct Client *, struct Client *, int, const char **);

static void h_svc_server_introduced(hook_data_client *);
static void h_svc_burst_client(hook_data_client *);
static void h_svc_whois(hook_data_client *);
static void h_svc_stats(hook_data_int *);

struct Message su_msgtab = {
	"SU", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_su, 2}, mg_ignore}
};

struct Message login_msgtab = {
	"LOGIN", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_login, 2}, mg_ignore}
};

struct Message rsfnc_msgtab = {
	"RSFNC", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_rsfnc, 3}, mg_ignore}
};

mapi_clist_av2 services_clist[] = {
	&su_msgtab, &login_msgtab, &rsfnc_msgtab, NULL
};

mapi_hfn_list_av2 services_hfnlist[] = {
	{"doing_stats", (hookfn) h_svc_stats},
	{"doing_whois", (hookfn) h_svc_whois},
	{"doing_whois_global", (hookfn) h_svc_whois},
	{"burst_client", (hookfn) h_svc_burst_client},
	{"server_introduced", (hookfn) h_svc_server_introduced},
	{NULL, NULL}
};

DECLARE_MODULE_AV2(services, NULL, NULL, services_clist, NULL, services_hfnlist,
		   "$Revision: 27325 $");

static int
me_su(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	if(!(source_p->flags & FLAGS_SERVICE))
		return 0;

	if((target_p = find_client(parv[1])) == NULL)
		return 0;

	if(!IsClient(target_p))
		return 0;

	if(EmptyString(parv[2]))
		target_p->user->suser[0] = '\0';
	else
		rb_strlcpy(target_p->user->suser, parv[2], sizeof(target_p->user->suser));

	return 0;
}

static int
clean_nick(const char *nick)
{
	int len = 0;

	if(EmptyString(nick) || *nick == '-' || IsDigit(*nick))
		return 0;

	for(; *nick; nick++)
	{
		len++;
		if(!IsNickChar(*nick))
			return 0;
	}

	if(len >= NICKLEN)
		return 0;

	return 1;
}

static int
me_rsfnc(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	struct Client *exist_p;
	char note[HOSTLEN + 10];
	time_t newts, curts;

	if(!(source_p->flags & FLAGS_SERVICE))
		return 0;

	if((target_p = find_person(parv[1])) == NULL)
		return 0;

	if(!MyClient(target_p))
		return 0;

	if(!clean_nick(parv[2]))
		return 0;

	curts = atol(parv[4]);

	/* if tsinfo is different from what it was when services issued the
	 * RSFNC, then we ignore it.  This can happen when a client changes
	 * nicknames before the RSFNC arrives.. --anfl
	 */
	if(target_p->tsinfo != curts)
		return 0;

	if((exist_p = find_named_client(parv[2])))
	{
		char buf[BUFSIZE];

		/* this would be one hell of a race condition to trigger
		 * this one given the tsinfo check above, but its here for 
		 * safety --anfl
		 */
		if(target_p == exist_p)
			return 0;

		if(MyClient(exist_p))
			sendto_one(exist_p, ":%s KILL %s :(Nickname regained by services)",
				   me.name, exist_p->name);

		exist_p->flags |= FLAGS_KILLED;
		/* Do not send kills to servers for unknowns -- jilles */
		if(IsClient(exist_p))
			kill_client_serv_butone(NULL, exist_p, "%s (Nickname regained by services)",
						me.name);

		rb_snprintf(buf, sizeof(buf), "Killed (%s (Nickname regained by services))",
			    me.name);
		exit_client(NULL, exist_p, &me, buf);
	}

	newts = atol(parv[3]);

	/* timestamp is older than 15mins, ignore it */
	if(newts < (rb_time() - 900))
		newts = rb_time() - 900;

	target_p->tsinfo = newts;

	monitor_signoff(target_p);

	invalidate_bancache_user(target_p);

	sendto_realops_flags(UMODE_NCHANGE, L_ALL,
			     "Nick change: From %s to %s [%s@%s]",
			     target_p->name, parv[2], target_p->username, target_p->host);

	sendto_common_channels_local(target_p, ":%s!%s@%s NICK :%s",
				     target_p->name, target_p->username, target_p->host, parv[2]);

	add_history(target_p, 1);
	sendto_server(NULL, NULL, CAP_TS6, NOCAPS, ":%s NICK %s :%ld",
		      target_p->id, parv[2], (long)target_p->tsinfo);

	del_from_hash(HASH_CLIENT, target_p->name, target_p);
	strcpy(target_p->user->name, parv[2]);
	add_to_hash(HASH_CLIENT, target_p->name, target_p);

	monitor_signon(target_p);

	del_all_accepts(target_p);
	rb_snprintf(note, sizeof(note), "Nick: %s", target_p->name);
	rb_note(target_p->localClient->F, note);
	return 0;
}

static int
me_login(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsClient(source_p) || !ServerInfo.hub)
		return 0;

	/* this command is *only* accepted from bursting servers */
	if(HasSentEob(source_p->servptr))
		return 0;

	rb_strlcpy(source_p->user->suser, parv[1], sizeof(source_p->user->suser));
	return 0;
}

static void
h_svc_burst_client(hook_data_client * hdata)
{
	if(EmptyString(hdata->target->user->suser))
		return;

	sendto_one(hdata->client, ":%s ENCAP * LOGIN %s",
		   get_id(hdata->target, hdata->client), hdata->target->user->suser);
}

static void
h_svc_server_introduced(hook_data_client * hdata)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, service_list.head)
	{
		if(!irccmp((const char *)ptr->data, hdata->target->name))
		{
			hdata->target->flags |= FLAGS_SERVICE;
			return;
		}
	}
}

static void
h_svc_whois(hook_data_client * data)
{
	if(!EmptyString(data->target->user->suser))
	{
		sendto_one(data->client, form_str(RPL_WHOISLOGGEDIN),
			   get_id(&me, data->client),
			   get_id(data->client, data->client),
			   data->target->name, data->target->user->suser);
	}
}

static void
h_svc_stats(hook_data_int * data)
{
	char statchar = (char)data->arg2;
	rb_dlink_node *ptr;

	if(statchar == 'U' && IsOper(data->client))
	{
		RB_DLINK_FOREACH(ptr, service_list.head)
		{
			sendto_one_numeric(data->client, RPL_STATSULINE,
					   form_str(RPL_STATSULINE),
					   (const char *)ptr->data, "*", "*", "s");
		}
	}
}

#endif
