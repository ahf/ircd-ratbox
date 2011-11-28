/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_server.c: Introduces a server.
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
 *  $Id: m_server.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"		/* client struct */
#include "channel.h"
#include "hash.h"		/* add_to_client_hash */
#include "match.h"
#include "ircd.h"		/* me */
#include "s_conf.h"		/* struct ConfItem */
#include "s_newconf.h"
#include "s_log.h"		/* log level defines */
#include "s_serv.h"		/* server_estab, check_server */
#include "scache.h"		/* find_or_add */
#include "send.h"		/* sendto_one */
#include "parse.h"
#include "hook.h"
#include "modules.h"
#include "s_stats.h"
#include "packet.h"
#include "s_user.h"
#include "reject.h"
#include "sslproc.h"

static int mr_server(struct Client *, struct Client *, int, const char **);
static int ms_server(struct Client *, struct Client *, int, const char **);
static int ms_sid(struct Client *, struct Client *, int, const char **);

struct Message server_msgtab = {
	"SERVER", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{{mr_server, 4}, mg_reg, mg_ignore, {ms_server, 4}, mg_ignore, mg_reg}
};

struct Message sid_msgtab = {
	"SID", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_reg, mg_ignore, {ms_sid, 5}, mg_ignore, mg_reg}
};

mapi_clist_av2 server_clist[] = { &server_msgtab, &sid_msgtab, NULL };

DECLARE_MODULE_AV2(server, NULL, NULL, server_clist, NULL, NULL, "$Revision: 27173 $");

static int set_server_gecos(struct Client *, const char *);

static int check_server(const char *name, struct Client *client_p);
static int server_estab(struct Client *client_p);


/* enums for check_server */
enum
{
	NO_NLINE = -1,
	INVALID_PASS = -2,
	INVALID_HOST = -3,
	INVALID_SERVERNAME = -4,
	NEED_SSL = -5,
};


/*
 * mr_server - SERVER message handler
 *      parv[1] = servername
 *      parv[2] = serverinfo/hopcount
 *      parv[3] = serverinfo
 */
static int
mr_server(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char info[REALLEN + 1];
	const char *name;
	struct Client *target_p;
	int hop;

	name = parv[1];
	hop = atoi(parv[2]);
	rb_strlcpy(info, parv[3], sizeof(info));

	/* 
	 * Reject a direct nonTS server connection if we're TS_ONLY -orabidoo
	 */
	if(!DoesTS(client_p))
	{
		exit_client(client_p, client_p, client_p, "Non-TS server");
		return 0;
	}

	if(!valid_servername(name))
	{
		exit_client(client_p, client_p, client_p, "Invalid servername.");
		return 0;
	}

	/* Now we just have to call check_server and everything should be
	 * check for us... -A1kmm. */
	switch (check_server(name, client_p))
	{
	case NO_NLINE:
		if(ConfigFileEntry.warn_no_nline)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Unauthorised server connection attempt from [@255.255.255.255]: "
					     "No entry for servername %s", name);

			ilog(L_SERVER, "Access denied, No N line for server %s",
			     log_client_name(client_p, SHOW_IP));
		}

		exit_client(client_p, client_p, client_p, "Invalid servername.");
		return 0;
		/* NOT REACHED */
		break;

	case INVALID_PASS:
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Unauthorised server connection attempt from [@255.255.255.255]: "
				     "Bad password for server %s", name);

		ilog(L_SERVER, "Access denied, invalid password for server %s",
		     log_client_name(client_p, SHOW_IP));

		exit_client(client_p, client_p, client_p, "Invalid password.");
		return 0;
	case INVALID_HOST:
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Unauthorised server connection attempt from [@255.255.255.255]: "
				     "Invalid host for server %s", name);

		ilog(L_SERVER, "Access denied, invalid host for server %s",
		     log_client_name(client_p, SHOW_IP));

		exit_client(client_p, client_p, client_p, "Invalid host.");
		return 0;
		/* servername is > HOSTLEN */
	case INVALID_SERVERNAME:
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Invalid servername %s from [@255.255.255.255]",
				     client_p->name);
		ilog(L_SERVER, "Access denied, invalid servername from %s",
		     log_client_name(client_p, SHOW_IP));

		exit_client(client_p, client_p, client_p, "Invalid servername.");
		return 0;
	case NEED_SSL:
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Connection from servername %s requires SSL/TLS but is plaintext",
				     name);
		ilog(L_SERVER, "Access denied, requires SSL/TLS but is plaintext from %s",
		     log_client_name(client_p, SHOW_IP));

		exit_client(client_p, client_p, client_p,
			    "Access denied, requires SSL/TLS but is plaintext");
		return 0;
	default:
		break;
	}

	/* require TS6 for direct links */
	if(!IsCapable(client_p, CAP_TS6))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s dropped, TS6 protocol is required", name);
		exit_client(client_p, client_p, client_p, "Incompatible TS version");
		return 0;
	}

	if((target_p = find_server(NULL, name)))
	{
		/*
		 * This link is trying feed me a server that I already have
		 * access through another path -- multiple paths not accepted
		 * currently, kill this link immediately!!
		 *
		 * Rather than KILL the link which introduced it, KILL the
		 * youngest of the two links. -avalon
		 *
		 * Definitely don't do that here. This is from an unregistered
		 * connect - A1kmm.
		 */
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Attempt to re-introduce server %s from [@255.255.255.255]",
				     name);
		ilog(L_SERVER, "Attempt to re-introduce server %s from %s",
		     name, log_client_name(client_p, SHOW_IP));

		sendto_one(client_p, "ERROR :Server already exists.");
		exit_client(client_p, client_p, client_p, "Server Exists");
		return 0;
	}

	if((target_p = find_id(client_p->id)) != NULL)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Attempt to re-introduce SID %s from %s[@255.255.255.255]",
				     client_p->id, name);
		ilog(L_SERVER, "Attempt to re-introduce SID %s from %s",
		     name, log_client_name(client_p, SHOW_IP));

		sendto_one(client_p, "ERROR :SID already exists.");
		exit_client(client_p, client_p, client_p, "SID Exists");
		return 0;
	}

	/*
	 * if we are connecting (Handshake), we already have the name from the
	 * C:line in client_p->name
	 */

	client_p->name = scache_add(name);
	set_server_gecos(client_p, info);
	client_p->hopcount = hop;
	server_estab(client_p);

	return 0;
}

/*
 * ms_server - SERVER message handler
 *      parv[1] = servername
 *      parv[2] = serverinfo/hopcount
 *      parv[3] = serverinfo
 */
static int
ms_server(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *name = parv[1];

	sendto_one(client_p, "ERROR :Introduced server %s is not TS6", name);
	sendto_realops_flags(UMODE_ALL, L_ALL, "Link %s cancelled, introduced server %s is not TS6", client_p->name, name);
	exit_client(client_p, client_p, &me, "Introduced server not TS6");
	return 0;
}

static int
ms_sid(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	struct remote_conf *hub_p;
	hook_data_client hdata;
	rb_dlink_node *ptr;
	int hop;
	int hlined = 0;
	int llined = 0;

	hop = atoi(parv[2]);

	/* collision on the name? */
	if((target_p = find_server(NULL, parv[1])) != NULL)
	{
		sendto_one(client_p, "ERROR :Server %s already exists", parv[1]);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s cancelled, server %s already exists",
				     client_p->name, parv[1]);
		ilog(L_SERVER, "Link %s cancelled, server %s already exists",
		     client_p->name, parv[1]);
		exit_client(NULL, client_p, &me, "Server Exists");
		return 0;
	}

	/* collision on the SID? */
	if((target_p = find_id(parv[3])) != NULL)
	{
		sendto_one(client_p, "ERROR :SID %s already exists", parv[3]);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s cancelled, SID %s already exists",
				     client_p->name, parv[3]);
		ilog(L_SERVER, "Link %s cancelled, SID %s already exists", client_p->name, parv[3]);
		exit_client(NULL, client_p, &me, "SID Exists");
		return 0;
	}

	if(!valid_servername(parv[1]) || strlen(parv[1]) > HOSTLEN)
	{
		sendto_one(client_p, "ERROR :Invalid servername");
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s cancelled, servername %s invalid",
				     client_p->name, parv[1]);
		ilog(L_SERVER, "Link %s cancelled, servername %s invalid", client_p->name, parv[1]);
		exit_client(NULL, client_p, &me, "Bogus server name");
		return 0;
	}

	if(!IsDigit(parv[3][0]) || !IsIdChar(parv[3][1]) ||
	   !IsIdChar(parv[3][2]) || parv[3][3] != '\0')
	{
		sendto_one(client_p, "ERROR :Invalid SID");
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s cancelled, SID %s invalid", client_p->name, parv[3]);
		ilog(L_SERVER, "Link %s cancelled, SID %s invalid", client_p->name, parv[3]);
		exit_client(NULL, client_p, &me, "Bogus SID");
		return 0;
	}

	/* for the directly connected server:
	 * H: allows it to introduce a server matching that mask
	 * L: disallows it introducing a server matching that mask
	 */
	RB_DLINK_FOREACH(ptr, hubleaf_conf_list.head)
	{
		hub_p = ptr->data;

		if(match(hub_p->server, client_p->name) && match(hub_p->host, parv[1]))
		{
			if(hub_p->flags & CONF_HUB)
				hlined++;
			else
				llined++;
		}
	}

	/* no matching hub_mask */
	if(!hlined)
	{
		sendto_one(client_p, "ERROR :No matching hub_mask");
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Non-Hub link %s introduced %s.", client_p->name, parv[1]);
		ilog(L_SERVER, "Non-Hub link %s introduced %s.", client_p->name, parv[1]);
		exit_client(NULL, client_p, &me, "No matching hub_mask.");
		return 0;
	}

	/* matching leaf_mask */
	if(llined)
	{
		sendto_one(client_p, "ERROR :Matching leaf_mask");
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s introduced leafed server %s.",
				     client_p->name, parv[1]);
		ilog(L_SERVER, "Link %s introduced leafed server %s.", client_p->name, parv[1]);
		exit_client(NULL, client_p, &me, "Leafed Server.");
		return 0;
	}

	/* ok, alls good */
	target_p = make_client(client_p);
	make_server(target_p);

	target_p->name = scache_add(parv[1]);

	target_p->hopcount = atoi(parv[2]);
	strcpy(target_p->id, parv[3]);
	set_server_gecos(target_p, parv[4]);

	target_p->servptr = source_p;
	SetServer(target_p);

	rb_dlinkAddTail(target_p, &target_p->node, &global_client_list);
	rb_dlinkAddTailAlloc(target_p, &global_serv_list);
	add_to_hash(HASH_CLIENT, target_p->name, target_p);
	add_to_hash(HASH_ID, target_p->id, target_p);
	rb_dlinkAdd(target_p, &target_p->lnode, &target_p->servptr->serv->servers);

	sendto_server(client_p, NULL, CAP_TS6, NOCAPS,
		      ":%s SID %s %d %s :%s%s",
		      source_p->id, target_p->name, target_p->hopcount + 1,
		      target_p->id, IsHidden(target_p) ? "(H) " : "", target_p->info);

	sendto_realops_flags(UMODE_EXTERNAL, L_ALL,
			     "Server %s being introduced by %s", target_p->name, source_p->name);

	/* quick, dirty EOB.  you know you love it. */
	sendto_one(target_p, ":%s PING %s %s",
		   get_id(&me, target_p), me.name, get_id(target_p, target_p));

	hdata.client = source_p;
	hdata.target = target_p;
	call_hook(h_server_introduced, &hdata);

	return 0;
}

/* set_server_gecos()
 *
 * input	- pointer to client
 * output	- none
 * side effects - servers gecos field is set
 */
static int
set_server_gecos(struct Client *client_p, const char *info)
{
	/* check the info for [IP] */
	if(info[0])
	{
		char *p;
		char *s;
		char *t;

		s = LOCAL_COPY(info);

		/* we should only check the first word for an ip */
		if((p = strchr(s, ' ')))
			*p = '\0';

		/* check for a ] which would symbolise an [IP] */
		if((t = strchr(s, ']')))
		{
			/* set s to after the first space */
			if(p)
				s = ++p;
			else
				s = NULL;
		}
		/* no ], put the space back */
		else if(p)
			*p = ' ';

		/* p may have been set to a trailing space, so check s exists and that
		 * it isnt \0 */
		if(s && (*s != '\0'))
		{
			/* a space? if not (H) could be the last part of info.. */
			if((p = strchr(s, ' ')))
				*p = '\0';

			/* check for (H) which is a hidden server */
			if(!strcmp(s, "(H)"))
			{
				SetHidden(client_p);

				/* if there was no space.. theres nothing to set info to */
				if(p)
					s = ++p;
				else
					s = NULL;
			}
			else if(p)
				*p = ' ';

			/* if there was a trailing space, s could point to \0, so check */
			if(s && (*s != '\0'))
			{
				rb_strlcpy(client_p->info, s, sizeof(client_p->info));
				return 1;
			}
		}
	}

	rb_strlcpy(client_p->info, "(Unknown Location)", sizeof(client_p->info));

	return 1;
}


static int
check_server(const char *name, struct Client *client_p)
{
	struct server_conf *server_p = NULL;
	struct server_conf *tmp_p;
	rb_dlink_node *ptr;
	int error = NO_NLINE;

	s_assert(NULL != client_p);
	if(client_p == NULL)
		return error;

	if(!(client_p->localClient->passwd))
		return INVALID_PASS;

	if(strlen(name) > HOSTLEN)
		return INVALID_SERVERNAME;

	RB_DLINK_FOREACH(ptr, server_conf_list.head)
	{
		tmp_p = ptr->data;

		if(ServerConfIllegal(tmp_p))
			continue;

		if(irccmp(name, tmp_p->name))
			continue;

		error = INVALID_HOST;

		/* XXX: Fix me for IPv6 */
		/* XXX sockhost is the IPv4 ip as a string */
		if(match(tmp_p->host, client_p->host) || match(tmp_p->host, client_p->sockhost))
		{
			error = INVALID_PASS;

			if(ServerConfEncrypted(tmp_p))
			{
				if(!strcmp(tmp_p->passwd, rb_crypt(client_p->localClient->passwd,
								   tmp_p->passwd)))
				{
					server_p = tmp_p;
					break;
				}
			}
			else if(!strcmp(tmp_p->passwd, client_p->localClient->passwd))
			{
				server_p = tmp_p;
				break;
			}
		}
	}

	if(server_p == NULL)
		return error;

	if(ServerConfSSL(server_p) && client_p->localClient->ssl_ctl == NULL)
	{
		return NEED_SSL;
	}

	attach_server_conf(client_p, server_p);

	/* clear ZIP/TB if they support but we dont want them */
	if(!ServerConfCompressed(server_p))
		ClearCap(client_p, CAP_ZIP);

	if(!ServerConfTb(server_p))
		ClearCap(client_p, CAP_TB);

#ifdef RB_IPV6
	if(GET_SS_FAMILY(&client_p->localClient->ip) == AF_INET6)
	{
		if(IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)&server_p->ipnum)->sin6_addr))
		{
			memcpy(&((struct sockaddr_in6 *)&server_p->ipnum)->sin6_addr,
			       &((struct sockaddr_in6 *)&client_p->localClient->ip)->sin6_addr,
			       sizeof(struct in6_addr));
			SET_SS_LEN(&server_p->ipnum, sizeof(struct sockaddr_in6));
		}
	}
	else
#endif
	{
		if(((struct sockaddr_in *)&server_p->ipnum)->sin_addr.s_addr == INADDR_NONE)
		{
			((struct sockaddr_in *)&server_p->ipnum)->sin_addr.s_addr =
				((struct sockaddr_in *)&client_p->localClient->ip)->sin_addr.s_addr;
		}
		SET_SS_LEN(&server_p->ipnum, sizeof(struct sockaddr_in));
	}

	return 0;
}

/* burst_modes_TS6()
 *
 * input	- client to burst to, channel name, list to burst, mode flag
 * output	-
 * side effects - client is sent a list of +b, +e, or +I modes
 */
static void
burst_modes_TS6(struct Client *client_p, struct Channel *chptr, rb_dlink_list *list, char flag)
{
	char buf[BUFSIZE];
	rb_dlink_node *ptr;
	struct Ban *banptr;
	char *t;
	int tlen;
	int mlen;
	int cur_len;

	cur_len = mlen = rb_sprintf(buf, ":%s BMASK %ld %s %c :",
				    me.id, (long)chptr->channelts, chptr->chname, flag);
	t = buf + mlen;

	RB_DLINK_FOREACH(ptr, list->head)
	{
		banptr = ptr->data;

		tlen = strlen(banptr->banstr) + 1;

		/* uh oh */
		if(cur_len + tlen > BUFSIZE - 3)
		{
			/* the one we're trying to send doesnt fit at all! */
			if(cur_len == mlen)
			{
				s_assert(0);
				continue;
			}

			/* chop off trailing space and send.. */
			*(t - 1) = '\0';
			sendto_one_buffer(client_p, buf);
			cur_len = mlen;
			t = buf + mlen;
		}

		rb_sprintf(t, "%s ", banptr->banstr);
		t += tlen;
		cur_len += tlen;
	}

	/* cant ever exit the loop above without having modified buf,
	 * chop off trailing space and send.
	 */
	*(t - 1) = '\0';
	sendto_one_buffer(client_p, buf);
}


/*
 * burst_TS6
 * 
 * inputs	- client (server) to send nick towards
 * 		- client to send nick for
 * output	- NONE
 * side effects	- NICK message is sent towards given client_p
 */
static void
burst_TS6(struct Client *client_p)
{
	static char ubuf[12];
	char buf[BUFSIZE];
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	hook_data_client hclientinfo;
	hook_data_channel hchaninfo;
	rb_dlink_node *ptr;
	rb_dlink_node *uptr;
	char *t;
	int tlen, mlen;
	int cur_len = 0;

	hclientinfo.client = hchaninfo.client = client_p;

	RB_DLINK_FOREACH(ptr, global_client_list.head)
	{
		target_p = ptr->data;

		if(!IsClient(target_p))
			continue;

		send_umode(NULL, target_p, 0, SEND_UMODES, ubuf);
		if(!*ubuf)
		{
			ubuf[0] = '+';
			ubuf[1] = '\0';
		}

		sendto_one(client_p, ":%s UID %s %d %ld %s %s %s %s %s :%s",
			   target_p->servptr->id, target_p->name,
			   target_p->hopcount + 1,
			   (long)target_p->tsinfo, ubuf,
			   target_p->username, target_p->host,
			   IsIPSpoof(target_p) ? "0" : target_p->sockhost,
			   target_p->id, target_p->info);

		if(ConfigFileEntry.burst_away && !EmptyString(target_p->user->away))
			sendto_one(client_p, ":%s AWAY :%s",
				   target_p->id, target_p->user->away);

		hclientinfo.target = target_p;
		call_hook(h_burst_client, &hclientinfo);
	}

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		chptr = ptr->data;

		s_assert(rb_dlink_list_length(&chptr->members) > 0);
		if(rb_dlink_list_length(&chptr->members) <= 0)
			continue;

		if(*chptr->chname != '#')
			continue;

		cur_len = mlen = rb_sprintf(buf, ":%s SJOIN %ld %s %s :", me.id,
					    (long)chptr->channelts, chptr->chname,
					    channel_modes(chptr, client_p));

		t = buf + mlen;

		RB_DLINK_FOREACH(uptr, chptr->members.head)
		{
			msptr = uptr->data;

			tlen = strlen(use_id(msptr->client_p)) + 1;
			if(is_chanop(msptr))
				tlen++;
			if(is_voiced(msptr))
				tlen++;

			if(cur_len + tlen >= BUFSIZE - 3)
			{
				*(t - 1) = '\0';
				sendto_one_buffer(client_p, buf);
				cur_len = mlen;
				t = buf + mlen;
			}

			rb_sprintf(t, "%s%s ", find_channel_status(msptr, 1),
				   use_id(msptr->client_p));

			cur_len += tlen;
			t += tlen;
		}

		/* remove trailing space */
		*(t - 1) = '\0';
		sendto_one_buffer(client_p, buf);

		if(rb_dlink_list_length(&chptr->banlist) > 0)
			burst_modes_TS6(client_p, chptr, &chptr->banlist, 'b');

		if(IsCapable(client_p, CAP_EX) && rb_dlink_list_length(&chptr->exceptlist) > 0)
			burst_modes_TS6(client_p, chptr, &chptr->exceptlist, 'e');

		if(IsCapable(client_p, CAP_IE) && rb_dlink_list_length(&chptr->invexlist) > 0)
			burst_modes_TS6(client_p, chptr, &chptr->invexlist, 'I');

		if(IsCapable(client_p, CAP_TB) && chptr->topic != NULL)
			sendto_one(client_p, ":%s TB %s %ld %s%s:%s",
				   me.id, chptr->chname, (long)chptr->topic->topic_time,
				   ConfigChannel.burst_topicwho ? chptr->topic->topic_info : "",
				   ConfigChannel.burst_topicwho ? " " : "", chptr->topic->topic);

		hchaninfo.chptr = chptr;
		call_hook(h_burst_channel, &hchaninfo);
	}

	hclientinfo.target = NULL;
	call_hook(h_burst_finished, &hclientinfo);
}

/*
 * server_estab
 *
 * inputs       - pointer to a struct Client
 * output       -
 * side effects -
 */
static int
server_estab(struct Client *client_p)
{
	struct Client *target_p;
	struct server_conf *server_p;
	hook_data_client hdata;
	const char *host;
	char note[HOSTLEN + 10];
	rb_dlink_node *ptr;

	s_assert(NULL != client_p);
	if(client_p == NULL)
		return -1;

	host = client_p->name;

	if((server_p = client_p->localClient->att_sconf) == NULL)
	{
		/* This shouldn't happen, better tell the ops... -A1kmm */
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Warning: Lost connect{} block for server %s!", host);
		ilog(L_SERVER, "Lost connect{} block for server %s", host);
		return exit_client(client_p, client_p, client_p, "Lost connect{} block!");
	}

	/* We shouldn't have to check this, it should already done before
	 * server_estab is called. -A1kmm
	 */
	if(client_p->localClient->passwd)
	{
		memset(client_p->localClient->passwd, 0, strlen(client_p->localClient->passwd));
		rb_free(client_p->localClient->passwd);
		client_p->localClient->passwd = NULL;
	}

	/* Its got identd , since its a server */
	SetGotId(client_p);

	/* If there is something in the serv_list, it might be this
	 * connecting server..
	 */
	if(!ServerInfo.hub && serv_list.head)
	{
		if(client_p != serv_list.head->data || serv_list.head->next)
		{
			ServerStats.is_ref++;
			sendto_one(client_p, "ERROR :I'm a leaf not a hub");
			return exit_client(client_p, client_p, client_p, "I'm a leaf");
		}
	}

	if(IsUnknown(client_p))
	{
		/*
		 * jdc -- 1.  Use EmptyString(), not [0] index reference.
		 *        2.  Check ->spasswd, not ->passwd.
		 */
		if(!EmptyString(server_p->spasswd))
		{
			sendto_one(client_p, "PASS %s TS %d :%s",
				   server_p->spasswd, TS_CURRENT, me.id);
		}

		/* pass info to new server */
		send_capabilities(client_p, default_server_capabs
				  | (ServerConfCompressed(server_p) && zlib_ok ? CAP_ZIP : 0)
				  | (ServerConfTb(server_p) ? CAP_TB : 0));

		sendto_one(client_p, "SERVER %s 1 :%s%s",
			   me.name,
			   ConfigServerHide.hidden ? "(H) " : "",
			   (me.info[0]) ? (me.info) : "IRCers United");
	}

	if(!rb_set_buffers(client_p->localClient->F, READBUF_SIZE))
		report_error("rb_set_buffers failed for server %s:%s",
			     client_p->name, log_client_name(client_p, SHOW_IP), errno);

	/* Buffer up the burst before trying to send anything.
	 * In any case, this saves on system calls, and for ziplinks it
	 * is required so that we only start sending it when ssld confirms
	 * it has enabled compression ('R' message on control pipe).
	 */
	SetCork(client_p);

	/* Enable compression now */
	if(IsCapable(client_p, CAP_ZIP))
	{
		start_zlib_session(client_p);
	}
	sendto_one(client_p, "SVINFO %d %d 0 :%ld", TS_CURRENT, TS_MIN,
		   (long int)rb_time());

	client_p->servptr = &me;

	if(IsAnyDead(client_p))
		return CLIENT_EXITED;

	SetServer(client_p);

	/* Update the capability combination usage counts */
	set_chcap_usage_counts(client_p);

	rb_dlinkAdd(client_p, &client_p->lnode, &me.serv->servers);
	rb_dlinkMoveNode(&client_p->localClient->tnode, &unknown_list, &serv_list);
	rb_dlinkAddTailAlloc(client_p, &global_serv_list);

	add_to_hash(HASH_ID, client_p->id, client_p);

	add_to_hash(HASH_CLIENT, client_p->name, client_p);
	/* doesnt duplicate client_p->serv if allocated this struct already */
	make_server(client_p);

	client_p->serv->caps = client_p->localClient->caps;

	if(client_p->localClient->fullcaps)
	{
		client_p->serv->fullcaps = rb_strdup(client_p->localClient->fullcaps);
		rb_free(client_p->localClient->fullcaps);
		client_p->localClient->fullcaps = NULL;
	}

	/* add it to scache */
	scache_add(client_p->name);
	client_p->localClient->firsttime = rb_time();
	/* fixing eob timings.. -gnp */

	/* Show the real host/IP to admins */
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "Link with %s established: (%s) link",
			     client_p->name, show_capabilities(client_p));

	ilog(L_SERVER, "Link with %s established: (%s) link",
	     log_client_name(client_p, SHOW_IP), show_capabilities(client_p));

	if(IsCapable(client_p, CAP_SAVE) && !IsCapable(client_p, CAP_SAVETS_100))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s SAVE protocol mismatch.  Users timestamps may be desynced after SAVE",
				     client_p->name);
		ilog(L_SERVER,
		     "Link %s SAVE protocol mismatch.  Users timestamps may be desynced after SAVE",
		     log_client_name(client_p, SHOW_IP));
	}

	hdata.client = &me;
	hdata.target = client_p;
	call_hook(h_server_introduced, &hdata);

	rb_snprintf(note, sizeof(note), "Server: %s", client_p->name);
	rb_note(client_p->localClient->F, note);

	/*
	 ** Old sendto_serv_but_one() call removed because we now
	 ** need to send different names to different servers
	 ** (domain name matching) Send new server to other servers.
	 */
	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		if(target_p == client_p)
			continue;

		sendto_one(target_p, ":%s SID %s 2 %s :%s%s",
			   me.id, client_p->name, client_p->id,
			   IsHidden(client_p) ? "(H) " : "", client_p->info);

		if(IsCapable(target_p, CAP_ENCAP) && !EmptyString(client_p->serv->fullcaps))
			sendto_one(target_p, ":%s ENCAP * GCAP :%s",
				   client_p->id, client_p->serv->fullcaps);
	}

	/*
	 ** Pass on my client information to the new server
	 **
	 ** First, pass only servers (idea is that if the link gets
	 ** cancelled beacause the server was already there,
	 ** there are no NICK's to be cancelled...). Of course,
	 ** if cancellation occurs, all this info is sent anyway,
	 ** and I guess the link dies when a read is attempted...? --msa
	 ** 
	 ** Note: Link cancellation to occur at this point means
	 ** that at least two servers from my fragment are building
	 ** up connection this other fragment at the same time, it's
	 ** a race condition, not the normal way of operation...
	 **
	 ** ALSO NOTE: using the get_client_name for server names--
	 **    see previous *WARNING*!!! (Also, original inpath
	 **    is destroyed...)
	 */
	RB_DLINK_FOREACH(ptr, global_serv_list.head)
	{
		target_p = ptr->data;

		/* target_p->from == target_p for target_p == client_p */
		if(IsMe(target_p) || target_p->from == client_p)
			continue;

		/* presumption, if target has an id, so does its uplink */
		sendto_one(client_p, ":%s SID %s %d %s :%s%s",
			   target_p->servptr->id, target_p->name,
			   target_p->hopcount + 1, target_p->id,
			   IsHidden(target_p) ? "(H) " : "", target_p->info);

		if(IsCapable(client_p, CAP_ENCAP) && !EmptyString(target_p->serv->fullcaps))
			sendto_one(client_p, ":%s ENCAP * GCAP :%s",
				   get_id(target_p, client_p), target_p->serv->fullcaps);
	}

	burst_TS6(client_p);

	/* Always send a PING after connect burst is done */
	sendto_one(client_p, "PING :%s", get_id(&me, client_p));

	ClearCork(client_p);
	send_pop_queue(client_p);
	return 0;
}
