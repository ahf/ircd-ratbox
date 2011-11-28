/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_join.c: Joins a channel.
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
 *  $Id: m_join.c 27325 2011-11-12 22:57:45Z jilles $
 */

#include "stdinc.h"
#include "struct.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "s_serv.h"
#include "s_conf.h"
#include "parse.h"
#include "modules.h"
#include "s_log.h"

static int m_join(struct Client *, struct Client *, int, const char **);
static int ms_join(struct Client *, struct Client *, int, const char **);
static int ms_sjoin(struct Client *, struct Client *, int, const char **);

struct Message join_msgtab = {
	"JOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_join, 2}, {ms_join, 2}, mg_ignore, mg_ignore, {m_join, 2}}
};

struct Message sjoin_msgtab = {
	"SJOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_ignore, mg_ignore, {ms_sjoin, 0}, mg_ignore, mg_ignore}
};

mapi_clist_av2 join_clist[] = { &join_msgtab, &sjoin_msgtab, NULL };

DECLARE_MODULE_AV2(join, NULL, NULL, join_clist, NULL, NULL, "$Revision: 27325 $");

static void do_join_0(struct Client *client_p, struct Client *source_p);
static int check_channel_name_loc(struct Client *source_p, const char *name);

static int can_join(struct Client *source_p, struct Channel *chptr, char *key);
static void send_join_error(struct Client *source_p, int numeric, const char *name);

static void set_final_mode(struct Client *, struct Channel *, struct Mode *, struct Mode *);
static void remove_our_modes(struct Channel *chptr);
static void remove_ban_list(struct Channel *chptr, struct Client *source_p,
			    rb_dlink_list *list, char c, int cap, int mems);

/*
 * m_join
 *      parv[1] = channel
 *      parv[2] = channel password (key)
 */
static int
m_join(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static char jbuf[BUFSIZE];
	struct Channel *chptr = NULL;
	struct ConfItem *aconf;
	char *name;
	char *key = NULL;
	int i, flags = 0;
	char *p = NULL, *p2 = NULL;
	char *chanlist;
	char *mykey;
	int successful_join_count = 0;	/* Number of channels successfully joined */

	jbuf[0] = '\0';

	/* rebuild the list of channels theyre supposed to be joining.
	 * this code has a side effect of losing keys, but..
	 */
	chanlist = LOCAL_COPY(parv[1]);
	for(name = rb_strtok_r(chanlist, ",", &p); name; name = rb_strtok_r(NULL, ",", &p))
	{
		/* check the length and name of channel is ok */
		if(!check_channel_name_loc(source_p, name) || (strlen(name) > LOC_CHANNELLEN))
		{
			sendto_one_numeric(source_p, ERR_BADCHANNAME,
					   form_str(ERR_BADCHANNAME), (unsigned char *)name);
			continue;
		}

		/* join 0 parts all channels */
		if(*name == '0' && (name[1] == ',' || name[1] == '\0') && name == chanlist)
		{
			(void)strcpy(jbuf, "0");
			continue;
		}

		/* check it begins with # or &, and local chans are disabled */
		else if(!IsChannelName(name))
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
					   form_str(ERR_NOSUCHCHANNEL), name);
			continue;
		}

		/* see if its resv'd */
		if(!IsExemptResv(source_p) && (aconf = hash_find_resv(name)))
		{
			sendto_one_numeric(source_p, ERR_BADCHANNAME,
					   form_str(ERR_BADCHANNAME), name);

			/* dont warn for opers */
			if(!IsExemptJupe(source_p) && !IsOper(source_p))
				sendto_realops_flags(UMODE_SPY, L_ALL,
						     "User %s (%s@%s) is attempting to join locally juped channel %s (%s)",
						     source_p->name, source_p->username,
						     source_p->host, name, aconf->passwd);

			/* dont update tracking for jupe exempt users, these
			 * are likely to be spamtrap leaves
			 */
			else if(IsExemptJupe(source_p))
				aconf->port--;

			continue;
		}

		if(splitmode && !IsOper(source_p) && (*name != '&') &&
		   ConfigChannel.no_join_on_split)
		{
			sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
				   me.name, source_p->name, name);
			continue;
		}

		if(*jbuf)
			(void)strcat(jbuf, ",");
		(void)rb_strlcat(jbuf, name, sizeof(jbuf));
	}

	if(parc > 2)
	{
		mykey = LOCAL_COPY(parv[2]);
		key = rb_strtok_r(mykey, ",", &p2);
	}

	for(name = rb_strtok_r(jbuf, ",", &p); name;
	    key = (key) ? rb_strtok_r(NULL, ",", &p2) : NULL, name = rb_strtok_r(NULL, ",", &p))
	{
		/* JOIN 0 simply parts all channels the user is in */
		if(*name == '0' && !atoi(name))
		{
			if(source_p->user->channel.head == NULL)
				continue;

			do_join_0(&me, source_p);
			continue;
		}

		/* look for the channel */
		if((chptr = find_channel(name)) != NULL)
		{
			if(IsMember(source_p, chptr))
				continue;

			if(rb_dlink_list_length(&chptr->members) == 0)
				flags = CHFL_CHANOP;
			else
				flags = 0;
		}
		else
		{
			if(splitmode && !IsOper(source_p) && (*name != '&') &&
			   ConfigChannel.no_create_on_split)
			{
				sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
					   me.name, source_p->name, name);
				continue;
			}

			flags = CHFL_CHANOP;
		}

		if((rb_dlink_list_length(&source_p->user->channel) >=
		    (unsigned long)ConfigChannel.max_chans_per_user) &&
		   (!IsOper(source_p) ||
		    (rb_dlink_list_length(&source_p->user->channel) >=
		     (unsigned long)ConfigChannel.max_chans_per_user * 3)))
		{
			sendto_one(source_p, form_str(ERR_TOOMANYCHANNELS),
				   me.name, source_p->name, name);
			if(successful_join_count)
				source_p->localClient->last_join_time = rb_time();
			return 0;
		}

		if(flags == 0)	/* if channel doesn't exist, don't penalize */
			successful_join_count++;

		if(chptr == NULL)	/* If I already have a chptr, no point doing this */
		{
			chptr = get_or_create_channel(source_p, name, NULL);

			if(chptr == NULL)
			{
				sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
					   me.name, source_p->name, name);
				if(successful_join_count > 0)
					successful_join_count--;
				continue;
			}
		}

		if(!IsOper(source_p) && !IsExemptSpambot(source_p))
			check_spambot_warning(source_p, name);

		/* can_join checks for +i key, bans etc */
		if((i = can_join(source_p, chptr, key)))
		{
			send_join_error(source_p, i, name);
			if(successful_join_count > 0)
				successful_join_count--;
			continue;
		}

		/* add the user to the channel */
		add_user_to_channel(chptr, source_p, flags);

		/* we send the user their join here, because we could have to
		 * send a mode out next.
		 */
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);

		/* its a new channel, set +nt and burst. */
		if(flags & CHFL_CHANOP)
		{
			chptr->channelts = rb_time();
			chptr->mode.mode |= MODE_TOPICLIMIT;
			chptr->mode.mode |= MODE_NOPRIVMSGS;

			sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s +nt",
					     me.name, chptr->chname);

			if(*chptr->chname == '#')
			{
				sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
					      ":%s SJOIN %ld %s +nt :@%s",
					      me.id, (long)chptr->channelts,
					      chptr->chname, source_p->id);
			}
		}
		else
		{
			sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
				      ":%s JOIN %ld %s +",
				      source_p->id, (long)chptr->channelts, chptr->chname);
		}

		del_invite(chptr, source_p);

		if(chptr->topic != NULL)
		{
			sendto_one(source_p, form_str(RPL_TOPIC), me.name,
				   source_p->name, chptr->chname, chptr->topic->topic);

			sendto_one(source_p, form_str(RPL_TOPICWHOTIME),
				   me.name, source_p->name, chptr->chname,
				   chptr->topic->topic_info,
				   (unsigned long)chptr->topic->topic_time);
		}

		channel_member_names(chptr, source_p, 1);

		if(successful_join_count)
			source_p->localClient->last_join_time = rb_time();
	}

	return 0;
}

/*
 * ms_join
 *
 * inputs	-
 * output	- none
 * side effects	- handles remote JOIN's sent by servers. In TSora
 *		  remote clients are joined using SJOIN, hence a 
 *		  JOIN sent by a server on behalf of a client is an error.
 *		  here, the initial code is in to take an extra parameter
 *		  and use it for the TimeStamp on a new channel.
 */
static int
ms_join(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	static struct Mode mode;
	time_t oldts;
	time_t newts;
	int isnew;
	int keep_our_modes = YES;
	int keep_new_modes = YES;

	/* special case for join 0 */
	if((parv[1][0] == '0') && (parv[1][1] == '\0') && parc == 2)
	{
		do_join_0(client_p, source_p);
		return 0;
	}

	if(parc < 4)
		return 0;

	if(!IsChannelName(parv[2]) || !check_channel_name(parv[2]))
		return 0;

	/* joins for local channels cant happen. */
	if(parv[2][0] == '&')
		return 0;

	mode.key[0] = '\0';
	mode.mode = mode.limit = 0;

	if((chptr = get_or_create_channel(source_p, parv[2], &isnew)) == NULL)
		return 0;

	newts = atol(parv[1]);
	oldts = chptr->channelts;

	/* making a channel TS0 */
	if(!isnew && !newts && oldts)
	{
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s changed from %ld to 0",
				     me.name, chptr->chname, chptr->chname, (long)oldts);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Server %s changing TS on %s from %ld to 0",
				     source_p->name, chptr->chname, (long)oldts);
	}

	if(isnew)
		chptr->channelts = newts;
	else if(newts == 0 || oldts == 0)
		chptr->channelts = 0;
	else if(newts == oldts)
		;
	else if(newts < oldts)
	{
		keep_our_modes = NO;
		chptr->channelts = newts;
	}
	else
		keep_new_modes = NO;

	/* Lost the TS, other side wins, so remove modes on this side */
	if(!keep_our_modes)
	{
		remove_our_modes(chptr);
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s changed from %ld to %ld",
				     me.name, chptr->chname, chptr->chname, (long)oldts,
				     (long)newts);
		set_final_mode(source_p->servptr, chptr, &mode, &chptr->mode);
		chptr->mode = mode;
	}

	if(!IsMember(source_p, chptr))
	{
		add_user_to_channel(chptr, source_p, CHFL_PEON);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
				     source_p->name, source_p->username,
				     source_p->host, chptr->chname);
	}

	sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
		      ":%s JOIN %ld %s +", source_p->id, (long)chptr->channelts, chptr->chname);
	return 0;
}

/*
 * ms_sjoin
 * parv[1] - TS
 * parv[2] - channel
 * parv[3] - modes + n arguments (key and/or limit)
 * parv[4+n] - flags+nick list (all in one parameter)
 * 
 * process a SJOIN, taking the TS's into account to either ignore the
 * incoming modes or undo the existing ones or merge them, and JOIN
 * all the specified users while sending JOIN/MODEs to local clients
 */
static int
ms_sjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static char modebuf[MODEBUFLEN];
	static char *mbuf;
	static char buf_uid[BUFSIZE];
	static const char *para[MAXMODEPARAMS];
	static const char empty_modes[] = "0";
	struct Channel *chptr;
	struct Client *target_p;
	time_t newts;
	time_t oldts;
	static struct Mode mode, *oldmode;
	const char *modes;
	int args = 0;
	int keep_our_modes = 1;
	int keep_new_modes = 1;
	int fl;
	int isnew;
	int mlen_uid;
	int len_uid;
	int len;
	int joins = 0;
	const char *s;
	char *ptr_uid;
	char *p;
	int i;
	static char empty[] = "";
	int pargs;

	/* I dont trust servers *not* to end up sending us a blank sjoin, so
	 * its better not to make a big deal about it. --fl
	 */
	if(parc < 5 || EmptyString(parv[4]))
		return 0;

	if(!IsChannelName(parv[2]) || !check_channel_name(parv[2]))
		return 0;

	/* SJOIN's for local channels can't happen. */
	if(*parv[2] == '&')
		return 0;

	mode.key[0] = '\0';
	mode.mode = mode.limit = 0;

	newts = atol(parv[1]);

	s = parv[3];
	while(*s)
	{
		switch (*(s++))
		{
		case 'i':
			mode.mode |= MODE_INVITEONLY;
			break;
		case 'n':
			mode.mode |= MODE_NOPRIVMSGS;
			break;
		case 'p':
			mode.mode |= MODE_PRIVATE;
			break;
		case 's':
			mode.mode |= MODE_SECRET;
			break;
		case 'm':
			mode.mode |= MODE_MODERATED;
			break;
		case 't':
			mode.mode |= MODE_TOPICLIMIT;
			break;
#ifdef ENABLE_SERVICES
		case 'r':
			mode.mode |= MODE_REGONLY;
			break;
#endif
		case 'S':
			mode.mode |= MODE_SSLONLY;
			break;
		case 'k':
			rb_strlcpy(mode.key, parv[4 + args], sizeof(mode.key));
			args++;
			if(parc < 5 + args)
				return 0;
			break;
		case 'l':
			mode.limit = atoi(parv[4 + args]);
			args++;
			if(parc < 5 + args)
				return 0;
			break;
		}
	}

	s = parv[args + 4];

	/* remove any leading spaces */
	while(*s == ' ')
		s++;

	if(EmptyString(s))
		return 0;

	if((chptr = get_or_create_channel(source_p, parv[2], &isnew)) == NULL)
		return 0;	/* channel name too long? */


	oldts = chptr->channelts;
	oldmode = &chptr->mode;

	if(!isnew && !newts && oldts)
	{
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s "
				     "changed from %ld to 0",
				     me.name, chptr->chname, chptr->chname, (long)oldts);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Server %s changing TS on %s from %ld to 0",
				     source_p->name, chptr->chname, (long)oldts);
	}

	if(isnew)
		chptr->channelts = newts;
	else if(newts == 0 || oldts == 0)
		chptr->channelts = 0;
	else if(newts == oldts)
		;
	else if(newts < oldts)
	{
		keep_our_modes = NO;
		chptr->channelts = newts;
	}
	else
		keep_new_modes = NO;

	if(!keep_new_modes)
		mode = *oldmode;
	else if(keep_our_modes)
	{
		mode.mode |= oldmode->mode;
		if(oldmode->limit > mode.limit)
			mode.limit = oldmode->limit;
		if(strcmp(mode.key, oldmode->key) < 0)
			strcpy(mode.key, oldmode->key);
	}

	/* Lost the TS, other side wins, so remove modes on this side */
	if(!keep_our_modes)
	{
		remove_our_modes(chptr);
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s changed from %ld to %ld",
				     me.name, chptr->chname, chptr->chname,
				     (long)oldts, (long)newts);
	}

	set_final_mode(source_p, chptr, &mode, oldmode);
	chptr->mode = mode;

	*modebuf = '\0';

	if(parv[3][0] != '0' && keep_new_modes)
		modes = channel_modes(chptr, source_p);
	else
		modes = empty_modes;

	mlen_uid = rb_sprintf(buf_uid, ":%s SJOIN %ld %s %s :",
			      source_p->id, (long)chptr->channelts, parv[2], modes);
	ptr_uid = buf_uid + mlen_uid;

	mbuf = modebuf;
	para[0] = para[1] = para[2] = para[3] = empty;
	pargs = 0;
	len_uid = 0;

	*mbuf++ = '+';

	/* if theres a space, theres going to be more than one nick, change the
	 * first space to \0, so s is just the first nick, and point p to the
	 * second nick
	 */
	if((p = strchr(s, ' ')) != NULL)
	{
		*p++ = '\0';
	}

	while(s)
	{
		fl = 0;

		for(i = 0; i < 2; i++)
		{
			if(*s == '@')
			{
				fl |= CHFL_CHANOP;
				s++;
			}
			else if(*s == '+')
			{
				fl |= CHFL_VOICE;
				s++;
			}
		}

		/* if the client doesnt exist or is fake direction, skip. */
		if(!(target_p = find_client(s)) ||
		   (target_p->from != client_p) || !IsClient(target_p))
			goto nextnick;

		/* we assume for these we can fit at least one nick/uid in.. */

		/* check we can fit another status+nick+space into a buffer */

		if((mlen_uid + len_uid + IDLEN + 3) > (BUFSIZE - 3))
		{
			*(ptr_uid - 1) = '\0';
			sendto_server(client_p->from, NULL, CAP_TS6, NOCAPS, "%s", buf_uid);
			ptr_uid = buf_uid + mlen_uid;
			len_uid = 0;
		}

		if(keep_new_modes)
		{
			if(fl & CHFL_CHANOP)
			{
				*ptr_uid++ = '@';
				len_uid++;
			}
			if(fl & CHFL_VOICE)
			{
				*ptr_uid++ = '+';
				len_uid++;
			}
		}

		len = rb_sprintf(ptr_uid, "%s ", target_p->id);
		ptr_uid += len;
		len_uid += len;

		if(!keep_new_modes)
		{
			if(fl & CHFL_CHANOP)
				fl = CHFL_DEOPPED;
			else
				fl = 0;
		}

		if(!IsMember(target_p, chptr))
		{
			add_user_to_channel(chptr, target_p, fl);
			sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
					     target_p->name,
					     target_p->username, target_p->host, parv[2]);
			joins++;
		}

		if(fl & CHFL_CHANOP)
		{
			*mbuf++ = 'o';
			para[pargs++] = target_p->name;

			/* a +ov user.. bleh */
			if(fl & CHFL_VOICE)
			{
				/* its possible the +o has filled up MAXMODEPARAMS, if so, start
				 * a new buffer
				 */
				if(pargs >= MAXMODEPARAMS)
				{
					*mbuf = '\0';
					sendto_channel_local(ALL_MEMBERS, chptr,
							     ":%s MODE %s %s %s %s %s %s",
							     source_p->name, chptr->chname,
							     modebuf,
							     para[0], para[1], para[2], para[3]);
					mbuf = modebuf;
					*mbuf++ = '+';
					para[0] = para[1] = para[2] = para[3] = NULL;
					pargs = 0;
				}

				*mbuf++ = 'v';
				para[pargs++] = target_p->name;
			}
		}
		else if(fl & CHFL_VOICE)
		{
			*mbuf++ = 'v';
			para[pargs++] = target_p->name;
		}

		if(pargs >= MAXMODEPARAMS)
		{
			*mbuf = '\0';
			sendto_channel_local(ALL_MEMBERS, chptr,
					     ":%s MODE %s %s %s %s %s %s",
					     source_p->name,
					     chptr->chname,
					     modebuf, para[0], para[1], para[2], para[3]);
			mbuf = modebuf;
			*mbuf++ = '+';
			para[0] = para[1] = para[2] = para[3] = NULL;
			pargs = 0;
		}

	      nextnick:
		/* p points to the next nick */
		s = p;

		/* if there was a trailing space and p was pointing to it, then we
		 * need to exit.. this has the side effect of breaking double spaces
		 * in an sjoin.. but that shouldnt happen anyway
		 */
		if(s && (*s == '\0'))
			s = p = NULL;

		/* if p was NULL due to no spaces, s wont exist due to the above, so
		 * we cant check it for spaces.. if there are no spaces, then when
		 * we next get here, s will be NULL
		 */
		if(s && ((p = strchr(s, ' ')) != NULL))
		{
			*p++ = '\0';
		}
	}

	*mbuf = '\0';
	if(pargs)
	{
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s MODE %s %s %s %s %s %s",
				     source_p->name, chptr->chname, modebuf,
				     para[0], CheckEmpty(para[1]), CheckEmpty(para[2]),
				     CheckEmpty(para[3]));
	}

	if(!joins)
	{
		if(isnew)
			destroy_channel(chptr);

		return 0;
	}

	*(ptr_uid - 1) = '\0';

	sendto_server(client_p->from, NULL, CAP_TS6, NOCAPS, "%s", buf_uid);

	/* if the source does TS6 we have to remove our bans.  Its now safe
	 * to issue -b's to the non-ts6 servers, as the sjoin we've just
	 * sent will kill any ops they have.
	 */
	if(!keep_our_modes && source_p->id[0] != '\0')
	{
		if(rb_dlink_list_length(&chptr->banlist) > 0)
			remove_ban_list(chptr, source_p, &chptr->banlist, 'b', NOCAPS, ALL_MEMBERS);

		if(rb_dlink_list_length(&chptr->exceptlist) > 0)
			remove_ban_list(chptr, source_p, &chptr->exceptlist,
					'e', CAP_EX, ONLY_CHANOPS);

		if(rb_dlink_list_length(&chptr->invexlist) > 0)
			remove_ban_list(chptr, source_p, &chptr->invexlist,
					'I', CAP_IE, ONLY_CHANOPS);

		chptr->ban_serial++;
	}


	return 0;
}


/*
 * do_join_0
 *
 * inputs	- pointer to client doing join 0
 * output	- NONE
 * side effects	- Use has decided to join 0. This is legacy
 *		  from the days when channels were numbers not names. *sigh*
 *		  There is a bunch of evilness necessary here due to
 * 		  anti spambot code.
 */
static void
do_join_0(struct Client *client_p, struct Client *source_p)
{
	struct membership *msptr;
	struct Channel *chptr = NULL;
	rb_dlink_node *ptr;

	/* Finish the flood grace period... */
	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);


	sendto_server(client_p, NULL, CAP_TS6, NOCAPS, ":%s JOIN 0", source_p->id);

	if(source_p->user->channel.head && MyConnect(source_p) &&
	   !IsOper(source_p) && !IsExemptSpambot(source_p))
		check_spambot_warning(source_p, NULL);

	while((ptr = source_p->user->channel.head))
	{
		msptr = ptr->data;
		chptr = msptr->chptr;
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s PART %s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);
		remove_user_from_channel(msptr);
	}
}

static int
check_channel_name_loc(struct Client *source_p, const char *name)
{
	const char *p;

	s_assert(name != NULL);
	if(EmptyString(name))
		return 0;

	if(ConfigFileEntry.disable_fake_channels && !IsOper(source_p))
	{
		for(p = name; *p; ++p)
		{
			if(!IsChanChar(*p) || IsFakeChanChar(*p))
				return 0;
		}
	}
	else
	{
		for(p = name; *p; ++p)
		{
			if(!IsChanChar(*p))
				return 0;
		}
	}

	if(ConfigChannel.only_ascii_channels)
	{
		for(p = name; *p; ++p)
			if(*p < 33 || *p > 126)
				return 0;
	}

	return 1;
}

/* can_join()
 *
 * input	- client to check, channel to check for, key
 * output	- reason for not being able to join, else 0
 * side effects -
 */
static int
can_join(struct Client *source_p, struct Channel *chptr, char *key)
{
	rb_dlink_node *lp;
	rb_dlink_node *ptr;
	struct Ban *invex = NULL;
	char src_host[NICKLEN + USERLEN + HOSTLEN + 6];
	char src_iphost[NICKLEN + USERLEN + HOSTLEN + 6];

	s_assert(source_p->localClient != NULL);

	rb_sprintf(src_host, "%s!%s@%s", source_p->name, source_p->username, source_p->host);
	rb_sprintf(src_iphost, "%s!%s@%s", source_p->name, source_p->username, source_p->sockhost);

	if((is_banned(chptr, source_p, NULL, src_host, src_iphost)) == CHFL_BAN)
		return (ERR_BANNEDFROMCHAN);

	if(chptr->mode.mode & MODE_INVITEONLY)
	{
		RB_DLINK_FOREACH(lp, source_p->localClient->invited.head)
		{
			if(lp->data == chptr)
				break;
		}
		if(lp == NULL)
		{
			if(!ConfigChannel.use_invex)
				return (ERR_INVITEONLYCHAN);
			RB_DLINK_FOREACH(ptr, chptr->invexlist.head)
			{
				invex = ptr->data;
				if(match(invex->banstr, src_host)
				   || match(invex->banstr, src_iphost)
				   || match_cidr(invex->banstr, src_iphost))
					break;
			}
			if(ptr == NULL)
				return (ERR_INVITEONLYCHAN);
		}
	}

	if(*chptr->mode.key && (EmptyString(key) || irccmp(chptr->mode.key, key)))
		return (ERR_BADCHANNELKEY);

	if(chptr->mode.limit &&
	   rb_dlink_list_length(&chptr->members) >= (unsigned long)chptr->mode.limit)
		return (ERR_CHANNELISFULL);

#ifdef ENABLE_SERVICES
	if(chptr->mode.mode & MODE_REGONLY && EmptyString(source_p->user->suser))
		return ERR_NEEDREGGEDNICK;
#endif

	if(ConfigChannel.use_sslonly && chptr->mode.mode & MODE_SSLONLY && !IsSSL(source_p))
		return ERR_SSLONLYCHAN;

	return 0;
}

/* send_join_error()
 *
 * input	- client to send to, reason, channel name
 * output	- none
 * side effects - error message sent to client
 */
static void
send_join_error(struct Client *source_p, int numeric, const char *name)
{
	/* This stuff is necessary because the form_str macro only
	 * accepts constants.
	 */
	switch (numeric)
	{
#define NORMAL_NUMERIC(i)						\
		case i:							\
			sendto_one(source_p, form_str(i),		\
					me.name, source_p->name, name);	\
			break

		NORMAL_NUMERIC(ERR_BANNEDFROMCHAN);
		NORMAL_NUMERIC(ERR_INVITEONLYCHAN);
		NORMAL_NUMERIC(ERR_BADCHANNELKEY);
		NORMAL_NUMERIC(ERR_CHANNELISFULL);
		NORMAL_NUMERIC(ERR_SSLONLYCHAN);
#ifdef ENABLE_SERVICES
		NORMAL_NUMERIC(ERR_NEEDREGGEDNICK);
#endif

		default:
			sendto_one_numeric(source_p, numeric,
					"%s :Cannot join channel", name);
			break;
	}
}

static struct mode_letter
{
	int mode;
	char letter;
} flags[] =
{
	{
	MODE_NOPRIVMSGS, 'n'},
	{
	MODE_TOPICLIMIT, 't'},
	{
	MODE_SECRET, 's'},
	{
	MODE_MODERATED, 'm'},
	{
	MODE_INVITEONLY, 'i'},
	{
	MODE_PRIVATE, 'p'},
#ifdef ENABLE_SERVICES
	{
	MODE_REGONLY, 'r'},
#endif
	{
	MODE_SSLONLY, 'S'},
	{
	0, 0}
};

static void
set_final_mode(struct Client *source_p, struct Channel *chptr,
	       struct Mode *mode, struct Mode *oldmode)
{
	static char lmodebuf[MODEBUFLEN];
	static char lparabuf[MODEBUFLEN];
	int dir = MODE_QUERY;
	char *mbuf = lmodebuf;
	char *pbuf = lparabuf;
	int i;

	lparabuf[0] = '\0';

	/* ok, first get a list of modes we need to add */
	for(i = 0; flags[i].letter; i++)
	{
		if((mode->mode & flags[i].mode) && !(oldmode->mode & flags[i].mode))
		{
			if(dir != MODE_ADD)
			{
				*mbuf++ = '+';
				dir = MODE_ADD;
			}
			*mbuf++ = flags[i].letter;
		}
	}

	/* now the ones we need to remove. */
	for(i = 0; flags[i].letter; i++)
	{
		if((oldmode->mode & flags[i].mode) && !(mode->mode & flags[i].mode))
		{
			if(dir != MODE_DEL)
			{
				*mbuf++ = '-';
				dir = MODE_DEL;
			}
			*mbuf++ = flags[i].letter;
		}
	}

	if(oldmode->limit && !mode->limit)
	{
		if(dir != MODE_DEL)
		{
			*mbuf++ = '-';
			dir = MODE_DEL;
		}
		*mbuf++ = 'l';
	}
	if(oldmode->key[0] && !mode->key[0])
	{
		if(dir != MODE_DEL)
		{
			*mbuf++ = '-';
			dir = MODE_DEL;
		}
		*mbuf++ = 'k';
		pbuf += rb_sprintf(pbuf, "%s ", oldmode->key);
	}
	if(mode->limit && oldmode->limit != mode->limit)
	{
		if(dir != MODE_ADD)
		{
			*mbuf++ = '+';
			dir = MODE_ADD;
		}
		*mbuf++ = 'l';
		pbuf += rb_sprintf(pbuf, "%d ", mode->limit);
	}
	if(mode->key[0] && strcmp(oldmode->key, mode->key))
	{
		if(dir != MODE_ADD)
		{
			*mbuf++ = '+';
			dir = MODE_ADD;
		}
		*mbuf++ = 'k';
		pbuf += rb_sprintf(pbuf, "%s ", mode->key);
	}

	*mbuf = '\0';

	if(!EmptyString(lmodebuf))
	{
		/* arguments, cut trailing space */
		if(!EmptyString(lparabuf))
		{
			*(pbuf - 1) = '\0';
			sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s %s %s",
					     source_p->name, chptr->chname, lmodebuf, lparabuf);
		}
		else
			sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s %s",
					     source_p->name, chptr->chname, lmodebuf);
	}
}

/*
 * remove_our_modes
 *
 * inputs	-
 * output	- 
 * side effects	- 
 */
static void
remove_our_modes(struct Channel *chptr)
{
	struct membership *msptr;
	rb_dlink_node *ptr;
	char lmodebuf[MODEBUFLEN];
	const char *lpara[MAXMODEPARAMS];
	char *mbuf;
	int count = 0;
	int i;

	mbuf = lmodebuf;
	*mbuf++ = '-';

	for(i = 0; i < MAXMODEPARAMS; i++)
		lpara[i] = NULL;

	RB_DLINK_FOREACH(ptr, chptr->members.head)
	{
		msptr = ptr->data;

		if(is_chanop(msptr))
		{
			msptr->flags &= ~CHFL_CHANOP;
			lpara[count++] = msptr->client_p->name;
			*mbuf++ = 'o';

			/* +ov, might not fit so check. */
			if(is_voiced(msptr))
			{
				if(count >= MAXMODEPARAMS)
				{
					*mbuf = '\0';
					sendto_channel_local(ALL_MEMBERS, chptr,
							     ":%s MODE %s %s %s %s %s %s",
							     me.name, chptr->chname,
							     lmodebuf, lpara[0], lpara[1],
							     lpara[2], lpara[3]);

					/* preserve the initial '-' */
					mbuf = lmodebuf;
					*mbuf++ = '-';
					count = 0;

					for(i = 0; i < MAXMODEPARAMS; i++)
						lpara[i] = NULL;
				}

				msptr->flags &= ~CHFL_VOICE;
				lpara[count++] = msptr->client_p->name;
				*mbuf++ = 'v';
			}
		}
		else if(is_voiced(msptr))
		{
			msptr->flags &= ~CHFL_VOICE;
			lpara[count++] = msptr->client_p->name;
			*mbuf++ = 'v';
		}
		else
			continue;

		if(count >= MAXMODEPARAMS)
		{
			*mbuf = '\0';
			sendto_channel_local(ALL_MEMBERS, chptr,
					     ":%s MODE %s %s %s %s %s %s",
					     me.name, chptr->chname, lmodebuf,
					     lpara[0], lpara[1], lpara[2], lpara[3]);
			mbuf = lmodebuf;
			*mbuf++ = '-';
			count = 0;

			for(i = 0; i < MAXMODEPARAMS; i++)
				lpara[i] = NULL;
		}
	}

	if(count != 0)
	{
		*mbuf = '\0';
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s MODE %s %s %s %s %s %s",
				     me.name, chptr->chname, lmodebuf,
				     EmptyString(lpara[0]) ? "" : lpara[0],
				     EmptyString(lpara[1]) ? "" : lpara[1],
				     EmptyString(lpara[2]) ? "" : lpara[2],
				     EmptyString(lpara[3]) ? "" : lpara[3]);

	}
}

/* remove_ban_list()
 *
 * inputs	- channel, source, list to remove, char of mode, caps needed
 * outputs	-
 * side effects - given list is removed, with modes issued to local clients
 * 		  and non-TS6 servers.
 */
static void
remove_ban_list(struct Channel *chptr, struct Client *source_p,
		rb_dlink_list *list, char c, int cap, int mems)
{
	static char lmodebuf[BUFSIZE];
	static char lparabuf[BUFSIZE];
	struct Ban *banptr;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	char *mbuf, *pbuf;
	int count = 0;
	int cur_len, mlen, plen;

	pbuf = lparabuf;

	cur_len = mlen = rb_sprintf(lmodebuf, ":%s MODE %s -", source_p->name, chptr->chname);
	mbuf = lmodebuf + mlen;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list->head)
	{
		banptr = ptr->data;

		/* trailing space, and the mode letter itself */
		plen = strlen(banptr->banstr) + 2;

		if(count >= MAXMODEPARAMS || (cur_len + plen) > BUFSIZE - 4)
		{
			/* remove trailing space */
			*mbuf = '\0';
			*(pbuf - 1) = '\0';

			sendto_channel_local(mems, chptr, "%s %s", lmodebuf, lparabuf);

			cur_len = mlen;
			mbuf = lmodebuf + mlen;
			pbuf = lparabuf;
			count = 0;
		}

		*mbuf++ = c;
		cur_len += plen;
		pbuf += rb_sprintf(pbuf, "%s ", banptr->banstr);
		count++;

		free_ban(banptr);
	}

	*mbuf = '\0';
	*(pbuf - 1) = '\0';
	sendto_channel_local(mems, chptr, "%s %s", lmodebuf, lparabuf);

	list->head = list->tail = NULL;
	list->length = 0;
}
