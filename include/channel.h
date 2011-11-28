/*
 *  ircd-ratbox: A slightly useful ircd.
 *  channel.h: The ircd channel header.
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
 *  $Id: channel.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef INCLUDED_channel_h
#define INCLUDED_channel_h

#define MODEBUFLEN      200

/* Maximum mode changes allowed per client, per server is different */
#define MAXMODEPARAMS   4
#define MAXMODEPARAMSSERV 10

extern struct ev_entry *checksplit_ev;
struct Client;

/* mode structure for channels */
struct Mode
{
	unsigned int mode;
	int limit;
	char key[KEYLEN];
};

struct topic_info
{
	char *topic;
	char topic_info[USERHOST_REPLYLEN];
	time_t topic_time;
};

/* channel structure */
struct Channel
{
	rb_dlink_node node;
	struct Mode mode;
	struct topic_info *topic;
	time_t last_knock;	/* don't allow knock to flood */

	rb_dlink_list members;	/* channel members */
	rb_dlink_list locmembers;	/* local channel members */

	rb_dlink_list invites;
	rb_dlink_list banlist;
	rb_dlink_list exceptlist;
	rb_dlink_list invexlist;

	time_t first_received_message_time;	/* channel flood control */
	int received_number_of_privmsgs;
	int flood_noticed;

	uint32_t ban_serial;
	time_t channelts;
	char *chname;
};

struct membership
{
	rb_dlink_node channode;
	rb_dlink_node locchannode;
	rb_dlink_node usernode;

	struct Channel *chptr;
	struct Client *client_p;
	uint8_t flags;

	uint32_t ban_serial;
};

#define BANLEN NICKLEN+USERLEN+HOSTLEN+6
struct Ban
{
	char *banstr;
	char *who;
	time_t when;
	rb_dlink_node node;
};

struct ChModeChange
{
	char letter;
	const char *arg;
	const char *id;
	int dir;
	int caps;
	int nocaps;
	int mems;
	struct Client *client;
};

struct ChCapCombo
{
	int count;
	int cap_yes;
	int cap_no;
};

/* can_send results */
#define CAN_SEND_NO	0
#define CAN_SEND_NONOP  1
#define CAN_SEND_OPV	2

/* channel status flags */
#define CHFL_PEON		0x0000	/* normal member of channel */
#define CHFL_CHANOP     	0x0001	/* Channel operator */
#define CHFL_VOICE      	0x0002	/* the power to speak */
#define CHFL_DEOPPED    	0x0004	/* deopped on sjoin, bounce modes */
#define CHFL_BANNED		0x0008	/* cached as banned */
#define ONLY_SERVERS		0x0010
#define ALL_MEMBERS		CHFL_PEON
#define ONLY_CHANOPS		CHFL_CHANOP
#define ONLY_CHANOPSVOICED	(CHFL_CHANOP|CHFL_VOICE)

#define is_chanop(x)	((x) && (x)->flags & CHFL_CHANOP)
#define is_voiced(x)	((x) && (x)->flags & CHFL_VOICE)
#define is_chanop_voiced(x) ((x) && (x)->flags & (CHFL_CHANOP|CHFL_VOICE))
#define is_deop(x)	((x) && (x)->flags & CHFL_DEOPPED)
#define can_send_banned(x) ((x) && (x)->flags & CHFL_BANNED)

/* channel modes ONLY */
#define MODE_PRIVATE    0x0001
#define MODE_SECRET     0x0002
#define MODE_MODERATED  0x0004
#define MODE_TOPICLIMIT 0x0008
#define MODE_INVITEONLY 0x0010
#define MODE_NOPRIVMSGS 0x0020
#define MODE_REGONLY	0x0040
#define MODE_SSLONLY	0x0080
#define CHFL_BAN        0x0100	/* ban channel flag */
#define CHFL_EXCEPTION  0x0200	/* exception to ban channel flag */
#define CHFL_INVEX      0x0400

/* mode flags for direction indication */
#define MODE_QUERY     0
#define MODE_ADD       1
#define MODE_DEL       -1

#define SecretChannel(x)        ((x) && ((x)->mode.mode & MODE_SECRET))
#define HiddenChannel(x)        ((x) && ((x)->mode.mode & MODE_PRIVATE))
#define PubChannel(x)           ((!x) || ((x)->mode.mode &\
				 (MODE_PRIVATE | MODE_SECRET)) == 0)

/* channel visible */
#define ShowChannel(v,c)        (PubChannel(c) || IsMember((v),(c)))

#define IsMember(who, chan) ((who && who->user && \
		find_channel_membership(chan, who)) ? 1 : 0)

#define IsChannelName(name) ((name) && (*(name) == '#' || *(name) == '&'))

extern rb_dlink_list global_channel_list;
void init_channels(void);

struct Channel *allocate_channel(const char *chname);
void free_channel(struct Channel *chptr);
struct Ban *allocate_ban(const char *, const char *);
void free_ban(struct Ban *bptr);


void destroy_channel(struct Channel *);

int can_send(struct Channel *chptr, struct Client *who, struct membership *);
int is_banned(struct Channel *chptr, struct Client *who,
	      struct membership *msptr, const char *, const char *);

struct membership *find_channel_membership(struct Channel *, struct Client *);
const char *find_channel_status(struct membership *msptr, int combine);
void add_user_to_channel(struct Channel *, struct Client *, int flags);
void remove_user_from_channel(struct membership *);
void remove_user_from_channels(struct Client *);
void invalidate_bancache_user(struct Client *);

void free_channel_list(rb_dlink_list *);

int check_channel_name(const char *name);

void channel_member_names(struct Channel *chptr, struct Client *, int show_eon);

void del_invite(struct Channel *chptr, struct Client *who);

const char *channel_modes(struct Channel *chptr, struct Client *who);

void check_spambot_warning(struct Client *source_p, const char *name);

void check_splitmode(void *);

void set_channel_topic(struct Channel *chptr, const char *topic,
		       const char *topic_info, time_t topicts);

void init_chcap_usage_counts(void);
void set_chcap_usage_counts(struct Client *serv_p);
void unset_chcap_usage_counts(struct Client *serv_p);
void send_cap_mode_changes(struct Client *client_p, struct Client *source_p,
			   struct Channel *chptr, struct ChModeChange foo[], int);


#endif /* INCLUDED_channel_h */
