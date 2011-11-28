/*
 *  ircd-ratbox: A slightly useful ircd.
 *  client.h: The ircd client header.
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
 *  $Id: client.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef INCLUDED_client_h
#define INCLUDED_client_h

#if !defined(CONFIG_RATBOX_LEVEL_3)
#error Incorrect config.h for this revision of ircd.
#endif

#define PASSWDLEN       128

/*
 * pre declare structs
 */
struct ConfItem;
struct Whowas;
struct DNSReply;
struct Listener;
struct Client;
struct LocalUser;

/*
 * status macros.
 */
#define STAT_CONNECTING         0x01
#define STAT_HANDSHAKE          0x02
#define STAT_ME                 0x04
#define STAT_UNKNOWN            0x08
#define STAT_REJECT		0x10
#define STAT_SERVER             0x20
#define STAT_CLIENT             0x40


#define IsRegisteredUser(x)     ((x)->status == STAT_CLIENT)
#define IsRegistered(x)         (((x)->status  > STAT_UNKNOWN) && ((x)->status != STAT_REJECT))
#define IsConnecting(x)         ((x)->status == STAT_CONNECTING)
#define IsHandshake(x)          ((x)->status == STAT_HANDSHAKE)
#define IsMe(x)                 ((x)->status == STAT_ME)
#define IsUnknown(x)            ((x)->status == STAT_UNKNOWN)
#define IsServer(x)             ((x)->status == STAT_SERVER)
#define IsClient(x)             ((x)->status == STAT_CLIENT)
#define IsReject(x)		((x)->status == STAT_REJECT)

#define IsAnyServer(x)          (IsServer(x) || IsHandshake(x) || IsConnecting(x))

#define IsOper(x)		((x)->umodes & UMODE_OPER)
#define IsAdmin(x)		((x)->umodes & UMODE_ADMIN)

#define SetReject(x)		{(x)->status = STAT_REJECT; \
				 (x)->handler = UNREGISTERED_HANDLER; }

#define SetConnecting(x)        {(x)->status = STAT_CONNECTING; \
				 (x)->handler = UNREGISTERED_HANDLER; }

#define SetHandshake(x)         {(x)->status = STAT_HANDSHAKE; \
				 (x)->handler = UNREGISTERED_HANDLER; }

#define SetMe(x)                {(x)->status = STAT_ME; \
				 (x)->handler = UNREGISTERED_HANDLER; }

#define SetUnknown(x)           {(x)->status = STAT_UNKNOWN; \
				 (x)->handler = UNREGISTERED_HANDLER; }

#define SetServer(x)            {(x)->status = STAT_SERVER; \
				 (x)->handler = SERVER_HANDLER; }

#define SetClient(x)            {(x)->status = STAT_CLIENT; \
				 (x)->handler = IsOper((x)) ? \
					OPER_HANDLER : CLIENT_HANDLER; }
#define SetRemoteClient(x)	{(x)->status = STAT_CLIENT; \
				 (x)->handler = RCLIENT_HANDLER; }

#define STAT_CLIENT_PARSE (STAT_UNKNOWN | STAT_CLIENT)
#define STAT_SERVER_PARSE (STAT_CONNECTING | STAT_HANDSHAKE | STAT_SERVER)

#define PARSE_AS_CLIENT(x)      ((x)->status & STAT_CLIENT_PARSE)
#define PARSE_AS_SERVER(x)      ((x)->status & STAT_SERVER_PARSE)


/*
 * ts stuff
 */
#define TS_CURRENT	6
#define TS_MIN          6

#define TS_DOESTS       0x10000000
#define DoesTS(x)       ((x)->tsinfo & TS_DOESTS)

#define has_id(source)	((source)->id[0] != '\0')
#define use_id(source)	((source)->id[0] != '\0' ? (source)->id : (source)->name)

/* if target is TS6, use id if it has one, else name */
#define get_id(source, target) ((IsServer(target->from) && has_id(target->from)) ? \
				use_id(source) : (source)->name)

/* housekeeping flags */

#define FLAGS_PINGSENT		0x00000001	/* Unreplied ping sent */
#define FLAGS_DEAD		0x00000002	/* Local socket is dead--Exiting soon */
#define FLAGS_KILLED		0x00000004	/* Prevents "QUIT" from being sent for this */
#define FLAGS_CLOSING		0x00000008	/* set when closing to suppress errors */
#define FLAGS_GOTID		0x00000010	/* successful ident lookup achieved */
#define FLAGS_NEEDID		0x00000020	/* I-lines say must use ident return */
#define FLAGS_NORMALEX		0x00000040	/* Client exited normally */
#define FLAGS_MARK		0x00000080	/* marked client */
#define FLAGS_HIDDEN		0x00000100	/* hidden server */
#define FLAGS_EOB		0x00000200	/* EOB */
#define FLAGS_MYCONNECT		0x00000400	/* MyConnect */
#define FLAGS_IOERROR      	0x00000800	/* IO error */
#define FLAGS_SERVICE	   	0x00001000
#define FLAGS_TGCHANGE     	0x00002000	/* we're allowed to clear something */
#define FLAGS_EXEMPTRESV	0x00004000
#define FLAGS_EXEMPTGLINE       0x00008000
#define FLAGS_EXEMPTKLINE       0x00010000
#define FLAGS_EXEMPTFLOOD       0x00020000
#define FLAGS_NOLIMIT           0x00040000
#define FLAGS_IDLE_LINED        0x00080000
#define FLAGS_CLICAP		0x00100000
#define FLAGS_PING_COOKIE       0x00200000
#define FLAGS_IP_SPOOFING       0x00400000
#define FLAGS_FLOODDONE         0x00800000
#define FLAGS_EXEMPTSPAMBOT	0x01000000
#define FLAGS_EXEMPTSHIDE	0x02000000
#define FLAGS_EXEMPTJUPE	0x04000000

/* flags for local clients, this needs stuff moved from above to here at some point */
#define LFLAGS_SSL		0x00000001
#define LFLAGS_FLUSH		0x00000002
#define LFLAGS_CORK		0x00000004
#define LFLAGS_SENTUSER		0x00000008

/* umodes, settable flags */

#define UMODE_SERVNOTICE   0x0001	/* server notices such as kill */
#define UMODE_CCONN        0x0002	/* Client Connections */
#define UMODE_REJ          0x0004	/* Bot Rejections */
#define UMODE_SKILL        0x0008	/* Server Killed */
#define UMODE_FULL         0x0010	/* Full messages */
#define UMODE_SPY          0x0020	/* see STATS / LINKS */
#define UMODE_DEBUG        0x0040	/* 'debugging' info */
#define UMODE_NCHANGE      0x0080	/* Nick change notice */
#define UMODE_WALLOP       0x0100	/* send wallops to them */
#define UMODE_OPERWALL     0x0200	/* Operwalls */
#define UMODE_INVISIBLE    0x0400	/* makes user invisible */
#define UMODE_BOTS         0x0800	/* shows bots */
#define UMODE_EXTERNAL     0x1000	/* show servers introduced and splitting */
#define UMODE_CALLERID     0x2000	/* block unless caller id's */
#define UMODE_UNAUTH       0x4000	/* show unauth connects here */
#define UMODE_LOCOPS       0x8000	/* show locops */
#define UMODE_OPERSPY	   0x10000
#define UMODE_CCONNEXT     0x20000	/* extended client connections */
#define UMODE_SERVICE      0x40000
#define UMODE_DEAF	   0x80000

/* user information flags, only settable by remote mode or local oper */
#define UMODE_OPER         0x100000	/* Operator */
#define UMODE_ADMIN        0x200000	/* Admin on server */

#define UMODE_ALL	   UMODE_SERVNOTICE

/* overflow flags */
/* EARLIER FLAGS ARE IN s_newconf.h */

#define SEND_UMODES  (UMODE_INVISIBLE | UMODE_OPER | UMODE_WALLOP | \
		      UMODE_ADMIN | UMODE_SERVICE | UMODE_DEAF)
#define DEFAULT_OPER_UMODES (UMODE_SERVNOTICE | UMODE_OPERWALL | \
			     UMODE_WALLOP | UMODE_LOCOPS)
#define ALL_UMODES   (SEND_UMODES | UMODE_SERVNOTICE | UMODE_CCONN | \
		      UMODE_REJ | UMODE_SKILL | UMODE_FULL | UMODE_SPY | \
		      UMODE_NCHANGE | UMODE_OPERWALL | UMODE_DEBUG | \
		      UMODE_BOTS | UMODE_EXTERNAL | UMODE_LOCOPS | \
		      UMODE_ADMIN | UMODE_UNAUTH | UMODE_CALLERID | \
		      UMODE_OPERSPY | UMODE_CCONNEXT | UMODE_SERVICE | \
		      UMODE_DEAF)

#define CLICAP_MULTI_PREFIX	0x0001

/*
 * flags macros.
 */
#define MyConnect(x)		((x)->flags & FLAGS_MYCONNECT)
#define SetMyConnect(x)		((x)->flags |= FLAGS_MYCONNECT)
#define ClearMyConnect(x)	((x)->flags &= ~FLAGS_MYCONNECT)

#define MyClient(x)             (MyConnect(x) && IsClient(x))
#define SetMark(x)		((x)->flags |= FLAGS_MARK)
#define ClearMark(x)		((x)->flags &= ~FLAGS_MARK)
#define IsMarked(x)		((x)->flags & FLAGS_MARK)
#define SetHidden(x)		((x)->flags |= FLAGS_HIDDEN)
#define ClearHidden(x)		((x)->flags &= ~FLAGS_HIDDEN)
#define IsHidden(x)		((x)->flags & FLAGS_HIDDEN)
#define ClearEob(x)		((x)->flags &= ~FLAGS_EOB)
#define SetEob(x)		((x)->flags |= FLAGS_EOB)
#define HasSentEob(x)		((x)->flags & FLAGS_EOB)
#define IsDead(x)          	((x)->flags &  FLAGS_DEAD)
#define SetDead(x)         	((x)->flags |= FLAGS_DEAD)
#define IsClosing(x)		((x)->flags & FLAGS_CLOSING)
#define SetClosing(x)		((x)->flags |= FLAGS_CLOSING)
#define IsIOError(x)		((x)->flags & FLAGS_IOERROR)
#define SetIOError(x)		((x)->flags |= FLAGS_IOERROR)
#define IsAnyDead(x)		(IsIOError(x) || IsDead(x) || IsClosing(x))
#define IsTGChange(x)		((x)->flags & FLAGS_TGCHANGE)
#define SetTGChange(x)		((x)->flags |= FLAGS_TGCHANGE)
#define ClearTGChange(x)	((x)->flags &= ~FLAGS_TGCHANGE)

/* local flags */

#define IsSSL(x)		((x)->localClient->localflags & LFLAGS_SSL)
#define SetSSL(x)		((x)->localClient->localflags |= LFLAGS_SSL)
#define ClearSSL(x)		((x)->localClient->localflags &= ~LFLAGS_SSL)

#define IsFlush(x)		((x)->localClient->localflags & LFLAGS_FLUSH)
#define SetFlush(x)		((x)->localClient->localflags |= LFLAGS_FLUSH)
#define ClearFlush(x)		((x)->localClient->localflags &= ~LFLAGS_FLUSH)

#define HasSentUser(x)		((x)->localClient->localflags & LFLAGS_SENTUSER)
#define SetSentUser(x)		((x)->localClient->localflags |= LFLAGS_SENTUSER)


/* oper flags */
#define MyOper(x)               (MyConnect(x) && IsOper(x))

#define SetOper(x)              {(x)->umodes |= UMODE_OPER; \
				 if (MyClient((x))) (x)->handler = OPER_HANDLER;}

#define ClearOper(x)            {(x)->umodes &= ~(UMODE_OPER|UMODE_ADMIN); \
				 if (MyClient((x)) && !IsOper((x)) && !IsServer((x))) \
				  (x)->handler = CLIENT_HANDLER; }

#define IsPrivileged(x)         (IsOper(x) || IsServer(x))

/* umode flags */
#define IsInvisible(x)          ((x)->umodes & UMODE_INVISIBLE)
#define SetInvisible(x)         ((x)->umodes |= UMODE_INVISIBLE)
#define ClearInvisible(x)       ((x)->umodes &= ~UMODE_INVISIBLE)
#define SendWallops(x)          ((x)->umodes & UMODE_WALLOP)
#define ClearWallops(x)         ((x)->umodes &= ~UMODE_WALLOP)
#define SendLocops(x)           ((x)->umodes & UMODE_LOCOPS)
#define SendServNotice(x)       ((x)->umodes & UMODE_SERVNOTICE)
#define SendOperwall(x)         ((x)->umodes & UMODE_OPERWALL)
#define SendCConnNotice(x)      ((x)->umodes & UMODE_CCONN)
#define SendRejNotice(x)        ((x)->umodes & UMODE_REJ)
#define SendSkillNotice(x)      ((x)->umodes & UMODE_SKILL)
#define SendFullNotice(x)       ((x)->umodes & UMODE_FULL)
#define SendSpyNotice(x)        ((x)->umodes & UMODE_SPY)
#define SendDebugNotice(x)      ((x)->umodes & UMODE_DEBUG)
#define SendNickChange(x)       ((x)->umodes & UMODE_NCHANGE)
#define SetWallops(x)           ((x)->umodes |= UMODE_WALLOP)
#define SetCallerId(x)		((x)->umodes |= UMODE_CALLERID)
#define IsSetCallerId(x)	((x)->umodes & UMODE_CALLERID)
#define IsService(x)		((x)->umodes & UMODE_SERVICE)
#define IsDeaf(x)		((x)->umodes & UMODE_DEAF)

#define SetNeedId(x)            ((x)->flags |= FLAGS_NEEDID)
#define IsNeedId(x)             (((x)->flags & FLAGS_NEEDID) != 0)

#define SetGotId(x)             ((x)->flags |= FLAGS_GOTID)
#define IsGotId(x)              (((x)->flags & FLAGS_GOTID) != 0)

#define IsExemptKline(x)        ((x)->flags & FLAGS_EXEMPTKLINE)
#define SetExemptKline(x)       ((x)->flags |= FLAGS_EXEMPTKLINE)
#define IsExemptLimits(x)       ((x)->flags & FLAGS_NOLIMIT)
#define SetExemptLimits(x)      ((x)->flags |= FLAGS_NOLIMIT)
#define IsExemptGline(x)        ((x)->flags & FLAGS_EXEMPTGLINE)
#define SetExemptGline(x)       ((x)->flags |= FLAGS_EXEMPTGLINE)
#define IsExemptFlood(x)        ((x)->flags & FLAGS_EXEMPTFLOOD)
#define SetExemptFlood(x)       ((x)->flags |= FLAGS_EXEMPTFLOOD)
#define IsExemptSpambot(x)	((x)->flags & FLAGS_EXEMPTSPAMBOT)
#define SetExemptSpambot(x)	((x)->flags |= FLAGS_EXEMPTSPAMBOT)
#define IsExemptShide(x)	((x)->flags & FLAGS_EXEMPTSHIDE)
#define SetExemptShide(x)	((x)->flags |= FLAGS_EXEMPTSHIDE)
#define IsExemptJupe(x)		((x)->flags & FLAGS_EXEMPTJUPE)
#define SetExemptJupe(x)	((x)->flags |= FLAGS_EXEMPTJUPE)
#define IsExemptResv(x)		((x)->flags & FLAGS_EXEMPTRESV)
#define SetExemptResv(x)	((x)->flags |= FLAGS_EXEMPTRESV)
#define IsIPSpoof(x)            ((x)->flags & FLAGS_IP_SPOOFING)
#define SetIPSpoof(x)           ((x)->flags |= FLAGS_IP_SPOOFING)

#define SetIdlelined(x)         ((x)->flags |= FLAGS_IDLE_LINED)
#define IsIdlelined(x)          ((x)->flags & FLAGS_IDLE_LINED)

#define IsFloodDone(x)          ((x)->flags & FLAGS_FLOODDONE)
#define SetFloodDone(x)         ((x)->flags |= FLAGS_FLOODDONE)


/* These also operate on the uplink from which it came */
#define IsCork(x)		(MyConnect(x) ? (x)->localClient->cork_count : (x)->from->localClient->cork_count)
#define SetCork(x)		(MyConnect(x) ? (x)->localClient->cork_count++ : (x)->from->localClient->cork_count++ )
#define ClearCork(x)		(MyConnect(x) ? (x)->localClient->cork_count-- : (x)->from->localClient->cork_count--)


/*
 * definitions for get_client_name
 */
enum
{
	HIDE_IP,
	SHOW_IP,
	MASK_IP
};


enum
{
	D_LINED,
	K_LINED,
	G_LINED
};

void check_banned_lines(void);
void check_klines_event(void *unused);
void check_klines(void);

const char *get_client_name(struct Client *client, int show_ip);
const char *log_client_name(struct Client *, int);
void init_client(void);
struct Client *make_client(struct Client *from);
void free_client(struct Client *client);

int exit_client(struct Client *, struct Client *, struct Client *, const char *);

void error_exit_client(struct Client *, int);



void count_local_client_memory(size_t *count, size_t *memory);
void count_remote_client_memory(size_t *count, size_t *memory);

struct Client *find_chasing(struct Client *, const char *, int *);
struct Client *find_person(const char *);
struct Client *find_named_person(const char *);
struct Client *next_client(struct Client *, const char *);
void notify_banned_client(struct Client *client_p, struct ConfItem *aconf, int ban);

void del_from_accept(struct Client *source, struct Client *target);

#define accept_message(s, t) ((s) == (t) || (rb_dlinkFind((s), &((t)->localClient->allow_list))))
void del_all_accepts(struct Client *client_p);

void dead_link(struct Client *client_p, int);
int show_ip(struct Client *source_p, struct Client *target_p);
int show_ip_conf(struct ConfItem *aconf, struct Client *target_p);

void free_user(struct User *, struct Client *);
struct User *make_user(struct Client *);
struct Server *make_server(struct Client *);
void close_connection(struct Client *);
void init_uid(void);
char *generate_uid(void);

void flood_endgrace(struct Client *);
void allocate_away(struct Client *);
void free_away(struct Client *);

#endif /* INCLUDED_client_h */
