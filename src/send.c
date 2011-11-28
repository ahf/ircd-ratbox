/*
 *  ircd-ratbox: A slightly useful ircd.
 *  send.c: Functions for sending messages.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2004 ircd-ratbox development team
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
 *  $Id: send.c 26576 2009-05-28 15:26:34Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "send.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "hook.h"
#include "monitor.h"

#define LOG_BUFSIZE 2048

uint32_t current_serial = 0L;
static void send_queued_write(rb_fde_t *F, void *data);
static void send_queued(struct Client *to);


/* send_linebuf()
 *
 * inputs	- client to send to, linebuf to attach
 * outputs	-
 * side effects - linebuf is attached to client
 */
static int
send_linebuf(struct Client *to, buf_head_t * linebuf)
{
	if(IsMe(to))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send message to myself!");
		return 0;
	}

	if(!MyConnect(to) || IsIOError(to))
		return 0;

	if(rb_linebuf_len(&to->localClient->buf_sendq) > get_sendq(to))
	{
		if(IsServer(to))
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Max SendQ limit exceeded for %s: %u > %lu",
					     to->name,
					     rb_linebuf_len(&to->localClient->buf_sendq),
					     get_sendq(to));

			ilog(L_SERVER, "Max SendQ limit exceeded for %s: %u > %lu",
			     log_client_name(to, SHOW_IP),
			     rb_linebuf_len(&to->localClient->buf_sendq), get_sendq(to));
		}

		dead_link(to, 1);
		return -1;
	}
	else
	{
		/* just attach the linebuf to the sendq instead of
		 * generating a new one
		 */
		rb_linebuf_attach(&to->localClient->buf_sendq, linebuf);
	}

	/*
	 ** Update statistics. The following is slightly incorrect
	 ** because it counts messages even if queued, but bytes
	 ** only really sent. Queued bytes get updated in SendQueued.
	 */
	to->localClient->sendM += 1;
	me.localClient->sendM += 1;

	if(rb_linebuf_len(&to->localClient->buf_sendq) > 0)
		send_queued(to);
	return 0;
}

void
send_pop_queue(struct Client *to)
{
	if(to->from != NULL)
		to = to->from;
	if(!MyConnect(to) || IsIOError(to))
		return;
	if(rb_linebuf_len(&to->localClient->buf_sendq) > 0)
		send_queued(to);
}

/* send_rb_linebuf_remote()
 *
 * inputs	- client to attach to, sender, linebuf
 * outputs	-
 * side effects - client has linebuf attached
 */
static void
send_rb_linebuf_remote(struct Client *to, struct Client *from, buf_head_t * linebuf)
{
	if(to->from)
		to = to->from;

	/* test for fake direction */
	if(!MyClient(from) && IsClient(to) && (to == from->from))
	{
		if(IsServer(from))
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Send message to %s[%s] dropped from %s(Fake Dir)",
					     to->name, to->from->name, from->name);
			return;
		}

		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Ghosted: %s[%s@%s] from %s[%s@%s] (%s)",
				     to->name, to->username, to->host,
				     from->name, from->username, from->host, to->from->name);
		kill_client_serv_butone(NULL, to, "%s (%s[%s@%s] Ghosted %s)",
					me.name, to->name, to->username, to->host, to->from->name);

		to->flags |= FLAGS_KILLED;

		exit_client(NULL, to, &me, "Ghosted client");
		return;
	}

	send_linebuf(to, linebuf);
	return;
}

static void
send_queued(struct Client *to)
{
	int retlen;
#ifdef USE_IODEBUG_HOOKS
	hook_data_int hd;
#endif
	/* cant write anything to a dead socket. */
	if(IsIOError(to))
		return;

	/* Something wants us to not send anything currently */
	if(IsCork(to))
		return;

	/* try to flush later when the write event resets this */
	if(IsFlush(to))
		return;

#ifdef USE_IODEBUG_HOOKS
	hd.client = to;
	if(to->localClient->buf_sendq.list.head)
		hd.arg1 = ((buf_line_t *) to->localClient->buf_sendq.list.head->data)->buf +
			to->localClient->buf_sendq.writeofs;
#endif

	if(rb_linebuf_len(&to->localClient->buf_sendq))
	{
		while((retlen =
		       rb_linebuf_flush(to->localClient->F, &to->localClient->buf_sendq)) > 0)
		{
			/* We have some data written .. update counters */
#ifdef USE_IODEBUG_HOOKS
			hd.arg2 = retlen;
			call_hook(h_iosend_id, &hd);

			if(to->localClient->buf_sendq.list.head)
				hd.arg1 =
					((buf_line_t *) to->localClient->buf_sendq.list.
					 head->data)->buf + to->localClient->buf_sendq.writeofs;
#endif

			ClearFlush(to);

			to->localClient->sendB += retlen;
			me.localClient->sendB += retlen;
		}

		if(retlen == 0 || (retlen < 0 && !rb_ignore_errno(errno)))
		{
			dead_link(to, 0);
			return;
		}
	}
	if(rb_linebuf_len(&to->localClient->buf_sendq))
	{
		SetFlush(to);
		rb_setselect(to->localClient->F, RB_SELECT_WRITE, send_queued_write, to);
	}
	else
		ClearFlush(to);

}

/* send_queued_write()
 *
 * inputs	- fd to have queue sent, client we're sending to
 * outputs	- contents of queue
 * side effects - write is scheduled if queue isnt emptied
 */
static void
send_queued_write(rb_fde_t *F, void *data)
{
	struct Client *to = data;
	ClearFlush(to);
	send_queued(to);
}

/* sendto_one_buffer()
 *
 * inputs	- client to send to, buffer
 * outputs	- client has message put into its queue
 */
void
sendto_one_buffer(struct Client *target_p, const char *buffer)
{
	buf_head_t linebuf;

	if(target_p->from != NULL)
		target_p = target_p->from;

	if(IsIOError(target_p))
		return;

	rb_linebuf_newbuf(&linebuf);
	rb_linebuf_putbuf(&linebuf, buffer);
	send_linebuf(target_p, &linebuf);
	rb_linebuf_donebuf(&linebuf);
}

/* sendto_one()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has message put into its queue
 * side effects - 
 */
void
sendto_one(struct Client *target_p, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		target_p = target_p->from;

	if(IsIOError(target_p))
		return;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	send_linebuf(target_p, &linebuf);

	rb_linebuf_donebuf(&linebuf);

}


/* sendto_one_prefix()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has message put into its queue
 * side effects - source(us)/target is chosen based on TS6 capability
 */
void
sendto_one_prefix(struct Client *target_p, struct Client *source_p,
		  const char *command, const char *pattern, ...)
{
	struct Client *dest_p;
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		dest_p = target_p->from;
	else
		dest_p = target_p;

	if(IsIOError(dest_p))
		return;

	if(IsMe(dest_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send to myself!");
		return;
	}

	rb_linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args,
			  ":%s %s %s ",
			  get_id(source_p, target_p), command, get_id(target_p, target_p));
	va_end(args);

	send_linebuf(dest_p, &linebuf);
	rb_linebuf_donebuf(&linebuf);
}

/*
 * sendto_one_notice_local()
 * inputs	- client to send to, va_args
 * outputs	- client has a NOTICE put into its queue
 * side effects - fast path for local clients 
 */
static void
sendto_one_notice_local(struct Client *target_p, const char *pattern, va_list * ap)
{
	buf_head_t linebuf;
	rb_linebuf_newbuf(&linebuf);
	rb_linebuf_putmsg(&linebuf, pattern, ap, ":%s NOTICE %s ", me.name, target_p->name);
	send_linebuf(target_p, &linebuf);
	rb_linebuf_donebuf(&linebuf);
}

/* sendto_one_notice()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has a NOTICE put into its queue
 * side effects - source(us)/target is chosen based on TS6 capability
 */
void
sendto_one_notice(struct Client *target_p, const char *pattern, ...)
{
	struct Client *dest_p;
	va_list args;
	buf_head_t linebuf;

	if(MyConnect(target_p))
	{
		if(IsIOError(target_p))
			return;
		va_start(args, pattern);
		sendto_one_notice_local(target_p, pattern, &args);
		va_end(args);
		return;
	}

	dest_p = target_p->from;

	if(IsIOError(dest_p))
		return;

	if(IsMe(dest_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send to myself!");
		return;
	}

	rb_linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args,
			  ":%s NOTICE %s ", get_id(&me, target_p), get_id(target_p, target_p));
	va_end(args);

	send_linebuf(dest_p, &linebuf);
	rb_linebuf_donebuf(&linebuf);
}


/* sendto_one_numeric()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has message put into its queue
 * side effects - source/target is chosen based on TS6 capability
 */
void
sendto_one_numeric(struct Client *target_p, int numeric, const char *pattern, ...)
{
	struct Client *dest_p;
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		dest_p = target_p->from;
	else
		dest_p = target_p;

	if(IsIOError(dest_p))
		return;

	if(IsMe(dest_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send to myself!");
		return;
	}

	rb_linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args,
			  ":%s %03d %s ",
			  get_id(&me, target_p), numeric, get_id(target_p, target_p));
	va_end(args);

	send_linebuf(dest_p, &linebuf);
	rb_linebuf_donebuf(&linebuf);
}

/*
 * sendto_server
 * 
 * inputs       - pointer to client to NOT send to
 *              - caps or'd together which must ALL be present
 *              - caps or'd together which must ALL NOT be present
 *              - printf style format string
 *              - args to format string
 * output       - NONE
 * side effects - Send a message to all connected servers, except the
 *                client 'one' (if non-NULL), as long as the servers
 *                support ALL capabs in 'caps', and NO capabs in 'nocaps'.
 *            
 * This function was written in an attempt to merge together the other
 * billion sendto_*serv*() functions, which sprung up with capabs, uids etc
 * -davidt
 */
void
sendto_server(struct Client *one, struct Channel *chptr, unsigned long caps,
	      unsigned long nocaps, const char *format, ...)
{
	va_list args;
	struct Client *target_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	buf_head_t linebuf;

	if(nocaps & CAP_TS6)
	{
		/* nothing should do this now */
		abort();
	}

	/* noone to send to.. */
	if(rb_dlink_list_length(&serv_list) == 0)
		return;

	if(chptr != NULL && *chptr->chname != '#')
		return;

	rb_linebuf_newbuf(&linebuf);
	va_start(args, format);
	rb_linebuf_putmsg(&linebuf, format, &args, NULL);
	va_end(args);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, serv_list.head)
	{
		target_p = ptr->data;

		/* check against 'one' */
		if(one != NULL && (target_p == one->from))
			continue;

		/* check we have required capabs */
		if(!IsCapable(target_p, caps))
			continue;

		/* check we don't have any forbidden capabs */
		if(!NotCapable(target_p, nocaps))
			continue;

		send_linebuf(target_p, &linebuf);
	}

	rb_linebuf_donebuf(&linebuf);

}

/* sendto_channel_flags()
 *
 * inputs	- server not to send to, flags needed, source, channel, va_args
 * outputs	- message is sent to channel members
 * side effects -
 */
void
sendto_channel_flags(struct Client *one, int type, struct Client *source_p,
		     struct Channel *chptr, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	buf_head_t rb_linebuf_local;
	buf_head_t rb_linebuf_id;
	struct Client *target_p;
	struct membership *msptr;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	rb_linebuf_newbuf(&rb_linebuf_local);
	rb_linebuf_newbuf(&rb_linebuf_id);

	current_serial++;

	va_start(args, pattern);
	rb_vsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	if(IsServer(source_p))
		rb_linebuf_putmsg(&rb_linebuf_local, NULL, NULL, ":%s %s", source_p->name, buf);
	else
		rb_linebuf_putmsg(&rb_linebuf_local, NULL, NULL,
				  ":%s!%s@%s %s",
				  source_p->name, source_p->username, source_p->host, buf);

	rb_linebuf_putmsg(&rb_linebuf_id, NULL, NULL, ":%s %s", source_p->id, buf);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, chptr->members.head)
	{
		msptr = ptr->data;
		target_p = msptr->client_p;

		if(IsIOError(target_p->from) || target_p->from == one)
			continue;

		if(type && ((msptr->flags & type) == 0))
			continue;

		if(IsDeaf(target_p))
			continue;

		if(!MyClient(target_p))
		{
			/* if we've got a specific type, target must support
			 * CHW.. --fl
			 */
			if(type && NotCapable(target_p->from, CAP_CHW))
				continue;

			if(target_p->from->localClient->serial != current_serial)
			{
				send_rb_linebuf_remote(target_p, source_p, &rb_linebuf_id);
				target_p->from->localClient->serial = current_serial;
			}
		}
		else
			send_linebuf(target_p, &rb_linebuf_local);
	}

	rb_linebuf_donebuf(&rb_linebuf_local);
	rb_linebuf_donebuf(&rb_linebuf_id);
}


/* sendto_channel_local()
 *
 * inputs	- flags to send to, channel to send to, va_args
 * outputs	- message to local channel members
 * side effects -
 */
void
sendto_channel_local(int type, struct Channel *chptr, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;
	struct membership *msptr;
	struct Client *target_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, chptr->locmembers.head)
	{
		msptr = ptr->data;
		target_p = msptr->client_p;

		if(IsIOError(target_p))
			continue;

		if(type && ((msptr->flags & type) == 0))
			continue;

		send_linebuf(target_p, &linebuf);
	}

	rb_linebuf_donebuf(&linebuf);
}

/*
 * sendto_common_channels_local()
 *
 * inputs	- pointer to client
 *		- pattern to send
 * output	- NONE
 * side effects	- Sends a message to all people on local server who are
 * 		  in same channel with user. 
 *		  used by m_nick.c and exit_one_client.
 */
void
sendto_common_channels_local(struct Client *user, const char *pattern, ...)
{
	va_list args;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	rb_dlink_node *uptr;
	rb_dlink_node *next_uptr;
	struct Channel *chptr;
	struct Client *target_p;
	struct membership *msptr;
	struct membership *mscptr;
	buf_head_t linebuf;

	rb_linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	++current_serial;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, user->user->channel.head)
	{
		mscptr = ptr->data;
		chptr = mscptr->chptr;

		RB_DLINK_FOREACH_SAFE(uptr, next_uptr, chptr->locmembers.head)
		{
			msptr = uptr->data;
			target_p = msptr->client_p;

			if(IsIOError(target_p) || target_p->localClient->serial == current_serial)
				continue;

			target_p->localClient->serial = current_serial;
			send_linebuf(target_p->from ? target_p->from : target_p, &linebuf);
		}
	}

	/* this can happen when the user isnt in any channels, but we still
	 * need to send them the data, ie a nick change
	 */
	if(MyConnect(user) && (user->localClient->serial != current_serial))
		send_linebuf(user->from ? user->from : user, &linebuf);

	rb_linebuf_donebuf(&linebuf);
}

/* sendto_match_butone()
 *
 * inputs	- server not to send to, source, mask, type of mask, va_args
 * output	-
 * side effects - message is sent to matching clients
 */
void
sendto_match_butone(struct Client *one, struct Client *source_p,
		    const char *mask, int what, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	struct Client *target_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	buf_head_t rb_linebuf_local;
	buf_head_t rb_linebuf_id;

	rb_linebuf_newbuf(&rb_linebuf_local);
	rb_linebuf_newbuf(&rb_linebuf_id);

	va_start(args, pattern);
	rb_vsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	if(IsServer(source_p))
		rb_linebuf_putmsg(&rb_linebuf_local, NULL, NULL, ":%s %s", source_p->name, buf);
	else
		rb_linebuf_putmsg(&rb_linebuf_local, NULL, NULL,
				  ":%s!%s@%s %s",
				  source_p->name, source_p->username, source_p->host, buf);

	rb_linebuf_putmsg(&rb_linebuf_id, NULL, NULL, ":%s %s", source_p->id, buf);

	if(what == MATCH_HOST)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
		{
			target_p = ptr->data;

			if(match(mask, target_p->host))
				send_linebuf(target_p, &rb_linebuf_local);
		}
	}
	/* what = MATCH_SERVER, if it doesnt match us, just send remote */
	else if(match(mask, me.name))
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
		{
			target_p = ptr->data;
			send_linebuf(target_p, &rb_linebuf_local);
		}
	}

	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		if(target_p == one)
			continue;

		send_rb_linebuf_remote(target_p, source_p, &rb_linebuf_id);
	}

	rb_linebuf_donebuf(&rb_linebuf_local);
	rb_linebuf_donebuf(&rb_linebuf_id);
}

/* sendto_match_servs()
 *
 * inputs       - source, mask to send to, caps needed, va_args
 * outputs      - 
 * side effects - message is sent to matching servers with caps.
 */
void
sendto_match_servs(struct Client *source_p, const char *mask, int cap,
		   int nocap, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	rb_dlink_node *ptr;
	struct Client *target_p;
	buf_head_t rb_linebuf_id;

	if(EmptyString(mask))
		return;

	rb_linebuf_newbuf(&rb_linebuf_id);

	va_start(args, pattern);
	rb_vsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	rb_linebuf_putmsg(&rb_linebuf_id, NULL, NULL, ":%s %s", source_p->id, buf);

	current_serial++;

	RB_DLINK_FOREACH(ptr, global_serv_list.head)
	{
		target_p = ptr->data;

		/* dont send to ourselves, or back to where it came from.. */
		if(IsMe(target_p) || target_p->from == source_p->from)
			continue;

		if(target_p->from->localClient->serial == current_serial)
			continue;

		if(match(mask, target_p->name))
		{
			/* if we set the serial here, then we'll never do
			 * a match() again if !IsCapable()
			 */
			target_p->from->localClient->serial = current_serial;

			if(cap && !IsCapable(target_p->from, cap))
				continue;

			if(nocap && !NotCapable(target_p->from, nocap))
				continue;

			send_linebuf(target_p->from, &rb_linebuf_id);
		}
	}

	rb_linebuf_donebuf(&rb_linebuf_id);
}

/* sendto_monitor()
 *
 * inputs	- monitor nick to send to, format, va_args
 * outputs	- message to local users monitoring the given nick
 * side effects -
 */
void
sendto_monitor(struct monitor *monptr, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;
	struct Client *target_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, monptr->users.head)
	{
		target_p = ptr->data;

		if(IsIOError(target_p))
			continue;

		send_linebuf(target_p, &linebuf);
	}

	rb_linebuf_donebuf(&linebuf);
}

/* sendto_anywhere()
 *
 * inputs	- target, source, va_args
 * outputs	-
 * side effects - client is sent message with correct prefix.
 */
void
sendto_anywhere(struct Client *target_p, struct Client *source_p,
		const char *command, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);

	if(MyClient(target_p))
	{
		if(IsServer(source_p))
			rb_linebuf_putmsg(&linebuf, pattern, &args, ":%s %s %s ",
					  source_p->name, command, target_p->name);
		else
			rb_linebuf_putmsg(&linebuf, pattern, &args,
					  ":%s!%s@%s %s %s ",
					  source_p->name, source_p->username,
					  source_p->host, command, target_p->name);
	}
	else
		rb_linebuf_putmsg(&linebuf, pattern, &args, ":%s %s %s ",
				  get_id(source_p, target_p), command, get_id(target_p, target_p));
	va_end(args);

	if(MyClient(target_p))
		send_linebuf(target_p, &linebuf);
	else
		send_rb_linebuf_remote(target_p, source_p, &linebuf);

	rb_linebuf_donebuf(&linebuf);
}

/* sendto_realops_flags()
 *
 * inputs	- umode needed, level (opers/admin), va_args
 * output	-
 * side effects - message is sent to opers with matching umodes
 */
void
sendto_realops_flags(int flags, int level, const char *pattern, ...)
{
	struct Client *client_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	va_list args;
	buf_head_t linebuf;

	if(EmptyString(me.name))
		return;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args, ":%s NOTICE * :*** Notice -- ", me.name);
	va_end(args);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, oper_list.head)
	{
		client_p = ptr->data;

		/* If we're sending it to opers and theyre an admin, skip.
		 * If we're sending it to admins, and theyre not, skip.
		 */
		if(((level == L_ADMIN) && !IsAdmin(client_p)) ||
		   ((level == L_OPER) && IsAdmin(client_p)))
			continue;

		if(client_p->umodes & flags)
			send_linebuf(client_p, &linebuf);
	}

	rb_linebuf_donebuf(&linebuf);
}

/*
 * sendto_wallops_flags
 *
 * inputs       - flag types of messages to show to real opers
 *              - client sending request
 *              - var args input message
 * output       - NONE
 * side effects - Send a wallops to local opers
 */
void
sendto_wallops_flags(int flags, struct Client *source_p, const char *pattern, ...)
{
	struct Client *client_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	va_list args;
	buf_head_t linebuf;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);

	if(IsClient(source_p))
		rb_linebuf_putmsg(&linebuf, pattern, &args,
				  ":%s!%s@%s WALLOPS :", source_p->name,
				  source_p->username, source_p->host);
	else
		rb_linebuf_putmsg(&linebuf, pattern, &args, ":%s WALLOPS :", source_p->name);

	va_end(args);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, oper_list.head)
	{
		client_p = ptr->data;
		if(client_p->umodes & flags)
			send_linebuf(client_p, &linebuf);
	}

	rb_linebuf_donebuf(&linebuf);
}

/* kill_client()
 *
 * input	- client to send kill to, client to kill, va_args
 * output	-
 * side effects - we issue a kill for the client
 */
void
kill_client(struct Client *target_p, struct Client *diedie, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;

	rb_linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	rb_linebuf_putmsg(&linebuf, pattern, &args, ":%s KILL %s :",
			  get_id(&me, target_p), get_id(diedie, target_p));
	va_end(args);

	send_linebuf(target_p->from ? target_p->from : target_p, &linebuf);
	rb_linebuf_donebuf(&linebuf);
}


/*
 * kill_client_serv_butone
 *
 * inputs	- pointer to client to not send to
 *		- pointer to client to kill
 * output	- NONE
 * side effects	- Send a KILL for the given client
 *		  message to all connected servers
 *                except the client 'one'. Also deal with
 *		  client being unknown to leaf, as in lazylink...
 */
void
kill_client_serv_butone(struct Client *one, struct Client *target_p, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	struct Client *client_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	buf_head_t rb_linebuf_id;

	rb_linebuf_newbuf(&rb_linebuf_id);

	va_start(args, pattern);
	rb_vsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	rb_linebuf_putmsg(&rb_linebuf_id, NULL, NULL, ":%s KILL %s :%s",
			  use_id(&me), target_p->id, buf);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, serv_list.head)
	{
		client_p = ptr->data;

		/* ok, if the client we're supposed to not send to has an
		 * ID, then we still want to issue the kill there..
		 */
		if(one != NULL && (client_p == one->from) &&
		   (!has_id(client_p) || !has_id(target_p)))
			continue;

		send_linebuf(client_p, &rb_linebuf_id);
	}

	rb_linebuf_donebuf(&rb_linebuf_id);
}
