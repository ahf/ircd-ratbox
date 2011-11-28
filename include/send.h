/*
 *  ircd-ratbox: A slightly useful ircd.
 *  send.h: A header for the message sending functions.
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
 *  $Id: send.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef INCLUDED_send_h
#define INCLUDED_send_h

struct Client;
struct Channel;
struct rb_dlink_list;
struct monitor;

void send_pop_queue(struct Client *);
void
sendto_one(struct Client *target_p, const char *, ...)
AFP(2, 3);
     void sendto_one_buffer(struct Client *target_p, const char *buffer);
     void sendto_one_notice(struct Client *target_p, const char *, ...) AFP(2, 3);
     void sendto_one_prefix(struct Client *target_p, struct Client *source_p,
			    const char *command, const char *, ...) AFP(4, 5);
     void sendto_one_numeric(struct Client *target_p, int numeric, const char *, ...) AFP(3, 4);

     void sendto_server(struct Client *one, struct Channel *chptr,
			unsigned long caps, unsigned long nocaps,
			const char *format, ...) AFP(5, 6);

     void sendto_channel_flags(struct Client *one, int type, struct Client *source_p,
			       struct Channel *chptr, const char *, ...) AFP(5, 6);

     void sendto_channel_local(int type, struct Channel *, const char *, ...) AFP(3, 4);
     void sendto_common_channels_local(struct Client *, const char *, ...) AFP(2, 3);


     void sendto_match_butone(struct Client *, struct Client *,
			      const char *, int, const char *, ...) AFP(5, 6);
     void sendto_match_servs(struct Client *source_p, const char *mask,
			     int capab, int, const char *, ...) AFP(5, 6);

     void sendto_monitor(struct monitor *monptr, const char *, ...) AFP(2, 3);

     void sendto_anywhere(struct Client *, struct Client *, const char *,
			  const char *, ...) AFP(4, 5);

     void sendto_realops_flags(int, int, const char *, ...) AFP(3, 4);
     void sendto_wallops_flags(int, struct Client *, const char *, ...) AFP(3, 4);

     void kill_client(struct Client *client_p, struct Client *diedie,
		      const char *pattern, ...) AFP(3, 4);
     void kill_client_serv_butone(struct Client *one, struct Client *source_p,
				  const char *pattern, ...) AFP(3, 4);

#define L_ALL 	0
#define L_OPER 	1
#define L_ADMIN	2

#define NOCAPS          0	/* no caps */

/* used when sending to #mask or $mask */
#define MATCH_SERVER  1
#define MATCH_HOST    2

#endif /* INCLUDED_send_h */
