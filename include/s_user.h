/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_user.h: A header for the user functions.
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
 *  $Id: s_user.h 24650 2007-12-02 02:56:04Z androsyn $
 */

#ifndef INCLUDED_s_user_h
#define INCLUDED_s_user_h

struct Client;
struct User;
struct oper_conf;
extern time_t LastUsedWallops;

int valid_hostname(const char *hostname);
int valid_username(const char *username);

int user_mode(struct Client *, struct Client *, int, const char **);
void send_umode(struct Client *, struct Client *, int, int, char *);
void send_umode_out(struct Client *, struct Client *, int);
int show_lusers(struct Client *source_p);
int register_local_user(struct Client *, struct Client *, const char *);

void introduce_client(struct Client *client_p, struct Client *source_p);

extern int user_modes_from_c_to_bitmask[];
void show_isupport(struct Client *);

#define UserModeBitmask(c) user_modes_from_c_to_bitmask[(unsigned char)c]

#endif
