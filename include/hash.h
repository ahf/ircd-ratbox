/*
 *  ircd-ratbox: A slightly useful ircd.
 *  hash.h: A header for the ircd hashtable code.
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
 *  $Id: hash.h 26405 2009-01-16 21:38:41Z jilles $
 */

#ifndef INCLUDED_hash_h
#define INCLUDED_hash_h

extern rb_dlink_list resvTable[];
extern rb_dlink_list ndTable[];

/* Magic value for FNV hash functions */
#define FNV1_32_INIT 0x811c9dc5UL

/* Client hash table size, used in hash.c/s_debug.c */
#define U_MAX_BITS 17
#define U_MAX (1<<U_MAX_BITS)

/* Client fd hash table size, used in hash.c */
#define CLI_FD_MAX 4096

/* Channel hash table size, hash.c/s_debug.c */
#define CH_MAX_BITS 16
#define CH_MAX (1<<CH_MAX_BITS)	/* 2^16 */

/* hostname hash table size */
#define HOST_MAX_BITS 17
#define HOST_MAX (1<<HOST_MAX_BITS)	/* 2^17 */

/* RESV/XLINE hash table size, used in hash.c */
#define R_MAX_BITS 10
#define R_MAX (1<<R_MAX_BITS)	/* 2^10 */


#define HASH_WALK(i, max, ptr, table) for (i = 0; i < max; i++) { RB_DLINK_FOREACH(ptr, table[i].head)
#define HASH_WALK_SAFE(i, max, ptr, nptr, table) for (i = 0; i < max; i++) { RB_DLINK_FOREACH_SAFE(ptr, nptr, table[i].head)
#define HASH_WALK_END }

typedef enum
{
	HASH_CLIENT,
	HASH_ID,
	HASH_CHANNEL,
	HASH_HOSTNAME,
	HASH_RESV
} hash_type;

struct Client;
struct Channel;
struct ConfItem;
struct cachefile;
struct nd_entry;

uint32_t fnv_hash_upper(const unsigned char *s, unsigned int bits, unsigned int unused);
uint32_t fnv_hash(const unsigned char *s, unsigned int bits, unsigned int unused);
uint32_t fnv_hash_len(const unsigned char *s, unsigned int bits, unsigned int len);
uint32_t fnv_hash_upper_len(const unsigned char *s, unsigned int bits, unsigned int len);

void init_hash(void);

void add_to_hash(hash_type, const char *, void *);
void del_from_hash(hash_type, const char *, void *);

struct Client *find_client(const char *name);
struct Client *find_named_client(const char *name);
struct Client *find_server(struct Client *source_p, const char *name);

struct Client *find_id(const char *name);

struct Channel *get_or_create_channel(struct Client *client_p, const char *chname, int *isnew);
struct Channel *find_channel(const char *name);

rb_dlink_node *find_hostname(const char *);

struct ConfItem *hash_find_resv(const char *name);
void clear_resv_hash(void);

void add_to_help_hash(const char *name, struct cachefile *hptr);
void clear_help_hash(void);
struct cachefile *hash_find_help(const char *name, int flags);

void add_to_nd_hash(const char *name, struct nd_entry *nd);
struct nd_entry *hash_find_nd(const char *name);

void add_to_cli_fd_hash(struct Client *client_p);
void del_from_cli_fd_hash(struct Client *client_p);
struct Client *find_cli_fd_hash(int fd);

void hash_stats(struct Client *);

#endif /* INCLUDED_hash_h */
