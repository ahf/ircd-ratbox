/* 
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 * monitor.h: Code for server-side notify lists.
 *
 * Copyright (C) 2005 Lee Hardy <lee -at- leeh.co.uk>
 * Copyright (C) 2005 ircd-ratbox development team
 *
 * $Id: monitor.h 24794 2007-12-28 02:36:59Z androsyn $
 */
#ifndef INCLUDED_monitor_h
#define INCLUDED_monitor_h

struct BlockHeap;

struct monitor
{
	struct monitor *hnext;
	char name[NICKLEN];
	rb_dlink_list users;
};

extern struct monitor *monitorTable[];

#define MONITOR_HASH_BITS 16
#define MONITOR_HASH_SIZE (1<<MONITOR_HASH_BITS)

void init_monitor(void);
struct monitor *find_monitor(const char *name, int add);
void free_monitor(struct monitor *);

void clear_monitor(struct Client *);

void monitor_signon(struct Client *);
void monitor_signoff(struct Client *);

#endif
