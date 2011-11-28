/*
 * res.h for referencing functions in res.c, reslib.c
 *
 * $Id: res.h 26690 2009-10-09 23:14:04Z jilles $
 */

#ifndef _RATBOX_RES_H
#define _RATBOX_RES_H

/* set MAXNS to 5, which matches with adns did in the past. */

#define IRCD_MAXNS 5

/* Longest hostname we're willing to work with.
 * Due to DNSBLs this is more than HOSTLEN.
 */
#define IRCD_RES_HOSTLEN 255


struct DNSReply
{
	char *h_name;
	struct rb_sockaddr_storage addr;
};


struct DNSQuery
{
	void *ptr;		/* pointer used by callback to identify request */
	void (*callback) (void *vptr, struct DNSReply * reply);	/* callback to call */
};

void init_resolver(void);
void restart_resolver(void);
//static void delete_resolver_queries(const struct DNSQuery *);
void gethost_byname_type(const char *, struct DNSQuery *, int);
void gethost_byaddr(const struct rb_sockaddr_storage *, struct DNSQuery *);
//static void add_local_domain(char *, size_t);
//static void report_dns_servers(struct Client *);


#endif
