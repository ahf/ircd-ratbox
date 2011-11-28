/*
 * res.c: resolver related code
 *
 * Portions are:
 * Copyright (C) 2008 ircd-ratbox development team
 * Copyright (C) 2005,2008 Aaron Sethman <androsyn@ratbox.org>
 *
 * $Id: res.c 27173 2011-03-28 18:24:39Z moggie $
 * 
 * This is base on the resolver from charybdis, which in turn is based on the
 * resolver from hybrid.  
 *
 * The original comments follow below:
 * 
 * A rewrite of Darren Reeds original res.c As there is nothing
 * left of Darrens original code, this is now licensed by the hybrid group.
 * (Well, some of the function names are the same, and bits of the structs..)
 * You can use it where it is useful, free even. Buy us a beer and stuff.
 *
 * The authors takes no responsibility for any damage or loss
 * of property which results from the use of this software.
 *
 * from charybdis Id: res.c 3301 2007-03-28 15:04:06Z jilles $
 * from Hybrid Id: res.c 459 2006-02-12 22:21:37Z db $
 *
 * July 1999 - Rewrote a bunch of stuff here. Change hostent builder code,
 *     added callbacks and reference counting of returned hostents.
 *     --Bleep (Thomas Helvey <tomh@inxpress.net>)
 *
 * This was all needlessly complicated for irc. Simplified. No more hostent
 * All we really care about is the IP -> hostname mappings. Thats all. 
 *
 * Apr 28, 2003 --cryogen and Dianora
 *
 * DNS server flooding lessened, AAAA-or-A lookup removed, ip6.int support
 * removed, various robustness fixes
 *
 * 2006 --jilles and nenolod
 *
 */
#include <ratbox_lib.h>
#include "setup.h"
#include "res.h"
#include "reslib.h"


static PF res_readreply;

#define MAXPACKET      1024	/* rfc sez 512 but we expand names so ... */
#define RES_MAXALIASES 35	/* maximum aliases allowed */
#define RES_MAXADDRS   35	/* maximum addresses allowed */
#define AR_TTL         600	/* TTL in seconds for dns cache entries */

/* RFC 1104/1105 wasn't very helpful about what these fields
 * should be named, so for now, we'll just name them this way.
 * we probably should look at what named calls them or something.
 */
#define TYPE_SIZE         (size_t)2
#define CLASS_SIZE        (size_t)2
#define TTL_SIZE          (size_t)4
#define RDLENGTH_SIZE     (size_t)2
#define ANSWER_FIXED_SIZE (TYPE_SIZE + CLASS_SIZE + TTL_SIZE + RDLENGTH_SIZE)

#ifdef RB_IPV6
extern struct in6_addr ipv6_addr;
#endif
extern struct in_addr ipv4_addr;

extern struct rb_sockaddr_storage irc_nsaddr_list[];
extern int irc_nscount;
struct reslist
{
	rb_dlink_node node;
	int id;
	int sent;		/* number of requests sent */
	time_t ttl;
	char type;
	char queryname[IRCD_RES_HOSTLEN + 1]; /* name currently being queried */
	char retries;		/* retry counter */
	char sends;		/* number of sends (>1 means resent) */
	time_t sentat;
	time_t timeout;
	struct rb_sockaddr_storage addr;
	char *name;
	struct DNSQuery *query;	/* query callback for this request */
	rb_fde_t *ipv4_F;	/* socket to send request on */
	rb_fde_t *ipv6_F;
};

static rb_dlink_list request_list = { NULL, NULL, 0 };

static void rem_request(struct reslist *request);
static struct reslist *make_request(struct DNSQuery *query);
static void do_query_name(struct DNSQuery *query, const char *name, struct reslist *request, int);
static void do_query_number(struct DNSQuery *query, const struct rb_sockaddr_storage *,
			    struct reslist *request);
static void query_name(struct reslist *request);
static int send_res_msg(void *buf, int len, struct reslist *request);
static void resend_query(struct reslist *request);
static int check_question(struct reslist *request, HEADER * header, char *buf, char *eob);
static int proc_answer(struct reslist *request, HEADER * header, char *, char *);
static struct reslist *find_id(uint16_t id);
static struct DNSReply *make_dnsreply(struct reslist *request);
static int generate_random_port(void);


/*
 * int
 * res_ourserver(inp)
 *      looks up "inp" in irc_nsaddr_list[]
 * returns:
 *      0  : not found
 *      >0 : found
 * author:
 *      paul vixie, 29may94
 *      revised for ircd, cryogen(stu) may03
 */
static int
res_ourserver(const struct rb_sockaddr_storage *inp)
{
#ifdef RB_IPV6
	const struct sockaddr_in6 *v6;
	const struct sockaddr_in6 *v6in = (const struct sockaddr_in6 *)inp;
#endif
	const struct sockaddr_in *v4;
	const struct sockaddr_in *v4in = (const struct sockaddr_in *)inp;
	int ns;

	for(ns = 0; ns < irc_nscount; ns++)
	{
		const struct rb_sockaddr_storage *srv = &irc_nsaddr_list[ns];
#ifdef RB_IPV6
		v6 = (const struct sockaddr_in6 *)srv;
#endif
		v4 = (const struct sockaddr_in *)srv;

		/* could probably just memcmp(srv, inp, srv.ss_len) here
		 * but we'll air on the side of caution - stu
		 */
		switch (GET_SS_FAMILY(srv))
		{
#ifdef RB_IPV6
		case AF_INET6:
			if(GET_SS_FAMILY(srv) == GET_SS_FAMILY(inp))
				if(v6->sin6_port == v6in->sin6_port)
					if((memcmp(&v6->sin6_addr.s6_addr, &v6in->sin6_addr.s6_addr,
						   sizeof(struct in6_addr)) == 0) ||
					   (memcmp(&v6->sin6_addr.s6_addr, &in6addr_any,
						   sizeof(struct in6_addr)) == 0))
						return 1;
			break;
#endif
		case AF_INET:
			if(GET_SS_FAMILY(srv) == GET_SS_FAMILY(inp))
				if(v4->sin_port == v4in->sin_port)
					if((v4->sin_addr.s_addr == INADDR_ANY)
					   || (v4->sin_addr.s_addr == v4in->sin_addr.s_addr))
						return 1;
			break;
		default:
			break;
		}
	}

	return 0;
}

/*
 * timeout_query_list - Remove queries from the list which have been 
 * there too long without being resolved.
 */
static time_t
timeout_query_list(time_t now)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	struct reslist *request;
	time_t next_time = 0;
	time_t timeout = 0;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, request_list.head)
	{
		request = ptr->data;
		timeout = request->sentat + request->timeout;

		if(now >= timeout)
		{
			if(--request->retries <= 0)
			{
				(*request->query->callback) (request->query->ptr, NULL);
				rem_request(request);
				continue;
			}
			else
			{
				request->sentat = now;
				request->timeout += request->timeout;
				resend_query(request);
			}
		}

		if((next_time == 0) || timeout < next_time)
		{
			next_time = timeout;
		}
	}

	return (next_time > now) ? next_time : (now + AR_TTL);
}

/*
 * timeout_resolver - check request list
 */
static void
timeout_resolver(void *notused)
{
	timeout_query_list(rb_time());
}

static struct ev_entry *timeout_resolver_ev = NULL;

/*
 * start_resolver - do everything we need to read the resolv.conf file
 * and initialize the resolver file descriptor if needed
 */
static void
start_resolver(void)
{
	irc_res_init();
	timeout_resolver_ev = rb_event_add("timeout_resolver", timeout_resolver, NULL, 1);
}

/*
 * init_resolver - initialize resolver and resolver library
 */
void
init_resolver(void)
{
	start_resolver();
}

/*
 * restart_resolver - reread resolv.conf, reopen socket
 */
void
restart_resolver(void)
{
	rb_event_delete(timeout_resolver_ev);	/* -ddosen */
	start_resolver();
}

#if 0
/*
 * add_local_domain - Add the domain to hostname, if it is missing
 * (as suggested by eps@TOASTER.SFSU.EDU)
 */
void
add_local_domain(char *hname, size_t size)
{
	/* try to fix up unqualified names */
	if(strchr(hname, '.') == NULL)
	{
		if(irc_domain[0])
		{
			size_t len = strlen(hname);

			if((strlen(irc_domain) + len + 2) < size)
			{
				hname[len++] = '.';
				strcpy(hname + len, irc_domain);
			}
		}
	}
}
#endif

/*
 * rem_request - remove a request from the list. 
 * This must also free any memory that has been allocated for 
 * temporary storage of DNS results.
 */
static void
rem_request(struct reslist *request)
{
	rb_dlinkDelete(&request->node, &request_list);
	if(request->ipv4_F != NULL)
		rb_close(request->ipv4_F);
#ifdef RB_IPV6
	if(request->ipv6_F != NULL)
		rb_close(request->ipv6_F);
#endif
	rb_free(request->name);
	rb_free(request);
}

/*
 * make_request - Create a DNS request record for the server.
 */
static struct reslist *
make_request(struct DNSQuery *query)
{
	struct reslist *request = rb_malloc(sizeof(struct reslist));

	request->sentat = rb_time();
	request->retries = 3;
	request->timeout = 4;	/* start at 4 and exponential inc. */
	request->query = query;

	rb_dlinkAdd(request, &request->node, &request_list);

	return request;
}

/*
 * delete_resolver_queries - cleanup outstanding queries 
 * for which there no longer exist clients or conf lines.
 */
#if 0
static void
delete_resolver_queries(const struct DNSQuery *query)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	struct reslist *request;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, request_list.head)
	{
		if((request = ptr->data) != NULL)
		{
			if(query == request->query)
				rem_request(request);
		}
	}
}
#endif

#ifdef RES_MIN
#undef RES_MIN
#endif

#define RES_MIN(a, b)  ((a) < (b) ? (a) : (b))

static rb_fde_t *
random_socket(int family)
{
	rb_fde_t *F;
	int nport;
	int i;
	rb_socklen_t len;
	struct rb_sockaddr_storage sockaddr;
	F = rb_socket(family, SOCK_DGRAM, 0, "UDP resolver socket");
	if(F == NULL)
		return NULL;

	memset(&sockaddr, 0, sizeof(sockaddr));

	SET_SS_FAMILY(&sockaddr, family);

#ifdef RB_IPV6
	if(family == AF_INET6)
	{
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&sockaddr;
		memcpy(&in6->sin6_addr, &ipv6_addr, sizeof(struct in6_addr));
		len = (rb_socklen_t) sizeof(struct sockaddr_in6);
	}
	else
#endif
	{
		struct sockaddr_in *in = (struct sockaddr_in *)&sockaddr;
		in->sin_addr.s_addr = ipv4_addr.s_addr;
		len = (rb_socklen_t) sizeof(struct sockaddr_in);
	}

	for(i = 0; i < 10; i++)
	{
		nport = htons(generate_random_port());

		if(family == AF_INET)
			((struct sockaddr_in *)&sockaddr)->sin_port = nport;
#ifdef RB_IPV6
		else
			((struct sockaddr_in6 *)&sockaddr)->sin6_port = nport;

#endif
		if(bind(rb_get_fd(F), (struct sockaddr *)&sockaddr, len) == 0)
			return F;
	}
	rb_close(F);
	return NULL;
}

/*
 * send_res_msg - sends msg to all nameservers found in the "_res" structure.
 * This should reflect /etc/resolv.conf. We will get responses
 * which arent needed but is easier than checking to see if nameserver
 * isnt present. Returns number of messages successfully sent to 
 * nameservers or -1 if no successful sends.
 */
static int
send_res_msg(void *msg, int len, struct reslist *request)
{
	int i;
	int sent = 0;
	rb_fde_t *F = NULL;
	int rcount = request->sends;
	int max_queries = RES_MIN(irc_nscount, rcount);

	/* RES_PRIMARY option is not implemented
	 * if (res.options & RES_PRIMARY || 0 == max_queries)
	 */
	if(max_queries == 0)
		max_queries = 1;

	for(i = 0; sent < max_queries && i < irc_nscount; i++)
	{
		if(GET_SS_FAMILY(&irc_nsaddr_list[i]) == AF_INET)
		{
			if(request->ipv4_F == NULL)
			{
				request->ipv4_F = random_socket(AF_INET);
			}
			F = request->ipv4_F;
		}
#ifdef RB_IPV6
		else
		{
			if(GET_SS_FAMILY(&irc_nsaddr_list[i]) == AF_INET6)
			{
				request->ipv6_F = random_socket(AF_INET6);
			}
			F = request->ipv6_F;
		}
#endif
		if(F == NULL)
			continue;
		if(sendto(rb_get_fd(F), msg, len, 0,
			  (struct sockaddr *)&(irc_nsaddr_list[i]),
			  GET_SS_LEN(&irc_nsaddr_list[i])) == len)
			++sent;
		res_readreply(F, NULL);
	}

	return (sent);
}

/*
 * find_id - find a dns request id (id is determined by dn_mkquery)
 */
static struct reslist *
find_id(uint16_t id)
{
	rb_dlink_node *ptr;
	struct reslist *request;

	RB_DLINK_FOREACH(ptr, request_list.head)
	{
		request = ptr->data;

		if(request->id == id)
			return (request);
	}

	return (NULL);
}


static uint16_t
generate_random_id(void)
{
	uint16_t id;

	do
	{
		rb_get_pseudo_random(&id, sizeof(id));
		if(id == 0xffff)
			continue;
	}
	while(find_id(id));
	return id;
}

static int
generate_random_port(void)
{
	uint16_t port;

	while(1)
	{
		rb_get_pseudo_random(&port, sizeof(port));
		if(port > 1024)
			break;
	}
	return (int)port;
}


/* 
 * gethost_byname_type - get host address from name
 *
 */
void
gethost_byname_type(const char *name, struct DNSQuery *query, int type)
{
	assert(name != 0);
	do_query_name(query, name, NULL, type);
}

/*
 * gethost_byaddr - get host name from address
 */
void
gethost_byaddr(const struct rb_sockaddr_storage *addr, struct DNSQuery *query)
{
	do_query_number(query, addr, NULL);
}

/*
 * do_query_name - nameserver lookup name
 */
static void
do_query_name(struct DNSQuery *query, const char *name, struct reslist *request, int type)
{
	char host_name[IRCD_RES_HOSTLEN + 1];

	rb_strlcpy(host_name, name, sizeof(host_name));
//      add_local_domain(host_name, IRCD_RES_HOSTLEN);

	if(request == NULL)
	{
		request = make_request(query);
		request->name = rb_strdup(host_name);
	}

	rb_strlcpy(request->queryname, host_name, sizeof(request->queryname));
	request->type = type;
	query_name(request);
}

/*
 * do_query_number - Use this to do reverse IP# lookups.
 */
static void
do_query_number(struct DNSQuery *query, const struct rb_sockaddr_storage *addr,
		struct reslist *request)
{
	const unsigned char *cp;

	if(request == NULL)
	{
		request = make_request(query);
		memcpy(&request->addr, addr, sizeof(struct rb_sockaddr_storage));
		request->name = (char *)rb_malloc(IRCD_RES_HOSTLEN + 1);
	}

	if(GET_SS_FAMILY(addr) == AF_INET)
	{
		const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
		cp = (const unsigned char *)&v4->sin_addr.s_addr;

		rb_sprintf(request->queryname, "%u.%u.%u.%u.in-addr.arpa", (unsigned int)(cp[3]),
			   (unsigned int)(cp[2]), (unsigned int)(cp[1]), (unsigned int)(cp[0]));
	}
#ifdef RB_IPV6
	else if(GET_SS_FAMILY(addr) == AF_INET6)
	{
		const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
		cp = (const unsigned char *)&v6->sin6_addr.s6_addr;

		rb_sprintf(request->queryname,
			   "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
			   "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa",
			   (unsigned int)(cp[15] & 0xf), (unsigned int)(cp[15] >> 4),
			   (unsigned int)(cp[14] & 0xf), (unsigned int)(cp[14] >> 4),
			   (unsigned int)(cp[13] & 0xf), (unsigned int)(cp[13] >> 4),
			   (unsigned int)(cp[12] & 0xf), (unsigned int)(cp[12] >> 4),
			   (unsigned int)(cp[11] & 0xf), (unsigned int)(cp[11] >> 4),
			   (unsigned int)(cp[10] & 0xf), (unsigned int)(cp[10] >> 4),
			   (unsigned int)(cp[9] & 0xf), (unsigned int)(cp[9] >> 4),
			   (unsigned int)(cp[8] & 0xf), (unsigned int)(cp[8] >> 4),
			   (unsigned int)(cp[7] & 0xf), (unsigned int)(cp[7] >> 4),
			   (unsigned int)(cp[6] & 0xf), (unsigned int)(cp[6] >> 4),
			   (unsigned int)(cp[5] & 0xf), (unsigned int)(cp[5] >> 4),
			   (unsigned int)(cp[4] & 0xf), (unsigned int)(cp[4] >> 4),
			   (unsigned int)(cp[3] & 0xf), (unsigned int)(cp[3] >> 4),
			   (unsigned int)(cp[2] & 0xf), (unsigned int)(cp[2] >> 4),
			   (unsigned int)(cp[1] & 0xf), (unsigned int)(cp[1] >> 4),
			   (unsigned int)(cp[0] & 0xf), (unsigned int)(cp[0] >> 4));
	}
#endif

	request->type = T_PTR;
	query_name(request);
}

/*
 * query_name - generate a query based on class, type and name.
 */
static void
query_name(struct reslist *request)
{
	void *buf = alloca(MAXPACKET);
	int request_len = 0;

	memset(buf, 0, MAXPACKET);

	if((request_len =
	    irc_res_mkquery(request->queryname, C_IN, request->type, buf, MAXPACKET)) > 0)
	{
		HEADER *header = (HEADER *) buf;
		/*
		 * generate an unique id
		 * NOTE: we don't have to worry about converting this to and from
		 * network byte order, the nameserver does not interpret this value
		 * and returns it unchanged
		 */

		header->id = generate_random_id();

		request->id = header->id;
		++request->sends;

		request->sent += send_res_msg(buf, request_len, request);
	}
}

static void
resend_query(struct reslist *request)
{
	switch (request->type)
	{
	case T_PTR:
		do_query_number(NULL, &request->addr, request);
		break;
	case T_A:
#ifdef RB_IPV6
	case T_AAAA:
#endif
		do_query_name(NULL, request->name, request, request->type);
		break;
	default:
		break;
	}
}

/*
 * check_question - check if the reply really belongs to the
 * name we queried (to guard against late replies from previous
 * queries with the same id).
 */
static int
check_question(struct reslist *request, HEADER * header, char *buf, char *eob)
{
	char hostbuf[IRCD_RES_HOSTLEN + 1];	/* working buffer */
	unsigned char *current;	/* current position in buf */
	int n;			/* temp count */

	current = (unsigned char *)buf + sizeof(HEADER);
	if(header->qdcount != 1)
		return 0;
	n = irc_dn_expand((unsigned char *)buf, (unsigned char *)eob, current, hostbuf,
			  sizeof(hostbuf));
	if(n <= 0)
		return 0;
	if(strcasecmp(hostbuf, request->queryname))
		return 0;
	return 1;
}

/*
 * proc_answer - process name server reply
 */
static int
proc_answer(struct reslist *request, HEADER * header, char *buf, char *eob)
{
	char hostbuf[IRCD_RES_HOSTLEN + 100];	/* working buffer */
	unsigned char *current;	/* current position in buf */
	int query_class;	/* answer class */
	int type;		/* answer type */
	int n;			/* temp count */
	int rd_length;
	struct sockaddr_in *v4;	/* conversion */
#ifdef RB_IPV6
	struct sockaddr_in6 *v6;
#endif
	current = (unsigned char *)buf + sizeof(HEADER);

	for(; header->qdcount > 0; --header->qdcount)
	{
		if((n = irc_dn_skipname(current, (unsigned char *)eob)) < 0)
			return 0;

		current += (size_t)n + QFIXEDSZ;
	}

	/*
	 * process each answer sent to us blech.
	 */
	while(header->ancount > 0 && (char *)current < eob)
	{
		header->ancount--;

		n = irc_dn_expand((unsigned char *)buf, (unsigned char *)eob, current, hostbuf,
				  sizeof(hostbuf));

		if(n < 0)
		{
			/*
			 * broken message
			 */
			return (0);
		}
		else if(n == 0)
		{
			/*
			 * no more answers left
			 */
			return (0);
		}

		hostbuf[IRCD_RES_HOSTLEN] = '\0';

		/* With Address arithmetic you have to be very anal
		 * this code was not working on alpha due to that
		 * (spotted by rodder/jailbird/dianora)
		 */
		current += (size_t)n;

		if(!(((char *)current + ANSWER_FIXED_SIZE) < eob))
			break;

		type = irc_ns_get16(current);
		current += TYPE_SIZE;

		query_class = irc_ns_get16(current);
		current += CLASS_SIZE;

		request->ttl = irc_ns_get32(current);
		current += TTL_SIZE;

		rd_length = irc_ns_get16(current);
		current += RDLENGTH_SIZE;

		/* 
		 * Wait to set request->type until we verify this structure 
		 */
		switch (type)
		{
		case T_A:
			if(request->type != T_A)
				return (0);

			/*
			 * check for invalid rd_length or too many addresses
			 */
			if(rd_length != sizeof(struct in_addr))
				return (0);
			v4 = (struct sockaddr_in *)&request->addr;
			SET_SS_LEN(&request->addr, sizeof(struct sockaddr_in));
			v4->sin_family = AF_INET;
			memcpy(&v4->sin_addr, current, sizeof(struct in_addr));
			return (1);
			break;
#ifdef RB_IPV6
		case T_AAAA:
			if(request->type != T_AAAA)
				return (0);
			if(rd_length != sizeof(struct in6_addr))
				return (0);
			SET_SS_LEN(&request->addr, sizeof(struct sockaddr_in6));
			v6 = (struct sockaddr_in6 *)&request->addr;
			v6->sin6_family = AF_INET6;
			memcpy(&v6->sin6_addr, current, sizeof(struct in6_addr));
			return (1);
			break;
#endif
		case T_PTR:
			if(request->type != T_PTR)
				return (0);
			n = irc_dn_expand((unsigned char *)buf, (unsigned char *)eob, current,
					  hostbuf, sizeof(hostbuf));
			if(n < 0)
				return (0);	/* broken message */
			else if(n == 0)
				return (0);	/* no more answers left */

			rb_strlcpy(request->name, hostbuf, IRCD_RES_HOSTLEN + 1);

			return (1);
			break;
		case T_CNAME:
			/* real answer will follow */
			current += rd_length;
			break;

		default:
			/* XXX I'd rather just throw away the entire bogus thing
			 * but its possible its just a broken nameserver with still
			 * valid answers. But lets do some rudimentary logging for now...
			 */
//                      ilog(L_MAIN, "irc_res.c bogus type %d", type);
			break;
		}
	}

	return (1);
}

/*
 * res_read_single_reply - read a dns reply from the nameserver and process it.
 * Return value: 1 if a packet was read, 0 otherwise
 */
static int
res_read_single_reply(rb_fde_t *F, void *data)
{
	int buflen = sizeof(HEADER) + MAXPACKET;
	void *buf = alloca(buflen);

	HEADER *header;
	struct reslist *request = NULL;
	struct DNSReply *reply = NULL;
	int rc;
	int answer_count;
	rb_socklen_t len = sizeof(struct rb_sockaddr_storage);
	struct rb_sockaddr_storage lsin;

	rc = recvfrom(rb_get_fd(F), buf, buflen, 0, (struct sockaddr *)&lsin, &len);

	/* No packet */
	if(rc == 0 || rc == -1)
		return 0;

	/* Too small */
	if(rc <= (int)(sizeof(HEADER)))
		return 1;

	/*
	 * convert DNS reply reader from Network byte order to CPU byte order.
	 */
	header = (HEADER *) buf;
	header->ancount = ntohs(header->ancount);
	header->qdcount = ntohs(header->qdcount);
	header->nscount = ntohs(header->nscount);
	header->arcount = ntohs(header->arcount);

	/*
	 * response for an id which we have already received an answer for
	 * just ignore this response.
	 */
	if(0 == (request = find_id(header->id)))
		return 1;

	/*
	 * check against possibly fake replies
	 */
	if(!res_ourserver(&lsin))
		return 1;

	if(!check_question(request, header, (char *)buf, ((char *)buf) + rc))
		return 1;

	if((header->rcode != NO_ERRORS) || (header->ancount == 0))
	{
		/*
		 * If a bad error was returned, we stop here and dont send
		 * send any more (no retries granted).
		 */
		(*request->query->callback) (request->query->ptr, NULL);
		rem_request(request);
		return -1;
	}
	/*
	 * If this fails there was an error decoding the received packet, 
	 * give up. -- jilles
	 */
	answer_count = proc_answer(request, header, (char *)buf, ((char *)buf) + rc);

	if(answer_count)
	{
		if(request->type == T_PTR)
		{
			if(request->name == NULL)
			{
				/*
				 * got a PTR response with no name, something bogus is happening
				 * don't bother trying again, the client address doesn't resolve
				 */
				(*request->query->callback) (request->query->ptr, reply);
				rem_request(request);
				return -1;
			}

			/*
			 * Lookup the 'authoritative' name that we were given for the
			 * ip#. 
			 *
			 */
#ifdef RB_IPV6
			if(GET_SS_FAMILY(&request->addr) == AF_INET6)
				gethost_byname_type(request->name, request->query, T_AAAA);
			else
#endif
				gethost_byname_type(request->name, request->query, T_A);
			rem_request(request);
		}
		else
		{
			/*
			 * got a name and address response, client resolved
			 */
			reply = make_dnsreply(request);
			(*request->query->callback) (request->query->ptr, reply);
			rb_free(reply);
			rem_request(request);
		}
	}
	else
	{
		/* couldn't decode, give up -- jilles */
		(*request->query->callback) (request->query->ptr, NULL);
		rem_request(request);
	}
	return -1;
}

static void
res_readreply(rb_fde_t *F, void *data)
{
	int rc;
	while((rc = res_read_single_reply(F, data)) > 0)
		;;
	if(rc != -1)
		rb_setselect(F, RB_SELECT_READ, res_readreply, NULL);
}

static struct DNSReply *
make_dnsreply(struct reslist *request)
{
	struct DNSReply *cp;

	cp = (struct DNSReply *)rb_malloc(sizeof(struct DNSReply));

	cp->h_name = request->name;
	memcpy(&cp->addr, &request->addr, sizeof(cp->addr));
	return (cp);
}
