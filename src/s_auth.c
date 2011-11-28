/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_auth.c: Functions for querying a users ident.
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
 *  $Id: s_auth.c 27309 2011-11-12 20:48:41Z dubkat $ */

/*
 * Changes:
 *   July 6, 1999 - Rewrote most of the code here. When a client connects
 *     to the server and passes initial socket validation checks, it
 *     is owned by this module (auth) which returns it to the rest of the
 *     server when dns and auth queries are finished. Until the client is
 *     released, the server does not know it exists and does not process
 *     any messages from it.
 *     --Bleep  Thomas Helvey <tomh@inxpress.net>
 */
#include "stdinc.h"
#include "setup.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "s_auth.h"
#include "s_conf.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "packet.h"
#include "s_log.h"
#include "s_stats.h"
#include "send.h"
#include "hook.h"
#include "dns.h"


struct AuthRequest
{
	rb_dlink_node node;
	struct Client *client;	/* pointer to client struct for request */
	uint16_t dns_query;	/* DNS Query */
	rb_fde_t *authF;
	unsigned int flags;	/* current state of request */
	time_t timeout;		/* time when query expires */
	int lport;
	int rport;
};


#define REPORT_DO_DNS	"NOTICE AUTH :*** Looking up your hostname..."
#define REPORT_FIN_DNS	"NOTICE AUTH :*** Found your hostname"
#define REPORT_FAIL_DNS "NOTICE AUTH :*** Couldn't look up your hostname"
#define REPORT_DO_ID	"NOTICE AUTH :*** Checking Ident"
#define REPORT_FIN_ID	"NOTICE AUTH :*** Got Ident response"
#define REPORT_FAIL_ID	"NOTICE AUTH :*** No Ident response"
#define REPORT_HOST_TOOLONG	"NOTICE AUTH :*** Your hostname is too long, ignoring hostname"

#define sendheader(c, r) sendto_one(c, "%s", r)

static rb_dlink_list auth_poll_list;
static rb_bh *auth_heap;
static EVH timeout_auth_queries_event;
static void read_auth(rb_fde_t *F, void *data);


/*
 * init_auth()
 *
 * Initialise the auth code
 */
void
init_auth(void)
{
	memset(&auth_poll_list, 0, sizeof(auth_poll_list));
	rb_event_addish("timeout_auth_queries_event", timeout_auth_queries_event, NULL, 3);
	auth_heap = rb_bh_create(sizeof(struct AuthRequest), AUTH_HEAP_SIZE, "auth_heap");

}

/*
 * make_auth_request - allocate a new auth request
 */
static struct AuthRequest *
make_auth_request(struct Client *client)
{
	struct AuthRequest *request = rb_bh_alloc(auth_heap);
	client->localClient->auth_request = request;
	request->client = client;
	request->dns_query = 0;
	request->authF = NULL;
	request->timeout = rb_time() + ConfigFileEntry.connect_timeout;
	return request;
}

/*
 * free_auth_request - cleanup auth request allocations
 */
static void
free_auth_request(struct AuthRequest *request)
{
	rb_bh_free(auth_heap, request);
}

/*
 * release_auth_client - release auth client from auth system
 * this adds the client into the local client lists so it can be read by
 * the main io processing loop
 */
static void
release_auth_client(struct AuthRequest *auth)
{
	struct Client *client = auth->client;

	if(IsDNS(auth) || IsAuth(auth))
		return;

	client->localClient->auth_request = NULL;
	rb_dlinkDelete(&auth->node, &auth_poll_list);
	free_auth_request(auth);

	/*
	 * When a client has auth'ed, we want to start reading what it sends
	 * us. This is what read_packet() does.
	 *     -- adrian
	 */
	client->localClient->allow_read = MAX_FLOOD;
	rb_dlinkAddTail(client, &client->node, &global_client_list);
	read_packet(client->localClient->F, client);
}

/*
 * auth_dns_callback - called when resolver query finishes
 * if the query resulted in a successful search, hp will contain
 * a non-null pointer, otherwise hp will be null.
 * set the client on it's way to a connection completion, regardless
 * of success of failure
 */
static void
auth_dns_callback(const char *res, int status, int aftype, void *data)
{
	struct AuthRequest *auth = data;
	ClearDNS(auth);
	auth->dns_query = 0;
	/* The resolver has a higher limit. */
	if(status == 1 && strlen(res) >= sizeof(auth->client->host))
		status = 0, res = "HOSTTOOLONG";
	if(status == 1)
	{
		rb_strlcpy(auth->client->host, res, sizeof(auth->client->host));
		sendheader(auth->client, REPORT_FIN_DNS);
	}
	else
	{
		if(!strcmp(res, "HOSTTOOLONG"))
		{
			sendheader(auth->client, REPORT_HOST_TOOLONG);
		}
		sendheader(auth->client, REPORT_FAIL_DNS);
	}
	release_auth_client(auth);

}

/*
 * authsenderr - handle auth send errors
 */
static void
auth_error(struct AuthRequest *auth)
{
	ServerStats.is_abad++;

	if(auth->authF != NULL)
		rb_close(auth->authF);
	auth->authF = NULL;
	ClearAuth(auth);
	sendheader(auth->client, REPORT_FAIL_ID);
	release_auth_client(auth);
}



static void
auth_connect_callback(rb_fde_t *F, int status, void *data)
{
	struct AuthRequest *auth = data;
	char authbuf[32];

	if(status != RB_OK)
	{
		auth_error(auth);
		return;
	}

	/* one shot at the send, socket buffers should be able to handle it
	 * if not, oh well, you lose
	 */
	rb_snprintf(authbuf, sizeof(authbuf), "%d , %d\r\n", auth->rport, auth->lport);
	if(rb_write(auth->authF, authbuf, strlen(authbuf)) <= 0)
	{
		auth_error(auth);
		return;
	}
	read_auth(F, auth);
}


/*
 * start_auth_query - Flag the client to show that an attempt to 
 * contact the ident server on
 * the client's host.  The connect and subsequently the socket are all put
 * into 'non-blocking' mode.  Should the connect or any later phase of the
 * identifing process fail, it is aborted and the user is given a username
 * of "unknown".
 */
static void
start_auth_query(struct AuthRequest *auth)
{
	struct rb_sockaddr_storage *localaddr;
	struct rb_sockaddr_storage *remoteaddr;
	struct rb_sockaddr_storage destaddr;
	struct rb_sockaddr_storage bindaddr;
	int family;

	if(IsAnyDead(auth->client))
		return;

	sendheader(auth->client, REPORT_DO_ID);

	localaddr = auth->client->localClient->lip;
	remoteaddr = &auth->client->localClient->ip;

	family = GET_SS_FAMILY(remoteaddr);

	if((auth->authF = rb_socket(family, SOCK_STREAM, 0, "ident")) == NULL)
	{
		sendto_realops_flags(UMODE_DEBUG, L_ALL, "Error creating auth stream socket: %m");
		ilog(L_IOERROR, "creating auth stream socket %s: %m", auth->client->sockhost);
		auth_error(auth);
		return;
	}
	memcpy(&bindaddr, localaddr, sizeof(struct rb_sockaddr_storage));
	memcpy(&destaddr, remoteaddr, sizeof(struct rb_sockaddr_storage));
	
#ifdef RB_IPV6
	if(family == AF_INET6)
	{
		auth->lport = ntohs(((struct sockaddr_in6 *)localaddr)->sin6_port);
		auth->rport = ntohs(((struct sockaddr_in6 *)remoteaddr)->sin6_port);
		((struct sockaddr_in6 *)&bindaddr)->sin6_port = 0;
		((struct sockaddr_in6 *)&destaddr)->sin6_port = htons(113);

	}
	else
#endif
	{
		auth->lport = ntohs(((struct sockaddr_in *)localaddr)->sin_port);
		auth->rport = ntohs(((struct sockaddr_in *)remoteaddr)->sin_port);
		((struct sockaddr_in *)&bindaddr)->sin_port = 0;
		((struct sockaddr_in *)&destaddr)->sin_port = htons(113);
	}

	/* allocated in listener.c - after we copy this..we can discard it */
	rb_free(auth->client->localClient->lip);
	auth->client->localClient->lip = NULL;

	rb_connect_tcp(auth->authF, (struct sockaddr *)&destaddr, (struct sockaddr *)&bindaddr,
		       GET_SS_LEN(&destaddr), auth_connect_callback, auth,
		       GlobalSetOptions.ident_timeout);

	return;
}

static char *
GetValidIdent(char *xbuf)
{
	int remp = 0;
	int locp = 0;
	char *colon1Ptr;
	char *colon2Ptr;
	char *colon3Ptr;
	char *commaPtr;
	char *remotePortString;

	/* All this to get rid of a sscanf() fun. */
	remotePortString = xbuf;

	colon1Ptr = strchr(remotePortString, ':');
	if(!colon1Ptr)
		return NULL;

	*colon1Ptr = '\0';
	colon1Ptr++;
	colon2Ptr = strchr(colon1Ptr, ':');
	if(!colon2Ptr)
		return NULL;

	*colon2Ptr = '\0';
	colon2Ptr++;
	commaPtr = strchr(remotePortString, ',');

	if(!commaPtr)
		return NULL;

	*commaPtr = '\0';
	commaPtr++;

	remp = atoi(remotePortString);
	if(!remp)
		return NULL;

	locp = atoi(commaPtr);
	if(!locp)
		return NULL;

	/* look for USERID bordered by first pair of colons */
	if(!strstr(colon1Ptr, "USERID"))
		return NULL;

	colon3Ptr = strchr(colon2Ptr, ':');
	if(!colon3Ptr)
		return NULL;

	*colon3Ptr = '\0';
	colon3Ptr++;
	return (colon3Ptr);
}

/*
 * start_auth - starts auth (identd) and dns queries for a client
 */
void
start_auth(struct Client *client)
{
	struct AuthRequest *auth = 0;
	s_assert(0 != client);
	if(client == NULL)
		return;

	/* to aid bopm which needs something unique to match against */
	sendto_one(client, "NOTICE AUTH :*** Processing connection to %s", me.name);

	auth = make_auth_request(client);

	sendheader(client, REPORT_DO_DNS);

	rb_dlinkAdd(auth, &auth->node, &auth_poll_list);

	/* Note that the order of things here are done for a good reason
	 * if you try to do start_auth_query before lookup_ip there is a 
	 * good chance that you'll end up with a double free on the auth
	 * and that is bad.  But you still must keep the SetDNSPending 
	 * before the call to start_auth_query, otherwise you'll have
	 * the same thing.  So think before you hack 
	 */
	SetDNS(auth);		/* set both at the same time to eliminate possible race conditions */
	SetAuth(auth);
	if(ConfigFileEntry.disable_auth == 0)
	{
		start_auth_query(auth);
	}
	else {
		rb_free(client->localClient->lip);
		client->localClient->lip = NULL;
		ClearAuth(auth);
	}
	auth->dns_query =
		lookup_ip(client->sockhost, GET_SS_FAMILY(&client->localClient->ip),
			  auth_dns_callback, auth);
}

/*
 * timeout_auth_queries - timeout resolver and identd requests
 * allow clients through if requests failed
 */
static void
timeout_auth_queries_event(void *notused)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	struct AuthRequest *auth;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, auth_poll_list.head)
	{
		auth = ptr->data;

		if(auth->timeout < rb_time())
		{
			if(auth->authF != NULL)
			{
				rb_close(auth->authF);
				auth->authF = NULL;
			}
			if(IsAuth(auth))
			{
				ClearAuth(auth);
				ServerStats.is_abad++;
				sendheader(auth->client, REPORT_FAIL_ID);
			}
			if(IsDNS(auth))
			{
				ClearDNS(auth);
				cancel_lookup(auth->dns_query);
				auth->dns_query = 0;
				sendheader(auth->client, REPORT_FAIL_DNS);
			}

			auth->client->localClient->lasttime = rb_time();
			release_auth_client(auth);
		}
	}
	return;
}




#define AUTH_BUFSIZ 128
static void
read_auth(rb_fde_t *F, void *data)
{
	struct AuthRequest *auth = data;
	char *s = NULL, *t;
	char buf[AUTH_BUFSIZ + 1];
	int len, count;

	len = rb_read(auth->authF, buf, AUTH_BUFSIZ);

	if(len < 0 && rb_ignore_errno(errno))
	{
		rb_setselect(F, RB_SELECT_READ, read_auth, auth);
		return;
	}

	if(len > 0)
	{
		buf[len] = '\0';
		if((s = GetValidIdent(buf)))
		{
			t = auth->client->username;
			while(*s == '~' || *s == '^')
				s++;
			for(count = USERLEN; *s && count; s++)
			{
				if(*s == '@')
					break;
				if(!isspace(*s) && *s != ':' && *s != '[')
				{
					*t++ = *s;
					count--;
				}
			}
			*t = '\0';
		}
	}

	rb_close(auth->authF);
	auth->authF = NULL;
	ClearAuth(auth);

	if(s == NULL)
	{
		++ServerStats.is_abad;
		rb_strlcpy(auth->client->username, "unknown", sizeof(auth->client->username));
		sendheader(auth->client, REPORT_FAIL_ID);
	}
	else
	{
		sendheader(auth->client, REPORT_FIN_ID);
		++ServerStats.is_asuc;
		SetGotId(auth->client);
	}

	release_auth_client(auth);
}

/* this assumes the client is closing */
void
delete_auth_queries(struct Client *target_p)
{
	struct AuthRequest *auth;
	if(target_p == NULL || target_p->localClient == NULL
	   || target_p->localClient->auth_request == NULL)
		return;
	auth = target_p->localClient->auth_request;
	target_p->localClient->auth_request = NULL;

	if(IsDNS(auth) && auth->dns_query > 0)
	{
		cancel_lookup(auth->dns_query);
		auth->dns_query = 0;
	}


	if(auth->authF != NULL)
		rb_close(auth->authF);

	rb_dlinkDelete(&auth->node, &auth_poll_list);
	free_auth_request(auth);
}
