/*
 *   Copyright (C) infinity-infinity God <God@Heaven>
 *
 *   Bob was here 
 *   $Id: m_42.c 26377 2009-01-05 18:51:12Z androsyn $
 */

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "parse.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"

static int mclient_42(struct Client *client_p, struct Client *source_p, int parc,
		      const char *parv[]);
static int mclient_kilroy(struct Client *client_p, struct Client *source_p, int parc,
			  const char *parv[]);

struct Message hgtg_msgtab = {
	"42", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, {mclient_42, 0}, mg_ignore, mg_ignore, mg_ignore, {mclient_42, 0}
	 }
};

struct Message kilroy_msgtab = {
	"KILROY", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, {mclient_kilroy, 0}, mg_ignore, mg_ignore, mg_ignore, {mclient_kilroy, 0}
	 }
};


mapi_clist_av2 hgtg_clist[] = { &hgtg_msgtab, &kilroy_msgtab, NULL };


DECLARE_MODULE_AV2(42, NULL, NULL, hgtg_clist, NULL, NULL, "Revision 0.42");


static int
mclient_42(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	sendto_one(source_p, ":%s NOTICE %s :The Answer to Life, the Universe, and Everything.",
		   me.name, source_p->name);
	return 0;
}

static int
mclient_kilroy(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	SetCork(source_p);
	sendto_one(source_p, ":%s NOTICE %s :                ___              ", me.name,
		   source_p->name);
	sendto_one(source_p, ":%s NOTICE %s :___________mm__(O O)__mm_________", me.name,
		   source_p->name);
	sendto_one(source_p, ":%s NOTICE %s :           \"\"    U    \"\"         ", me.name,
		   source_p->name);
	ClearCork(source_p);
	sendto_one(source_p, ":%s NOTICE %s :Kilroy was here", me.name, source_p->name);
	return 0;
}
