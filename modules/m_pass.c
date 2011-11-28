/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_pass.c: Used to send a password for a server or client{} block.
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
 *  $Id: m_pass.c 26453 2009-02-15 22:52:33Z jilles $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"		/* client struct */
#include "match.h"
#include "send.h"		/* sendto_one */
#include "ircd.h"		/* me */
#include "parse.h"
#include "modules.h"
#include "s_serv.h"
#include "s_conf.h"

static int mr_pass(struct Client *, struct Client *, int, const char **);

struct Message pass_msgtab = {
	"PASS", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{{mr_pass, 2}, mg_reg, mg_ignore, mg_ignore, mg_ignore, mg_reg}
};

mapi_clist_av2 pass_clist[] = { &pass_msgtab, NULL };

DECLARE_MODULE_AV2(pass, NULL, NULL, pass_clist, NULL, NULL, "$Revision: 26453 $");

/*
 * m_pass() - Added Sat, 4 March 1989
 *
 *
 * mr_pass - PASS message handler
 *      parv[1] = password
 *      parv[2] = "TS" if this server supports TS.
 *      parv[3] = optional TS version field -- needed for TS6
 */
static int
mr_pass(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(client_p->localClient->passwd)
	{
		memset(client_p->localClient->passwd, 0, strlen(client_p->localClient->passwd));
		rb_free(client_p->localClient->passwd);
	}

	client_p->localClient->passwd = rb_strndup(parv[1], PASSWDLEN);

	if(parc > 2)
	{
		/* 
		 * It looks to me as if orabidoo wanted to have more
		 * than one set of option strings possible here...
		 * i.e. ":AABBTS" as long as TS was the last two chars
		 * however, as we are now using CAPAB, I think we can
		 * safely assume if there is a ":TS" then its a TS server
		 * -Dianora
		 */
		if(irccmp(parv[2], "TS") == 0 && client_p->tsinfo == 0)
			client_p->tsinfo = TS_DOESTS;

		if(parc == 5 && atoi(parv[3]) >= 6)
		{
			/* only mark as TS6 if the SID is valid.. */
			if(IsDigit(parv[4][0]) && IsIdChar(parv[4][1]) &&
			   IsIdChar(parv[4][2]) && parv[4][3] == '\0')
			{
				client_p->localClient->caps |= CAP_TS6;
				strcpy(client_p->id, parv[4]);
			}
		}
	}

	return 0;
}
