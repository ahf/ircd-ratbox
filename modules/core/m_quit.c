/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_quit.c: Makes a user quit from IRC.
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
 *  $Id: m_quit.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"

static int m_quit(struct Client *, struct Client *, int, const char **);
static int mr_quit(struct Client *, struct Client *, int, const char **);
static int ms_quit(struct Client *, struct Client *, int, const char **);

struct Message quit_msgtab = {
	"QUIT", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{{mr_quit, 0}, {m_quit, 0}, {ms_quit, 0}, mg_ignore, mg_ignore, {m_quit, 0}}
};

mapi_clist_av2 quit_clist[] = { &quit_msgtab, NULL };

DECLARE_MODULE_AV2(quit, NULL, NULL, quit_clist, NULL, NULL, "$Revision: 27173 $");


static int
mr_quit(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	exit_client(client_p, source_p, source_p, "Client Quit");
	return 0;
}

/*
** m_quit
**      parv[1] = comment
*/
static int
m_quit(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char *comment = LOCAL_COPY_N((parc > 1 && parv[1]) ? parv[1] : client_p->name, REASONLEN);
	char reason[REASONLEN + 1];

	source_p->flags |= FLAGS_NORMALEX;

	if(ConfigFileEntry.client_exit && comment[0])
	{
		rb_snprintf(reason, sizeof(reason), "Quit: %s", comment);
		comment = reason;
	}

	if(!IsOper(source_p) &&
	   (source_p->localClient->firsttime + ConfigFileEntry.anti_spam_exit_message_time) >
	   rb_time())
	{
		exit_client(client_p, source_p, source_p, "Client Quit");
		return 0;
	}

	exit_client(client_p, source_p, source_p, comment);

	return 0;
}

/*
** ms_quit
**      parv[1] = comment
*/
static int
ms_quit(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char *comment = LOCAL_COPY_N((parc > 1 && parv[1]) ? parv[1] : client_p->name, REASONLEN);

	source_p->flags |= FLAGS_NORMALEX;
	exit_client(client_p, source_p, source_p, comment);

	return 0;
}
