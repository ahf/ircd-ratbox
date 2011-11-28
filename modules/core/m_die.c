/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_die.c: Kills off this server.
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
 *  $Id: m_die.c 26377 2009-01-05 18:51:12Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "ircd.h"
#include "match.h"
#include "numeric.h"
#include "s_log.h"
#include "s_conf.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "s_newconf.h"

static int mo_die(struct Client *, struct Client *, int, const char **);

static struct Message die_msgtab = {
	"DIE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_die, 0}}
};

mapi_clist_av2 die_clist[] = { &die_msgtab, NULL };

DECLARE_MODULE_AV2(die, NULL, NULL, die_clist, NULL, NULL, "$Revision: 26377 $");

/*
 * mo_die - DIE command handler
 */
static int
mo_die(struct Client *client_p __unused, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsOperDie(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "die");
		return 0;
	}

	if(parc < 2 || EmptyString(parv[1]))
	{
		sendto_one_notice(source_p, ":Need server name /die %s", me.name);
		return 0;
	}
	else if(irccmp(parv[1], me.name))
	{
		sendto_one(source_p, ":Mismatch on /die %s", me.name);
		return 0;
	}

	ircd_shutdown(get_client_name(source_p, HIDE_IP));

	/* NOT REACHED */
	return 0;
}
