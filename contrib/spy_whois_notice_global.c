/*
 *  ircd-ratbox: A slightly useful ircd.
 *  spy_whois_notice.c: Sends a notice when someone uses WHOIS.
 *
 *  Copyright (C) 2002 by the past and present ircd coders, and others.
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
 *  $Id: spy_whois_notice_global.c 26377 2009-01-05 18:51:12Z androsyn $
 */
#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"

void show_whois_global(hook_data_client *);

mapi_hfn_list_av2 whois_global_hfnlist[] = {
	{"doing_whois_global", (hookfn) show_whois_global},
	{NULL, NULL}
};

DECLARE_MODULE_AV2(whois_global_spy, NULL, NULL, NULL, NULL, whois_global_hfnlist,
		   "$Revision: 26377 $");

void
show_whois_global(hook_data_client * data)
{
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;

	if(MyClient(target_p) && IsOper(target_p) && (source_p != target_p) &&
	   (target_p->umodes & UMODE_SPY))
	{
		sendto_one(target_p,
			   ":%s NOTICE %s :*** Notice -- %s (%s@%s) is doing a whois on you [%s]",
			   me.name, target_p->name, source_p->name,
			   source_p->username, source_p->host, source_p->servptr->name);
	}
}
