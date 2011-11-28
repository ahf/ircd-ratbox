/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_rehash.c: Re-reads the configuration file.
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
 *  $Id: m_rehash.c 26594 2009-06-12 15:38:09Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "match.h"
#include "ratbox_lib.h"
#include "ircd.h"
#include "s_gline.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "dns.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "hostmask.h"
#include "reject.h"
#include "hash.h"
#include "cache.h"
#include "s_auth.h"

static int mo_rehash(struct Client *, struct Client *, int, const char **);

struct Message rehash_msgtab = {
	"REHASH", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_rehash, 0}}
};

mapi_clist_av2 rehash_clist[] = { &rehash_msgtab, NULL };

DECLARE_MODULE_AV2(rehash, NULL, NULL, rehash_clist, NULL, NULL, "$Revision: 26594 $");

struct hash_commands
{
	const char *cmd;
	void (*handler) (struct Client * source_p);
};

static void
rehash_bans_loc(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is rehashing bans", get_oper_name(source_p));

	rehash_bans(0);
}

static void
rehash_dns(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is rehashing DNS", get_oper_name(source_p));

	rehash_resolver();
}

static void
rehash_motd(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s is forcing re-reading of MOTD file", get_oper_name(source_p));

	cache_user_motd();
}

static void
rehash_omotd(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s is forcing re-reading of OPER MOTD file", get_oper_name(source_p));

	free_cachefile(oper_motd);
	oper_motd = cache_file(OPATH, "opers.motd", 0);
}

static void
rehash_glines(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr, *next_ptr;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing G-lines", get_oper_name(source_p));

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, glines.head)
	{
		aconf = ptr->data;

		delete_one_address_conf(aconf->host, aconf);
		rb_dlinkDestroy(ptr, &glines);
	}
}

static void
rehash_pglines(struct Client *source_p)
{
	struct gline_pending *glp_ptr;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing pending glines",
			     get_oper_name(source_p));

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, pending_glines.head)
	{
		glp_ptr = ptr->data;

		rb_free(glp_ptr->reason1);
		rb_free(glp_ptr->reason2);
		rb_free(glp_ptr);
		rb_dlinkDestroy(ptr, &pending_glines);
	}
}

static void
rehash_tklines(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr, *next_ptr;
	int i;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing temp klines",
			     get_oper_name(source_p));

	for(i = 0; i < LAST_TEMP_TYPE; i++)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, temp_klines[i].head)
		{
			aconf = ptr->data;

			delete_one_address_conf(aconf->host, aconf);
			rb_dlinkDestroy(ptr, &temp_klines[i]);
		}
	}
}

static void
rehash_tdlines(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr, *next_ptr;
	int i;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing temp dlines",
			     get_oper_name(source_p));

	for(i = 0; i < LAST_TEMP_TYPE; i++)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, temp_dlines[i].head)
		{
			aconf = ptr->data;
			remove_dline(aconf);
			rb_dlinkDestroy(ptr, &temp_dlines[i]);
		}
	}
}

static void
rehash_txlines(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing temp xlines",
			     get_oper_name(source_p));

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, xline_conf_list.head)
	{
		aconf = ptr->data;

		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			continue;

		free_conf(aconf);
		rb_dlinkDestroy(ptr, &xline_conf_list);
	}
}

static void
rehash_tresvs(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	int i;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing temp resvs",
			     get_oper_name(source_p));

	HASH_WALK_SAFE(i, R_MAX, ptr, next_ptr, resvTable)
	{
		aconf = ptr->data;

		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			continue;

		free_conf(aconf);
		rb_dlinkDestroy(ptr, &resvTable[i]);
	}
	HASH_WALK_END RB_DLINK_FOREACH_SAFE(ptr, next_ptr, resv_conf_list.head)
	{
		aconf = ptr->data;

		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			continue;

		free_conf(aconf);
		rb_dlinkDestroy(ptr, &resv_conf_list);
	}
}

static void
rehash_rejectcache(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is clearing reject cache",
			     get_oper_name(source_p));
	flush_reject();

}

static void
rehash_help(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s is forcing re-reading of HELP files", get_oper_name(source_p));
	clear_help_hash();
	load_help();
}

/* *INDENT-OFF* */
static struct hash_commands rehash_commands[] =
{
	{"BANS",	rehash_bans_loc		},
	{"DNS", 	rehash_dns		},
	{"MOTD", 	rehash_motd		},
	{"OMOTD", 	rehash_omotd		},
	{"GLINES", 	rehash_glines		},
	{"PGLINES", 	rehash_pglines		},
	{"TKLINES", 	rehash_tklines		},
	{"TDLINES", 	rehash_tdlines		},
	{"TXLINES",	rehash_txlines		},
	{"TRESVS",	rehash_tresvs		},
	{"REJECTCACHE",	rehash_rejectcache	},
	{"HELP", 	rehash_help		},
	{NULL, 		NULL 			}
};
/* *INDENT-ON* */

/*
 * mo_rehash - REHASH message handler
 *
 */
static int
mo_rehash(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsOperRehash(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "rehash");
		return 0;
	}

	if(parc > 1)
	{
		int x;
		char cmdbuf[100];

		for(x = 0; rehash_commands[x].cmd != NULL && rehash_commands[x].handler != NULL;
		    x++)
		{
			if(irccmp(parv[1], rehash_commands[x].cmd) == 0)
			{
				sendto_one(source_p, form_str(RPL_REHASHING), me.name,
					   source_p->name, rehash_commands[x].cmd);
				rehash_commands[x].handler(source_p);
				ilog(L_MAIN, "REHASH %s From %s[%s]", parv[1],
				     get_oper_name(source_p), source_p->sockhost);
				return 0;
			}
		}

		/* We are still here..we didn't match */
		cmdbuf[0] = '\0';
		for(x = 0; rehash_commands[x].cmd != NULL && rehash_commands[x].handler != NULL;
		    x++)
		{
			rb_snprintf_append(cmdbuf, sizeof(cmdbuf), " %s", rehash_commands[x].cmd);
		}
		sendto_one_notice(source_p, ":rehash one of:%s", cmdbuf);
	}
	else
	{
		sendto_one(source_p, form_str(RPL_REHASHING), me.name, source_p->name,
			   ConfigFileEntry.configfile);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s is rehashing server config file", get_oper_name(source_p));
		ilog(L_MAIN, "REHASH From %s[%s]", get_oper_name(source_p), source_p->sockhost);
		rehash(0);
		return 0;
	}

	return 0;
}
