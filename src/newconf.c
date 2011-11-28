/*
 *  ircd-ratbox: A slightly useful ircd.
 *  newconf.c: Our new two-pass config file mangler
 *
 *  Copyright (C) 2007 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2007 ircd-ratbox development team
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
 *  $Id: newconf.c 27293 2011-11-01 21:24:10Z jilles $               
 * 
 */


#include "ratbox_lib.h"
#include "stdinc.h"
#ifdef USE_CHALLENGE
#include <openssl/pem.h>
#include <openssl/rsa.h>
#endif


#include "struct.h"
#include "client.h"
#include "s_log.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_newconf.h"
#include "hostmask.h"
#include "send.h"
#include "ircd.h"
#include "newconf.h"
#include "modules.h"
#include "match.h"
#include "class.h"
#include "listener.h"
#include "cache.h"
#include "reject.h"
#include "channel.h"
#include "hash.h"
#include "sslproc.h"
#include "blacklist.h"

#define CF_TYPE(x) ((x) & CF_MTYPE)


FILE *conf_fbfile_in;
char conffilebuf[IRCD_BUFSIZE + 1];
extern int conf_parse_failure;
static rb_dlink_list conflist;
static conf_t *curconf;

extern char *current_file;

typedef struct _valid_entry
{
	rb_dlink_node node;
	char *name;
	int type;
} valid_entry_t;


typedef struct _valid_block
{
	char *name;
	rb_dlink_list valid_entries;
	rb_dlink_node node;
	int needsub;
} valid_block_t;


struct topconf
{
	rb_dlink_node node;
	char *tc_name;
	void (*start_func) (conf_t *);
	void (*end_func) (conf_t *);
	int needsub;
	struct conf_items *itemtable;
};

static rb_dlink_list toplist;
static rb_dlink_list valid_blocks;

static const char *
conf_strtype(int type)
{
	switch (type & CF_MTYPE)
	{
	case CF_INT:
		return "integer value";
	case CF_STRING:
		return "unquoted string";
	case CF_YESNO:
		return "yes/no value";
	case CF_QSTRING:
		return "quoted string";
	case CF_TIME:
		return "time/size value";
	default:
		return "unknown type";
	}
}

struct mode_table
{
	const char *name;
	int mode;
};

/* *INDENT-OFF* */
static struct mode_table umode_table[] = {
	{"bots",	UMODE_BOTS	},
	{"cconn",	UMODE_CCONN	},
	{"cconnext",	UMODE_CCONNEXT	},
	{"debug",	UMODE_DEBUG	},
	{"full",	UMODE_FULL	},
	{"callerid",	UMODE_CALLERID	},
	{"invisible",	UMODE_INVISIBLE	},
	{"skill",	UMODE_SKILL	},
	{"locops",	UMODE_LOCOPS	},
	{"nchange",	UMODE_NCHANGE	},
	{"rej",		UMODE_REJ	},
	{"servnotice",	UMODE_SERVNOTICE},
	{"unauth",	UMODE_UNAUTH	},
	{"wallop",	UMODE_WALLOP	},
	{"external",	UMODE_EXTERNAL	},
	{"spy",		UMODE_SPY	},
	{"operwall",	UMODE_OPERWALL	},
	{"operspy",	UMODE_OPERSPY	},
	{NULL, 0}
};

static struct mode_table flag_table[] = {
	{"encrypted",		OPER_ENCRYPTED		},
	{"local_kill",		OPER_LOCKILL		},
	{"global_kill",		OPER_GLOBKILL|OPER_LOCKILL	},
	{"remote",		OPER_REMOTE		},
	{"kline",		OPER_KLINE		},
	{"unkline",		OPER_UNKLINE		},
	{"gline",		OPER_GLINE		},
	{"nick_changes",	OPER_NICKS		},
	{"rehash",		OPER_REHASH		},
	{"die",			OPER_DIE		},
	{"admin",		OPER_ADMIN		},
	{"hidden_admin",	OPER_HADMIN		},
	{"xline",		OPER_XLINE		},
	{"resv",		OPER_RESV		},
	{"operwall",		OPER_OPERWALL		},
	{"oper_spy",		OPER_SPY		},
	{"hidden_oper",		OPER_INVIS		},
	{"remoteban",		OPER_REMOTEBAN		},
	{"need_ssl",		OPER_NEEDSSL		},
	{NULL, 0}
};

static struct mode_table auth_table[] = {
	{"encrypted",		CONF_FLAGS_ENCRYPTED	},
	{"spoof_notice",	CONF_FLAGS_SPOOF_NOTICE	},
	{"exceed_limit",	CONF_FLAGS_NOLIMIT	},
	{"kline_exempt",	CONF_FLAGS_EXEMPTKLINE	},
	{"gline_exempt",	CONF_FLAGS_EXEMPTGLINE	},
	{"flood_exempt",	CONF_FLAGS_EXEMPTFLOOD	},
	{"spambot_exempt",	CONF_FLAGS_EXEMPTSPAMBOT },
	{"shide_exempt",	CONF_FLAGS_EXEMPTSHIDE	},
	{"jupe_exempt",		CONF_FLAGS_EXEMPTJUPE	},
	{"resv_exempt",		CONF_FLAGS_EXEMPTRESV	},
	{"no_tilde",		CONF_FLAGS_NO_TILDE	},
	{"need_ident",		CONF_FLAGS_NEED_IDENTD	},
	{"have_ident",		CONF_FLAGS_NEED_IDENTD	},
	{"need_ssl", 		CONF_FLAGS_NEED_SSL	},
	{"dnsbl_exempt",	CONF_FLAGS_EXEMPTDNSBL	},
	{NULL, 0}
};

static struct mode_table connect_table[] = {
	{ "autoconn",	SERVER_AUTOCONN		},
	{ "compressed",	SERVER_COMPRESSED	},
	{ "encrypted",	SERVER_ENCRYPTED	},
	{ "ssl",	SERVER_SSL		},
	{ "topicburst",	SERVER_TB		},
	{ NULL,		0			},
};


static struct mode_table cluster_table[] = {
	{ "kline",	SHARED_PKLINE	},
	{ "tkline",	SHARED_TKLINE	},
	{ "unkline",	SHARED_UNKLINE	},
	{ "locops",	SHARED_LOCOPS	},
	{ "xline",	SHARED_PXLINE	},
	{ "txline",	SHARED_TXLINE	},
	{ "unxline",	SHARED_UNXLINE	},
	{ "resv",	SHARED_PRESV	},
	{ "tresv",	SHARED_TRESV	},
	{ "unresv",	SHARED_UNRESV	},
	{ "all",	CLUSTER_ALL	},
	{NULL, 0}
};

static struct mode_table shared_table[] =
{
	{ "kline",	SHARED_PKLINE|SHARED_TKLINE	},
	{ "xline",	SHARED_PXLINE|SHARED_TXLINE	},
	{ "resv",	SHARED_PRESV|SHARED_TRESV	},
	{ "tkline",	SHARED_TKLINE	},
	{ "unkline",	SHARED_UNKLINE	},
	{ "txline",	SHARED_TXLINE	},
	{ "unxline",	SHARED_UNXLINE	},
	{ "tresv",	SHARED_TRESV	},
	{ "unresv",	SHARED_UNRESV	},
	{ "locops",	SHARED_LOCOPS	},
	{ "all",	SHARED_ALL	},
	{ "none",	0		},
	{NULL, 0}
};
/* *INDENT-ON* */


static void
conf_report_error_nl(const char *fmt, ...)
{
	va_list ap;
	char msg[IRCD_BUFSIZE + 1];

	va_start(ap, fmt);
	rb_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	conf_parse_failure++;
	if(testing_conf)
	{
		fprintf(stderr, "ERROR: %s\n", msg);
		return;
	}

	ilog(L_MAIN, "ERROR: %s", msg);
	sendto_realops_flags(UMODE_ALL, L_ALL, "ERROR: %s", msg);
}

static void
conf_report_warning_nl(const char *fmt, ...)
{
	va_list ap;
	char msg[IRCD_BUFSIZE + 1];

	va_start(ap, fmt);
	rb_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if(testing_conf)
	{
		fprintf(stderr, "Warning: %s\n", msg);
		return;
	}

	ilog(L_MAIN, "Warning: %s", msg);
	sendto_realops_flags(UMODE_ALL, L_ALL, "Warning: %s", msg);
}


static int
find_umode(struct mode_table *tab, const char *name)
{
	int i;

	for(i = 0; tab[i].name; i++)
	{
		if(strcmp(tab[i].name, name) == 0)
			return tab[i].mode;
	}

	return -1;
}

static void
set_modes_from_table(int *modes, const char *whatis, struct mode_table *tab, confentry_t * entry)
{
	rb_dlink_node *ptr;
	confentry_t *sub;
	const char *umode;
	int dir, mode;

	RB_DLINK_FOREACH(ptr, entry->flist.head)
	{
		sub = ptr->data;
		dir = 1;
		umode = sub->string;
		if(*umode == '~')
		{
			dir = 0;
			umode++;
		}

		mode = find_umode(tab, umode);
		if(mode == -1)
		{
			conf_report_warning_nl("Unknown flag %s %s", whatis,
					       sub->string);
			continue;
		}

		if(mode)
		{
			if(dir)
				*modes |= mode;
			else
				*modes &= ~mode;
		}
		else
			*modes = 0;
	}

}

static conf_t *
make_conf_block(const char *blockname)
{
	conf_t *conf;
	conf = rb_malloc(sizeof(conf_t));
	conf->confname = rb_strdup(blockname);
	rb_dlinkAddTail(conf, &conf->node, &conflist);
	return (conf);
}

static void
add_entry(conf_t * conf, const char *name, void *value, int type)
{
	confentry_t *entry = rb_malloc(sizeof(confentry_t));
	if(name == NULL)
	{
		return;
	}
	entry->entryname = rb_strdup(name);
	entry->line = lineno;
	entry->filename = rb_strdup(current_file);
	switch (CF_TYPE(type))
	{

	case CF_YESNO:
		if((long)value == 1)
			entry->string = rb_strdup("yes");
		else
			entry->string = rb_strdup("no");
	case CF_INT:
	case CF_TIME:
		entry->number = (long)value;
		entry->type = type;
		break;
	case CF_STRING:
	case CF_QSTRING:
		entry->string = rb_strdup(value);
		entry->type = type;
		break;
	default:
		rb_free(entry);
		return;
	}
	rb_dlinkAddTail(entry, &entry->node, &conf->entries);

	/* must use rb_malloc here as we are running too early
	 * to use rb_dlinkAddAlloc as the block heap isn't ready
	 * yet 
	 */
	rb_dlinkAdd(entry, rb_malloc(sizeof(rb_dlink_node)), &entry->flist);

}

static void
del_entry(conf_t * conf, confentry_t * entry)
{
	rb_dlink_node *ptr, *next;
	confentry_t *xentry;
	if(entry->type & CF_FLIST)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next, entry->flist.head)
		{
			xentry = ptr->data;
			switch (CF_TYPE(xentry->type))
			{
			case CF_STRING:
			case CF_QSTRING:
			case CF_YESNO:
				rb_free(xentry->string);
			default:
				break;
			}
			rb_dlinkDelete(&xentry->node, &entry->flist);
		}
	}
	else
	{
		ptr = entry->flist.head;
		rb_dlinkDelete(ptr, &entry->flist);
		rb_free(ptr);
	}
	switch (CF_TYPE(entry->type))
	{
	case CF_STRING:
	case CF_QSTRING:
	case CF_YESNO:
		rb_free(entry->string);
	default:
		break;
	}
	rb_free(entry->filename);
	rb_dlinkDelete(&entry->node, &conf->entries);

	rb_free(entry);
}


static void
del_conf(conf_t * conf)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, conf->entries.head)
	{
		confentry_t *entry = ptr->data;
		del_entry(conf, entry);
	}
	rb_free(conf->confname);
	rb_free(conf->filename);
	rb_dlinkDelete(&conf->node, &conflist);
	rb_free(conf);
}



void
delete_all_conf(void)
{
	rb_dlink_node *ptr, *next;

	RB_DLINK_FOREACH_SAFE(ptr, next, conflist.head)
	{
		conf_t *conf = ptr->data;
		del_conf(conf);
	}
}


static char *
strip_tabs(char *dest, const char *src, size_t len)
{
	char *d = dest;

	if(dest == NULL || src == NULL)
		return NULL;

	rb_strlcpy(dest, src, len);

	while(*d)
	{
		if(*d == '\t')
			*d = ' ';
		d++;
	}
	return dest;
}

/*
 * yyerror
 *
 * inputs	- message from parser
 * output	- none
 * side effects	- message to opers and log file entry is made
 */
void
yyerror(const char *msg)
{
	char newlinebuf[IRCD_BUFSIZE];

	strip_tabs(newlinebuf, linebuf, sizeof(newlinebuf));
	conf_parse_failure++;

	if(testing_conf)
	{
		fprintf(stderr, "\"%s\", line %d: %s\n", current_file, lineno + 1, msg);
		return;
	}

	sendto_realops_flags(UMODE_ALL, L_ALL, "\"%s\", line %d: %s at '%s'", conffilebuf,
			     lineno + 1, msg, newlinebuf);

	ilog(L_MAIN, "\"%s\", line %d: %s at '%s'", conffilebuf, lineno + 1, msg, newlinebuf);
}

int
conf_fgets(char *lbuf, int max_size, FILE * fb)
{
	char *p;

	if(fgets(lbuf, max_size, fb) == NULL)
		return (0);

	if((p = strpbrk(lbuf, "\r\n")) != NULL)
	{
		*p++ = '\n';
		*p = '\0';
	}
	return (strlen(lbuf));
}

int
conf_yy_fatal_error(const char *msg)
{
	conf_report_error("conf_yy_fatal_error: %s", msg);
	return (0);
}


void
conf_report_error(const char *fmt, ...)
{
	va_list ap;
	char msg[IRCD_BUFSIZE + 1];

	va_start(ap, fmt);
	rb_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	conf_parse_failure++;
	if(testing_conf)
	{
		fprintf(stderr, "\"%s\", line %d: %s\n", current_file, lineno + 1, msg);
		return;
	}

	ilog(L_MAIN, "\"%s\", line %d: %s", current_file, lineno + 1, msg);
	sendto_realops_flags(UMODE_ALL, L_ALL, "\"%s\", line %d: %s", current_file, lineno + 1,
			     msg);
}


int
conf_start_block(char *block, char *name)
{
	conf_t *conf;
	if(curconf != NULL)
	{
		conf_report_error("\"%s\", Previous block \"%s\" never closed", conffilebuf,
				  curconf->confname);
		return 1;
	}
	conf = make_conf_block(block);
	if(name != NULL)
		conf->subname = rb_strdup(name);
	conf->line = lineno;
	conf->filename = rb_strdup(current_file);
	curconf = conf;
	return 0;
}


int
conf_end_block(void)
{
	if(curconf != NULL)
	{
		curconf = NULL;
	}
	return 0;
}

// add_entry(conf_t *conf, const char *name, void *value, int type)

static void
add_entry_flist(conf_t * conf, const char *name, conf_parm_t * cp)
{
	confentry_t *entry = rb_malloc(sizeof(confentry_t));
	confentry_t *sub;
	if(name == NULL)
	{
		return;
	}
	entry->entryname = rb_strdup(name);
	entry->line = lineno;
	entry->filename = rb_strdup(current_file);
	entry->type = cp->type | CF_FLIST;
	for(; cp != NULL; cp = cp->next)
	{
		sub = rb_malloc(sizeof(confentry_t));
		sub->entryname = rb_strdup(name);
		sub->line = lineno;
		sub->filename = rb_strdup(current_file);

		switch (CF_TYPE(cp->type))
		{
		case CF_YESNO:
			if((long)cp->v.number == 1)
				sub->string = rb_strdup("yes");
			else
				sub->string = rb_strdup("no");
		case CF_INT:
		case CF_TIME:
			sub->number = (long)cp->v.number;
			sub->type = cp->type;
			break;
		case CF_STRING:
		case CF_QSTRING:
			sub->string = rb_strdup(cp->v.string);
			sub->type = cp->type;
			break;
		default:
			rb_free(sub);
			return;
		}
		rb_dlinkAddTail(sub, &sub->node, &entry->flist);
	}

	rb_dlinkAddTail(entry, &entry->node, &conf->entries);
}

int
conf_call_set(char *item, conf_parm_t * value, int type)
{
	conf_parm_t *cp;
	cp = value->v.list;

	if(value->type & CF_FLIST)
	{
		add_entry_flist(curconf, item, value->v.list);
		return 0;
	}

	for(; cp != NULL; cp = cp->next)
	{
		switch (CF_TYPE(cp->type))
		{
		case CF_STRING:
		case CF_QSTRING:
			add_entry(curconf, item, (void *)cp->v.string, cp->type);
			break;
		case CF_TIME:
		case CF_INT:
		case CF_YESNO:
			add_entry(curconf, item, (void *)(unsigned long)cp->v.number, cp->type);
			break;
		case CF_LIST:
			break;
		default:
			break;

		}
	}

	return 0;
}

int
read_config_file(const char *filename)
{
	conf_parse_failure = 0;
	delete_all_conf();
	rb_strlcpy(conffilebuf, filename, sizeof(conffilebuf));
	if((conf_fbfile_in = fopen(filename, "r")) == NULL)
	{
		conf_report_error_nl("Unable to open file %s %m", filename);
		return 1;
	}
	yyparse();

	fclose(conf_fbfile_in);
	return conf_parse_failure;

}

static void
add_valid_block(const char *name, int needsub)
{
	valid_block_t *valid = rb_malloc(sizeof(valid_block_t));
	valid->name = rb_strdup(name);
	valid->needsub = needsub;
	rb_dlinkAdd(valid, &valid->node, &valid_blocks);
}

static valid_block_t *
find_valid_block(const char *name)
{
	valid_block_t *t;
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, valid_blocks.head)
	{
		t = ptr->data;
		if(!strcasecmp(t->name, name))
			return t;
	}
	return NULL;
}

static void
add_valid_entry(const char *bname, const char *entryname, int type)
{
	valid_block_t *b;
	valid_entry_t *e;
	b = find_valid_block(bname);
	if(b == NULL)
		return;
	e = rb_malloc(sizeof(valid_entry_t));
	e->name = rb_strdup(entryname);
	e->type = type;
	rb_dlinkAdd(e, &e->node, &b->valid_entries);
}

static int
check_valid_block(const char *name)
{
	rb_dlink_node *ptr;
	valid_block_t *t;
	RB_DLINK_FOREACH(ptr, valid_blocks.head)
	{
		t = ptr->data;
		if(!strcasecmp(t->name, name))
		{
			return 1;
		}
	}
	return 0;
}

int
check_valid_blocks(void)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, conflist.head)
	{
		conf_t *conf = ptr->data;
		if(!check_valid_block(conf->confname))
		{
			conf_report_warning_nl("Invalid block: %s at %s:%d", conf->confname,
					       conf->filename, conf->line);
			return 0;
		}

	}
	return 1;
}

static int
check_valid_entry(valid_block_t * vt, conf_t * conf, confentry_t * entry)
{
	rb_dlink_node *ptr, *xptr;
	RB_DLINK_FOREACH(ptr, vt->valid_entries.head)
	{
		valid_entry_t *ve = ptr->data;
		if(!strcasecmp(ve->name, entry->entryname))
		{
			if(entry->type & CF_FLIST && !(ve->type & CF_FLIST))
			{
				conf_report_error_nl
					("Option %s:%s at %s:%d does not take a list of values",
					 conf->confname, entry->entryname, entry->filename,
					 entry->line);
				return 0;
			}

			if(entry->type & CF_FLIST)
			{
				RB_DLINK_FOREACH(xptr, entry->flist.head)
				{
					confentry_t *xentry = xptr->data;
					if(CF_TYPE(xentry->type) != CF_TYPE(ve->type))
					{
						conf_report_error_nl
							("Option %s:%s at %s:%d takes type \"%s\" not \"%s\"",
							 conf->confname, ve->name, xentry->filename,
							 xentry->line, conf_strtype(ve->type),
							 conf_strtype(xentry->type));
						return 0;
					}
				}
				return 1;
			}

			if(CF_TYPE(entry->type) != CF_TYPE(ve->type))
			{
				if((CF_TYPE(entry->type) == CF_INT && CF_TYPE(ve->type) == CF_TIME)
				   || (CF_TYPE(entry->type) == CF_TIME
				       && CF_TYPE(ve->type) == CF_INT))
					return 1;

				if(CF_TYPE(entry->type) == CF_YESNO
				   && CF_TYPE(ve->type) == CF_STRING)
				{
					return 1;
				}
				conf_report_error_nl
					("Option %s:%s at %s:%d takes type \"%s\" not \"%s\"",
					 conf->confname, ve->name, entry->filename, entry->line,
					 conf_strtype(ve->type), conf_strtype(entry->type));
				return 0;
			}
			return 1;
		}
	}
	conf_report_warning_nl("Invalid entry: %s::%s at %s:%d", conf->confname, entry->entryname,
			       entry->filename, entry->line);
	return 2;
}

int
check_valid_entries(void)
{
	rb_dlink_node *ptr, *xptr;
	conf_t *conf;
	confentry_t *entry;
	valid_block_t *vt;
	int ret = 0;
	RB_DLINK_FOREACH(ptr, conflist.head)
	{
		conf = ptr->data;
		vt = find_valid_block(conf->confname);
		if(vt == NULL)
		{
			conf_report_warning_nl("Invalid block: %s at %s:%d", conf->confname,
					       conf->filename, conf->line);
			/* ret++; treat invalid blocks as warnings only */
			continue;
		}
		if(vt->needsub && conf->subname == NULL)
		{
			conf_report_error_nl("Block %s at %s:%d requires a name", conf->confname,
					     conf->filename, conf->line);
			ret++;
			continue;
		}
		if(!vt->needsub && conf->subname != NULL)
		{
			conf_report_warning_nl
				("Block %s at %s:%d does not require a name, but has one",
				 conf->confname, conf->filename, conf->line);
			/* ret++; treat this as a warning as well */
			continue;
		}
		RB_DLINK_FOREACH(xptr, conf->entries.head)
		{
			entry = xptr->data;
			if(entry->entryname == NULL)
				continue;
			if(!check_valid_entry(vt, conf, entry))
			{
				ret++;
			}
		}

	}
	return ret;

}

static void
conf_set_modules_path(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
#ifndef STATIC_MODULES
	mod_add_path(entry->string);
#else
	conf_report_warning_nl
		("Ignoring modules::path at %s:%d -- loadable module support not present",
		 entry->filename, entry->line);
#endif
}

static void
conf_set_modules_module(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
#ifndef STATIC_MODULES
	char *m_bn;

	m_bn = rb_basename(entry->string);

	if(findmodule_byname(m_bn) != -1)
		return;

	load_one_module(entry->string, 0);

	rb_free(m_bn);
#else
	conf_report_error
		("Ignoring modules::module at %s:%d -- loadable module support not present.",
		 entry->filename, entry->line);
#endif


}


static void
conf_set_generic_value_cb(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char **location = item->data;

	switch (CF_TYPE(entry->type))
	{
	case CF_INT:
	case CF_TIME:
	case CF_YESNO:
		*((int *)item->data) = entry->number;
		break;
	case CF_STRING:
	case CF_QSTRING:
		if(item->len)
			*location = rb_strndup(entry->string, item->len);
		else
			*location = rb_strdup(entry->string);
	}
}


static void
conf_set_serverinfo_name(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(ServerInfo.name == NULL)
	{
		if(!valid_servername(entry->string))
		{
			conf_report_error_nl("serverinfo::name -- Invalid servername at %s:%d", conf->filename, conf->line);
			conf_report_error_nl("cannot continue without a valid servername");
			exit(1);
		}

		if(IsDigit(*entry->string))
		{
			conf_report_error_nl("serverinfo::name -- cannot begin with digit at %s:%d", conf->filename, conf->line);
			conf_report_error_nl("cannot continue without a valid servername");
			exit(1);
		}

		/* the ircd will exit() in main() if we dont set one */
		if(strlen(entry->string) <= HOSTLEN)
			ServerInfo.name = rb_strdup(entry->string);
		return;
	}
}


static void
conf_set_serverinfo_network_name(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *p;

	if((p = strchr((char *)entry->string, ' ')))
		*p = '\0';

	rb_free(ServerInfo.network_name);
	ServerInfo.network_name = rb_strdup(entry->string);
}


static void
conf_set_serverinfo_vhost(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(rb_inet_pton(AF_INET, (char *)entry->string, &ServerInfo.ip.sin_addr) <= 0)
	{
		conf_report_warning_nl("Invalid netmask for server IPv4 vhost (%s)", entry->string);
		return;
	}
	ServerInfo.ip.sin_family = AF_INET;
	ServerInfo.specific_ipv4_vhost = 1;
}

static void
conf_set_serverinfo_vhost6(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
#ifdef RB_IPV6
	if(rb_inet_pton(AF_INET6, (char *)entry->string, &ServerInfo.ip6.sin6_addr) <= 0)
	{
		conf_report_error_nl("Invalid netmask for server IPv6 vhost (%s)", entry->string);
		return;
	}

	ServerInfo.specific_ipv6_vhost = 1;
	ServerInfo.ip6.sin6_family = AF_INET6;
#else
	conf_report_warning_nl
		("Ignoring serverinfo::vhost6 -- IPv6 support not available.");
#endif
}

static void
conf_set_serverinfo_vhost_dns(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct rb_sockaddr_storage addr;
	if(rb_inet_pton(AF_INET, (char *)entry->string, &addr) <= 0)
	{
		conf_report_warning_nl
			("Ignoring serverinfo::vhost_dns -- Invalid vhost (%s)",
			 entry->string);
		return;
	}
	rb_free(ServerInfo.vhost_dns);
	ServerInfo.vhost_dns = rb_strdup(entry->string);
}

#ifdef RB_IPV6
static void
conf_set_serverinfo_vhost6_dns(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct rb_sockaddr_storage addr;
	if(rb_inet_pton(AF_INET6, (char *)entry->string, &addr) <= 0)
	{
		conf_report_warning_nl
			("Ignoring serverinfo::vhost6_dns -- Invalid vhost (%s)",
			 entry->string);
		return;
	}
	rb_free(ServerInfo.vhost6_dns);
	ServerInfo.vhost6_dns = rb_strdup(entry->string);
}
#endif


static void
conf_set_serverinfo_sid(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *sid = entry->string;

	if(ServerInfo.sid[0] == '\0')
	{
		if(!IsDigit(sid[0]) || !IsIdChar(sid[1]) || !IsIdChar(sid[2]) || sid[3] != '\0')
		{
			conf_report_error_nl("Error serverinfo::sid -- invalid sid at %s:%d", conf->filename, conf->line);
			return;
		}

		strcpy(ServerInfo.sid, sid);
	}
}

static void
conf_set_serverinfo_bandb_path(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *path = entry->string;
	
	if(access(path, F_OK) == -1)
	{
		char *dirname, *d = rb_dirname(path);
		dirname = LOCAL_COPY(d);
		rb_free(d);

		if(access(dirname, W_OK) == -1)
		{
			conf_report_error_nl("Unable to access bandb %s: %m ignoring...", path);
			return;
		}
	} else {
		if(access(path, W_OK) == -1)
		{
			conf_report_error_nl("Unable to access bandb %s: %m ignoring...", path);
			return;
		}
	}		
	rb_free(ServerInfo.bandb_path);
	ServerInfo.bandb_path = rb_strdup(path);
}

static struct Class *t_class;
static void
conf_set_class_end(conf_t * conf)
{
	add_class(t_class);
	t_class = NULL;
}

static void
conf_set_class_start(conf_t * conf)
{
	t_class = make_class();
	t_class->class_name = rb_strdup(conf->subname);
}

static void
conf_set_class_ping_time(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->ping_freq = entry->number;
	return;
}

static void
conf_set_class_cidr_ipv4_bitlen(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	int maxsize = 32;
	t_class->cidr_ipv4_bitlen = entry->number;
	if(t_class->cidr_ipv4_bitlen > maxsize)
	{
		conf_report_warning_nl
			("class::cidr_ipv4_bitlen argument exceeds maxsize (%d > %d) - truncating to %d.",
			 t_class->cidr_ipv4_bitlen, maxsize, maxsize);
		t_class->cidr_ipv4_bitlen = 32;
	}
	return;
}

#ifdef RB_IPV6
static void
conf_set_class_cidr_ipv6_bitlen(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	int maxsize = 128;
	t_class->cidr_ipv6_bitlen = entry->number;
	if(t_class->cidr_ipv6_bitlen > maxsize)
	{
		conf_report_warning_nl
			("class::cidr_ipv6_bitlen argument exceeds maxsize (%d > %d) - truncating to %d.",
			 t_class->cidr_ipv6_bitlen, maxsize, maxsize);
		t_class->cidr_ipv6_bitlen = 128;
	}
	return;
}
#endif


static void
conf_set_class_number_per_cidr(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->cidr_amount = entry->number;
}

static void
conf_set_class_number_per_ip(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->max_local = entry->number;
}

static void
conf_set_class_number_per_ip_global(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->max_global = entry->number;

}

static void
conf_set_class_number_per_ident(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->max_ident = entry->number;
}

static void
conf_set_class_connectfreq(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->con_freq = entry->number;
}

static void
conf_set_class_max_number(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->max_total = entry->number;
}

static void
conf_set_class_sendq(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_class->max_sendq = entry->number;
}

static struct ConfItem *t_aconf;
static char *t_aconf_class;
static rb_dlink_list t_aconf_list;


static void
conf_set_auth_end(conf_t * conf)
{
	rb_dlink_node *ptr, *next;
	struct ConfItem *tmp_conf;
	if(EmptyString(t_aconf->info.name))
		t_aconf->info.name = rb_strdup("NOMATCH");

	if(EmptyString(t_aconf->host))
	{
		conf_report_error_nl("auth block at %s:%d  -- missing user@host", conf->filename,
				     conf->line);
		return;
	}

	collapse(t_aconf->user);
	collapse(t_aconf->host);
	conf_add_class_to_conf(t_aconf, t_aconf_class);
	add_conf_by_address(t_aconf->host, CONF_CLIENT, t_aconf->user, t_aconf);

	RB_DLINK_FOREACH_SAFE(ptr, next, t_aconf_list.head)
	{
		tmp_conf = ptr->data;

		if(t_aconf->passwd)
			tmp_conf->passwd = rb_strdup(t_aconf->passwd);

		tmp_conf->info.name = rb_strdup(t_aconf->info.name);
		tmp_conf->flags = t_aconf->flags;
		tmp_conf->port = t_aconf->port;
		collapse(tmp_conf->user);
		collapse(tmp_conf->host);
		conf_add_class_to_conf(tmp_conf, t_aconf_class);
		add_conf_by_address(tmp_conf->host, CONF_CLIENT, tmp_conf->user, tmp_conf);
		rb_dlinkDestroy(ptr, &t_aconf_list);
	}
	rb_free(t_aconf_class);
	t_aconf_class = NULL;
	t_aconf = NULL;
}

static void
conf_set_auth_start(conf_t * conf)
{
	rb_dlink_node *ptr, *next;
	rb_free(t_aconf_class);
	t_aconf_class = NULL;
	RB_DLINK_FOREACH_SAFE(ptr, next, t_aconf_list.head)
	{
		free_conf(ptr->data);
		rb_dlinkDestroy(ptr, &t_aconf_list);
	}
	t_aconf = make_conf();
	t_aconf->status = CONF_CLIENT;
}

static void
conf_set_auth_user(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct ConfItem *tmp_conf;
	char *tmpname, *p;

	if(!EmptyString(t_aconf->host))
	{
		tmp_conf = make_conf();
		tmp_conf->status = CONF_CLIENT;
	}
	else
		tmp_conf = t_aconf;

	tmpname = LOCAL_COPY(entry->string);

	if((p = strchr(tmpname, '@')))
	{
		*p++ = '\0';

		tmp_conf->user = rb_strdup(tmpname);
		tmp_conf->host = rb_strdup(p);
	}
	else
	{
		tmp_conf->user = rb_strdup("*");
		tmp_conf->host = rb_strdup(tmpname);
	}
	if(t_aconf != tmp_conf)
		rb_dlinkAddAlloc(tmp_conf, &t_aconf_list);
	return;
}

static void
conf_set_auth_pass(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(t_aconf->passwd)
		memset(t_aconf->passwd, 0, strlen(t_aconf->passwd));
	rb_free(t_aconf->passwd);
	t_aconf->passwd = rb_strdup(entry->string);
	return;
}

static void
conf_set_auth_spoof(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *user = NULL, *host = NULL, *p;

	host = LOCAL_COPY(entry->string);
	user = host;
	/* user@host spoof */
	if((p = strchr(host, '@')) != NULL)
	{
		*p = '\0';
		host = p + 1;
		if(EmptyString(user))
		{
			conf_report_warning_nl("Invalid spoof (ident empty): %s::%s at %s:%d", 
						conf->confname, entry->entryname, entry->filename, entry->line);
			return;
		}

		if(strlen(user) > USERLEN)
		{
			conf_report_warning_nl("Invalid spoof (username too long): %s::%s at %s:%d", 
						conf->confname, entry->entryname, entry->filename, entry->line);
			return;
		}

		if(!valid_username(user))
		{
			conf_report_warning_nl("Invalid spoof (invalid username): %s::%s at %s:%d", 
						conf->confname, entry->entryname, entry->filename, entry->line);
			return;
		}

		/* this must be restored! */
		*p = '@';
	}

	if(EmptyString(host))
	{
		conf_report_warning_nl("Invalid spoof (empty hostname): %s::%s at %s:%d", 
				conf->confname, entry->entryname, entry->filename, entry->line);
		return;
	}

	if(strlen(host) > HOSTLEN)
	{
		conf_report_warning_nl("Invalid spoof (hostname too long): %s::%s at %s:%d", 
				conf->confname, entry->entryname, entry->filename, entry->line);
		return;
	}

	if(!valid_hostname(host))
	{
		conf_report_warning_nl("Invalid spoof (invalid hostname): %s::%s at %s:%d", 
				conf->confname, entry->entryname, entry->filename, entry->line);
		return;
	}

	rb_free(t_aconf->info.name);
	t_aconf->info.name = rb_strdup(user);
	t_aconf->flags |= CONF_FLAGS_SPOOF_IP;
	return;
}

static void
conf_set_auth_flags(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	set_modes_from_table((int *)&t_aconf->flags, "flag", auth_table, entry);
}

static void
conf_set_auth_redirserv(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_aconf->flags |= CONF_FLAGS_REDIR;
	rb_free(t_aconf->info.name);
	t_aconf->info.name = rb_strdup(entry->string);
	return;
}

static void
conf_set_auth_redirport(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	t_aconf->flags |= CONF_FLAGS_REDIR;
	t_aconf->port = entry->number;

}

static void
conf_set_auth_class(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	rb_free(t_aconf_class);
	t_aconf_class = rb_strdup(entry->string);
}

static struct oper_conf *t_oper;
static rb_dlink_list t_oper_list;

static void
conf_set_start_operator(conf_t * conf)
{
	rb_dlink_node *ptr, *next;
	if(t_oper != NULL)
	{
		free_oper_conf(t_oper);
		t_oper = NULL;
	}
	RB_DLINK_FOREACH_SAFE(ptr, next, t_oper_list.head)
	{
		free_oper_conf(ptr->data);
		rb_dlinkDestroy(ptr, &t_oper_list);
	}

	t_oper = make_oper_conf();
	t_oper->name = rb_strdup(conf->subname);
	t_oper->flags = OPER_ENCRYPTED | OPER_OPERWALL | OPER_REMOTEBAN;
}


static void
conf_set_end_operator(conf_t * conf)
{
	struct oper_conf *tmp_oper;
	rb_dlink_node *ptr, *next;

	if(EmptyString(t_oper->name))
	{
		conf_report_error_nl("operator block at %s:%d -- missing name", conf->filename,
				     conf->line);
		return;
	}

	if(EmptyString(t_oper->passwd)
#ifdef USE_CHALLENGE
	   && EmptyString(t_oper->rsa_pubkey_file))
#else
		)
#endif
	{
		conf_report_error_nl("operator block at %s:%d -- missing password", conf->filename,
				     conf->line);
		return;
	}

	RB_DLINK_FOREACH_SAFE(ptr, next, t_oper_list.head)
	{
		tmp_oper = ptr->data;
		tmp_oper->name = rb_strdup(t_oper->name);

		tmp_oper->flags = t_oper->flags;
		tmp_oper->umodes = t_oper->umodes;

		/* maybe an rsa key */
		if(!EmptyString(t_oper->passwd))
			tmp_oper->passwd = rb_strdup(t_oper->passwd);
#ifdef USE_CHALLENGE
		if(t_oper->rsa_pubkey_file != NULL)
		{
			BIO *file;
			if((file = BIO_new_file(t_oper->rsa_pubkey_file, "r")) == NULL)
			{
				conf_report_error_nl
					("operator block for %s at %s:%d rsa_public_key_file cannot be opened",
					 tmp_oper->name, conf->filename, conf->line);
				return;
			}
			tmp_oper->rsa_pubkey = (RSA *) PEM_read_bio_RSA_PUBKEY(file, NULL, 0, NULL);
			BIO_free(file);

			if(tmp_oper->rsa_pubkey == NULL)
			{
				conf_report_error_nl
					("operator block for %s at %s:%d -- invalid rsa_public_key_file",
					 tmp_oper->name, conf->filename, conf->line);
				return;
			}
		}
#endif
		rb_dlinkMoveNode(ptr, &t_oper_list, &oper_conf_list);
	}

}

static void
conf_set_oper_flags(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	set_modes_from_table((int *)&t_oper->flags, "flag", flag_table, entry);
}

static void
conf_set_oper_user(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct oper_conf *tmp_oper;
	char *p;
	char *host = LOCAL_COPY(entry->string);

	tmp_oper = make_oper_conf();

	if((p = strchr(host, '@')))
	{
		*p++ = '\0';
		tmp_oper->username = rb_strdup(host);
		tmp_oper->host = rb_strdup(p);
	}
	else
	{
		tmp_oper->username = rb_strdup("*");
		tmp_oper->host = rb_strdup(host);
	}

	if(EmptyString(tmp_oper->username) || EmptyString(tmp_oper->host))
	{
		conf_report_error_nl("operator at %s:%d -- missing username/host", entry->filename,
				     entry->line);
		free_oper_conf(tmp_oper);
		return;
	}
	rb_dlinkAddAlloc(tmp_oper, &t_oper_list);
}

static void
conf_set_oper_password(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(t_oper->passwd != NULL)
	{
		memset(t_oper->passwd, 0, strlen(t_oper->passwd));
		rb_free(t_oper->passwd);
	}
	t_oper->passwd = rb_strdup(entry->string);
}

static void
conf_set_oper_rsa_public_key_file(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
#ifdef USE_CHALLENGE
	rb_free(t_oper->rsa_pubkey_file);
	t_oper->rsa_pubkey_file = rb_strdup(entry->string);
#else
	conf_report_warning_nl
		("Ignoring rsa_public_key_file (OpenSSL support not available)");
#endif
}

static void
conf_set_oper_umodes(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	set_modes_from_table(&t_oper->umodes, "umode", umode_table, entry);
}


static char *listener_address;
static int listener_aftype = -1;
static void
conf_set_listen_init(conf_t * conf)
{
	rb_free(listener_address);
	listener_address = NULL;
	listener_aftype = -1;
}

static void
conf_set_listen_address(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	rb_free(listener_address);
	listener_address = rb_strdup(entry->string);
}

static void
conf_set_listen_aftype(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *aft = entry->string;

	if(!strcasecmp(aft, "ipv4"))
		listener_aftype = AF_INET;
#ifdef RB_IPV6
	else if(!strcasecmp(aft, "ipv6"))
		listener_aftype = AF_INET6;
#endif
	else
		conf_report_warning_nl("listen::aftype '%s' at %s:%d is unknown", aft,
				       entry->filename, entry->line);
}



static void
conf_set_listen_port_both(confentry_t * entry, conf_t * conf, struct conf_items *item, int ssl, int websocket)
{
	rb_dlink_node *ptr;
	confentry_t *xentry;
	int family = AF_INET;

	RB_DLINK_FOREACH(ptr, entry->flist.head)
	{
		xentry = ptr->data;
		if(listener_address == NULL)
		{
#ifdef RB_IPV6
			if(listener_aftype > 0)
				family = listener_aftype;
#endif
			add_listener(xentry->number, listener_address, family, ssl, websocket);
		}
		else
		{
#ifdef RB_IPV6
			if(listener_aftype <= 0 && strchr(listener_address, ':') != NULL)
				family = AF_INET6;
#endif
			add_listener(xentry->number, listener_address, family, ssl, websocket);
		}
	}
}

static void
conf_set_listen_port(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	conf_set_listen_port_both(entry, conf, item, /* ssl */ 0, /* websocket */ 0);
}

static void
conf_set_listen_sslport(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	conf_set_listen_port_both(entry, conf, item, /* ssl */ 1, /* websocket */ 0);
}

static void
conf_set_listen_websocketport(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	conf_set_listen_port_both(entry, conf, item, /* ssl */ 0, /* websocket */ 1);
}

static void
conf_set_listen_websocketsslport(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	conf_set_listen_port_both(entry, conf, item, /* ssl */ 1, /* websocket */ 1);
}

static struct ev_entry *cache_links_ev;
static void
conf_set_serverhide_links_delay(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	int val = entry->number;

	if((val > 0) && ConfigServerHide.links_disabled == 1)
	{
		cache_links_ev = rb_event_addish("cache_links", cache_links, NULL, val);
		ConfigServerHide.links_disabled = 0;
	}
	else if(val != ConfigServerHide.links_delay)
		rb_event_update(cache_links_ev, val);

	ConfigServerHide.links_delay = val;
}

static void
conf_set_exempt_ip(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct ConfItem *tmp;

	if(parse_netmask(entry->string, NULL, NULL) == HM_HOST)
	{
		conf_report_warning_nl("Ignoring exempt -- invalid exempt::ip.");
		return;
	}

	tmp = make_conf();
	tmp->passwd = rb_strdup("*");
	tmp->host = rb_strdup(entry->string);
	tmp->status = CONF_EXEMPTDLINE;
	add_eline(tmp);
}

static void
conf_set_general_kline_delay(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	ConfigFileEntry.kline_delay = entry->number;

	/* THIS MUST BE HERE to stop us being unable to check klines */
	kline_queued = 0;
}

static void
conf_set_general_hide_error_messages(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *val = entry->string;
	if(strcasecmp(val, "yes") == 0)
		ConfigFileEntry.hide_error_messages = 2;
	else if(strcasecmp(val, "opers") == 0)
		ConfigFileEntry.hide_error_messages = 1;
	else if(strcasecmp(val, "no") == 0)
		ConfigFileEntry.hide_error_messages = 0;
	else
		conf_report_warning_nl
			("Invalid setting '%s' for general::hide_error_messages at %s:%d", val,
			 entry->filename, entry->line);
}

static void
conf_set_general_oper_only_umodes(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	set_modes_from_table(&ConfigFileEntry.oper_only_umodes, "umode", umode_table, entry);
}

static void
conf_set_general_oper_umodes(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	set_modes_from_table(&ConfigFileEntry.oper_umodes, "umode", umode_table, entry);
}


static void
conf_set_general_stats_k_oper_only(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *val = entry->string;

	if(strcasecmp(val, "yes") == 0)
		ConfigFileEntry.stats_k_oper_only = 2;
	else if(strcasecmp(val, "masked") == 0)
		ConfigFileEntry.stats_k_oper_only = 1;
	else if(strcasecmp(val, "no") == 0)
		ConfigFileEntry.stats_k_oper_only = 0;
	else
		conf_report_warning_nl("Invalid setting '%s' for general::stats_k_oper_only at %s:%d", val, conf->filename, conf->line);
}

static void
conf_set_general_stats_i_oper_only(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *val = entry->string;

	if(strcasecmp(val, "yes") == 0)
		ConfigFileEntry.stats_i_oper_only = 2;
	else if(strcasecmp(val, "masked") == 0)
		ConfigFileEntry.stats_i_oper_only = 1;
	else if(strcasecmp(val, "no") == 0)
		ConfigFileEntry.stats_i_oper_only = 0;
	else
		conf_report_warning_nl("Invalid setting '%s' for general::stats_i_oper_only at %s:%d", val, conf->filename, conf->line);
}

static void
conf_set_general_compression_level(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
#ifdef HAVE_ZLIB
	ConfigFileEntry.compression_level = entry->number;

	if((ConfigFileEntry.compression_level < 1) || (ConfigFileEntry.compression_level > 9))
	{
		conf_report_warning_nl
			("Invalid general::compression_level %d at %s:%d -- using default.",
			 ConfigFileEntry.compression_level, entry->filename, entry->line);
		ConfigFileEntry.compression_level = 0;
	}
#else
	conf_report_warning_nl
		("Ignoring general::compression_level at %s:%d -- zlib not available.",
		 entry->filename, entry->line);
#endif

}

static void
conf_set_general_havent_read_conf(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(entry->number)
	{
		conf_report_error_nl("You haven't read your config file properly.");
		conf_report_error_nl
			("There is a line in the example conf that will kill your server if not removed.");
		conf_report_error_nl
			("Consider actually reading/editing the conf file, and removing this line.");
		if(!testing_conf)
			exit(0);
	}
}

static struct server_conf *t_server;
static void
conf_set_start_connect(conf_t * conf)
{
	if(t_server != NULL)
		free_server_conf(t_server);

	t_server = make_server_conf();
	t_server->port = PORTNUM;
	t_server->name = rb_strdup(conf->subname);
}


static void
conf_set_end_connect(conf_t * conf)
{
	if(EmptyString(t_server->name))
	{
		conf_report_warning_nl("Ignoring connect block at %s:%d -- missing name",
				       conf->filename, conf->line);
		return;
	}

	if(EmptyString(t_server->passwd) || EmptyString(t_server->spasswd))
	{
		conf_report_warning_nl("Ignoring connect block for %s at %s:%d -- missing password",
				       conf->subname, conf->filename, conf->line);
		return;
	}

	if(EmptyString(t_server->host))
	{
		conf_report_warning_nl("Ignoring connect block for %s at %s:%d -- missing host",
				       conf->subname, conf->filename, conf->line);
		return;
	}

#ifndef HAVE_ZLIB
	if(ServerConfCompressed(t_server))
	{
		t_server->flags &= ~SERVER_COMPRESSED;
	}
#endif

	add_server_conf(t_server);
	rb_dlinkAdd(t_server, &t_server->node, &server_conf_list);
	t_server = NULL;
}

static void
conf_set_connect_host(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	rb_free(t_server->host);
	t_server->host = rb_strdup(entry->string);
}

static void
conf_set_connect_vhost(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(rb_inet_pton_sock(entry->string, (struct sockaddr *)&t_server->my_ipnum) <= 0)
	{
		conf_report_warning_nl("Invalid netmask for server vhost (%s) at %s:%d", entry->string, conf->filename, conf->line);
		return;
	}

	t_server->flags |= SERVER_VHOSTED;
}

static void
conf_set_connect_send_password(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(t_server->spasswd != NULL)
	{
		memset(t_server->spasswd, 0, strlen(t_server->spasswd));
		rb_free(t_server->spasswd);
	}
	t_server->spasswd = rb_strdup(entry->string);
}

static void
conf_set_connect_accept_password(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(t_server->passwd != NULL)
	{
		memset(t_server->passwd, 0, strlen(t_server->passwd));
		rb_free(t_server->passwd);
	}
	t_server->passwd = rb_strdup(entry->string);
}

static void
conf_set_connect_port(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	int port = entry->number;
	if(port < 1)
		port = PORTNUM;
	t_server->port = port;
}

static void
conf_set_connect_aftype(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	char *aft = entry->string;

	if(!strcasecmp(aft, "ipv4"))
		SET_SS_FAMILY(&t_server->ipnum, AF_INET);
#ifdef RB_IPV6
	else if(!strcasecmp(aft, "ipv6"))
		SET_SS_FAMILY(&t_server->ipnum, AF_INET6);
#endif
	else
		conf_report_warning_nl("connect::aftype '%s' at %s:%d is unknown", aft,
				       entry->filename, entry->line);
}

static void
conf_set_connect_flags(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	set_modes_from_table(&t_server->flags, "flag", connect_table, entry);
}

static void
conf_set_connect_class(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	rb_free(t_server->class_name);
	t_server->class_name = rb_strdup(entry->string);
}

static void
conf_set_connect_leaf_mask(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct remote_conf *t_leaf;

	if(EmptyString(t_server->name))
		return;

	t_leaf = make_remote_conf();
	t_leaf->flags = CONF_LEAF;
	t_leaf->host = rb_strdup(entry->string);
	t_leaf->server = rb_strdup(t_server->name);
	rb_dlinkAdd(t_leaf, &t_leaf->node, &hubleaf_conf_list);
}

static void
conf_set_connect_hub_mask(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct remote_conf *t_hub;

	if(EmptyString(t_server->name))
		return;

	t_hub = make_remote_conf();
	t_hub->flags = CONF_HUB;
	t_hub->host = rb_strdup(entry->string);
	t_hub->server = rb_strdup(t_server->name);
	rb_dlinkAdd(t_hub, &t_hub->node, &hubleaf_conf_list);
}



static rb_dlink_list t_shared_list;
static rb_dlink_list t_cluster_list;
static struct remote_conf *t_shared;

static void
conf_set_cluster_cleanup(conf_t * conf)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, t_cluster_list.head)
	{
		free_remote_conf(ptr->data);
		rb_dlinkDestroy(ptr, &t_cluster_list);
	}
	if(t_shared != NULL)
	{
		free_remote_conf(t_shared);
		t_shared = NULL;
	}
}

static void
conf_set_cluster_name(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if(t_shared != NULL)
		free_remote_conf(t_shared);

	t_shared = make_remote_conf();
	t_shared->server = rb_strdup(entry->string);
	rb_dlinkAddAlloc(t_shared, &t_cluster_list);
	t_shared = NULL;
}

static void
conf_set_cluster_flags(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	int flags = 0;
	rb_dlink_node *ptr, *next;

	if(t_shared != NULL)
		free_remote_conf(t_shared);

	set_modes_from_table(&flags, "flag", cluster_table, entry);

	RB_DLINK_FOREACH_SAFE(ptr, next, t_cluster_list.head)
	{
		t_shared = ptr->data;
		t_shared->flags = flags;
		rb_dlinkAddTail(t_shared, &t_shared->node, &cluster_conf_list);
		rb_dlinkDestroy(ptr, &t_cluster_list);
	}
	t_shared = NULL;
}


static void
conf_set_shared_cleanup(conf_t * conf)
{
	rb_dlink_node *ptr, *next;

	RB_DLINK_FOREACH_SAFE(ptr, next, t_shared_list.head)
	{
		free_remote_conf(ptr->data);
		rb_dlinkDestroy(ptr, &t_shared_list);
	}

	if(t_shared != NULL)
	{
		free_remote_conf(t_shared);
		t_shared = NULL;
	}
}

static void
conf_set_shared_oper(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	rb_dlink_node *ptr;
	confentry_t *xentry;
	char *username, *p;
	int len;

	len = rb_dlink_list_length(&entry->flist);

	if(len > 2)
	{
		conf_report_error_nl("Too many options for shared::oper at %s:%d", entry->filename,
				     entry->line);
		return;
	}

	if(t_shared != NULL)
		free_remote_conf(t_shared);

	t_shared = make_remote_conf();

	/* if the list is one, head and tail are the same, 
	 * if its two, we still get what we want 
	 */
	xentry = entry->flist.tail->data;
	username = LOCAL_COPY(xentry->string);


	if(len == 1)
	{
		t_shared->server = rb_strdup("*");
	}
	else
	{
		xentry = entry->flist.head->data;
		t_shared->server = rb_strdup(xentry->string);
	}

	if((p = strchr(username, '@')) == NULL)
	{
		conf_report_error_nl("shared::oper at %s:%d -- oper is not a user@host",
				     entry->filename, entry->line);
		return;
	}

	*p++ = '\0';

	if(EmptyString(p))
		t_shared->host = rb_strdup("*");
	else
		t_shared->host = rb_strdup(p);

	if(EmptyString(username))
		t_shared->username = rb_strdup("*");
	else
		t_shared->username = rb_strdup(username);

	rb_dlinkAddAlloc(t_shared, &t_shared_list);
	t_shared = NULL;
	RB_DLINK_FOREACH(ptr, entry->flist.head)
	{
		xentry = ptr->data;
		t_shared = make_remote_conf();
		rb_strdup(xentry->string);
	}
}


static void
conf_set_shared_flags(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	int flags = 0;
	rb_dlink_node *ptr, *next;

	if(t_shared != NULL)
		free_remote_conf(t_shared);

	set_modes_from_table(&flags, "flag", shared_table, entry);

	RB_DLINK_FOREACH_SAFE(ptr, next, t_shared_list.head)
	{
		t_shared = ptr->data;
		t_shared->flags = flags;
		rb_dlinkDestroy(ptr, &t_shared_list);
		rb_dlinkAddTail(t_shared, &t_shared->node, &shared_conf_list);
	}
	t_shared = NULL;
}

static char *blacklist_host;

static void
conf_set_blacklist_cleanup(conf_t * conf)
{
	rb_free(blacklist_host);
	blacklist_host = NULL;
}

static void
conf_set_blacklist_host(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	rb_free(blacklist_host);
	blacklist_host = rb_strdup(entry->string);
}

static void
conf_set_blacklist_reason(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	if (blacklist_host == NULL) {
		conf_report_warning_nl("Ignoring blacklist::reason at %s:%d -- Missing host",
				       entry->filename, entry->line);
		return;
	}
	new_blacklist(blacklist_host, entry->string);
	rb_free(blacklist_host);
	blacklist_host = NULL;
}


#ifdef ENABLE_SERVICES
static void
conf_set_service_start(conf_t * conf)
{
	struct Client *target_p;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, global_serv_list.head)
	{
		target_p = ptr->data;
		target_p->flags &= ~FLAGS_SERVICE;
	}
}

static void
conf_set_service_name(confentry_t * entry, conf_t * conf, struct conf_items *item)
{
	struct Client *target_p;

	if(!valid_servername(entry->string))
	{
		conf_report_warning_nl("Ignoring service::name at %s:%d -- Invalid servername",
				       entry->filename, entry->line);
		return;
	}

	rb_dlinkAddAlloc(rb_strdup(entry->string), &service_list);
	if((target_p = find_server(NULL, entry->string)))
		target_p->flags |= FLAGS_SERVICE;
}
#endif


static void
add_top_conf(const char *name, void (*startfunc) (conf_t * conf), void (*endfunc) (conf_t * conf),
	     struct conf_items *itemtable, int needsub)
{
	int i;
	struct topconf *top;
	top = rb_malloc(sizeof(struct topconf));

	add_valid_block(name, needsub);
	top->tc_name = rb_strdup(name);
	top->start_func = startfunc;
	top->end_func = endfunc;
	top->itemtable = itemtable;
	for(i = 0; itemtable[i].type; i++)
	{
		add_valid_entry(name, itemtable[i].c_name, itemtable[i].type);
	}

	rb_dlinkAddTail(top, &top->node, &toplist);
}

static struct conf_items *
find_item(const char *name, struct conf_items *itemtable)
{
	int i;
	for(i = 0; itemtable[i].type != 0; i++)
	{
		if(!strcasecmp(name, itemtable[i].c_name))
			return &(itemtable[i]);
	}
	return NULL;
}

static void
register_top_confs(void)
{
	CONF_CB *func;
	rb_dlink_node *ptr, *xptr, *yptr;
	struct topconf *top;
	conf_t *conf;
	confentry_t *entry;
	struct conf_items *tab;

	RB_DLINK_FOREACH(ptr, toplist.head)
	{
		top = ptr->data;
		RB_DLINK_FOREACH(xptr, conflist.head)
		{
			conf = xptr->data;
			if(strcasecmp(conf->confname, top->tc_name))
				continue;

			if(top->start_func != NULL)
				top->start_func(conf);
			RB_DLINK_FOREACH(yptr, conf->entries.head)
			{
				entry = yptr->data;
				tab = find_item(entry->entryname, top->itemtable);
				if(tab == NULL)
					continue;
				if(tab->cb_func == NULL)
					func = conf_set_generic_value_cb;
				else
					func = tab->cb_func;

				func(entry, conf, tab);
			}
			if(top->end_func != NULL)
				top->end_func(conf);
		}
	}
}



void
load_conf_settings(void)
{
	register_top_confs();

	/* sanity check things */
	if(ConfigFileEntry.ts_warn_delta < TS_WARN_DELTA_MIN)
		ConfigFileEntry.ts_warn_delta = TS_WARN_DELTA_DEFAULT;

	if(ConfigFileEntry.ts_max_delta < TS_MAX_DELTA_MIN)
		ConfigFileEntry.ts_max_delta = TS_MAX_DELTA_DEFAULT;

	if(ServerInfo.network_name == NULL)
		ServerInfo.network_name = rb_strdup(NETWORK_NAME_DEFAULT);

	if(ServerInfo.ssld_count < 1)
		ServerInfo.ssld_count = 1;

	if((ConfigFileEntry.client_flood < CLIENT_FLOOD_MIN)
	   || (ConfigFileEntry.client_flood > CLIENT_FLOOD_MAX))
		ConfigFileEntry.client_flood = CLIENT_FLOOD_MAX;

	if(ConfigChannel.topiclen > MAX_TOPICLEN || ConfigChannel.topiclen < 0)
		ConfigChannel.topiclen = DEFAULT_TOPICLEN;

	if(!rb_setup_ssl_server
	   (ServerInfo.ssl_cert, ServerInfo.ssl_private_key, ServerInfo.ssl_dh_params))
	{
		ilog(L_MAIN, "WARNING: Unable to setup SSL.");
		ircd_ssl_ok = 0;
	}
	else
	{
		ircd_ssl_ok = 1;
		send_new_ssl_certs(ServerInfo.ssl_cert, ServerInfo.ssl_private_key,
				   ServerInfo.ssl_dh_params);
	}
	if(ServerInfo.ssld_count > get_ssld_count())
	{
		int start = ServerInfo.ssld_count - get_ssld_count();
		/* start up additional ssld if needed */
		start_ssldaemon(start, ServerInfo.ssl_cert, ServerInfo.ssl_private_key,
				ServerInfo.ssl_dh_params);

	}
	if(!split_users || !split_servers
	   || (!ConfigChannel.no_create_on_split && !ConfigChannel.no_join_on_split))
	{
		rb_event_delete(cache_links_ev);
		splitmode = 0;
		splitchecking = 0;
	}
	check_class();
}


/* *INDENT-OFF* */
static struct conf_items conf_modules_table[] =
{
	{ "path",	CF_QSTRING,	conf_set_modules_path, 		0, NULL },
	{ "module",	CF_QSTRING,	conf_set_modules_module,	0, NULL },
	{ NULL,		0,		NULL,				0, NULL }
};

static struct conf_items conf_serverinfo_table[] =
{
        { "description",        CF_QSTRING, NULL, 0, &ServerInfo.description    },
        { "hub",                CF_YESNO,   NULL, 0, &ServerInfo.hub            },
        { "default_max_clients",CF_INT,     NULL, 0, &ServerInfo.default_max_clients },
        { "network_name",       CF_QSTRING, conf_set_serverinfo_network_name,   0, NULL },
        { "name",               CF_QSTRING, conf_set_serverinfo_name,   0, NULL },
        { "sid",                CF_QSTRING, conf_set_serverinfo_sid,    0, NULL },
        { "bandb",		CF_QSTRING, conf_set_serverinfo_bandb_path,  0, NULL },
        { "vhost",              CF_QSTRING, conf_set_serverinfo_vhost,  0, NULL },
        { "vhost6",             CF_QSTRING, conf_set_serverinfo_vhost6, 0, NULL },
        { "ssl_private_key",    CF_QSTRING, NULL, 0, &ServerInfo.ssl_private_key },
        { "ssl_ca_cert",        CF_QSTRING, NULL, 0, &ServerInfo.ssl_ca_cert },
        { "ssl_cert",           CF_QSTRING, NULL, 0, &ServerInfo.ssl_cert },   
        { "ssl_dh_params",      CF_QSTRING, NULL, 0, &ServerInfo.ssl_dh_params },
        { "ssld_count",		CF_INT,	    NULL, 0, &ServerInfo.ssld_count },
        { "vhost_dns",		CF_QSTRING, conf_set_serverinfo_vhost_dns, 0, NULL },
#ifdef RB_IPV6
        { "vhost6_dns",		CF_QSTRING, conf_set_serverinfo_vhost6_dns, 0, NULL },
#endif
        { "\0", 0, NULL, 0, NULL }
};

static struct conf_items conf_admin_table[] =
{
	{ "name",	CF_QSTRING, NULL, 200, &AdminInfo.name		},
	{ "description",CF_QSTRING, NULL, 200, &AdminInfo.description	},
	{ "email",	CF_QSTRING, NULL, 200, &AdminInfo.email		},
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_log_table[] =
{
	{ "fname_userlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_userlog	},
	{ "fname_fuserlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_fuserlog	},
	{ "fname_operlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_operlog	},
	{ "fname_foperlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_foperlog	},
	{ "fname_serverlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_serverlog	},
	{ "fname_killlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_killlog	},
	{ "fname_glinelog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_glinelog	},
	{ "fname_klinelog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_klinelog	},
	{ "fname_operspylog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_operspylog	},
	{ "fname_ioerrorlog", 	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.fname_ioerrorlog },
	{ "\0",			0,	    NULL, 0,          NULL }
};

static struct conf_items conf_class_table[] =
{
	{ "ping_time", 		CF_TIME, conf_set_class_ping_time,			0, NULL },
	{ "cidr_ipv4_bitlen",	CF_INT,  conf_set_class_cidr_ipv4_bitlen,		0, NULL },
#ifdef RB_IPV6
	{ "cidr_ipv6_bitlen",	CF_INT,  conf_set_class_cidr_ipv6_bitlen,		0, NULL },
#endif
	{ "number_per_cidr",	CF_INT,  conf_set_class_number_per_cidr,		0, NULL },
	{ "number_per_ip",	CF_INT,  conf_set_class_number_per_ip,		0, NULL },
	{ "number_per_ip_global",CF_INT, conf_set_class_number_per_ip_global,	0, NULL },
	{ "number_per_ident", 	CF_INT,  conf_set_class_number_per_ident,		0, NULL },
	{ "connectfreq", 	CF_TIME, conf_set_class_connectfreq,		0, NULL },
	{ "max_number", 	CF_INT,  conf_set_class_max_number,			0, NULL },
	{ "sendq", 		CF_TIME, conf_set_class_sendq,			0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_auth_table[] =
{
	{ "user",	CF_QSTRING, conf_set_auth_user,		0, NULL },
	{ "password",	CF_QSTRING, conf_set_auth_pass,		0, NULL },
	{ "class",	CF_QSTRING, conf_set_auth_class,	0, NULL },
	{ "spoof",	CF_QSTRING, conf_set_auth_spoof,	0, NULL },
	{ "redirserv",	CF_QSTRING, conf_set_auth_redirserv,	0, NULL },
	{ "redirport",	CF_INT,     conf_set_auth_redirport,	0, NULL },
	{ "flags",	CF_STRING | CF_FLIST, conf_set_auth_flags,	0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_listen_table[] =
{
	{ "host",    CF_QSTRING, conf_set_listen_address, 0, NULL },
	{ "ip",	     CF_QSTRING, conf_set_listen_address, 0, NULL },
	{ "port",    CF_INT | CF_FLIST, conf_set_listen_port,    0, NULL},
	{ "sslport", CF_INT | CF_FLIST, conf_set_listen_sslport, 0, NULL},
	{ "websocketport", CF_INT | CF_FLIST, conf_set_listen_websocketport,       0, NULL},
	{ "websocketsslport", CF_INT | CF_FLIST, conf_set_listen_websocketsslport, 0, NULL},
	{ "aftype",  CF_STRING, conf_set_listen_aftype,	0, NULL},
	{ "\0", 	0, 	NULL, 0, NULL}
};

static struct conf_items conf_exempt_table[] = 
{
	{ "ip",	CF_QSTRING, conf_set_exempt_ip, 0, NULL },
	{ "\0", 	0, 	NULL, 0, NULL}
};

static struct conf_items conf_operator_table[] =
{
	{ "rsa_public_key_file",  CF_QSTRING, conf_set_oper_rsa_public_key_file, 0, NULL },
	{ "flags",	CF_STRING | CF_FLIST, conf_set_oper_flags,	0, NULL },
	{ "umodes",	CF_STRING | CF_FLIST, conf_set_oper_umodes,	0, NULL },
	{ "user",	CF_QSTRING, conf_set_oper_user,		0, NULL },
	{ "password",	CF_QSTRING, conf_set_oper_password,	0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_general_table[] =
{
	{ "oper_only_umodes", 	CF_STRING | CF_FLIST, conf_set_general_oper_only_umodes, 0, NULL },
	{ "oper_umodes", 	CF_STRING | CF_FLIST, conf_set_general_oper_umodes,	 0, NULL },
	{ "compression_level", 	CF_INT,    conf_set_general_compression_level,	0, NULL },
	{ "havent_read_conf", 	CF_YESNO,  conf_set_general_havent_read_conf,	0, NULL },
	{ "stats_k_oper_only", 	CF_STRING, conf_set_general_stats_k_oper_only,	0, NULL },
	{ "stats_i_oper_only", 	CF_STRING, conf_set_general_stats_i_oper_only,	0, NULL },
	{ "hide_error_messages",CF_STRING, conf_set_general_hide_error_messages,0, NULL },
	{ "kline_delay", 	CF_TIME,   conf_set_general_kline_delay,	0, NULL },
	{ "default_operstring",	CF_QSTRING, NULL, REALLEN,    &ConfigFileEntry.default_operstring },
	{ "default_adminstring",CF_QSTRING, NULL, REALLEN,    &ConfigFileEntry.default_adminstring },
	{ "egdpool_path",	CF_QSTRING, NULL, MAXPATHLEN, &ConfigFileEntry.egdpool_path },
	{ "kline_reason",	CF_QSTRING, NULL, REALLEN, &ConfigFileEntry.kline_reason },

	{ "anti_spam_exit_message_time", CF_TIME,  NULL, 0, &ConfigFileEntry.anti_spam_exit_message_time },
	{ "disable_fake_channels",	 CF_YESNO, NULL, 0, &ConfigFileEntry.disable_fake_channels },
	{ "min_nonwildcard_simple",	 CF_INT,   NULL, 0, &ConfigFileEntry.min_nonwildcard_simple },
	{ "non_redundant_klines",	 CF_YESNO, NULL, 0, &ConfigFileEntry.non_redundant_klines },
	{ "tkline_expire_notices",	 CF_YESNO, NULL, 0, &ConfigFileEntry.tkline_expire_notices },

	{ "anti_nick_flood",	CF_YESNO, NULL, 0, &ConfigFileEntry.anti_nick_flood	},
	{ "burst_away",		CF_YESNO, NULL, 0, &ConfigFileEntry.burst_away		},
	{ "caller_id_wait",	CF_TIME,  NULL, 0, &ConfigFileEntry.caller_id_wait	},
	{ "client_exit",	CF_YESNO, NULL, 0, &ConfigFileEntry.client_exit		},
	{ "client_flood",	CF_INT,   NULL, 0, &ConfigFileEntry.client_flood	},
	{ "connect_timeout",	CF_TIME,  NULL, 0, &ConfigFileEntry.connect_timeout	},
	{ "default_invisible",	CF_YESNO, NULL, 0, &ConfigFileEntry.default_invisible	},
	{ "default_floodcount", CF_INT,   NULL, 0, &ConfigFileEntry.default_floodcount	},
	{ "disable_auth",	CF_YESNO, NULL, 0, &ConfigFileEntry.disable_auth	},
	{ "dots_in_ident",	CF_INT,   NULL, 0, &ConfigFileEntry.dots_in_ident	},
	{ "failed_oper_notice",	CF_YESNO, NULL, 0, &ConfigFileEntry.failed_oper_notice	},
	{ "hide_spoof_ips",     CF_YESNO, NULL, 0, &ConfigFileEntry.hide_spoof_ips      },
	{ "glines",		CF_YESNO, NULL, 0, &ConfigFileEntry.glines		},
	{ "gline_min_cidr",	CF_INT,   NULL, 0, &ConfigFileEntry.gline_min_cidr	},
	{ "gline_min_cidr6",	CF_INT,   NULL, 0, &ConfigFileEntry.gline_min_cidr6	},
	{ "gline_time",		CF_TIME,  NULL, 0, &ConfigFileEntry.gline_time		},
	{ "dline_with_reason",	CF_YESNO, NULL, 0, &ConfigFileEntry.dline_with_reason	},
	{ "kline_with_reason",	CF_YESNO, NULL, 0, &ConfigFileEntry.kline_with_reason	},
	{ "map_oper_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.map_oper_only	},
	{ "max_accept",		CF_INT,   NULL, 0, &ConfigFileEntry.max_accept		},
	{ "max_monitor",	CF_INT,   NULL, 0, &ConfigFileEntry.max_monitor		},
	{ "max_nick_time",	CF_TIME,  NULL, 0, &ConfigFileEntry.max_nick_time	},
	{ "max_nick_changes",	CF_INT,   NULL, 0, &ConfigFileEntry.max_nick_changes	},
	{ "max_targets",	CF_INT,   NULL, 0, &ConfigFileEntry.max_targets		},
	{ "min_nonwildcard",	CF_INT,   NULL, 0, &ConfigFileEntry.min_nonwildcard	},
	{ "nick_delay",		CF_TIME,  NULL, 0, &ConfigFileEntry.nick_delay		},
	{ "no_oper_flood",	CF_YESNO, NULL, 0, &ConfigFileEntry.no_oper_flood	},
	{ "operspy_admin_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.operspy_admin_only	},
	{ "pace_wait",		CF_TIME,  NULL, 0, &ConfigFileEntry.pace_wait		},
	{ "pace_wait_simple",	CF_TIME,  NULL, 0, &ConfigFileEntry.pace_wait_simple	},
	{ "ping_cookie",	CF_YESNO, NULL, 0, &ConfigFileEntry.ping_cookie		},
	{ "reject_after_count",	CF_INT,   NULL, 0, &ConfigFileEntry.reject_after_count	},
	{ "reject_duration",	CF_TIME,  NULL, 0, &ConfigFileEntry.reject_duration	},
	{ "throttle_count",	CF_INT,   NULL, 0, &ConfigFileEntry.throttle_count	},
	{ "throttle_duration",	CF_TIME,  NULL, 0, &ConfigFileEntry.throttle_duration	},
	{ "post_registration_delay", CF_TIME, NULL, 0, &ConfigFileEntry.post_registration_delay },
	{ "short_motd",		CF_YESNO, NULL, 0, &ConfigFileEntry.short_motd		},
	{ "stats_c_oper_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.stats_c_oper_only	},
	{ "stats_e_disabled",	CF_YESNO, NULL, 0, &ConfigFileEntry.stats_e_disabled	},
	{ "stats_h_oper_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.stats_h_oper_only	},
	{ "stats_o_oper_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.stats_o_oper_only	},
	{ "stats_P_oper_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.stats_P_oper_only	},
	{ "stats_y_oper_only",	CF_YESNO, NULL, 0, &ConfigFileEntry.stats_y_oper_only	},
	{ "target_change",	CF_YESNO, NULL, 0, &ConfigFileEntry.target_change	},
	{ "collision_fnc",	CF_YESNO, NULL, 0, &ConfigFileEntry.collision_fnc	},
	{ "ts_max_delta",	CF_TIME,  NULL, 0, &ConfigFileEntry.ts_max_delta	},
	{ "use_egd",		CF_YESNO, NULL, 0, &ConfigFileEntry.use_egd		},
	{ "ts_warn_delta",	CF_TIME,  NULL, 0, &ConfigFileEntry.ts_warn_delta	},
	{ "use_whois_actually", CF_YESNO, NULL, 0, &ConfigFileEntry.use_whois_actually	},
	{ "warn_no_nline",	CF_YESNO, NULL, 0, &ConfigFileEntry.warn_no_nline	},
	{ "global_cidr_ipv4_bitlen", CF_INT,  NULL, 0, &ConfigFileEntry.global_cidr_ipv4_bitlen },
	{ "global_cidr_ipv4_count", CF_INT,  NULL, 0, &ConfigFileEntry.global_cidr_ipv4_count },
	{ "global_cidr_ipv6_bitlen", CF_INT,  NULL, 0, &ConfigFileEntry.global_cidr_ipv6_bitlen },
	{ "global_cidr_ipv6_count", CF_INT,  NULL, 0, &ConfigFileEntry.global_cidr_ipv6_count },
	{ "global_cidr", CF_YESNO,  NULL, 0, &ConfigFileEntry.global_cidr },
	{ "\0", 		0, 	  NULL, 0, NULL }
};

static struct conf_items conf_channel_table[] =
{
	{ "default_split_user_count",	CF_INT,  NULL, 0, &ConfigChannel.default_split_user_count	 },
	{ "default_split_server_count",	CF_INT,	 NULL, 0, &ConfigChannel.default_split_server_count },
	{ "burst_topicwho",	CF_YESNO, NULL, 0, &ConfigChannel.burst_topicwho	},
	{ "invite_ops_only",	CF_YESNO, NULL, 0, &ConfigChannel.invite_ops_only	},
	{ "knock_delay",	CF_TIME,  NULL, 0, &ConfigChannel.knock_delay		},
	{ "knock_delay_channel",CF_TIME,  NULL, 0, &ConfigChannel.knock_delay_channel	},
	{ "max_bans",		CF_INT,   NULL, 0, &ConfigChannel.max_bans		},
	{ "max_chans_per_user", CF_INT,   NULL, 0, &ConfigChannel.max_chans_per_user 	},
	{ "no_create_on_split", CF_YESNO, NULL, 0, &ConfigChannel.no_create_on_split 	},
	{ "no_join_on_split",	CF_YESNO, NULL, 0, &ConfigChannel.no_join_on_split	},
	{ "only_ascii_channels",CF_YESNO, NULL, 0, &ConfigChannel.only_ascii_channels	},
	{ "quiet_on_ban",	CF_YESNO, NULL, 0, &ConfigChannel.quiet_on_ban		},
	{ "use_except",		CF_YESNO, NULL, 0, &ConfigChannel.use_except		},
	{ "use_invex",		CF_YESNO, NULL, 0, &ConfigChannel.use_invex		},
	{ "use_knock",		CF_YESNO, NULL, 0, &ConfigChannel.use_knock		},
	{ "use_sslonly",	CF_YESNO, NULL, 0, &ConfigChannel.use_sslonly		},
	{ "topiclen",		CF_INT,	  NULL, 0, &ConfigChannel.topiclen		},
	{ "resv_forcepart",     CF_YESNO, NULL, 0, &ConfigChannel.resv_forcepart	},
	{ "\0", 		0, 	  NULL, 0, NULL }
};

static struct conf_items conf_serverhide_table[] =
{
	{ "disable_hidden",	CF_YESNO, NULL, 0, &ConfigServerHide.disable_hidden	},
	{ "flatten_links",	CF_YESNO, NULL, 0, &ConfigServerHide.flatten_links	},
	{ "hidden",		CF_YESNO, NULL, 0, &ConfigServerHide.hidden		},
	{ "links_delay",        CF_TIME,  conf_set_serverhide_links_delay, 0, NULL      },
	{ "\0", 		0, 	  NULL, 0, NULL }
};

static struct conf_items conf_connect_table[] =
{
	{ "send_password",	CF_QSTRING,   conf_set_connect_send_password,	0, NULL },
	{ "accept_password",	CF_QSTRING,   conf_set_connect_accept_password,	0, NULL },
	{ "flags",	CF_STRING | CF_FLIST, conf_set_connect_flags,	0, NULL },
	{ "host",	CF_QSTRING, conf_set_connect_host,	0, NULL },
	{ "vhost",	CF_QSTRING, conf_set_connect_vhost,	0, NULL },
	{ "port",	CF_INT,     conf_set_connect_port,	0, NULL },
	{ "aftype",	CF_STRING,  conf_set_connect_aftype,	0, NULL },
	{ "hub_mask",	CF_QSTRING, conf_set_connect_hub_mask,	0, NULL },
	{ "leaf_mask",	CF_QSTRING, conf_set_connect_leaf_mask,	0, NULL },
	{ "class",	CF_QSTRING, conf_set_connect_class,	0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_shared_table[] =
{
	{ "oper",  CF_QSTRING | CF_FLIST, conf_set_shared_oper,  0, NULL },
	{ "flags", CF_STRING | CF_FLIST,  conf_set_shared_flags, 0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_cluster_table[] =
{
	{ "name",  CF_QSTRING,		  conf_set_cluster_name,  0, NULL },
	{ "flags", CF_STRING | CF_FLIST,  conf_set_cluster_flags, 0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

static struct conf_items conf_blacklist_table[] =
{
	{ "host",   CF_QSTRING,		  conf_set_blacklist_host,   0, NULL },
	{ "reason", CF_QSTRING,		  conf_set_blacklist_reason, 0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

#ifdef ENABLE_SERVICES
static struct conf_items conf_service_table[] =
{
	{ "name",  CF_QSTRING,		  conf_set_service_name,  0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};
#endif

struct top_conf_table_t
{
	const char *name;
	void (*start) (conf_t *);
	void (*end)  (conf_t *);
	struct conf_items *items;
	int needsub;
};

static struct top_conf_table_t top_conf_table[] =
{
	{ "modules", 	NULL,			 NULL,			conf_modules_table, 	0},
	{ "serverinfo",	NULL,			 NULL,			conf_serverinfo_table,	0},
	{ "admin",	NULL,			 NULL,			conf_admin_table, 	0},
	{ "log",	NULL,			 NULL,			conf_log_table,		0},
	{ "general",	NULL,			 NULL,			conf_general_table,	0},
	{ "class",	conf_set_class_start,	 conf_set_class_end, 	conf_class_table,	1},
	{ "auth",	conf_set_auth_start,	 conf_set_auth_end,	conf_auth_table,	0},
	{ "channel",	NULL,			 NULL,			conf_channel_table,	0},
	{ "serverhide",	NULL,			 NULL,			conf_serverhide_table,	0},
	{ "listen",	conf_set_listen_init,	 conf_set_listen_init,	conf_listen_table,	0},
	{ "exempt",	NULL,			 NULL,			conf_exempt_table,	0},
	{ "operator",	conf_set_start_operator, conf_set_end_operator,	conf_operator_table,	1},
	{ "connect",	conf_set_start_connect,  conf_set_end_connect,	conf_connect_table,	1},
	{ "shared",	conf_set_shared_cleanup, conf_set_shared_cleanup,conf_shared_table,	0},
	{ "cluster",	conf_set_cluster_cleanup,conf_set_cluster_cleanup,conf_cluster_table,	0},
	{ "blacklist",	conf_set_blacklist_cleanup, conf_set_blacklist_cleanup, conf_blacklist_table,	0},
#ifdef ENABLE_SERVICES
	{ "service",	conf_set_service_start,  NULL,			conf_service_table,	0},
#endif
	{ NULL,		NULL,			 NULL,			NULL,			0},
};

/* *INDENT-ON* */



void
add_all_conf_settings(void)
{
	int i;
	struct top_conf_table_t *t;
	for(i = 0; top_conf_table[i].name != NULL; i++)
	{
		t = &top_conf_table[i];
		add_top_conf(t->name, t->start, t->end, t->items, t->needsub);
	}
}
