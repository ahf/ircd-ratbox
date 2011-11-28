/*
 *  ircd-ratbox: A slightly useful ircd.
 *  modules.h: A header for the modules functions.
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
 *  $Id: modules.h 26377 2009-01-05 18:51:12Z androsyn $
 */

#ifndef INCLUDED_modules_h
#define INCLUDED_modules_h

#define MAPI_RATBOX 1

#include "ltdl.h"
#include "patchlevel.h"

struct module
{
	char *name;
	const char *version;
	void *address;
	int core;
	int mapi_version;
	void *mapi_header;	/* actually struct mapi_mheader_av<mapi_version>    */
};

struct module_path
{
	char path[MAXPATHLEN];
};

#define MAPI_MAGIC_HDR	0x4D410000

#define MAPI_V2		(MAPI_MAGIC_HDR | 0x2)

#define MAPI_MAGIC(x)	((x) & 0xffff0000)
#define MAPI_VERSION(x)	((x) & 0x0000ffff)

typedef struct Message *mapi_clist_av2;

typedef struct
{
	const char *hapi_name;
	int *hapi_id;
} mapi_hlist_av2;

typedef struct
{
	const char *hapi_name;
	void (*hookfn) (void *);
} mapi_hfn_list_av2;

struct mapi_mheader_av2
{
	int mapi_version;	/* Module API version           */
	int (*mapi_register) (void);	/* Register function;
					   ret -1 = failure (unload)    */
	void (*mapi_unregister) (void);	/* Unregister function.         */
	mapi_clist_av2 *mapi_command_list;	/* List of commands to add.     */
	mapi_hlist_av2 *mapi_hook_list;	/* List of hooks to add.        */
	mapi_hfn_list_av2 *mapi_hfn_list;	/* List of hook_add_hook's to do */
	const char *mapi_module_version;	/* Module's version (freeform)  */
	int patchlevel;
	const char *patchlevel_string;
};

#ifndef STATIC_MODULES
# define DECLARE_MODULE_AV2(name,reg,unreg,cl,hl,hfnlist, v) \
	struct mapi_mheader_av2 _mheader = { MAPI_V2, reg, unreg, cl, hl, hfnlist, v, PATCHLEVEL_NUM, PATCHLEVEL}
#else
# define DECLARE_MODULE_AV2(name,reg,unreg,cl,hl,hfnlist, v) \
	struct mapi_mheader_av2 m_ ## name ## _mheader = { MAPI_V2, reg, unreg, cl, hl, hfnlist, v, PATCHLEVEL_NUM, PATCHLEVEL}
void load_static_modules(void);
#endif

/* add a path */
void mod_add_path(const char *path);
void mod_clear_paths(void);

/* load a module */
void load_module(char *path);

/* load all modules */
void load_all_modules(int warn);

/* load core modules */
void load_core_modules(int);

int unload_one_module(const char *, int);
int load_one_module(const char *, int);
int load_a_module(const char *, int, int);
int findmodule_byname(const char *);
void modules_init(void);

#endif /* INCLUDED_modules_h */
