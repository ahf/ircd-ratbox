/*
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 * hook.c - code for dealing with the hook system
 *
 * This code is basically a slow leaking array.  Events are simply just a
 * position in this array.  When hooks are added, events will be created if
 * they dont exist - this means modules with hooks can be loaded in any
 * order, and events are preserved through module reloads.
 *
 * Copyright (C) 2004-2005 Lee Hardy <lee -at- leeh.co.uk>
 * Copyright (C) 2004-2005 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: hook.c 26104 2008-09-20 02:24:38Z androsyn $
 */
#include "stdinc.h"
#include "ratbox_lib.h"
#include "hook.h"
#include "match.h"

struct hook_info
{
	rb_dlink_node node;
	hookfn fn;	
};

hook *hooks;

#define HOOK_INCREMENT 10

int num_hooks = 0;
int last_hook = 0;
int max_hooks = HOOK_INCREMENT;

#ifdef USE_IODEBUG_HOOKS
int h_iosend_id;
int h_iorecv_id;
int h_iorecvctrl_id;
#endif
int h_burst_client;
int h_burst_channel;
int h_burst_finished;
int h_server_introduced;

void
init_hook(void)
{
	hooks = rb_malloc(sizeof(hook) * HOOK_INCREMENT);

#ifdef USE_IODEBUG_HOOKS
	h_iosend_id = register_hook("iosend");
	h_iorecv_id = register_hook("iorecv");
	h_iorecvctrl_id = register_hook("iorecvctrl");
#endif

	h_burst_client = register_hook("burst_client");
	h_burst_channel = register_hook("burst_channel");
	h_burst_finished = register_hook("burst_finished");
	h_server_introduced = register_hook("server_introduced");
}

/* grow_hooktable()
 *   Enlarges the hook table by HOOK_INCREMENT
 */
static void
grow_hooktable(void)
{
	hook *newhooks;

	newhooks = rb_malloc(sizeof(hook) * (max_hooks + HOOK_INCREMENT));
	memcpy(newhooks, hooks, sizeof(hook) * num_hooks);

	rb_free(hooks);
	hooks = newhooks;
	max_hooks += HOOK_INCREMENT;
}

/* find_freehookslot()
 *   Finds the next free slot in the hook table, given by an entry with
 *   h->name being NULL.
 */
static int
find_freehookslot(void)
{
	int i;

	if((num_hooks + 1) > max_hooks)
		grow_hooktable();

	for(i = 0; i < max_hooks; i++)
	{
		if(!hooks[i].name)
			return i;
	}

	/* shouldnt ever get here */
	return (max_hooks - 1);
}

/* find_hook()
 *   Finds an event in the hook table.
 */
static int
find_hook(const char *name)
{
	int i;

	for(i = 0; i < max_hooks; i++)
	{
		if(!hooks[i].name)
			continue;

		if(!irccmp(hooks[i].name, name))
			return i;
	}

	return -1;
}

/* register_hook()
 *   Finds an events position in the hook table, creating it if it doesnt
 *   exist.
 */
int
register_hook(const char *name)
{
	int i;

	if((i = find_hook(name)) < 0)
	{
		i = find_freehookslot();
		hooks[i].name = rb_strdup(name);
		num_hooks++;
	}

	return i;
}


/* add_hook()
 *   Adds a hook to an event in the hook table, creating event first if
 *   needed.
 */
void
add_hook(const char *name, hookfn fn)
{
	struct hook_info *info;
	int i;

	i = register_hook(name);
	info = rb_malloc(sizeof(struct hook_info));
	info->fn = fn;
	rb_dlinkAdd(info, &info->node, &hooks[i].hooks);
}

/* remove_hook()
 *   Removes a hook from an event in the hook table.
 */
void
remove_hook(const char *name, hookfn fn)
{
	int i;
	struct hook_info *info;
	rb_dlink_node *ptr, *next;
	if((i = find_hook(name)) < 0)
		return;

	RB_DLINK_FOREACH_SAFE(ptr, next, hooks[i].hooks.head)
	{
		info = ptr->data;
		if(info->fn == fn)
		{
			rb_dlinkDelete(&info->node, &hooks[i].hooks);
			rb_free(info);
			return;		
		}				
	}
}

/* call_hook()
 *   Calls functions from a given event in the hook table.
 */
void
call_hook(int id, void *arg)
{
	rb_dlink_node *ptr;

	/* The ID we were passed is the position in the hook table of this
	 * hook
	 */
	RB_DLINK_FOREACH(ptr, hooks[id].hooks.head)
	{
		((struct hook_info *)ptr->data)->fn(arg);
	}
}
