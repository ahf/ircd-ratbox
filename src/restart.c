/*
 *  ircd-ratbox: A slightly useful ircd.
 *  restart.c: Functions to allow the ircd to restart.
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
 *  $Id: restart.c 26098 2008-09-20 01:08:38Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "restart.h"
#include "ircd.h"
#include "send.h"
#include "s_log.h"
#include "s_conf.h"
#include "client.h"
#include "ircd_signal.h"

/* external var */
extern char **myargv;

void
restart(const char *mesg)
{
	static int was_here = NO;	/* redundant due to restarting flag below */

	if(was_here)
		abort();
	was_here = YES;

	ilog(L_MAIN, "Restarting Server because: %s, memory data limit: %ld", mesg, get_maxrss());

	server_reboot();
}

void
server_reboot(void)
{
	char path[PATH_MAX + 1];

	sendto_realops_flags(UMODE_ALL, L_ALL, "Restarting server...");

	ilog(L_MAIN, "Restarting server...");

	/* set all the signal handlers to a dummy */
	setup_reboot_signals();
	/*
	 * XXX we used to call flush_connections() here. But since this routine
	 * doesn't exist anymore, we won't be flushing. This is ok, since 
	 * when close handlers come into existance, rb_close() will be called
	 * below, and the data flushing will be implicit.
	 *    -- adrian
	 *
	 * bah, for now, the program ain't coming back to here, so forcibly
	 * close everything the "wrong" way for now, and just LEAVE...
	 */
#ifndef _WIN32
	int i;
	for(i = 0; i < maxconnections; ++i)
		close(i);
#endif

	unlink(pidFileName);
#ifndef _WIN32
	int fd = open("/dev/null", O_RDWR);
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
#endif

	execv(SPATH, (void *)myargv);

	/* use this if execv of SPATH fails */
	rb_snprintf(path, sizeof(path), "%s/bin/ircd", ConfigFileEntry.dpath);

	execv(path, (void *)myargv);
	exit(-1);
}
