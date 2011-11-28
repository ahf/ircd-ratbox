/*
 *  ircd-ratbox: A slightly useful ircd.
 *  main.c: Stub main program
 *
 *  Copyright (C) 2005 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2005 ircd-ratbox development team
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
 *  $Id: main.c 26094 2008-09-19 15:33:46Z androsyn $
 *
 *  There is a good point to this.  On platforms where shared libraries cannot
 *  have unresolved symbols, we solve this by making the core of the ircd itself
 *  a shared library.  Its kinda funky, but such is life
 *
 */

int ratbox_main(int, char **);

int
main(int argc, char **argv)
{
	return ratbox_main(argc, argv);
}
