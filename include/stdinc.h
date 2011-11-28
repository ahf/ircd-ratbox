/*
 *  ircd-ratbox: A slightly useful ircd.
 *  stdinc.h: Pull in all of the necessary system headers
 *
 *  Copyright (C) 2002 Aaron Sethman <androsyn@ratbox.org>
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
 * $Id: stdinc.h 26094 2008-09-19 15:33:46Z androsyn $
 *
 */

#include "setup.h"
#include "config.h"		/* Gotta pull in the autoconf stuff */

/* we include common.h and ircd_defs.h down at bottom */

/* AIX requires this to be the first thing in the file.  */
#ifdef __GNUC__
#undef alloca
#define alloca __builtin_alloca
#else
# ifdef _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# else
#  if HAVE_ALLOCA_H
#   include <alloca.h>
#  else
#   ifdef _AIX
#pragma alloca
#   else
#    ifndef alloca		/* predefined by HP cc +Olibcalls */
char *alloca();
#    endif
#   endif
#  endif
# endif
#endif


#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef STRING_WITH_STRINGS
# include <string.h>
# include <strings.h>
#else
# ifdef HAVE_STRING_H
#  include <string.h>
# else
#  ifdef HAVE_STRINGS_H
#   include <strings.h>
#  endif
# endif
#endif


#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif



#include <stdio.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>


#include <stdarg.h>
#include <signal.h>
#include <ctype.h>

#include <limits.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/file.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <sys/stat.h>

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#else
extern int errno;
#endif

#if defined(__INTEL_COMPILER) || defined(__GNUC__)
# ifdef __unused
#  undef __unused
# endif
# ifdef __printf
#  undef __printf
# endif
# ifdef __noreturn
#  undef __noreturn
# endif

# define __unused __attribute__((__unused__))
# define __printf(x) __attribute__((__format__ (__printf__, x, x + 1)))
# define __noreturn __attribute__((__noreturn__))
#else
# define __unused
# define __printf
# define __noreturn
#endif



#ifdef strdupa
#define LOCAL_COPY(s) strdupa(s)
#else
#if defined(__INTEL_COMPILER) || defined(__GNUC__)
# define LOCAL_COPY(s) __extension__({ char *_s = alloca(strlen(s) + 1); strcpy(_s, s); _s; })
#else
# define LOCAL_COPY(s) strcpy(alloca(strlen(s) + 1), s)	/* XXX Is that allowed? */
#endif /* defined(__INTEL_COMPILER) || defined(__GNUC__) */
#endif /* strdupa */

/* LOCAL_COPY_N copies n part of string and adds one to terminate the string */
#ifdef strndupa
#define LOCAL_COPY_N(s, n) strndupa(s, n)
#else
#if defined(__INTEL_COMPILER) || defined(__GNUC__)
#define LOCAL_COPY_N(s, n) __extension__({ size_t _l = strlen(s); _l = n > _l ? _l : n; char *_s = alloca(_l+1); memcpy(_s, s, _l); _s[_l] = '\0' ; _s; })
#else
#define LOCAL_COPY_N(s, n) xc_strlcpy(alloca(strlen(s)+1), s, n)
INLINE_FUNC size_t
xc_strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if(size)
	{
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return dest;
}
#endif /* defined(__INTEL_COMPILER) || defined(__GNUC__) */
#endif /* strndupa */

#ifndef INADDR_NONE
# define INADDR_NONE ((in_addr_t) 0xffffffff)
#endif

#ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK ((in_addr_t) 0x7f000001)
#endif

#include "ratbox_lib.h"
#include "ircd_defs.h"
#include "common.h"
