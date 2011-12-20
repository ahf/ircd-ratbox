dnl $Id: configure.ac 27319 2011-11-12 22:32:11Z jilles $
dnl Process this file with autoconf to produce a configure script.

dnl TODO: clean up all the OpenSSL and shared module checking stuff;
dnl the most major changes have already been made and it looks like
dnl said functions need to be just about as complex as they already are.

AC_PREREQ(2.68)
AUTOMAKE_OPTIONS = 1.10
dnl Sneaky way to get an Id tag into the configure script
AC_COPYRIGHT([$Id: configure.ac 27319 2011-11-12 22:32:11Z jilles $])
AC_INIT([ircd-ratbox],[devel])
AM_INIT_AUTOMAKE

AC_CONFIG_MACRO_DIR([m4])
AM_CONFIG_HEADER(include/setup.h)

AC_PREFIX_DEFAULT(/usr/local/ircd)
AC_GNU_SOURCE

dnl Checks for programs.
AC_PATH_PROG(CP, cp)
AC_PATH_PROG(MV, mv)
AC_PATH_PROG(RB_RM, rm)


AC_PROG_CC_C99

if test x"$ac_cv_prog_cc_c99" = "xno"; then
	AC_ERROR([ircd-ratbox requires a C99 capable compiler])
fi


AM_PROG_LEX

AC_PROG_INSTALL
AC_PROG_EGREP

F77=no
GCJ=no

AM_DISABLE_STATIC
AM_ENABLE_SHARED
if test "$enable_static" = "yes"; then
	AM_DISABLE_SHARED
	AM_ENABLE_STATIC	
        AC_DEFINE([STATIC_MODULES], 1, [Define to 1 if dynamic modules cant be used.])
else
	enable_static="no"
fi

LT_INIT
LT_CONFIG_LTDL_DIR([libltdl])
LTDL_INIT([convenience])
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)
AC_LIBTOOL_DLOPEN
AM_PROG_CC_C_O
AM_MAINTAINER_MODE

AC_ISC_POSIX
AC_C_INLINE
AC_PROG_GCC_TRADITIONAL
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_YACC

srcpwd=`cd ${srcdir} ; ${PWDCMD-pwd}`

# We pase INSTALL explicitly to sub-makes.  Make sure that it is not
# a relative path.
if test "$INSTALL" = "${srcdir}/install-sh -c"; then
  INSTALL="${srcpwd}/install-sh -c"
fi

AC_LANG(C)

AM_CONDITIONAL([STATIC_MODULES], test "$enable_static" = "yes")

GCC_STACK_PROTECT_CC

cc_accepts_flag()
{
	cc_accepts_flag_CFLAGS="$CFLAGS"
	CFLAGS="$*"
	AC_MSG_CHECKING([whether $CC accepts $@])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([int main(){return 0;}])] ,
	[RC=0; AC_MSG_RESULT([yes])],
	[RC=1; AC_MSG_RESULT([no])])
	CFLAGS="$cc_accepts_flag_CFLAGS"
	return $RC
}

if cc_accepts_flag -fno-strict-aliasing; then
	CFLAGS="$CFLAGS -fno-strict-aliasing"
fi

WARNLIST="  
	all  
	cast-qual
	format
	format-security
	missing-declarations
	missing-prototypes
	nested-externs
	shadow
	write-strings
	no-unused
	unused-function
	unused-variable" 

for x in $WARNLIST; do 
	if cc_accepts_flag -W$x; then
		WARNFLAGS="$WARNFLAGS -W$x";
	fi
done

LIBTOOL="$LIBTOOL --silent"

AC_CONFIG_SUBDIRS(libratbox)

case "$host_os" in
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_HEADER(winsock2.h, , [AC_MSG_ERROR([** MinGW and no winsock2.h.  I give up.])])
     LIBS="$LIBS -lws2_32 -liphlpapi"
     is_mingw="yes"
     ;;
*)
     ;;
esac

AM_CONDITIONAL([MINGW], [test "$is_mingw" = "yes"])

if test "$LEX" != flex; then
  LEX="$SHELL $missing_dir/missing flex"
  AC_SUBST(LEX_OUTPUT_ROOT, lex.yy)
  AC_SUBST(LEXLIB, '')
fi

# backwards support for IRC_CFLAGS
CFLAGS="$IRC_CFLAGS $CFLAGS"

dnl Checks for header files.
AC_HEADER_STDC

AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT

AC_CHECK_HEADERS([sys/types.h sys/resource.h sys/param.h sys/stat.h sys/socket.h netinet/in.h arpa/inet.h errno.h stddef.h ])
AC_HEADER_TIME

AC_CHECK_FUNCS([snprintf])

dnl Networking Functions
dnl ====================

AC_SEARCH_LIBS(socket, [socket],,)

dnl this gets passed on to the libratbox configure
AC_ARG_ENABLE(ipv6,AC_HELP_STRING([--disable-ipv6],[Disable IPv6 support (not recommended)]),[ipv6=$enableval],[ipv6=yes])
        

dnl See whether we can include both string.h and strings.h.
AC_CACHE_CHECK([whether string.h and strings.h may both be included],
gcc_cv_header_string,
[
	AC_COMPILE_IFELSE([AC_LANG_SOURCE(
	[#include <string.h>
	#include <strings.h>
	])], 
	[gcc_cv_header_string=yes],
	[gcc_cv_header_string=no])
])

if test "$gcc_cv_header_string" = "yes"; then
	AC_DEFINE(STRING_WITH_STRINGS, 1, [Define to 1 if string.h may be included along with strings.h])
fi

AC_C_BIGENDIAN

dnl Check for stdarg.h - if we can't find it, halt configure
AC_CHECK_HEADER(stdarg.h, , [AC_MSG_ERROR([** stdarg.h could not be found - ircd-ratbox will not compile without it **])])

AC_FUNC_ALLOCA

dnl Specialized functions checks
dnl ============================


dnl OpenSSL support
AC_MSG_CHECKING(for OpenSSL)
AC_ARG_ENABLE(openssl,
[AC_HELP_STRING([--enable-openssl[=DIR]],[Enable OpenSSL support (DIR optional).])
AC_HELP_STRING([--disable-openssl],[Disable OpenSSL support.])],
[cf_enable_openssl=$enableval],
[cf_enable_openssl="auto"])

if test "$cf_enable_openssl" != "no" ; then
	cf_openssl_basedir=""
	if test "$cf_enable_openssl" != "auto" &&
	test "$cf_enable_openssl" != "yes" ; then
		dnl Support for --enable-openssl=/some/place
		cf_openssl_basedir="`echo ${cf_enable_openssl} | sed 's/\/$//'`"
	else
	dnl Do the auto-probe here.  Check some common directory paths.
		for dirs in /usr/local/ssl /usr/pkg /usr/local \
		/usr/local/openssl ; do
			if test -f "${dirs}/include/openssl/opensslv.h" ; then
				cf_openssl_basedir="${dirs}"
			break
			fi
		done
		unset dirs
	fi
	dnl Now check cf_openssl_found to see if we found anything.
	if test ! -z "$cf_openssl_basedir"; then
		if test -f "${cf_openssl_basedir}/include/openssl/opensslv.h" ; then
			SSL_INCLUDES="-I${cf_openssl_basedir}/include"
			SSL_LIBS="-L${cf_openssl_basedir}/lib $lt_cv_dlopen_libs"
		else
		dnl OpenSSL wasn't found in the directory specified.  Naughty
		dnl administrator...
		cf_openssl_basedir=""
		fi
	else
	dnl Check for stock FreeBSD 4.x and 5.x systems, since their files
	dnl are in /usr/include and /usr/lib.  In this case, we don't want to
	dnl change INCLUDES or LIBS, but still want to enable OpenSSL.
	dnl We can't do this check above, because some people want two versions
	dnl of OpenSSL installed (stock FreeBSD 4.x/5.x and /usr/local/ssl)
	dnl and they want /usr/local/ssl to have preference.
		if test -f "/usr/include/openssl/opensslv.h" ; then
			cf_openssl_basedir="/usr"
		fi
	fi

	dnl If we have a basedir defined, then everything is okay.  Otherwise,
	dnl we have a problem.
	if test ! -z "$cf_openssl_basedir"; then
		AC_MSG_RESULT($cf_openssl_basedir)
		cf_enable_openssl="yes"
	else
		AC_MSG_RESULT([not found. Specify a correct path?])
		cf_enable_openssl="no"
	fi
	unset cf_openssl_basedir
else
	dnl If --disable-openssl was specified
	AC_MSG_RESULT(disabled)
fi

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $SSL_INCLUDES"
save_LIBS="$LIBS"
LIBS="$LIBS $SSL_LIBS"



if test "$cf_enable_openssl" != no; then
	dnl Check OpenSSL version (must be 0.9.7 or above!)
	AC_MSG_CHECKING(for OpenSSL 0.9.7 or above)
	AC_RUN_IFELSE([
		AC_LANG_PROGRAM(
	    	[#include <openssl/opensslv.h>
		#include <stdlib.h>],
		[[if (OPENSSL_VERSION_NUMBER >= 0x00907000)
		exit(0); else exit(1);]])],
	cf_enable_openssl=yes,
	cf_enable_openssl=no,
	cf_enable_openssl=no)

	if test "$cf_enable_openssl" = yes; then
		AC_MSG_RESULT(found)
	else
		cf_enable_openssl=no
		AC_MSG_RESULT(not found - OpenSSL support disabled)
	fi
fi

if test "$cf_openssl_version_ok" != no; then
	CPPFLAGS="$CPPFLAGS $SSL_LIBS"
	AC_CHECK_LIB(crypto, RSA_free, 
		[SSL_LIBS="$SSL_LIBS -lcrypto $lt_cv_dlopen_libs"], 
		[cf_enable_openssl=no]  
	)
fi

if test "$cf_enable_openssl" != no; then
	AC_DEFINE(USE_CHALLENGE, 1, [Define to enable CHALLENGE support, requires OpenSSL])
fi

CPPFLAGS="$save_CPPFLAGS"
LIBS="$save_LIBS"

dnl End OpenSSL detection

ac_cv_build_sqlite3=no

AC_CHECK_SQLITE3


if test x"$ac_sqlite3" != xyes; then
	ac_cv_build_sqlite3=yes
	SQLITE_SUBDIR=sqlite3
	AC_SUBST(SQLITE_SUBDIR)
	SQLITE3_CFLAGS="-Isqlite3"
	save_LIBS=$LIBS
	AC_SEARCH_LIBS(fdatasync, [rt],,)
	FDATASYNCLIB=$ac_cv_search_fdatasync
	LIBS=$save_LIBS

	if test "$FDATASYNCLIB" = "none required"; then
	        unset FDATASYNCLIB
	fi
	
	if test "$FDATASYNCLIB" = "no"; then
		unset FDATASYNCLIB
	fi
        	
	SQLITE3_LIBS="$FDATASYNCLIB sqlite3/libsqlite3.a"
	AC_SUBST(SQLITE3_LIBS, $SQLITE3_LIBS)
	
fi

dnl AC_SUBST(SQLITE3_LIBS, $SQLITE3_LIBS)
dnl AC_SUBST(SQLITE3_CFLAGS, $SQLITE3_CFLAGS)

AM_CONDITIONAL([BUILD_SQLITE], [test "$ac_cv_build_sqlite3" = yes])



dnl Specialized functions and libraries
dnl ===================================

AC_ARG_WITH(zlib-path,
AC_HELP_STRING([--with-zlib-path=DIR],[Path to libz.so for ziplinks support.]),
[LIBS="$LIBS -L$withval"],)

AC_ARG_ENABLE(zlib,
AC_HELP_STRING([--disable-zlib],[Disable ziplinks support]),
[zlib=$enableval],[zlib=yes])
 
if test "$zlib" = yes; then

AC_CHECK_HEADER(zlib.h, [
	AC_CHECK_LIB(z, zlibVersion,
	[
		AC_SUBST(ZLIB_LD, -lz)
		AC_DEFINE(HAVE_ZLIB, 1, [Define to 1 if zlib (-lz) is available.])
	], zlib=no)
], zlib=no)

fi

dnl **********************************************************************
dnl Check for --with-confdir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify confdir])
AC_ARG_WITH(confdir, 
AC_HELP_STRING([--with-confdir=DIR],
	       [Directory to install config files.]),
	       [ confdir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(ETC_DIR, confdir, [Prefix where config files are installed.])
		 AC_SUBST_DIR([confdir]) ],
	       [ confdir='${prefix}/etc'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(ETC_DIR, confdir, [Prefix where config files are installed.])
	  	 AC_SUBST_DIR([confdir])]
)

dnl **********************************************************************
dnl Check for --with-logdir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify logdir])
AC_ARG_WITH(logdir, 
AC_HELP_STRING([--with-logdir=DIR],
	       [Directory where to write logfiles.]),
	       [ logdir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(LOG_DIR, logdir, [Prefix where to write logfiles.])
		 AC_SUBST_DIR([logdir]) ],
	       [ logdir='${prefix}/logs'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(LOG_DIR, logdir, [Prefix where to write logfiles.])
	  	 AC_SUBST_DIR([logdir])]
)

dnl **********************************************************************
dnl Check for --with-helpdir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify helpdir])
AC_ARG_WITH(helpdir, 
AC_HELP_STRING([--with-helpdir=DIR],
	       [Directory to install help files.]),
	       [ helpdir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(HELP_DIR, helpdir, [Prefix where help files are installed.])
		 AC_SUBST_DIR([helpdir]) ],
	       [ helpdir='${prefix}/help'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(HELP_DIR, helpdir, [Prefix where help file are installed.])
	  	 AC_SUBST_DIR([helpdir])]
)

dnl **********************************************************************
dnl Check for --with-moduledir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify moduledir])
AC_ARG_WITH(moduledir, 
AC_HELP_STRING([--with-moduledir=DIR],
	       [Directory to install modules.]),
	       [ moduledir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(MODULE_DIR, moduledir, [Prefix where modules are installed.])
		 AC_SUBST_DIR([moduledir]) ],
	       [ moduledir='${prefix}/modules'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(MODULE_DIR, moduledir, [Prefix where modules are installed.])
	  	 AC_SUBST_DIR([moduledir])]
)

dnl Debug-related options
dnl =====================

AC_ARG_ENABLE(assert,
AC_HELP_STRING([--enable-assert],[Enable assert(). Choose between soft(warnings) and hard(aborts the daemon)]),
[assert=$enableval], [assert=no])

if test "$assert" = no; then
	AC_DEFINE(NDEBUG, 1, [Define this to disable debugging support.])
elif test "$assert" = soft; then
	AC_DEFINE(SOFT_ASSERT, 1, [Define this to enable soft asserts.])
	AC_DEFINE(NDEBUG, 1, [Define this to disable debugging support.])
elif test "$assert" = yes; then
	assert = "hard";
fi

AC_MSG_CHECKING(if you want IO Debugging hooks)
AC_ARG_ENABLE(iodebug,
AC_HELP_STRING([--enable-iodebug],[Enable IO Debugging hooks]),
[iodebug=$enableval], [iodebug=no])

if test "$iodebug" = yes; then
	AC_DEFINE(USE_IODEBUG_HOOKS, 1, [Define this to enable IO Debug hooks.])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi


AC_MSG_CHECKING(if you want to do a profile build)
AC_ARG_ENABLE(profile,
AC_HELP_STRING([--enable-profile],[Enable profiling]),
[profile=$enableval], [profile=no])

if test "$profile" = yes; then
	if test "$ac_cv_c_compiler_gnu" = yes; then
		CFLAGS="$CFLAGS -pg -static"
		AC_MSG_RESULT([yes, adding -pg -static])
		AC_DEFINE(RATBOX_PROFILE, 1, [Defined to mark profiling is enabled])
	else
		AC_MSG_RESULT([no, profile builds only work with gcc])
	fi
else
	AC_MSG_RESULT(no)
fi


dnl Server Tweaks
dnl =============

AC_ARG_ENABLE(services,
AC_HELP_STRING([--enable-services],[Enable ratbox-services compatibility code.]),
[ratbox_services=$enableval], [ratbox_services=no])

M_SERVICES=""

if test "x$ratbox_services" = "xyes"; then
	AC_DEFINE([ENABLE_SERVICES], 1, [ratbox-services compatibility code])
	M_SERVICES="m_services.la"
fi

AM_CONDITIONAL([ENABLE_SERVICES], [test x"$M_SERVICES" != "x"])

AC_ARG_ENABLE(small-net,
AC_HELP_STRING([--enable-small-net],[Enable small network support.]),
[small_net=$enableval], [small_net=no])

if test "$small_net" = yes; then
dnl	AC_DEFINE([HASHSIZE], 4096, [Max number of buckets in hash tables.])
	AC_DEFINE([NICKNAMEHISTORYLENGTH], 1500, [Size of the WHOWAS array.])
	AC_DEFINE([CHANNEL_HEAP_SIZE], 256, [Size of the channel heap.])
	AC_DEFINE([BAN_HEAP_SIZE], 128, [Size of the ban heap.])
	AC_DEFINE([CLIENT_HEAP_SIZE], 256, [Size of the client heap.])
	AC_DEFINE([LCLIENT_HEAP_SIZE], 128, [Size of the local client heap.])
	AC_DEFINE([USER_HEAP_SIZE], 128, [Size of the user heap.])
	AC_DEFINE([DNODE_HEAP_SIZE], 512, [Size of the dlink_node heap.])
	AC_DEFINE([TOPIC_HEAP_SIZE], 256, [Size of the topic heap.])
	AC_DEFINE([LINEBUF_HEAP_SIZE], 128, [Size of the linebuf heap.])
	AC_DEFINE([MEMBER_HEAP_SIZE], 256, [Sizeof member heap.])
	AC_DEFINE([ND_HEAP_SIZE], 128, [Size of the nick delay heap.])
	AC_DEFINE([CONFITEM_HEAP_SIZE], 128, [Size of the confitem heap.])
	AC_DEFINE([MONITOR_HEAP_SIZE], 128, [Size of the monitor heap.])
	AC_DEFINE([AUTH_HEAP_SIZE], 128, [Size of the auth heap.])
	AC_DEFINE([WEBSOCKET_HEAP_SIZE], 128, [Size of the websocket heap.])
	AC_DEFINE([FD_HEAP_SIZE], 128, [Size of fd heap.])
	AC_DEFINE([AWAY_HEAP_SIZE], 128, [Size of away heap.])
else
dnl These settings are for a large network like efnet..they will use lots of memory
dnl so enable small net unless you really need this much support
        AC_DEFINE([NICKNAMEHISTORYLENGTH], 30000, [Size of the WHOWAS array.])
        AC_DEFINE([CHANNEL_HEAP_SIZE], 8192, [Size of the channel heap.])
        AC_DEFINE([BAN_HEAP_SIZE], 4096, [Size of the ban heap.])
        AC_DEFINE([CLIENT_HEAP_SIZE], 8192, [Size of the client heap.])
        AC_DEFINE([LCLIENT_HEAP_SIZE], 1024, [Size of the local client heap.])
        AC_DEFINE([USER_HEAP_SIZE], 8192, [Size of the user heap.])
        AC_DEFINE([DNODE_HEAP_SIZE], 8192, [Size of the dlink_node heap.])
        AC_DEFINE([TOPIC_HEAP_SIZE], 4096, [Size of the topic heap.])
        AC_DEFINE([LINEBUF_HEAP_SIZE], 2048, [Size of the linebuf heap.])
        AC_DEFINE([MEMBER_HEAP_SIZE], 32768, [Sizeof member heap.])
        AC_DEFINE([ND_HEAP_SIZE], 512, [Size of the nick delay heap.])
        AC_DEFINE([CONFITEM_HEAP_SIZE], 1024, [Size of the confitem heap.])
	AC_DEFINE([MONITOR_HEAP_SIZE], 1024, [Size of the monitor heap.])
	AC_DEFINE([AUTH_HEAP_SIZE], 256, [Size of the auth heap.])
	AC_DEFINE([WEBSOCKET_HEAP_SIZE], 256, [Size of the websocket heap.])
	AC_DEFINE([FD_HEAP_SIZE], 1024, [Size of fd heap.])
	AC_DEFINE([AWAY_HEAP_SIZE], 512, [Size of away heap.])

fi

AC_ARG_WITH(nicklen,
AC_HELP_STRING([--with-nicklen=LENGTH],[Set the nick length to LENGTH (default 9, max 50)]),
[
  if ! expr "$withval" + 0 >/dev/null 2>&1; then 
	AC_ERROR([NICKLEN must be a numeric value])
  fi 
  if test $withval -ge 50; then
	NICKLEN=50
	AC_MSG_WARN([NICKLEN has a hard limit of 50. Setting NICKLEN=50])
  else
	NICKLEN="$withval"
  fi
], [NICKLEN=9])

AC_DEFINE_UNQUOTED(NICKLEN, (${NICKLEN}+1), [Nickname length])
AC_DEFINE_UNQUOTED(RATBOX_CONFIGURE_OPTS, "$ac_configure_args", [configure arguments])


AC_SUBST(SSL_INCLUDES)
AC_SUBST(SSL_LIBS)
AC_SUBST(LDFLAGS)
AC_SUBST(PICFLAGS)
AC_SUBST(CFLAGS)
AC_SUBST(SEDOBJ)
AC_SUBST(WARNFLAGS)


if test "$prefix" = "NONE"; then 
	AC_DEFINE_UNQUOTED(IRCD_PREFIX, "$ac_default_prefix", [Prefix where the ircd is installed.])

else

dnl Don't get bitten by Cygwin's stupidity if the user specified
dnl a custom prefix with a trailing slash

	prefix=`echo $prefix | sed 's/\/$//'`
	AC_DEFINE_UNQUOTED(IRCD_PREFIX, "$prefix", [Prefix where the ircd is installed.])
	
fi

if test "x$libexecdir" = "xNONE"; then
	rb_cv_libexecdir=$ac_default_libexecdir
else
	rb_cv_libexecdir=$libexecdir
fi

libexecdir=`eval "echo ${rb_cv_libexecdir}/ircd-ratbox"`
AC_DEFINE_DIR(LIBEXEC_DIR, libexecdir, [Prefix where to install non-user executables.])

dnl lets see what libtool thinks our suffix is...
AC_MSG_CHECKING([for shared library suffix])
dnl this whole thing is a big hack...
module=yes
eval SHLIBEXT=\"$shrext_cmds\"
AC_MSG_RESULT($SHLIBEXT)
AC_SUBST(SHLIBEXT,$SHLIBEXT)
AC_SUBST(LT_OBJDIR,$lt_cv_objdir)
AC_DEFINE_UNQUOTED(SHLIBEXT,"$SHLIBEXT", [Extension that shared libs use])
                   
AC_SUBST(IRCD_PREFIX)

disable_backups=n
AC_ARG_ENABLE(backups,,disable_backups=y)
AM_CONDITIONAL([DISABLE_BACKUPS], [test x"$disable_backups" = "xy"])


AC_CONFIG_FILES(		\
	Makefile		\
	bandb/Makefile		\
	bandb/sqlite3/Makefile	\
	ssld/Makefile		\
	resolver/Makefile	\
	contrib/Makefile	\
	tools/Makefile		\
	doc/Makefile		\
	help/Makefile		\
	modules/Makefile	\
	src/Makefile		\
	install-mod.sh		\
	tools/ircd_crontab.sh
)

AC_OUTPUT

dnl Make it look sexay!

echo
echo "Compiling $PACKAGE_NAME $PACKAGE_VERSION"
echo

echo "Installing into: $prefix"

echo "Ziplinks ....................... $zlib"

echo "OpenSSL ........................ $cf_enable_openssl"

tmpresult=shared

if test "x$enable_static" = "xyes"; then
	tmpresult=static
fi

echo "Modules ........................ $tmpresult"
echo "IO Debugging hooks ............. $iodebug"
echo "Assert debugging ............... $assert"
echo "Small network .................. $small_net"
echo "ratbox-services compatibility .. $ratbox_services"
echo
echo "Configured limits:"
echo "NICKLEN ................. $NICKLEN"
echo

