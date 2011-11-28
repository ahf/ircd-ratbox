dnl Check for libsqlite3, based on version found at libdbi-drivers.sf.net (GPLv2-licensed)

AC_DEFUN([AC_FIND_FILE], [
  $3=no
  for i in $2; do
      for j in $1; do
          if test -r "$i/$j"; then
              $3=$i
              break 2
          fi
      done
  done ])

AC_DEFUN([AC_CHECK_SQLITE3], [
  have_sqlite3="no"
  ac_sqlite3="no"
  ac_sqlite3_incdir="no"
  ac_sqlite3_libdir="no"

  # exported variables
  SQLITE3_LIBS=""
  SQLITE3_CFLAGS=""

  AC_ARG_WITH(sqlite3,		AC_HELP_STRING([--with-sqlite3[=dir]],	[Compile with libsqlite3 at given dir]),
      [ ac_sqlite3="$withval" 
        if test "x$withval" != "xno" -a "x$withval" != "xyes"; then
            ac_sqlite3="yes"
            ac_sqlite3_incdir="$withval"/include
            ac_sqlite3_libdir="$withval"/lib
        fi ],
      [ ac_sqlite3="auto" ] )
  AC_ARG_WITH(sqlite3-incdir,	AC_HELP_STRING([--with-sqlite3-incdir],	[Specifies where the SQLite3 include files are.]),
      [  ac_sqlite3_incdir="$withval" ] )
  AC_ARG_WITH(sqlite3-libdir,	AC_HELP_STRING([--with-sqlite3-libdir],	[Specifies where the SQLite3 libraries are.]),
      [  ac_sqlite3_libdir="$withval" ] )

  AC_MSG_CHECKING([for SQLite3])
  
  # Try to automagically find SQLite, either with pkg-config, or without.
  if test "x$ac_sqlite3" = "xauto"; then
      if test "x$PKG_CONFIG" != "xno"; then
          SQLITE3_LIBS=`$PKG_CONFIG --libs sqlite3 2>/dev/null`
          SQLITE3_CFLAGS=`$PKG_CONFIG --cflags sqlite3 2>/dev/null`
          if test "x$SQLITE3_LIBS" = "x" -a "x$SQLITE3_CFLAGS" = "x"; then
	      AC_CHECK_LIB([sqlite3], [sqlite3_open], [ac_sqlite3="yes"], [ac_sqlite3="no"])
	  else
              ac_sqlite3="yes"
          fi
      else
          AC_CHECK_LIB([sqlite3], [sqlite3_open], [ac_sqlite3="yes"], [ac_sqlite3="no"])
      fi
  fi

  if test "x$ac_sqlite3" = "xyes"; then
      if test "$ac_sqlite3_incdir" = "no"; then
          sqlite3_incdirs="/usr/include /usr/local/include /usr/include/sqlite /usr/local/include/sqlite /usr/local/sqlite/include /opt/sqlite/include"
          AC_FIND_FILE(sqlite3.h, $sqlite3_incdirs, ac_sqlite3_incdir)
          if test "$ac_sqlite3_incdir" = "no"; then
              AC_MSG_WARN([Invalid SQLite directory - include files not found.])
              sqlite3_missing=yes
              ac_sqlite3=no
          fi
      fi
      if test "$ac_sqlite3_libdir" = "no"; then
          sqlite3_libdirs="/usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /usr/lib/sqlite usr/lib64/sqlite /usr/local/lib/sqlite /usr/local/sqlite/lib /opt/sqlite/lib"
          sqlite3_libs="libsqlite3.so libsqlite3.dylib libsqlite3.a"
          AC_FIND_FILE($sqlite3_libs, $sqlite3_libdirs, ac_sqlite3_libdir)
          if test "$ac_sqlite3_libdir" = "no"; then
              AC_MSG_WARN([Invalid SQLite directory - libraries not found.])
              sqlite3_missing=yes
              ac_sqlite3=no
          fi
      fi
      if test x"$sqlite3_missing" != "xyes"; then
	      have_sqlite3="yes"

	      if test x"$ac_sqlite3_libdir" = xno; then
	          test "x$SQLITE3_LIBS" = "x" && SQLITE3_LIBS="-lsqlite3"
	      else
	          test "x$SQLITE3_LIBS" = "x" && SQLITE3_LIBS="-L$ac_sqlite3_libdir -lsqlite3"
	      fi
	      test x"$ac_sqlite3_incdir" != xno && test "x$SQLITE3_CFLAGS" = "x" && SQLITE3_CFLAGS=-I$ac_sqlite3_incdir

	      AC_SUBST(SQLITE3_LIBS)
	      AC_SUBST(SQLITE3_CFLAGS)
      else
      	     ac_sqlite3=no
      fi
  fi

  AC_MSG_RESULT([$ac_sqlite3])
])
