#
# $Id: Makefile.am 25554 2008-06-19 15:06:52Z androsyn $
#
AUTOMAKE_OPTIONS = foreign subdir-objects

if BUILD_SQLITE
SUBDIRS = sqlite3
endif

libexec_PROGRAMS = bandb 
bin_PROGRAMS = bantool
AM_CFLAGS=$(WARNFLAGS)

INCLUDES = -I../include -I../libratbox/include @SQLITE3_CFLAGS@


bandb_SOURCES = bandb.c rsdb_sqlite3.c rsdb_snprintf.c

bandb_LDADD = ../libratbox/src/libratbox.la @SQLITE3_LIBS@

bantool_SOURCES = bantool.c rsdb_sqlite3.c rsdb_snprintf.c
bantool_LDADD = ../libratbox/src/libratbox.la @SQLITE3_LIBS@

