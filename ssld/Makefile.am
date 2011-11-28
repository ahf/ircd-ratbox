#
# $Id: Makefile.am 25271 2008-04-23 19:43:17Z androsyn $
#
libexec_PROGRAMS = ssld
AM_CFLAGS=$(WARNFLAGS)

INCLUDES = -I../include -I../libratbox/include 


ssld_SOURCES = ssld.c

ssld_LDADD = ../libratbox/src/libratbox.la @ZLIB_LD@


