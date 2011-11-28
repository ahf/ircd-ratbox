#
# $Id: Makefile.am 24471 2007-11-07 02:25:56Z androsyn $
#
libexec_PROGRAMS = resolver

INCLUDES = -I../include -I. -I../libratbox/include 
AM_CFLAGS=$(WARNFLAGS)

if MINGW
resolver_SOURCES = resolver.c res.c reslib.c getaddrinfo.c getnameinfo.c reslist.c
else
resolver_SOURCES = resolver.c res.c reslib.c
endif

resolver_LDADD = ../libratbox/src/libratbox.la



