# $Id: Makefile.am 27261 2011-10-21 15:07:29Z jilles $ 

bin_PROGRAMS = ratbox-mkpasswd
bin_SCRIPTS = ircd_crontab.sh
AM_CFLAGS=$(WARNFLAGS)

INCLUDES = $(DEFAULT_INCLUDES) -I../libratbox/include -I.


ratbox_mkpasswd_SOURCES = mkpasswd.c

ratbox_mkpasswd_LDADD = ../libratbox/src/libratbox.la

