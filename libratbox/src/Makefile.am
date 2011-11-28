# $Id: Makefile.am 27108 2010-10-08 13:34:32Z androsyn $

AUTOMAKE_OPTIONS = foreign

INCLUDES = -I. -I../include @SSL_CFLAGS@ @GNUTLS_CFLAGS@

CFLAGS=@EXTRA_WARNINGS@ @CFLAGS@

BUILT_SOURCES = version.c

version.c: version.c.SH ../CREDITS
	$(SHELL) ./version.c.SH
	$(CP) version.c version.c.last

version.lo: version.c ../include/serno.h
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

libratbox_la_SOURCES =			\
	unix.c				\
	win32.c				\
	crypt.c				\
	balloc.c			\
	commio.c			\
	openssl.c			\
	gnutls.c			\
	nossl.c				\
	event.c				\
	ratbox_lib.c			\
	rb_memory.c			\
	linebuf.c			\
	snprintf.c			\
	tools.c				\
	helper.c			\
	devpoll.c			\
	epoll.c				\
	poll.c				\
	ports.c				\
	select.c			\
	kqueue.c			\
	rawbuf.c			\
	patricia.c			\
	arc4random.c			\
	version.c
	

libratbox_la_LDFLAGS = @CRYPT_LIB@ @SSL_LIBS@ @GNUTLS_LIBS@  -avoid-version -no-undefined -export-symbols export-syms.txt
libratbox_la_LIBADD = @CRYPT_LIB@ @SSL_LIBS@ @GNUTLS_LIBS@
lib_LTLIBRARIES = libratbox.la

