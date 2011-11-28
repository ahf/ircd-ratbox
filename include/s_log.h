/*
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 *
 * Copyright (C) 2003 Lee Hardy <lee@leeh.co.uk>
 * Copyright (C) 2003-2005 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: s_log.h 26128 2008-10-03 18:07:46Z androsyn $
 */

#ifndef INCLUDED_s_log_h
#define INCLUDED_s_log_h

typedef enum ilogfile
{
	L_MAIN,
	L_USER,
	L_FUSER,
	L_OPERED,
	L_FOPER,
	L_SERVER,
	L_KILL,
	L_KLINE,
	L_GLINE,
	L_OPERSPY,
	L_IOERROR,
	LAST_LOGFILE
} ilogfile;

struct Client;

void init_main_logfile(const char *filename);
void open_logfiles(const char *filename);
void close_logfiles(void);
void
ilog(ilogfile dest, const char *fmt, ...)
AFP(2, 3);
     void report_operspy(struct Client *, const char *, const char *);
     const char *smalldate(time_t);
     void report_error(const char *, const char *, const char *, int);

#endif
