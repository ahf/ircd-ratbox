/*
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 *
 * Copyright (C) 2003 Lee H <lee@leeh.co.uk>
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
 * $Id: s_log.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "s_log.h"
#include "s_conf.h"
#include "send.h"
#include "client.h"
#include "s_serv.h"
#include "match.h"
#include "ircd.h"

static FILE *log_main;
static FILE *log_user;
static FILE *log_fuser;
static FILE *log_oper;
static FILE *log_foper;
static FILE *log_server;
static FILE *log_kill;
static FILE *log_gline;
static FILE *log_kline;
static FILE *log_operspy;
static FILE *log_ioerror;

struct log_struct
{
	char **name;
	FILE **logfile;
};

static struct log_struct log_table[LAST_LOGFILE] = {
	{NULL, &log_main},
	{&ConfigFileEntry.fname_userlog, &log_user},
	{&ConfigFileEntry.fname_fuserlog, &log_fuser},
	{&ConfigFileEntry.fname_operlog, &log_oper},
	{&ConfigFileEntry.fname_foperlog, &log_foper},
	{&ConfigFileEntry.fname_serverlog, &log_server},
	{&ConfigFileEntry.fname_killlog, &log_kill},
	{&ConfigFileEntry.fname_klinelog, &log_kline},
	{&ConfigFileEntry.fname_glinelog, &log_gline},
	{&ConfigFileEntry.fname_operspylog, &log_operspy},
	{&ConfigFileEntry.fname_ioerrorlog, &log_ioerror}
};


static void
verify_logfile_access(const char *filename)
{
	char *dirname, *d;
	char buf[512];
	d = rb_dirname(filename);
	dirname = LOCAL_COPY(d);
	rb_free(d);
	
	if(access(dirname, F_OK) == -1)
	{
		rb_snprintf(buf, sizeof(buf), "WARNING: Unable to access logfile %s - parent directory %s does not exist", filename, dirname);
		if(testing_conf || server_state_foreground)
			fprintf(stderr, "%s\n", buf);
		sendto_realops_flags(UMODE_ALL, L_ALL, "%s", buf);
		return;
	}

	if(access(filename, F_OK) == -1)
	{
		if(access(dirname, W_OK) == -1)
		{
			rb_snprintf(buf, sizeof(buf), "WARNING: Unable to access logfile %s - access to parent directory %s failed: %m", 
				    filename, dirname);
			if(testing_conf || server_state_foreground)
				fprintf(stderr, "%s\n", buf);
			sendto_realops_flags(UMODE_ALL, L_ALL, "%s", buf);
		}
		return;
	}
	
	if(access(filename, W_OK) == -1)
	{
		rb_snprintf(buf, sizeof(buf), "WARNING: Access denied for logfile %s: %m", filename);
		if(testing_conf || server_state_foreground)
			fprintf(stderr, "%s\n", buf);	
		sendto_realops_flags(UMODE_ALL, L_ALL, "%s", buf);
		return;
	}
	return;
}

void
init_main_logfile(const char *filename)
{
	verify_logfile_access(filename);
	if(log_main == NULL)
	{
		log_main = fopen(filename, "a");
	}
}

void
open_logfiles(const char *filename)
{
	int i;

	close_logfiles();

	log_main = fopen(filename, "a");

	/* log_main is handled above, so just do the rest */
	for(i = 1; i < LAST_LOGFILE; i++)
	{
		/* reopen those with paths */
		if(!EmptyString(*log_table[i].name))
		{
			verify_logfile_access(*log_table[i].name);
			*log_table[i].logfile = fopen(*log_table[i].name, "a");
		}
	}
}

void
close_logfiles(void)
{
	int i;

	if(log_main != NULL)
		fclose(log_main);

	/* log_main is handled above, so just do the rest */
	for(i = 1; i < LAST_LOGFILE; i++)
	{
		if(*log_table[i].logfile != NULL)
		{
			fclose(*log_table[i].logfile);
			*log_table[i].logfile = NULL;
		}
	}
}

void
ilog(ilogfile dest, const char *format, ...)
{
	FILE *logfile = *log_table[dest].logfile;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	va_list args;

#ifndef _WIN32

	if(logfile == NULL)
		return;
#endif
	va_start(args, format);
	rb_vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	rb_snprintf(buf2, sizeof(buf2), "%s %s\n", smalldate(rb_time()), buf);
#ifdef _WIN32
	fputs(buf2, stderr);
	fflush(stderr);

	if(logfile == NULL)
		return;
#endif
	if(fputs(buf2, logfile) < 0)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Closing logfile: %s (%m)",
				     *log_table[dest].name);
		fclose(logfile);
		*log_table[dest].logfile = NULL;
		return;
	}

	fflush(logfile);
}

void
report_operspy(struct Client *source_p, const char *token, const char *arg)
{
	/* if its not my client its already propagated */
	if(MyClient(source_p))
		sendto_match_servs(source_p, "*", CAP_ENCAP, NOCAPS,
				   "ENCAP * OPERSPY %s %s", token, arg ? arg : "");

	sendto_realops_flags(UMODE_OPERSPY,
			     ConfigFileEntry.operspy_admin_only ? L_ADMIN : L_ALL,
			     "OPERSPY %s %s %s", get_oper_name(source_p), token, arg ? arg : "");

	ilog(L_OPERSPY, "OPERSPY %s %s %s", get_oper_name(source_p), token, arg ? arg : "");
}

const char *
smalldate(time_t ltime)
{
	static char buf[MAX_DATE_STRING];
	struct tm *lt;

	lt = gmtime(&ltime);

	rb_snprintf(buf, sizeof(buf), "%d/%d/%d %02d.%02d",
		    lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min);

	return buf;
}

/*
 * report_error - report an error from an errno. 
 * Record error to log and also send a copy to all *LOCAL* opers online.
 *
 *        text        is a *format* string for outputing error. It must
 *                contain only two '%s', the first will be replaced
 *                by the sockhost from the client_p, and the latter will
 *                be taken from sys_errlist[errno].
 *
 *        client_p        if not NULL, is the *LOCAL* client associated with
 *                the error.
 *
 * Cannot use perror() within daemon. stderr is closed in
 * ircd and cannot be used. And, worse yet, it might have
 * been reassigned to a normal connection...
 * 
 * Actually stderr is still there IFF ircd was run with -s --Rodder
 */

void
report_error(const char *text, const char *who, const char *wholog, int error)
{
	who = (who) ? who : "";
	wholog = (wholog) ? wholog : "";

	sendto_realops_flags(UMODE_DEBUG, L_ALL, text, who, strerror(error));

	ilog(L_IOERROR, text, wholog, strerror(error));
}
