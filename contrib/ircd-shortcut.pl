#!/usr/bin/perl
#
# ircd-shortcut.pl
# This script generates ircd command shortcuts for use with 
# ratbox-services.  These are notably safer to use than users simply 
# messaging the service nicknames, as they cannot be intercepted 
# by other users when services is split.
#
# This file will output to m_rsshortcut.c, which can then be compiled
# as an ircd module and installed.  The module generated is for use
# with ircd-ratbox-2.1.x.
# 
# Copyright (C) 2005 Lee Hardy <lee -at- leeh.co.uk>
# Copyright (C) 2005 ircd-ratbox development team
#
# $Id: ircd-shortcut.pl 20411 2005-05-18 14:31:19Z leeh $

#####################################
##### -- BEGIN CONFIGURATION -- #####
#####################################

# The servername of your services as it appears on IRC.
# 
my $servername = "services.ircd-ratbox.org";

# The list of services you wish to generate shortcuts for.
# This list must be the actual nicknames, as they appear on IRC
# of each service.
# 
my @services = ("USERSERV", "CHANSERV", "NICKSERV", "ALIS",
		"OPERBOT", "OPERSERV", "JUPESERV", "GLOBAL");


######################################
##### -- END OF CONFIGURATION -- #####
######################################


open(FILE, '>', 'm_rsshortcut.c');

print FILE <<".EOF.";
/* m_rsshortcut.c
 *   Contains the code for command shortcuts for ratbox-services
 *
 * Copyright (C) 2005 Lee Hardy <lee -at- leeh.co.uk>
 * Copyright (C) 2005 ircd-ratbox development team
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
 */
#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "modules.h"
#include "parse.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_serv.h"
#include "hash.h"
.EOF.

# generating function names with capital letters is ugly
foreach my $sname (@services) {
	$sname =~ tr/A-Z/a-z/;
}

foreach my $sname (@services) {
	print FILE "static int m_$sname(struct Client *, struct Client *, int, const char **);\n";
}

print FILE "\n";

foreach my $sname (@services) {
	# the command name needs to be in capitals
	my $snamecaps = $sname;
	$snamecaps =~ tr/a-z/A-Z/;
	print FILE "struct Message " . $sname . "_msgtab = {\n";
	print FILE "\t\"$snamecaps\", 0, 0, 0, MFLG_SLOW,\n";
	print FILE "\t{mg_ignore, {m_$sname, 2}, mg_ignore, mg_ignore, mg_ignore, {m_$sname, 2}}\n";
	print FILE "};\n";
};

print FILE "mapi_clist_av2 rsshortcut_clist[] = {\n";

foreach my $sname (@services) {
	print FILE "\t\&" . $sname . "_msgtab,\n";
}

print FILE "\tNULL\n};\n\n";
print FILE "DECLARE_MODULE_AV2(rsshortcut, NULL, NULL, rsshortcut_clist, NULL, NULL, \"1.0\");\n\n";

foreach my $sname (@services) {
	print FILE << ".EOF.";

static int
m_$sname(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	char buf[BUFSIZE];
	int i = 1;

	if(find_server(NULL, "$servername") == NULL)
	{
		sendto_one(source_p, 
			":%s 440 %s $sname :Services are currently unavailable",
			me.name, source_p->name);
		return 0;
	}

	buf[0] = '\\0';

	while(i < parc)
	{
		rb_strlcat(buf, parv[i], sizeof(buf));
		rb_strlcat(buf, " ", sizeof(buf));
		i++;
	}

	sendto_match_servs(client_p, "$servername", CAP_ENCAP, NOCAPS,
			"ENCAP $servername RSMSG $sname %s",
			buf);
	return 0;
}
.EOF.

}

close(FILE);

print <<".EOF.";

Output generated to m_rsshortcut.c
  1. Run make m_rsshortcut.la from the contrib directory
  2. Run sh ../install-mod.sh m_rsshortcut.la PREFIX/modules/autoload
  3. On irc: /quote modrestart
.EOF.
