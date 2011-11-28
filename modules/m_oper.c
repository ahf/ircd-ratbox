/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_oper.c: Makes a user an IRC Operator.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 *  $Id: m_oper.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"

#ifdef USE_CHALLENGE
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include "struct.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "s_user.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "cache.h"


#define CHALLENGE_WIDTH BUFSIZE - (NICKLEN + HOSTLEN + 12)
#define CHALLENGE_EXPIRES	180	/* 180 seconds should be more than long enough */
#define CHALLENGE_SECRET_LENGTH	128	/* how long our challenge secret should be */

static int m_oper(struct Client *, struct Client *, int, const char **);
static int oper_up(struct Client *source_p, struct oper_conf *oper_p);
static int match_oper_password(const char *password, struct oper_conf *oper_p);
static void send_oper_motd(struct Client *source_p);

struct Message oper_msgtab = {
	"OPER", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_oper, 3}, mg_ignore, mg_ignore, mg_ignore, {m_oper, 3}}
};


static int m_challenge(struct Client *, struct Client *, int, const char **);

struct Message challenge_msgtab = {
	"CHALLENGE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_challenge, 2}, mg_ignore, mg_ignore, mg_ignore, {m_challenge, 2}}
};

mapi_clist_av2 oper_clist[] = { &oper_msgtab, &challenge_msgtab, NULL };

DECLARE_MODULE_AV2(oper, NULL, NULL, oper_clist, NULL, NULL, "$Revision: 27173 $");


/*
 * m_oper
 *      parv[1] = oper name
 *      parv[2] = oper password
 */
static int
m_oper(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct oper_conf *oper_p;
	const char *name;
	const char *password;

	name = parv[1];
	password = parv[2];

	if(IsOper(source_p))
	{
		sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
		send_oper_motd(source_p);
		return 0;
	}

	/* end the grace period */
	if(!IsFloodDone(source_p))
		flood_endgrace(source_p);

	oper_p = find_oper_conf(source_p->username, source_p->host, source_p->sockhost, name);

	if(oper_p == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
		ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
		     name, source_p->name, source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed OPER attempt - host mismatch by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		}

		return 0;
	}
	if(IsOperConfNeedSSL(oper_p) && !IsSSL(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
		ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s) -- requires SSL/TLS",
		     name, source_p->name, source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed OPER attempt - missing SSL/TLS by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		}
		return 0;
	}

	if(match_oper_password(password, oper_p))
	{
		oper_up(source_p, oper_p);

		ilog(L_OPERED, "OPER %s by %s!%s@%s",
		     name, source_p->name, source_p->username, source_p->host);
		return 0;
	}
	else
	{
		sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, source_p->name);

		ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
		     name, source_p->name, source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed OPER attempt by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		}
	}

	return 0;
}


/* send_oper_motd()
 *
 * inputs	- client to send motd to
 * outputs	- client is sent oper motd if exists
 * side effects -
 */
static void
send_oper_motd(struct Client *source_p)
{
	struct cacheline *lineptr;
	rb_dlink_node *ptr;

	if(oper_motd == NULL || rb_dlink_list_length(&oper_motd->contents) == 0)
		return;
	SetCork(source_p);
	sendto_one(source_p, form_str(RPL_OMOTDSTART), me.name, source_p->name);

	RB_DLINK_FOREACH(ptr, oper_motd->contents.head)
	{
		lineptr = ptr->data;
		sendto_one(source_p, form_str(RPL_OMOTD), me.name, source_p->name, lineptr->data);
	}
	ClearCork(source_p);
	sendto_one(source_p, form_str(RPL_ENDOFOMOTD), me.name, source_p->name);
}


/*
 * match_oper_password
 *
 * inputs       - pointer to given password
 *              - pointer to Conf 
 * output       - YES or NO if match
 * side effects - none
 */
static int
match_oper_password(const char *password, struct oper_conf *oper_p)
{
	const char *encr;

	/* passwd may be NULL pointer. Head it off at the pass... */
	if(EmptyString(oper_p->passwd))
		return NO;

	if(IsOperConfEncrypted(oper_p))
	{
		/* use first two chars of the password they send in as salt */
		/* If the password in the conf is MD5, and ircd is linked   
		 * to scrypt on FreeBSD, or the standard crypt library on
		 * glibc Linux, then this code will work fine on generating
		 * the proper encrypted hash for comparison.
		 */
		if(!EmptyString(password))
			encr = rb_crypt(password, oper_p->passwd);
		else
			encr = "";
	}
	else
		encr = password;

	if(strcmp(encr, oper_p->passwd) == 0)
		return YES;
	else
		return NO;
}

/* oper_up()
 *
 * inputs	- pointer to given client to oper
 *		- pointer to ConfItem to use
 * output	- none
 * side effects	- opers up source_p using aconf for reference
 */
static int
oper_up(struct Client *source_p, struct oper_conf *oper_p)
{
	int old = (source_p->umodes & ALL_UMODES);

	SetOper(source_p);

	if(oper_p->umodes)
		source_p->umodes |= oper_p->umodes & ALL_UMODES;
	else if(ConfigFileEntry.oper_umodes)
		source_p->umodes |= ConfigFileEntry.oper_umodes & ALL_UMODES;
	else
		source_p->umodes |= DEFAULT_OPER_UMODES & ALL_UMODES;

	Count.oper++;

	SetExemptKline(source_p);

	source_p->operflags |= oper_p->flags;
	source_p->localClient->opername = rb_strdup(oper_p->name);

	rb_dlinkAddAlloc(source_p, &oper_list);

	if(IsOperAdmin(source_p) && !IsOperHiddenAdmin(source_p))
		source_p->umodes |= UMODE_ADMIN;
	if(!IsOperN(source_p))
		source_p->umodes &= ~UMODE_NCHANGE;
	if(!IsOperOperwall(source_p))
		source_p->umodes &= ~UMODE_OPERWALL;

	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s (%s@%s) is now an operator", source_p->name,
			     source_p->username, source_p->host);
	if(!(old & UMODE_INVISIBLE) && IsInvisible(source_p))
		++Count.invisi;
	if((old & UMODE_INVISIBLE) && !IsInvisible(source_p))
		--Count.invisi;
	send_umode_out(source_p, source_p, old);
	sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
	sendto_one_notice(source_p, ":*** Oper privs are %s", get_oper_privs(oper_p->flags));
	send_oper_motd(source_p);

	return (1);
}


#ifndef USE_CHALLENGE
static int
m_challenge(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	sendto_one_notice(source_p, ":Challenge not implemented");
	return 0;
}

#else

static int generate_challenge(uint8_t **r_challenge, uint8_t **r_response, RSA * rsa);

static void
cleanup_challenge(struct Client *target_p)
{
	if(target_p->localClient == NULL)
		return;

	rb_free(target_p->localClient->chal_resp);
	rb_free(target_p->localClient->opername);
	target_p->localClient->chal_resp = NULL;
	target_p->localClient->opername = NULL;
	target_p->localClient->chal_time = 0;
}

/*
 * m_challenge - generate RSA challenge for wouldbe oper
 * parv[1] = operator to challenge for, or +response
 *
 */

static int
m_challenge(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct oper_conf *oper_p;
	uint8_t *challenge = NULL;
	char chal_line[CHALLENGE_WIDTH];
	uint8_t *b_response;
	int len = 0;
	size_t cnt;

	if(IsOper(source_p))
	{
		sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
		send_oper_motd(source_p);
		return 0;
	}

	if(*parv[1] == '+')
	{
		if(source_p->localClient->chal_resp == NULL)
			return 0;

		if((rb_time() - source_p->localClient->chal_time) > CHALLENGE_EXPIRES)
		{
			sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, source_p->name);
			ilog(L_FOPER, "EXPIRED CHALLENGE (%s) by (%s!%s@%s)",
			     source_p->localClient->opername, source_p->name,
			     source_p->username, source_p->host);

			if(ConfigFileEntry.failed_oper_notice)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Expired CHALLENGE attempt by %s (%s@%s)",
						     source_p->name, source_p->username,
						     source_p->host);
			cleanup_challenge(source_p);
			return 0;
		}

		parv[1]++;
		b_response =
			rb_base64_decode((const unsigned char *)parv[1], strlen(parv[1]), &len);

		if(len != SHA_DIGEST_LENGTH
		   || memcmp(source_p->localClient->chal_resp, b_response, SHA_DIGEST_LENGTH))
		{
			sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, source_p->name);
			ilog(L_FOPER, "FAILED CHALLENGE (%s) by (%s!%s@%s)",
			     source_p->localClient->opername, source_p->name,
			     source_p->username, source_p->host);

			if(ConfigFileEntry.failed_oper_notice)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Failed CHALLENGE attempt by %s (%s@%s)",
						     source_p->name, source_p->username,
						     source_p->host);

			rb_free(b_response);
			cleanup_challenge(source_p);
			return 0;
		}

		rb_free(b_response);

		oper_p = find_oper_conf(source_p->username, source_p->host,
					source_p->sockhost, source_p->localClient->opername);

		if(oper_p == NULL)
		{
			sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
			ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
			     source_p->localClient->opername, source_p->name,
			     source_p->username, source_p->host);

			if(ConfigFileEntry.failed_oper_notice)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Failed CHALLENGE attempt - host mismatch by %s (%s@%s)",
						     source_p->name, source_p->username,
						     source_p->host);
			return 0;
		}

		cleanup_challenge(source_p);

		oper_up(source_p, oper_p);

		ilog(L_OPERED, "OPER %s by %s!%s@%s",
		     source_p->localClient->opername, source_p->name,
		     source_p->username, source_p->host);
		return 0;
	}

	cleanup_challenge(source_p);

	oper_p = find_oper_conf(source_p->username, source_p->host, source_p->sockhost, parv[1]);

	if(oper_p == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
		ilog(L_FOPER, "FAILED CHALLENGE (%s) by (%s!%s@%s)",
		     parv[1], source_p->name, source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed CHALLENGE attempt - host mismatch by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		return 0;
	}

	if(!oper_p->rsa_pubkey)
	{
		sendto_one_notice(source_p, ":I'm sorry, PK authentication "
				  "is not enabled for your oper{} block.");
		return 0;
	}

	if(IsOperConfNeedSSL(oper_p) && !IsSSL(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
		ilog(L_FOPER, "FAILED CHALLENGE (%s) by (%s!%s@%s) -- requires SSL/TLS",
		     parv[1], source_p->name, source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed CHALLENGE attempt - missing SSL/TLS by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		}
		return 0;
	}


	if(!generate_challenge(&challenge, &source_p->localClient->chal_resp, oper_p->rsa_pubkey))
	{
		char *chal = (char *)challenge;
		source_p->localClient->chal_time = rb_time();
		SetCork(source_p);
		for(;;)
		{
			cnt = rb_strlcpy(chal_line, chal, CHALLENGE_WIDTH);
			sendto_one(source_p, form_str(RPL_RSACHALLENGE2), me.name, source_p->name,
				   chal_line);
			if(cnt > CHALLENGE_WIDTH)
				chal += CHALLENGE_WIDTH - 1;
			else
				break;

		}
		ClearCork(source_p);
		sendto_one(source_p, form_str(RPL_ENDOFRSACHALLENGE2), me.name, source_p->name);

		source_p->localClient->opername = rb_strdup(oper_p->name);
		rb_free(challenge);
	}
	else
		sendto_one_notice(source_p, ":Failed to generate challenge.");

	return 0;
}


static int
generate_challenge(uint8_t **r_challenge, uint8_t **r_response, RSA * rsa)
{
	SHA_CTX ctx;
	uint8_t secret[CHALLENGE_SECRET_LENGTH], *tmp;
	unsigned long length;
	unsigned long e = 0;
	unsigned long cnt = 0;
	int ret;

	if(!rsa)
		return -1;
	if(rb_get_random(secret, CHALLENGE_SECRET_LENGTH))
	{
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, secret, CHALLENGE_SECRET_LENGTH);
		*r_response = rb_malloc(SHA_DIGEST_LENGTH);
		SHA1_Final((uint8_t *)*r_response, &ctx);

		length = RSA_size(rsa);
		tmp = rb_malloc(length);
		ret = RSA_public_encrypt(CHALLENGE_SECRET_LENGTH, secret, tmp, rsa,
					 RSA_PKCS1_OAEP_PADDING);

		if(ret >= 0)
		{
			*r_challenge = rb_base64_encode(tmp, ret);
			rb_free(tmp);
			return 0;
		}

		rb_free(tmp);
		rb_free(*r_response);
		*r_response = NULL;
	}

	ERR_load_crypto_strings();
	while((cnt < 100) && (e = ERR_get_error()))
	{
		ilog(L_MAIN, "SSL error: %s", ERR_error_string(e, 0));
		cnt++;
	}

	return (-1);
}

#endif /* USE_CHALLENGE */
