#!/bin/sh
# Simple and straight forward openssl cert generator for ircd-ratbox
# Copyright (C) 2008-2011 ircd-ratbox development team
# $Id: genssl.sh 27247 2011-10-21 00:04:02Z dubkat $

if [ $# -eq 0 ]; then
	echo
	echo "usage: $0 <IRC_SERVER_NAME> [<LENGTH_IN_DAYS_KEYS_ARE_VALID>]"
	echo "       default lenth of time keys are valid is 365 days."
	echo
	exit 1;
fi

SERVER="$1"
DAYS_VALID="$2"

SSL_DAYS_VALID="365"
if [ "$DAYS_VALID" -gt "365" ]; then
	SSL_DAYS_VALID="$DAYS_VALID"
fi

echo
echo "Generating 1024-bit self-signed RSA key for ${SERVER}... "
openssl req -new -newkey rsa:1024 -days ${SSL_DAYS_VALID} -nodes -x509 -keyout ${SERVER}.pem  -out ${SERVER}.pem
echo "Done creating self-signed cert"

echo -n "Generating DH parameters file... "
openssl dhparam -out dh.pem 1024
echo "Done."

echo
echo "Your SSL keys for ${SERVER} are valid for ${SSL_DAYS_VALID} days."
echo "If you wish to increase the number of days, run:"
echo "    $0 ${SERVER} <NUMBER_OF_DAYS>"
echo
echo "Move ${SERVER}.pem and dh.pem to your ircd config directory if necessary."
echo "Adjust ircd.conf to reflect any changes."
echo "Your serverinfo {} block should contain the following (adjust paths accordingly)"
echo
echo "ssl_private_key = \"`pwd`/${SERVER}.pem\";"
echo "ssl_cert = \"`pwd`/${SERVER}.pem\";"
echo "ssl_dh_params = \"`pwd`/dh.pem\";"

echo
exit 0

