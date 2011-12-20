/*
 *  ircd-ratbox: A slightly useful ircd.
 *  http.h: Structures and helper functions for handling HTTP requests.
 *
 *  Copyright (C) 2011 Alexander Færøy <ahf@0x90.dk>
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
 */

#ifndef GUARD_HTTP_H
#define GUARD_HTTP_H

#include "http_parser.h"

#define ToHttpRequest(x) ((x)->localClient->websocket_request->http_request)

struct Client;

struct HttpRequest
{
    /* The HTTP parser. */
    http_parser *parser;
    http_parser_settings *settings;

    /* Current header field state. */
    int header_field_state;

    /* HTTP headers. */
    char *sec_websocket_key;    // "Sec-WebSocket-Key".
    char *upgrade;              // "Upgrade".
};

enum HttpStatusCode
{
    HTTP_BAD_REQUEST = 400
};

struct HttpRequest *make_http_request(struct Client *client);
void free_http_request(struct HttpRequest *http_request);
void http_parse_data(struct Client *client, char *buffer, size_t length);
void http_send_protocol_upgrade_reply(struct Client *client, char *nonce);
void http_error(struct Client *client, char *message);

#endif
