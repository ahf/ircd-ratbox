/*
 *  ircd-ratbox: A slightly useful ircd.
 *  http.c: Structures and helper functions for handling HTTP requests.
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

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "client.h"
#include "websocket.h"

#include <string.h>
#include <ctype.h>

#include "http.h"

#define HTTP_HEADER_FIELD_SEC_WEBSOCKET_KEY         "Sec-WebSocket-Key"
#define HTTP_HEADER_FIELD_UPGRADE                   "Upgrade"

#define IsHeaderSecWebSocketKey(data, length)       (strncasecmp(HTTP_HEADER_FIELD_SEC_WEBSOCKET_KEY, (data), (length)) == 0)
#define IsHeaderUpgrade(data, length)               (strncasecmp(HTTP_HEADER_FIELD_UPGRADE, (data), (length)) == 0)

#define HTTP_HEADER_FIELD_SEC_WEBSOCKET_KEY_STATE   0x01
#define HTTP_HEADER_FIELD_UPGRADE_STATE             0x02

#define SetHeaderStateSecWebSocketKey(x)            ((x)->header_field_state = HTTP_HEADER_FIELD_SEC_WEBSOCKET_KEY_STATE)
#define IsHeaderStateSecWebSocketKey(x)             ((x)->header_field_state == HTTP_HEADER_FIELD_SEC_WEBSOCKET_KEY_STATE)

#define SetHeaderStateUpgrade(x)                    ((x)->header_field_state = HTTP_HEADER_FIELD_UPGRADE_STATE)
#define IsHeaderStateUpgrade(x)                     ((x)->header_field_state == HTTP_HEADER_FIELD_UPGRADE_STATE)

#define ClearHeaderState(x)                         ((x)->header_field_state = 0)

#define HTTP_GENERIC_REPLY                          "HTTP/1.1 %d %s\r\n"          \
                                                    "Content-Type: text/html; charset=UTF-8\r\n" \
                                                    "Content-Length: %zu\r\n"     \
                                                    "\r\n"                        \
                                                    "%s"

#define HTTP_PROTOCOL_UPGRADE_REPLY                 "HTTP/1.1 101 Switching Protocols\r\n" \
                                                    "Upgrade: websocket\r\n"               \
                                                    "Connection: Upgrade\r\n"              \
                                                    "Sec-WebSocket-Accept: %s\r\n"         \
                                                    "\r\n"

static char http_reply_buffer[2048];

static const char *http_status_string(enum HttpStatusCode status)
{
    switch (status)
    {
        case HTTP_BAD_REQUEST:
            return "Bad Request";
    }

    return NULL;
}

static void http_send_reply(struct Client *client, enum HttpStatusCode status, char *body)
{
    int length;
    length = rb_snprintf(http_reply_buffer, sizeof(http_reply_buffer), HTTP_GENERIC_REPLY, status, http_status_string(status), strlen(body), body);
    rb_write(client->localClient->F, http_reply_buffer, length);
}

static char *extract_http_header(char *buffer, size_t length)
{
    // Sanity check.
    if (!buffer || !length)
        return NULL;

    // Trim any leading spaces.
    while (isspace(*buffer))
    {
        buffer++;
        --length;
    }

    // Did the string contain spaces only?
    if (*buffer == '\0')
        return NULL;

    // Trim any trailing spaces.
    while (length > 0 && isspace(buffer[length - 1]))
        --length;

    buffer[length] = '\0';

    return rb_strdup(buffer);
}

static int on_message_complete_callback(http_parser *parser)
{
    if (!parser->upgrade)
        release_websocket_client(parser->client);

    return 0;
}

static int on_header_field_callback(http_parser *parser, const char *buffer, size_t length)
{
    struct HttpRequest *http_request = ToHttpRequest(parser->client);

    // HTTP Header: "Sec-WebSocket-Key".
    if (IsHeaderSecWebSocketKey(buffer, length))
    {
        SetHeaderStateSecWebSocketKey(http_request);
        return 0;
    }

    // HTTP Header: "Upgrade".
    if (IsHeaderUpgrade(buffer, length))
    {
        SetHeaderStateUpgrade(http_request);
        return 0;
    }

    return 0;
}

static int on_header_value_callback(http_parser *parser, const char *buffer, size_t length)
{
    struct HttpRequest *http_request = ToHttpRequest(parser->client);

    // Extract HTTP header value for "Sec-WebSocket-Key".
    if (IsHeaderStateSecWebSocketKey(http_request))
    {
        http_request->sec_websocket_key = extract_http_header(buffer, length);
        ClearHeaderState(http_request);
        return 0;
    }

    // Extract HTTP header value for "Upgrade".
    if (IsHeaderStateUpgrade(http_request))
    {
        http_request->upgrade = extract_http_header(buffer, length);
        ClearHeaderState(http_request);
        return 0;
    }

    return 0;
}

struct HttpRequest *make_http_request(struct Client *client)
{
    struct HttpRequest *http_request = rb_malloc(sizeof(struct HttpRequest));

    // Allocate and initialize the HTTP Parser.
    http_request->parser = rb_malloc(sizeof(http_parser));
    http_request->parser->client = client;
    http_parser_init(http_request->parser, HTTP_REQUEST);

    // Allocate and set callback functions for the HTTP parser.
    http_request->settings = rb_malloc(sizeof(http_parser_settings));
    memset(http_request->settings, 0, sizeof(http_parser_settings));

    http_request->settings->on_message_complete = on_message_complete_callback;
    http_request->settings->on_header_field = on_header_field_callback;
    http_request->settings->on_header_value = on_header_value_callback;

    // Clear the HTTP header state.
    ClearHeaderState(http_request);

    // HTTP Headers.
    http_request->sec_websocket_key = NULL;
    http_request->upgrade = NULL;

    return http_request;
}

void free_http_request(struct HttpRequest *http_request)
{
    if (!http_request)
        return;

    rb_free(http_request->parser);
    rb_free(http_request->settings);
    rb_free(http_request->sec_websocket_key);
    rb_free(http_request->upgrade);
    rb_free(http_request);
}

void http_parse_data(struct Client *client, char *buffer, size_t length)
{
    if (!IsWebSocket(client))
        return;

    struct HttpRequest *http_request = ToHttpRequest(client);
    int status;

    // Try parsing the incoming buffer.
    status = http_parser_execute(http_request->parser, http_request->settings, buffer, length);

    // Is this an HTTP upgrade request?
    if (http_request->parser->upgrade)
        release_websocket_client(client);
}

void http_send_protocol_upgrade_reply(struct Client *client, char *nonce)
{
    int length;
    length = rb_snprintf(http_reply_buffer, sizeof(http_reply_buffer), HTTP_PROTOCOL_UPGRADE_REPLY, nonce);
    rb_write(client->localClient->F, http_reply_buffer, length);
}

void http_error(struct Client *client, char *message)
{
    http_send_reply(client, HTTP_BAD_REQUEST, message);
    close_connection(client);
}
