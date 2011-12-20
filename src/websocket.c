/*
 *  ircd-ratbox: A slightly useful ircd.
 *  websocket.c: Structures and helper functions for handling WebSocket clients.
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

#include "s_conf.h"
#include "struct.h"
#include "client.h"
#include "packet.h"
#include "http.h"
#include "websocket.h"

#include <openssl/sha.h>

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static rb_dlink_list websocket_poll_list;
static rb_bh *websocket_heap;
static EVH timeout_websocket_queries_event;

static unsigned char *generate_nonce_accept(const char *buffer, size_t length)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX context;

    SHA1_Init(&context);
    SHA1_Update(&context, buffer, length);
    SHA1_Update(&context, WEBSOCKET_GUID, sizeof(WEBSOCKET_GUID) - 1);
    SHA1_Final(digest, &context);

    return rb_base64_encode(digest, SHA_DIGEST_LENGTH);
}

static struct WebSocketRequest *make_websocket_request(struct Client *client)
{
    struct WebSocketRequest *websocket_request = rb_bh_alloc(websocket_heap);

    // Attach to the client.
    client->localClient->websocket_request = websocket_request;
    websocket_request->client = client;

    // Timeout.
    websocket_request->timeout = rb_time() + ConfigFileEntry.connect_timeout;

    // HTTP request.
    websocket_request->http_request = make_http_request(client);

    // Mark the client as being in handshaking mode.
    SetWebSocketHandshaking(websocket_request);

    return websocket_request;
}

static void free_websocket_request(struct WebSocketRequest *websocket_request)
{
    if (!websocket_request)
        return;

    rb_free(websocket_request->http_request);
    rb_bh_free(websocket_heap, websocket_request);
}

static void timeout_websocket_queries_event(void *unused)
{
    struct WebSocketRequest *websocket_request;

    rb_dlink_node *ptr;
    rb_dlink_node *next_ptr;

    RB_DLINK_FOREACH_SAFE(ptr, next_ptr, websocket_poll_list.head)
    {
        websocket_request = ptr->data;

        if (websocket_request->timeout < rb_time())
        {
            rb_dlinkDelete(&websocket_request->node, &websocket_poll_list);
            http_error(websocket_request->client, "<h1>Timed out</h1>");
            free_websocket_request(websocket_request);
        }
    }
}

static void websocket_parse_data(struct Client *client, char *buffer, size_t length)
{
    printf("Got WebSocket frame of length %zu: '", length);

    size_t i;
    for (i = 0; i < length ; ++i)
        printf("\\x%02x", (uint8_t)buffer[i]);

    printf("'\n");

    char *end = buffer + length;

    for (; buffer < end; ++buffer)
    {
        uint8_t byte = *buffer;
    }
}

void init_websocket()
{
    memset(&websocket_poll_list, 0, sizeof(websocket_poll_list));
    rb_event_addish("timeout_websocket_queries_event", timeout_websocket_queries_event, NULL, 3);
    websocket_heap = rb_bh_create(sizeof(struct WebSocketRequest), WEBSOCKET_HEAP_SIZE, "websocket_heap");
}

void start_websocket_handshake(struct Client *client)
{
    if (!client)
        return;

    struct WebSocketRequest *websocket_request = make_websocket_request(client);
    rb_dlinkAdd(websocket_request, &websocket_request->node, &websocket_poll_list);
    read_packet(client->localClient->F, client);
}

void websocket_parse(struct Client *client, char *buffer, size_t length)
{
    if (!IsWebSocket(client) || !MyConnect(client))
        return;

    struct WebSocketRequest *websocket_request = ToWebSocketRequest(client);

    if (IsWebSocketHandshaking(websocket_request))
        http_parse_data(client, buffer, length);
    else
        websocket_parse_data(client, buffer, length);
}

void release_websocket_client(struct Client *client)
{
    struct WebSocketRequest *websocket_request = ToWebSocketRequest(client);
    struct HttpRequest *http_request = ToHttpRequest(client);
    char *nonce;

    if (!IsWebSocketHandshaking(websocket_request))
        return;

    if (!http_request->upgrade || !http_request->sec_websocket_key)
    {
        http_error(client, "<h1>Bad Request</h1><p>This server only accepts WebSocket connections.</p>");
        rb_dlinkDelete(&websocket_request->node, &websocket_poll_list);
        free_websocket_request(websocket_request);
        return;
    }

    if (strcasecmp(http_request->upgrade, "websocket") != 0)
    {
        http_error(client, "<h1>Bad Request</h1><p>Unknown HTTP upgrade protocol.</p>");
        rb_dlinkDelete(&websocket_request->node, &websocket_poll_list);
        free_websocket_request(websocket_request);
        return;
    }

    // Send protocol upgrade reply.
    nonce = generate_nonce_accept(http_request->sec_websocket_key, strlen(http_request->sec_websocket_key));
    http_send_protocol_upgrade_reply(client, nonce);
    rb_free(nonce);

    // Done shaking hands.
    ClearWebSocketHandshaking(websocket_request);

    // Release HTTP request memory.
    free_http_request(websocket_request->http_request);
    websocket_request->http_request = NULL;

    // Release the client from the WebSocket timeout loop.
    rb_dlinkDelete(&websocket_request->node, &websocket_poll_list);
}
