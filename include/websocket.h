/*
 *  ircd-ratbox: A slightly useful ircd.
 *  websocket.h: Structures and helper functions for handling WebSocket clients.
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

#ifndef GUARD_WEBSOCKET_H
#define GUARD_WEBSOCKET_H

#define SetWebSocketHandshaking(x)      ((x)->handshaking = 1)
#define ClearWebSocketHandshaking(x)    ((x)->handshaking = 0)
#define IsWebSocketHandshaking(x)       ((x)->handshaking)

#define ToWebSocketRequest(x)           ((x)->localClient->websocket_request)

struct Client;
struct HttpRequest;

struct WebSocketRequest
{
    /* Node in the WebSocket handshaking client list. */
    rb_dlink_node node;

    /* Client. */
    struct Client *client;

    /* HTTP request. */
    struct HttpRequest *http_request;

    /* Timeout. */
    time_t timeout;

    /* Handshaking state. */
    int handshaking;
};

void init_websocket();
void start_websocket_handshake(struct Client *client);
void websocket_parse(struct Client *client, char *buffer, size_t length);
void release_websocket_client(struct Client *client);

#endif
