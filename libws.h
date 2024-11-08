/*
 * Copyright (C) 2024  Luca Giacometti <samelinux@gmail.com>
 * Copyright (C) 2016-2021  Davidson Francis <davidsondfgl@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/**
 * @dir include/
 * @brief wsServer include directory
 *
 * @file ws.h
 * @brief wsServer constants and functions.
 */
#ifndef WS_H
#define WS_H

#include <stdint.h>

/**
 * @brief events Web Socket events types.
 */
struct ws_events
{
	/**
	 * @brief On open event, called when a new client connects.
	 */
	void (*onopen)(int);
	/**
	 * @brief On close event, called when a client disconnects.
	 */
	void (*onclose)(int);
	/**
	 * @brief On message event, called when a client sends a text
	 * or binary message.
	 */
	void (*onmessage)(int, const unsigned char *,long long int, int);
};

/* Functions declarations. */
extern char *ws_getaddress(int fd);
int ws_sendframe(int fd, const char *msg, uint64_t size, bool broadcast, int type);
int ws_sendtxt(int fd, const char *msg, bool broadcast);
int ws_sendbin(int fd, const char *msg, uint64_t size, bool broadcast);
int ws_close_client(int fd);

int ws_socket(struct ws_events *evs, uint16_t port,int maxClients);
void ws_main_loop(void);
void ws_shutdown(void);

#endif /* WS_H */

