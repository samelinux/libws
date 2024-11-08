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

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#define _GNU_SOURCE
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

// ssl
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// sha1 and base64
#include <openssl/sha.h>
#include <openssl/evp.h>

// utf8
#include <inttypes.h>

#include "libws.h"

/**
 * @brief Debug
 */
//#define VERBOSE_MODE
#ifdef VERBOSE_MODE
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

/**
 * @name Global configurations
 */
/**
 * @brief Socket timeout for setsockopt
 */
#define SOCKET_TIMEOUT_SECOND (30)
#define SOCKET_TIMEOUT_USECOND (0)
/**
 * @brief Message buffer length.
 */
#define MESSAGE_LENGTH 2048
/**
 * @brief Maximum frame/message length.
 */
#define MAX_FRAME_LENGTH (16*1024*1024)
/**
 * @brief WebSocket key length.
 */
#define WS_KEY_LEN     24
/**
 * @brief Magic string length.
 */
#define WS_MS_LEN      36
/**
 * @brief Accept message response length.
 */
#define WS_KEYMS_LEN   (WS_KEY_LEN + WS_MS_LEN)
/**
 * @brief Magic string.
 */
#define MAGIC_STRING   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
/**
 * @brief Alias for 'Sec-WebSocket-Key'.
 */
#define WS_HS_REQ      "Sec-WebSocket-Key"
/**
 * @brief Handshake accept message length.
 */
#define WS_HS_ACCLEN   130
/**
 * @brief Handshake accept message.
 */
#define WS_HS_ACCEPT                       \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Upgrade: websocket\r\n"               \
	"Connection: Upgrade\r\n"              \
	"Sec-WebSocket-Accept: "

/**
 * @name Frame types.
 */
/**@{*/
/**
 * @brief Frame FIN.
 */
#define WS_FIN      128
/**
 * @brief Frame FIN shift
 */
#define WS_FIN_SHIFT  7
/**
 * @brief Continuation frame.
 */
#define WS_FR_OP_CONT 0
/**
 * @brief Text frame.
 */
#define WS_FR_OP_TXT  1
/**
 * @brief Binary frame.
 */
#define WS_FR_OP_BIN  2
/**
 * @brief Close frame.
 */
#define WS_FR_OP_CLSE 8
/**
 * @brief Ping frame.
 */
#define WS_FR_OP_PING 0x9
/**
 * @brief Pong frame.
 */
#define WS_FR_OP_PONG 0xA
/**
 * @brief Unsupported frame.
 */
#define WS_FR_OP_UNSUPPORTED 0xF
/**@}*/

/**
 * @name Close codes
 */
/**
 * @brief Normal close
 */
#define WS_CLSE_NORMAL  1000
/**
 * @brief Protocol error
 */
#define WS_CLSE_PROTERR 1002
/**
 * @brief Inconsistent message (invalid utf-8)
 */
#define WS_CLSE_INVUTF8 1007

/**
 * @name Connection states
 */
/**
 * @brief Connection not established yet.
 */
#define WS_STATE_CONNECTING 0
/**
 * @brief Communicating.
 */
#define WS_STATE_OPEN       1
/**
 * @brief Closing state.
 */
#define WS_STATE_CLOSING    2
/**
 * @brief Closed.
 */
#define WS_STATE_CLOSED     3

#define UTF8_ACCEPT 0
#define UTF8_REJECT 1
extern int is_utf8(uint8_t* s);
extern int is_utf8_len(uint8_t *s, size_t len);
extern uint32_t is_utf8_len_state(uint8_t *s, size_t len, uint32_t state);
static const uint8_t utf8d[] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
	8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
	0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
	0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
	0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
	1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
	1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
	1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
};

/* Windows and macOS seems to not have MSG_NOSIGNAL */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/**
 * @brief wsServer main routines.
 */

/**
 * @brief Server socket.
 */
int server_socket=-1;

/**
 * @brief Maximum number for connected clients
 */
int max_clients=0;

/**
 * @brief poll data structure and variables
 */
static struct pollfd* serverFds;
static int serverFdsCount=0;
#define SERVER_POLL_TIMEOUT 500

/**
 * @brief event handler to notify changes
 */
struct ws_events eventsHandler;

/**
 * @brief Client socks.
 */
struct ws_connection
{
	int client_sock; /**< Client socket FD.        */
	SSL* ssl_sock;
	int state;       /**< WebSocket current state. */
};

/**
 * @brief Clients list.
 */
struct ws_connection* client_socks;

/**
 * @brief WebSocket frame data
 */
struct ws_frame_data
{
	/**
	 * @brief Frame read.
	 */
	unsigned char frm[MESSAGE_LENGTH];
	/**
	 * @brief Processed message at the moment.
	 */
	unsigned char *msg;
	/**
	 * @brief Control frame payload
	 */
	unsigned char msg_ctrl[125];
	/**
	 * @brief Current byte position.
	 */
	size_t cur_pos;
	/**
	 * @brief Amount of read bytes.
	 */
	size_t amt_read;
	/**
	 * @brief Frame type, like text or binary.
	 */
	int frame_type;
	/**
	 * @brief Frame size.
	 */
	uint64_t frame_size;
	/**
	 * @brief Error flag, set when a read was not possible.
	 */
	int error;
	/**
	 * @brief Client socket file descriptor.
	 */
	int sock;
	SSL* ssl_sock;
};

/**
 * @brief Issues an error message and aborts the program.
 *
 * @param s Error message.
 */
#define panic(s)   \
	do             \
{              \
	perror(s); \
	exit(-1);  \
} while (0);

/**
 * Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * Amazing utf8 decoder & validator grabbed from:
 *   http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
 *
 * All rights goes to the original author.
 */
static
uint32_t decode(uint32_t* state, uint32_t* codep, uint32_t byte) {
	uint32_t type = utf8d[byte];

	*codep = (*state != UTF8_ACCEPT) ?
		(byte & 0x3fu) | (*codep << 6) :
		(0xff >> type) & (byte);

	*state = utf8d[256 + *state*16 + type];
	return *state;
}

int is_utf8(uint8_t *s) {
	uint32_t codepoint, state = 0;

	while (*s)
		decode(&state, &codepoint, *s++);

	return state == UTF8_ACCEPT;
}

int is_utf8_len(uint8_t *s, size_t len) {
	uint32_t codepoint, state = 0;
	size_t i;

	for (i = 0; i < len; i++)
		decode(&state, &codepoint, *s++);

	return state == UTF8_ACCEPT;
}

uint32_t is_utf8_len_state(uint8_t *s, size_t len, uint32_t state) {
	uint32_t codepoint;
	size_t i;

	for (i = 0; i < len; i++)
		decode(&state, &codepoint, *s++);

	return state;
}

/**
 * @brief Handshake routines.
 */

/**
 * @brief Gets the field Sec-WebSocket-Accept on response, by
 * an previously informed key.
 *
 * @param wsKey Sec-WebSocket-Key
 * @param dest source to be stored the value.
 *
 * @return Returns 0 if success and a negative number
 * otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
int get_handshake_accept(char *wsKey, unsigned char **dest)
{
	char *str;                        /* WebSocket key + magic string. */
	unsigned char hash[SHA_DIGEST_LENGTH];

	/* Invalid key. */
	if (!wsKey)
		return (-1);

	str = calloc(1, sizeof(char) * (WS_KEY_LEN + WS_MS_LEN + 1));
	if (!str)
		return (-1);

	strncpy(str, wsKey, WS_KEY_LEN);
	strcat(str, MAGIC_STRING);

	memset(hash,0,SHA_DIGEST_LENGTH);
	SHA1((unsigned char*)str,WS_KEYMS_LEN,hash);

	int b64len=(1 + ((SHA_DIGEST_LENGTH + 2) / 3 * 4));
	*dest=malloc(sizeof(char)*b64len);
	memset(*dest,0,b64len);
	EVP_EncodeBlock(*dest,hash,SHA_DIGEST_LENGTH);
	free(str);
	return (0);
}

/**
 * @brief Gets the complete response to accomplish a succesfully
 * handshake.
 *
 * @param hsrequest  Client request.
 * @param hsresponse Server response.
 *
 * @return Returns 0 if success and a negative number
 * otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
int get_handshake_response(char *hsrequest, char **hsresponse)
{
	unsigned char *accept; /* Accept message.     */
	char *saveptr;         /* strtok_r() pointer. */
	char *s;               /* Current string.     */
	int ret;               /* Return value.       */

	saveptr = NULL;
	for (s = strtok_r(hsrequest, "\r\n", &saveptr); s != NULL;
			s = strtok_r(NULL, "\r\n", &saveptr))
	{
		if (strstr(s, WS_HS_REQ) != NULL)
			break;
	}

	/* Ensure that we have a valid pointer. */
	if (s == NULL)
		return (-1);

	saveptr = NULL;
	s       = strtok_r(s, " ", &saveptr);
	s       = strtok_r(NULL, " ", &saveptr);

	ret = get_handshake_accept(s, &accept);
	if (ret < 0)
		return (ret);

	*hsresponse = malloc(sizeof(char) * WS_HS_ACCLEN);
	if (*hsresponse == NULL)
		return (-1);

	strcpy(*hsresponse, WS_HS_ACCEPT);
	strcat(*hsresponse, (const char *)accept);
	strcat(*hsresponse, "\r\n\r\n");

	free(accept);
	return (0);
}

/**
 * @brief Shutdown and close a given socket.
 *
 * @param fd Socket file descriptor to be closed.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static void close_socket(int fd,SSL** ssl_sock)
{
	if(ssl_sock!=NULL && *ssl_sock!=NULL)
	{
		SSL_free (*ssl_sock);
		*ssl_sock=NULL;
	}
#ifndef _WIN32
	shutdown(fd, SHUT_RDWR);
	close(fd);
#else
	closesocket(fd);
#endif
}

/**
 * @brief Send a given message @p buf on a socket @p sockfd.
 *
 * @param sockfd Target socket.
 * @param buf Message to be sent.
 * @param len Message length.
 * @param flags Send flags.
 *
 * @return Returns 0 if success (i.e: all message was sent),
 * -1 otherwise.
 *
 * @note Technically this shouldn't be necessary, since send() should
 * block until all content is sent, since _we_ don't use 'O_NONBLOCK'.
 * However, it was reported (issue #22 on GitHub) that this was
 * happening, so just to be cautious, I will keep using this routine.
 */
static ssize_t send_all(SSL* sockfd, const void *buf, size_t len)
{
	const char *p;
	ssize_t ret;
	p = buf;
	while (len)
	{
		ret = SSL_write(sockfd, p, len);
		if (ret == -1)
			return (-1);
		p += ret;
		len -= ret;
	}
	return (0);
}

/**
 * @brief For a given client @p fd, returns its
 * client index if exists, or -1 otherwise.
 *
 * @param fd Client fd.
 *
 * @return Return the client index or -1 if invalid
 * fd.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int get_client_index(int fd)
{
	int i;
	for (i = 0; i < max_clients; i++)
		if (client_socks[i].client_sock == fd)
			break;
	return i;
}

/**
 * @brief Returns the current client state for a given
 * client @p idx.
 *
 * @param idx Client index.
 *
 * @return Returns the client state, -1 otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int get_client_state(int idx)
{
	int state;

	if (idx < 0 || idx >= max_clients)
		return (-1);

	state = client_socks[idx].state;
	return (state);
}

/**
 * @brief Set a state @p state to the client index
 * @p idx.
 *
 * @param idx Client index.
 * @param state State to be set.
 *
 * @return Returns 0 if success, -1 otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int set_client_state(int idx, int state)
{
	if (idx < 0 || idx >= max_clients)
		return (-1);

	if (state < 0 || state > 3)
		return (-1);

	client_socks[idx].state = state;
	return (0);
}

/**
 * @brief For a valid client index @p idx, starts
 * the timeout thread and set the current state
 * to 'CLOSING'.
 *
 * @param idx Client index.
 *
 * @return Returns 0 if success, -1 otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int close_connection(int idx)
{
	if (idx < 0 || idx >= max_clients)
		return (-1);

	if (client_socks[idx].state != WS_STATE_OPEN)
		return 0;

	close_socket(client_socks[idx].client_sock,&(client_socks[idx].ssl_sock));
	client_socks[idx].client_sock = -1;
	client_socks[idx].ssl_sock = NULL;
	client_socks[idx].state       = WS_STATE_CLOSED;

	return (0);
}

/**
 * @brief Gets the IP address relative to a file descriptor opened
 * by the server.
 *
 * @param fd File descriptor target.
 *
 * @return Pointer the ip address, or NULL if fails.
 *
 * @note It is up the caller to free the returned string.
 */
char *ws_getaddress(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_size;
	char *client;

	addr_size = sizeof(struct sockaddr_in);
	if (getpeername(fd, (struct sockaddr *)&addr, &addr_size) < 0)
		return (NULL);

	client = malloc(sizeof(char) * INET_ADDRSTRLEN);
	if (!client)
		return (NULL);

	if (!inet_ntop(AF_INET, &addr.sin_addr, client, INET_ADDRSTRLEN))
	{
		free(client);
		return (NULL);
	}
	return (client);
}

/**
 * @brief Creates and send an WebSocket frame with some payload data.
 *
 * This routine is intended to be used to create a websocket frame for
 * a given type e sending to the client. For higher level routines,
 * please check @ref ws_sendframe_txt and @ref ws_sendframe_bin.
 *
 * @param fd        Target to be send.
 * @param msg       Message to be send.
 * @param size      Binary message size.
 * @param broadcast Enable/disable broadcast.
 * @param type      Frame type.
 *
 * @return Returns the number of bytes written, -1 if error.
 *
 * @note If @p size is -1, it is assumed that a text frame is being sent,
 * otherwise, a binary frame. In the later case, the @p size is used.
 */
int ws_sendframe_ssl(SSL* fd, const char *msg, uint64_t size, bool broadcast, int type)
{
	unsigned char *response; /* Response data.     */
	unsigned char frame[10]; /* Frame.             */
	uint8_t idx_first_rData; /* Index data.        */
	uint64_t length;         /* Message length.    */
	int idx_response;        /* Index response.    */
	ssize_t output;          /* Bytes sent.        */
	ssize_t send_ret;        /* Ret send function  */

	frame[0] = (WS_FIN | type);
	length   = (uint64_t)size;

	/* Split the size between octets. */
	if (length <= 125)
	{
		frame[1]        = length & 0x7F;
		idx_first_rData = 2;
	}

	/* Size between 126 and 65535 bytes. */
	else if (length >= 126 && length <= 65535)
	{
		frame[1]        = 126;
		frame[2]        = (length >> 8) & 255;
		frame[3]        = length & 255;
		idx_first_rData = 4;
	}

	/* More than 65535 bytes. */
	else
	{
		frame[1]        = 127;
		frame[2]        = (unsigned char)((length >> 56) & 255);
		frame[3]        = (unsigned char)((length >> 48) & 255);
		frame[4]        = (unsigned char)((length >> 40) & 255);
		frame[5]        = (unsigned char)((length >> 32) & 255);
		frame[6]        = (unsigned char)((length >> 24) & 255);
		frame[7]        = (unsigned char)((length >> 16) & 255);
		frame[8]        = (unsigned char)((length >> 8) & 255);
		frame[9]        = (unsigned char)(length & 255);
		idx_first_rData = 10;
	}

	/* Add frame bytes. */
	idx_response = 0;
	response     = malloc(sizeof(unsigned char) * (idx_first_rData + length + 1));
	if (!response)
		return (-1);

	for (int i = 0; i < idx_first_rData; i++)
	{
		response[i] = frame[i];
		idx_response++;
	}

	/* Add data bytes. */
	for (uint64_t i = 0; i < length; i++)
	{
		response[idx_response] = msg[i];
		idx_response++;
	}

	response[idx_response] = '\0';
	output                 = send_all(fd, response, idx_response);

	if (output != -1 && broadcast)
	{
		for (int i = 0; i < max_clients; i++)
		{
			if(client_socks[i].ssl_sock!=NULL && client_socks[i].ssl_sock!=fd)
			{
				if ((send_ret = send_all(client_socks[i].ssl_sock, response, idx_response)) != -1)
					output += send_ret;
				else
				{
					output = -1;
					break;
				}
			}
		}
	}

	free(response);
	return ((int)output);
}

/**
 * @brief Sends a WebSocket frame.
 *
 * @param fd         Target to be send.
 * @param msg        Buffer to be send.
 * @param size       Buffer size
 * @param broadcast  Enable/disable broadcast (0-disable/anything-enable).
 * @param type       Frame type
 *
 * @return Returns the number of bytes written, -1 if error.
 */
int ws_sendframe(int fd, const char *msg, uint64_t size, bool broadcast, int type)
{
	return ws_sendframe_ssl(client_socks[get_client_index(fd)].ssl_sock,
			msg,size,broadcast,type);
}

/**
 * @brief Sends a WebSocket text frame.
 *
 * @param fd         Target to be send.
 * @param msg        Text message to be send.
 * @param broadcast  Enable/disable broadcast (0-disable/anything-enable).
 *
 * @return Returns the number of bytes written, -1 if error.
 */
int ws_sendtxt(int fd, const char *msg, bool broadcast)
{
	return ws_sendframe_ssl(client_socks[get_client_index(fd)].ssl_sock,
			msg, (uint64_t)strlen(msg), broadcast, WS_FR_OP_TXT);
}

/**
 * @brief Sends a WebSocket binary frame.
 *
 * @param fd         Target to be send.
 * @param msg        Bytes to be send.
 * @param broadcast  Enable/disable broadcast (0-disable/anything-enable).
 *
 * @return Returns the number of bytes written, -1 if error.
 */
int ws_sendbin(int fd, const char *msg, uint64_t size, bool broadcast)
{
	return ws_sendframe_ssl(client_socks[get_client_index(fd)].ssl_sock,
			msg, size, broadcast, WS_FR_OP_BIN);
}

/**
 * @brief Close the client connection for the given @p fd
 * with normal close code (1000) and no reason string.
 *
 * @param fd Client fd.
 *
 * @return Returns 0 on success, -1 otherwise.
 *
 * @note If the client did not send a close frame in
 * TIMEOUT_MS milliseconds, the server will close the
 * connection with error code (1002).
 */
int ws_close_client(int fd)
{
	unsigned char clse_code[2];
	int cc;
	int i;

	/* Check if fd belongs to a connected client. */
	if ((i = get_client_index(fd)) == -1)
		return (-1);

	SSL* sslSock=client_socks[i].ssl_sock;

	/*
	 * Instead of using do_close(), we use this to avoid using
	 * msg_ctrl buffer from wfd and avoid a race condition
	 * if this is invoked asynchronously.
	 */
	cc           = WS_CLSE_NORMAL;
	clse_code[0] = (cc >> 8);
	clse_code[1] = (cc & 0xFF);
	if (ws_sendframe_ssl(sslSock, (const char *)clse_code, sizeof(char) * 2, false,
				WS_FR_OP_CLSE) < 0)
	{
		DEBUG_LOG("An error has occurred while sending closing frame!\n");
		return (-1);
	}

	close_connection(i);
	return (0);
}

/**
 * @brief Checks is a given opcode @p frame
 * belongs to a control frame or not.
 *
 * @param frame Frame opcode to be checked.
 *
 * @return Returns 1 if is a control frame, 0 otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static inline int is_control_frame(int frame)
{
	return (
			frame == WS_FR_OP_CLSE || frame == WS_FR_OP_PING || frame == WS_FR_OP_PONG);
}

/**
 * @brief Do the handshake process.
 *
 * @param wfd Websocket Frame Data.
 * @param p_index Client port index.
 *
 * @return Returns 0 if success, a negative number otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int do_handshake(struct ws_frame_data *wfd)
{
	char *response; /* Handshake response message. */
	char *p;        /* Last request line pointer.  */
	ssize_t n;      /* Read/Write bytes.           */

	/* Read the very first client message. */
	if ((n = SSL_read(wfd->ssl_sock, wfd->frm, sizeof(wfd->frm) - 1)) < 0)
		return (-1);

	/* Advance our pointers before the first next_byte(). */
	p = strstr((const char *)wfd->frm, "\r\n\r\n");
	if (p == NULL)
	{
		DEBUG_LOG("An empty line with \\r\\n was expected!\n");
		return (-1);
	}
	wfd->amt_read = n;
	wfd->cur_pos  = (size_t)((ptrdiff_t)(p - (char *)wfd->frm)) + 4;

	/* Get response. */
	if (get_handshake_response((char *)wfd->frm, &response) < 0)
	{
		DEBUG_LOG("Cannot get handshake response, request was: %s\n", wfd->frm);
		return (-1);
	}

	/* Valid request. */
	DEBUG_LOG("Handshaked, response: \n %s",response);

	/* Send handshake. */
	if (send_all(wfd->ssl_sock, response, strlen(response)) < 0)
	{
		free(response);
		DEBUG_LOG("As error has occurred while handshaking!\n");
		return (-1);
	}

	for(int i=1;i<=max_clients;i++)
	{
		if(serverFds[i].fd==-1)
		{
			serverFds[i].fd=wfd->sock;
			serverFdsCount+=1;
			break;
		}
	}

	/* Trigger events and clean up buffers. */
	eventsHandler.onopen(wfd->sock);
	free(response);
	return (0);
}

/**
 * @brief Sends a close frame, accordingly with the @p close_code
 * or the message inside @p wfd.
 *
 * @param wfd Websocket Frame Data.
 * @param close_code Websocket close code.
 *
 * @return Returns 0 if success, a negative number otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int do_close(struct ws_frame_data *wfd, int close_code)
{
	int cc; /* Close code.           */

	/* If custom close-code. */
	if (close_code != -1)
	{
		cc = close_code;
		goto custom_close;
	}

	/* If empty or have a close reason, just re-send. */
	if (wfd->frame_size == 0 || wfd->frame_size > 2)
		goto send;

	/* Parse close code and check if valid, if not, we issue an protocol error. */
	if (wfd->frame_size == 1)
		cc = wfd->msg_ctrl[0];
	else
		cc = ((int)wfd->msg_ctrl[0]) << 8 | wfd->msg_ctrl[1];

	/* Check if it's not valid, if so, we send a protocol error (1002). */
	if ((cc < 1000 || cc > 1003) && (cc < 1007 || cc > 1011) &&
			(cc < 3000 || cc > 4999))
	{
		cc = WS_CLSE_PROTERR;

custom_close:
		wfd->msg_ctrl[0] = (cc >> 8);
		wfd->msg_ctrl[1] = (cc & 0xFF);

		if (ws_sendframe_ssl(wfd->ssl_sock, (const char *)wfd->msg_ctrl,
					sizeof(char) * 2, false, WS_FR_OP_CLSE) < 0)
		{
			DEBUG_LOG("An error has occurred while sending closing frame!\n");
			return (-1);
		}
		return (0);
	}

	/* Send the data inside wfd->msg_ctrl. */
send:
	if (ws_sendframe_ssl(wfd->ssl_sock, (const char *)wfd->msg_ctrl,
				wfd->frame_size, false, WS_FR_OP_CLSE) < 0)
	{
		DEBUG_LOG("An error has occurred while sending closing frame!\n");
		return (-1);
	}
	return (0);
}

/**
 * @brief Send a pong frame in response to a ping frame.
 *
 * Accordingly to the RFC, a pong frame must have the same
 * data payload as the ping frame, so we just send a
 * ordinary frame with PONG opcode.
 *
 * @param wfd Websocket frame data.
 *
 * @return Returns 0 if success and a negative number
 * otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int do_pong(struct ws_frame_data *wfd, uint64_t frame_size)
{
	if (ws_sendframe_ssl(wfd->ssl_sock, (const char *)wfd->msg_ctrl, frame_size,
				false, WS_FR_OP_PONG) < 0)
	{
		wfd->error = 1;
		DEBUG_LOG("An error has occurred while ponging!\n");
		return (-1);
	}
	return (0);
}

/**
 * @brief Read a chunk of bytes and return the next byte
 * belonging to the frame.
 *
 * @param wfd Websocket Frame Data.
 *
 * @return Returns the byte read, or -1 if error.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static inline int next_byte(struct ws_frame_data *wfd)
{
	ssize_t n;

	/* If empty or full. */
	if (wfd->cur_pos == 0 || wfd->cur_pos == wfd->amt_read)
	{
		if ((n = SSL_read(wfd->ssl_sock, wfd->frm, sizeof(wfd->frm))) <= 0)
		{
			wfd->error = 1;
			DEBUG_LOG("An error has occurred while trying to read next byte\n");
			return (-1);
		}
		wfd->amt_read = (size_t)n;
		wfd->cur_pos  = 0;
	}
	return (wfd->frm[wfd->cur_pos++]);
}

/**
 * @brief Skips @p frame_size bytes of the current frame.
 *
 * @param wfd Websocket Frame Data.
 * @param frame_size Amount of bytes to be skipped.
 *
 * @return Returns 0 if success, a negative number
 * otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int skip_frame(struct ws_frame_data *wfd, uint64_t frame_size)
{
	uint64_t i;
	for (i = 0; i < frame_size; i++)
	{
		if (next_byte(wfd) == -1)
		{
			wfd->error = 1;
			return (-1);
		}
	}
	return (0);
}

/**
 * @brief Reads the current frame isolating data from control frames.
 * The parameters are changed in order to reflect the current state.
 *
 * @param wfd Websocket Frame Data.
 * @param opcode Frame opcode.
 * @param buf Buffer to be written.
 * @param frame_length Length of the current frame.
 * @param frame_size Total size of the frame (considering CONT frames)
 *                   read until the moment.
 * @param msg_idx Message index, reflects the current buffer pointer state.
 * @param masks Masks vector.
 * @param is_fin Is FIN frame indicator.
 *
 * @return Returns 0 if success, a negative number otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int read_frame(struct ws_frame_data *wfd,
		int opcode,
		unsigned char **buf,
		uint64_t *frame_length,
		uint64_t *frame_size,
		uint64_t *msg_idx,
		uint8_t *masks,
		int is_fin)
{
	unsigned char *tmp; /* Tmp message.     */
	unsigned char *msg; /* Current message. */
	int cur_byte;       /* Curr byte read.  */
	uint64_t i;         /* Loop index.      */

	msg = *buf;

	/* Decode masks and length for 16-bit messages. */
	if (*frame_length == 126)
	{
		*frame_length = (((uint64_t)next_byte(wfd)) << 8) | next_byte(wfd);
	}

	/* 64-bit messages. */
	else if (*frame_length == 127)
	{
		*frame_length =
			(((uint64_t)next_byte(wfd)) << 56) | /* frame[2]. */
			(((uint64_t)next_byte(wfd)) << 48) | /* frame[3]. */
			(((uint64_t)next_byte(wfd)) << 40) | /* frame[4]. */
			(((uint64_t)next_byte(wfd)) << 32) | /* frame[5]. */
			(((uint64_t)next_byte(wfd)) << 24) | /* frame[6]. */
			(((uint64_t)next_byte(wfd)) << 16) | /* frame[7]. */
			(((uint64_t)next_byte(wfd)) << 8) | /* frame[8]. */
			(((uint64_t)next_byte(wfd))); /* frame[9]. */
	}

	*frame_size += *frame_length;

	/*
	 * Check frame size
	 *
	 * We need to limit the amount supported here, since if
	 * we follow strictly to the RFC, we have to allow 2^64
	 * bytes. Also keep in mind that this is still true
	 * for continuation frames.
	 */
	if (*frame_size > MAX_FRAME_LENGTH)
	{
		DEBUG_LOG("Current frame from client %d, exceeds the maximum\n"
				"amount of bytes allowed (%" PRId64 "/%d)!",
				wfd->sock, *frame_size + *frame_length, MAX_FRAME_LENGTH);

		wfd->error = 1;
		return (-1);
	}

	/* Read masks. */
	masks[0] = next_byte(wfd);
	masks[1] = next_byte(wfd);
	masks[2] = next_byte(wfd);
	masks[3] = next_byte(wfd);

	/*
	 * Abort if error.
	 *
	 * This is tricky: we may have multiples error codes from the
	 * previous next_bytes() calls, but, since we're only setting
	 * variables and flags, there is no major issue in setting
	 * them wrong _if_ we do not use their values, thing that
	 * we do here.
	 */
	if (wfd->error)
		return (-1);

	/*
	 * Allocate memory.
	 *
	 * The statement below will allocate a new chunk of memory
	 * if msg is NULL with size total_length. Otherwise, it will
	 * resize the total memory accordingly with the message index
	 * and if the current frame is a FIN frame or not, if so,
	 * increment the size by 1 to accommodate the line ending \0.
	 */
	if (*frame_length > 0)
	{
		if (!is_control_frame(opcode))
		{
			tmp = realloc(
					msg, sizeof(unsigned char) * (*msg_idx + *frame_length + is_fin));
			if (!tmp)
			{
				DEBUG_LOG("Cannot allocate memory, requested: % " PRId64 "\n",
						(*msg_idx + *frame_length + is_fin));

				wfd->error = 1;
				return (-1);
			}
			msg  = tmp;
			*buf = msg;
		}

		/* Copy to the proper location. */
		for (i = 0; i < *frame_length; i++, (*msg_idx)++)
		{
			/* We were able to read? .*/
			cur_byte = next_byte(wfd);
			if (cur_byte == -1)
				return (-1);

			msg[*msg_idx] = cur_byte ^ masks[i % 4];
		}
	}

	/* If we're inside a FIN frame, lets... */
	if (is_fin && *frame_size > 0)
	{
		/* Increase memory if our FIN frame is of length 0. */
		if (!*frame_length && !is_control_frame(opcode))
		{
			tmp = realloc(msg, sizeof(unsigned char) * (*msg_idx + 1));
			if (!tmp)
			{
				DEBUG_LOG("Cannot allocate memory, requested: %" PRId64 "\n",
						(*msg_idx + 1));

				wfd->error = 1;
				return (-1);
			}
			msg  = tmp;
			*buf = msg;
		}
		msg[*msg_idx] = '\0';
	}

	return (0);
}

/**
 * @brief Reads the next frame, whether if a TXT/BIN/CLOSE
 * of arbitrary size.
 *
 * @param wfd Websocket Frame Data.
 * @param idx Websocket connection index.
 *
 * @return Returns 0 if success, a negative number otherwise.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static int next_frame(struct ws_frame_data *wfd, int idx)
{
	unsigned char *msg_data; /* Data frame.                */
	unsigned char *msg_ctrl; /* Control frame.             */
	uint8_t masks_data[4];   /* Masks data frame array.    */
	uint8_t masks_ctrl[4];   /* Masks control frame array. */
	uint64_t msg_idx_data;   /* Current msg index.         */
	uint64_t msg_idx_ctrl;   /* Current msg index.         */
	uint64_t frame_length;   /* Frame length.              */
	uint64_t frame_size;     /* Current frame size.        */
#ifdef VALIDATE_UTF8
	uint32_t utf8_state;     /* Current UTF-8 state.       */
#endif
	uint8_t opcode;          /* Frame opcode.              */
	uint8_t is_fin;          /* Is FIN frame flag.         */
	uint8_t mask;            /* Mask.                      */
	int cur_byte;            /* Current frame byte.        */

	msg_data        = NULL;
	msg_ctrl        = wfd->msg_ctrl;
	is_fin          = 0;
	frame_length    = 0;
	frame_size      = 0;
	msg_idx_data    = 0;
	msg_idx_ctrl    = 0;
	wfd->frame_size = 0;
	wfd->frame_type = -1;
	wfd->msg        = NULL;
#ifdef VALIDATE_UTF8
	utf8_state      = UTF8_ACCEPT;
#endif

	/* Read until find a FIN or a unsupported frame. */
	do
	{
		/*
		 * Obs: next_byte() can return error if not possible to read the
		 * next frame byte, in this case, we return an error.
		 *
		 * However, please note that this check is only made here and in
		 * the subsequent next_bytes() calls this also may occur too.
		 * wsServer is assuming that the client only create right
		 * frames and we will do not have disconnections while reading
		 * the frame but just when waiting for a frame.
		 */
		cur_byte = next_byte(wfd);
		if (cur_byte == -1)
			return (-1);

		is_fin = (cur_byte & 0xFF) >> WS_FIN_SHIFT;
		opcode = (cur_byte & 0xF);

		/*
		 * Check for RSV field.
		 *
		 * Since wsServer do not negotiate extensions if we receive
		 * a RSV field, we must drop the connection.
		 */
		if (cur_byte & 0x70)
		{
			DEBUG_LOG("RSV is set while wsServer do not negotiate extensions!\n");
			wfd->error = 1;
			break;
		}

		/*
		 * Check if the current opcode makes sense:
		 * a) If we're inside a cont frame but no previous data frame
		 *
		 * b) If we're handling a data-frame and receive another data
		 *    frame. (it's expected to receive only CONT or control
		 *    frames).
		 *
		 * It is worth to note that in a), we do not need to check
		 * if the previous frame was FIN or not: if was FIN, an
		 * on_message event was triggered and this function returned;
		 * so the only possibility here is a previous non-FIN data
		 * frame, ;-).
		 */
		if ((wfd->frame_type == -1 && opcode == WS_FR_OP_CONT) ||
				(wfd->frame_type != -1 && !is_control_frame(opcode) &&
				 opcode != WS_FR_OP_CONT))
		{
			DEBUG_LOG("Unexpected frame was received!, opcode: %d, previous: %d\n",
					opcode, wfd->frame_type);
			wfd->error = 1;
			break;
		}

		/* Check if one of the valid opcodes. */
		if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN ||
				opcode == WS_FR_OP_CONT || opcode == WS_FR_OP_PING ||
				opcode == WS_FR_OP_PONG || opcode == WS_FR_OP_CLSE)
		{
			/*
			 * Check our current state: if CLOSING, we only accept close
			 * frames.
			 *
			 * Since the server may, at any time, asynchronously, asks
			 * to close the client connection, we should terminate
			 * immediately.
			 */
			if (get_client_state(idx) == WS_STATE_CLOSING && opcode != WS_FR_OP_CLSE)
			{
				DEBUG_LOG(
						"Unexpected frame received, expected CLOSE (%d), received: (%d)",
						WS_FR_OP_CLSE, opcode);
				wfd->error = 1;
				break;
			}

			/* Only change frame type if not a CONT frame. */
			if (opcode != WS_FR_OP_CONT && !is_control_frame(opcode))
				wfd->frame_type = opcode;

			mask         = next_byte(wfd);
			frame_length = mask & 0x7F;
			frame_size   = 0;
			msg_idx_ctrl = 0;

			/*
			 * We should deny non-FIN control frames or that have
			 * more than 125 octets.
			 */
			if (is_control_frame(opcode) && (!is_fin || frame_length > 125))
			{
				DEBUG_LOG("Control frame bigger than 125 octets or not a FIN frame!\n");
				wfd->error = 1;
				break;
			}

			/* Normal data frames. */
			if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN ||
					opcode == WS_FR_OP_CONT)
			{
				read_frame(wfd, opcode, &msg_data, &frame_length, &wfd->frame_size,
						&msg_idx_data, masks_data, is_fin);

#ifdef VALIDATE_UTF8
				/* UTF-8 Validate partial (or not) frame. */
				if (wfd->frame_type == WS_FR_OP_TXT)
				{
					if (is_fin)
					{
						if (is_utf8_len_state(
									msg_data + (msg_idx_data - frame_length),
									frame_length, utf8_state) != UTF8_ACCEPT)
						{
							DEBUG_LOG("Dropping invalid complete message!\n");
							wfd->error = 1;
							do_close(wfd, WS_CLSE_INVUTF8);
						}
					}

					/* Check current state for a CONT or initial TXT frame. */
					else
					{
						utf8_state = is_utf8_len_state(
								msg_data + (msg_idx_data - frame_length), frame_length,
								utf8_state);

						/* We can be in any state, except reject. */
						if (utf8_state == UTF8_REJECT)
						{
							DEBUG_LOG("Dropping invalid cont/initial frame!\n");
							wfd->error = 1;
							do_close(wfd, WS_CLSE_INVUTF8);
						}
					}
				}
#endif
			}

			/*
			 * We _never_ send a PING frame, so it's not expected to receive a PONG
			 * frame. However, the specs states that a client could send an
			 * unsolicited PONG frame. The server just have to ignore the
			 * frame.
			 *
			 * The skip amount will always be 4 (masks vector size) + frame size
			 */
			else if (opcode == WS_FR_OP_PONG)
			{
				skip_frame(wfd, 4 + frame_length);
				is_fin = 0;
				continue;
			}

			/* We should answer to a PING frame as soon as possible. */
			else if (opcode == WS_FR_OP_PING)
			{
				if (read_frame(wfd, opcode, &msg_ctrl, &frame_length, &frame_size,
							&msg_idx_ctrl, masks_ctrl, is_fin) < 0)
					break;

				if (do_pong(wfd, frame_size) < 0)
					break;

				/* Quick hack to keep our loop. */
				is_fin = 0;
			}

			/* We interrupt the loop as soon as we find a CLOSE frame. */
			else
			{
				if (read_frame(wfd, opcode, &msg_ctrl, &frame_length, &frame_size,
							&msg_idx_ctrl, masks_ctrl, is_fin) < 0)
					break;

#ifdef VALIDATE_UTF8
				/* If there is a close reason, check if it is UTF-8 valid. */
				if (frame_size > 2 && !is_utf8_len(msg_ctrl + 2, frame_size - 2))
				{
					DEBUG_LOG("Invalid close frame payload reason! (not UTF-8)\n");
					wfd->error = 1;
					break;
				}
#endif

				/* Since we're aborting, we can scratch the 'data'-related
				 * vars here. */
				wfd->frame_size = frame_size;
				wfd->frame_type = WS_FR_OP_CLSE;
				if(msg_data)
				{
					free(msg_data);
				}
				return (0);
			}
		}

		/* Anything else (unsupported frames). */
		else
		{
			DEBUG_LOG("Unsupported frame opcode: %d\n", opcode);
			/* We should consider as error receive an unknown frame. */
			wfd->frame_type = opcode;
			wfd->error      = 1;
		}

	} while (!is_fin && !wfd->error);

	/* Check for error. */
	if (wfd->error)
	{
		free(msg_data);
		wfd->msg = NULL;
		return (-1);
	}

	wfd->msg = msg_data;
	return (0);
}

//static void ws_pingconnection(int idx)
//{
// if(ws_sendframe_ssl(client_socks[idx].ssl_sock,(const char*)"ping",4,false,WS_FR_OP_PING)<0)
// {
//  close_connection(idx);
// }
//}

/**
 * @brief Establishes to connection with the client and trigger
 * events when occurs one.
 *
 * @param vsock Client connection index.
 *
 * @return Returns @p vsock.
 *
 * @note This will be run on a different thread.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static void ws_establishconnection(int connection_index)
{
	struct ws_frame_data wfd; /* WebSocket frame data.   */
	int sock;                 /* File descriptor.        */
	SSL* ssl_sock;

	sock             = client_socks[connection_index].client_sock;
	ssl_sock         = client_socks[connection_index].ssl_sock;

	/* Prepare frame data. */
	memset(&wfd, 0, sizeof(wfd));
	wfd.sock = sock;
	wfd.ssl_sock=ssl_sock;

	/* Do handshake. */
	if (do_handshake(&wfd) < 0)
	{
		//client disconnected badly or bad handshake
		eventsHandler.onclose(sock);
		for(int i=1;i<=max_clients;i++)
		{
			if(serverFds[i].fd==sock)
			{
				serverFds[i].fd=-1;
				serverFdsCount-=1;
				break;
			}
		}
		client_socks[connection_index].client_sock = -1;
		client_socks[connection_index].ssl_sock = NULL;
		client_socks[connection_index].state       = WS_STATE_CLOSED;
		close_socket(sock,&ssl_sock);
		return;
	}

	/* Change state. */
	set_client_state(connection_index, WS_STATE_OPEN);
}

void process_connection(int connection_index)
{
	struct ws_frame_data wfd; /* WebSocket frame data.   */
	int sock=client_socks[connection_index].client_sock; /* File descriptor. */
	SSL* ssl_sock=client_socks[connection_index].ssl_sock;

	/* Prepare frame data. */
	memset(&wfd, 0, sizeof(wfd));
	wfd.sock = sock;
	wfd.ssl_sock=ssl_sock;
	/* Read next frame until client disconnects or an error occur. */
	if(next_frame(&wfd, connection_index) >= 0)
	{
		/* Text/binary event. */
		if ((wfd.frame_type == WS_FR_OP_TXT || wfd.frame_type == WS_FR_OP_BIN) &&
				!wfd.error)
		{
			eventsHandler.onmessage(
					sock, wfd.msg, wfd.frame_size, wfd.frame_type);
		}

		/* Close event. */
		else if (wfd.frame_type == WS_FR_OP_CLSE && !wfd.error)
		{
			// client disconnected normally
			eventsHandler.onclose(sock);
			for(int i=1;i<=max_clients;i++)
			{
				if(serverFds[i].fd==sock)
				{
					serverFds[i].fd=-1;
					serverFdsCount-=1;
					break;
				}
			}
			/* We only send a close frameSend close frame */
			do_close(&wfd, -1);
			client_socks[connection_index].client_sock = -1;
			client_socks[connection_index].ssl_sock = NULL;
			client_socks[connection_index].state       = WS_STATE_CLOSED;
			close_socket(sock,&ssl_sock);
		}

		if(wfd.msg)
		{
			free(wfd.msg);
		}
	}
	else
	{
		//client disconnected badly
		eventsHandler.onclose(sock);
		for(int i=1;i<=max_clients;i++)
		{
			if(serverFds[i].fd==sock)
			{
				serverFds[i].fd=-1;
				serverFdsCount-=1;
				break;
			}
		}
		client_socks[connection_index].client_sock = -1;
		client_socks[connection_index].ssl_sock = NULL;
		client_socks[connection_index].state       = WS_STATE_CLOSED;
		close_socket(sock,&ssl_sock);
	}
}

void ws_init_ssl(void)
{
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
}


void ws_deinit_ssl(void)
{
	ERR_free_strings();
	EVP_cleanup();
}

/**
 * @brief Main loop that keeps accepting new connections.
 *
 * @param data Accept thread data: sock and port index.
 *
 * @return Returns @p data.
 *
 * @note This may be run on a different thread.
 *
 * @attention This is part of the internal API and is documented just
 * for completeness.
 */
static void ws_accept()
{
	struct sockaddr_in client;     /* Client.                */
	int connection_index;          /* Free connection slot.  */
	int new_sock;                  /* New opened connection. */
	int len;                       /* Length of sockaddr.    */
	int i;                         /* Loop index.            */

	connection_index = 0;
	len              = sizeof(struct sockaddr_in);

	/* Accept. */
	new_sock =
		accept(server_socket, (struct sockaddr *)&client, (socklen_t *)&len);

	SSL_CTX *sslctx;
	SSL *cSSL=NULL;

	sslctx = SSL_CTX_new( SSLv23_server_method());
	//  sslctx = SSL_CTX_new( TLS_method()());
	SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_use_certificate_file(sslctx, "./server.crt" , SSL_FILETYPE_PEM);

	SSL_CTX_use_PrivateKey_file(sslctx, "./server.key", SSL_FILETYPE_PEM);

	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, new_sock);
	SSL_accept(cSSL);
	SSL_CTX_free(sslctx);

	if (new_sock > -1)
	{
		struct timeval timeout;
		timeout.tv_sec = SOCKET_TIMEOUT_SECOND;
		timeout.tv_usec = SOCKET_TIMEOUT_USECOND;
		if (setsockopt (new_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
					sizeof(timeout)) < 0)
			panic("setsockopt failed while setting socket timeout\n");

		/* Adds client socket to socks list. */
		for (i = 0; i < max_clients; i++)
		{
			if (client_socks[i].client_sock == -1)
			{
				client_socks[i].client_sock = new_sock;
				client_socks[i].ssl_sock = cSSL;
				client_socks[i].state       = WS_STATE_CONNECTING;
				connection_index            = i;
				break;
			}
		}

		/* Client socket added to socks list ? */
		if (i == max_clients)
		{
			close_socket(new_sock,&(client_socks[i].ssl_sock));
		}
		else
		{
			// is this right?
			ws_establishconnection(connection_index);
		}
	}
}

void ws_shutdown()
{
	shutdown(server_socket,SHUT_RDWR);
	ws_deinit_ssl();
	free(client_socks);
	client_socks=NULL;
	free(serverFds);
	serverFds=NULL;
	serverFdsCount=0;
	server_socket=-1;
	max_clients=0;
}

void ws_main_loop(void)
{
	for(int i=0;i<=max_clients;i++)
	{
		serverFds[i].revents=0;
	}
	int poll_count=poll(serverFds,serverFdsCount,SERVER_POLL_TIMEOUT);
	if (poll_count<0)
	{
		return;
	}
	if (serverFds[0].revents & POLLIN)
	{
		ws_accept();
	}

	for(int i=1;i<=max_clients;i++)
	{
		if(serverFds[i].fd!=-1 && (serverFds[i].revents & POLLIN))
		{
			int clientIndex=get_client_index(serverFds[i].fd);
			process_connection(clientIndex);
		}
	}
}

/**
 * @brief Server setup.
 *
 * @param evs  Events structure.
 * @param port Server port.
 * @param thread_loop If any value other than zero, runs
 *                    the accept loop in another thread
 *                    and immediately returns. If 0, runs
 *                    in the same thread and blocks execution.
 *
 * @return If @p thread_loop != 0, returns 0. Otherwise, never
 * returns.
 *
 * @note Note that this function can be called multiples times,
 * from multiples different threads (depending on the @ref MAX_PORTS)
 * value. Each call _should_ have a different port and can have
 * different events configured.
 */
int ws_socket(struct ws_events *evs, uint16_t port,int maxClients)
{
	struct sockaddr_in server;     /* Server.                */
	int reuse;                     /* Socket option.         */

	if(server_socket!=-1)
		return -1;

	ws_init_ssl();

	/* Checks if the event list is a valid pointer. */
	if (evs == NULL)
		panic("Invalid event list!");

	/* Copy events. */
	memcpy(&eventsHandler, evs, sizeof(struct ws_events));

	max_clients=maxClients;

	/* Create socket. */
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0)
		panic("Could not create socket");

	/* Reuse previous address. */
	reuse = 1;
	if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
				sizeof(reuse)) < 0)
		panic("setsockopt(SO_REUSEADDR) failed");

	/* Prepare the sockaddr_in structure. */
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(port);

	/* Bind. */
	if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0)
		panic("Bind failed");

	/* Listen. */
	if(listen(server_socket, max_clients)<0)
		panic("Listen failed");

	client_socks=malloc(sizeof(struct ws_connection)*max_clients);
	if(client_socks==NULL)
		panic("Could not allocate clients data structure");

	/* Wait for incoming connections. */
	DEBUG_LOG("Waiting for incoming connections...\n");
	for(int i=0;i<max_clients;i++)
	{
		client_socks[i].client_sock=-1;
		client_socks[i].ssl_sock=NULL;
		client_socks[i].state=WS_STATE_CLOSED;
	}

	serverFds=malloc(sizeof(struct pollfd)*(max_clients+1));
	if(serverFds==NULL)
		panic("Could not allocate poll data structure");

	serverFdsCount=1;
	serverFds[0].fd=server_socket;
	serverFds[0].events=POLLIN;
	for (int i=1;i<=max_clients;i++)
	{
		serverFds[i].fd=-1;
		serverFds[i].events=POLLIN;
	}

	return (0);
}

