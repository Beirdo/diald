/*
 * access.h - Access flags for monitor connections
 *
 * Copyright (c) 1998 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 */

#define ACCESS_CONTROL	0x00000001	/* Accept commands on this connection.
					 * If this is not set every received
					 * line is treated as a message.
					 */
#define ACCESS_CONFIG	0x00000002	/* Allow on-the-fly config changes. */
#define ACCESS_BLOCK	0x00000004	/* Allow the link to be blocked. */
#define ACCESS_UNBLOCK	0x00000008	/* Allow the link to be unblocked. */
#define ACCESS_FORCE	0x00000010	/* Allow the link to be forced up. */
#define ACCESS_UNFORCE	0x00000020	/* Allow a force to be removed. */
#define ACCESS_DOWN	0x00000040	/* Allow the link to be requested to
					 * go down.
					 */
#define ACCESS_UP	0x00000080	/* Allow the link to be requested to
					 * go up.
					 */
#define ACCESS_DELQUIT	0x00000100	/* Allow diald to be asked to quit
					 * when the link next goes down.
					 */
#define ACCESS_QUIT	0x00000200	/* Allow diald to be asked to quit
					 * immediately.	
					 */
#define ACCESS_RESET	0x00000400	/* Allow diald to be reset. */
#define ACCESS_QUEUE	0x00000800	/* Allow a queue dump to the syslog
					 * and monitors to be requested.
					 */
#define ACCESS_DEBUG	0x00001000	/* Allow the debug flags to be set. */
#define ACCESS_DYNAMIC	0x00002000	/* Allow the link addresses to be
					 * set with the "dynamic" command.
					 */
#define ACCESS_MONITOR	0x00004000	/* Allow monitor data to be requested
					 * on this connection.
					 */
#define ACCESS_MESSAGE	0x00008000	/* Allow messages to be sent. */
#define ACCESS_CONNECT	0x00010000	/* Allow external link up requests
					 * to be made via this connection.
					 */
#define ACCESS_DEMAND	0x00020000	/* Allow demand dialling to be
					 * enabled.
					 */
#define ACCESS_NODEMAND	0x00040000	/* Allow demand dialling to be
					 * disabled.
					 */
#define ACCESS_AUTH	0x80000000	/* Allow the access flags for the
					 * connection to be changed with
					 * the "auth" command.
					 */


extern int ctrl_access(char *buf);
