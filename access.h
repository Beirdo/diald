/*
 * access.h - Access flags for monitor connections
 *
 * Copyright (c) 1998 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 */

#define ACCESS_CONTROL	0x00000001
#define ACCESS_CONFIG	0x00000002
#define ACCESS_BLOCK	0x00000004
#define ACCESS_UNBLOCK	0x00000008
#define ACCESS_FORCE	0x00000010
#define ACCESS_UNFORCE	0x00000020
#define ACCESS_DOWN	0x00000040
#define ACCESS_UP	0x00000080
#define ACCESS_DELQUIT	0x00000100
#define ACCESS_QUIT	0x00000200
#define ACCESS_RESET	0x00000400
#define ACCESS_QUEUE	0x00000800
#define ACCESS_DEBUG	0x00001000
#define ACCESS_DYNAMIC	0x00002000
#define ACCESS_MONITOR	0x00004000
#define ACCESS_MESSAGE	0x00008000
#define ACCESS_CONNECT	0x00010000
