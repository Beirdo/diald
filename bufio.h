/*
 * bufio.h - Buffio header.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

typedef struct pipe {
    struct pipe *next;
    char *name;		/* the name given to this channel */
    int is_ctrl;	/* is this a control pipe or just script output? */
    int fd;		/* file descriptor */
    int count;		/* number of characters in the buffer now */
    char buf[1024];
} PIPE;

