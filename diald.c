/*
 * diald.c - Demand dialing daemon for ppp.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * Portions of this code were derived from the code for pppd copyright
 * (c) 1989 Carnegie Mellon University. The copyright notice on this code
 * is reproduced below.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>

#include <diald.h>
#include <version.h>

#if HAVE_LIBWRAP
#  include <tcpd.h>

   int allow_severity = LOG_INFO;
   int deny_severity = LOG_NOTICE;
#endif


/* intialized variables. */
int clk_tck = 0;		/* clock ticks per second */
int af_packet = 1;		/* kernel has AF_PACKET sockets */
int modem_fd = -1;		/* modem device fp (for proxy reads) */
MONITORS *monitors = 0;		/* Monitor pipes */
PIPE *pipes = 0;		/* Command pipes */
int modem_hup = 0;		/* have we seen a modem HUP? */
int sockfd = -1;		/* socket for doing interface ioctls */
int delayed_quit = 0;		/* has the user requested a delayed quit? */
int request_down = 0;		/* has the user requested link down? */
int request_up = 0;		/* has the user requested link down? */
int forced = 0;			/* has the user requested the link forced up? */
int link_pid = 0;		/* current protocol control command pid */
int dial_pid = 0;		/* current dial command pid */
int running_pid = 0;		/* current system command pid */
int running_status = 0;		/* status of last system command */
int dial_status = 0;		/* status from last dial command */
int state_timeout = -1;		/* state machine timeout counter */
int proxy_ifunit = 0;		/* Interface for the proxy */
int link_iface = -1;		/* Interface for the link */
int force_dynamic = 0;		/* true if connect passed back an addr */
int redial_rtimeout = -1;	/* initialized value */
int dial_failures = 0;		/* count of dialing failures */
int ppp_half_dead = 0;		/* is the ppp link half dead? */
int terminate = 0;
char *pidfile = 0;
static PIPE *fifo_pipe;
int argc_save;
char **argv_save;
proxy_t proxy;

void do_config(void)
{
#ifdef SCHED_OTHER
    struct sched_param sp;
#endif
    if (deinitializer) {
	if (devices && devices[0])
		setenv("MODEM", devices[0], 1);
	run_shell(SHELL_WAIT, "deinit", deinitializer, -1);
    }

    init_vars();
    flush_prules();
    flush_vars();
    flush_filters();
    /* Get the default defs and config files first */
    parse_options_file(DIALD_DEFS_FILE);
    parse_options_file(DIALD_CONFIG_FILE);
    /* Get the command line modifications */
    parse_args(argc_save-1,argv_save+1);
    /* Do validity checks on the setup */
    check_setup();

    orig_local_ip = (local_ip ? strdup(local_ip) : NULL);
    orig_remote_ip = (remote_ip ? strdup(remote_ip) : NULL);
    orig_broadcast_ip = (broadcast_ip ? strdup(broadcast_ip) : NULL);
    orig_netmask = (netmask ? strdup(netmask) : NULL);

    if (initializer) {
	if (devices && devices[0])
	    setenv("MODEM", devices[0], 1);
	run_shell(SHELL_WAIT, "init", initializer, -1);
    }

#ifdef SCHED_OTHER
    sp.sched_priority = (scheduler == SCHED_OTHER ? 0 : priority);
    sched_setscheduler(0, scheduler, &sp);
    if (scheduler == SCHED_OTHER)
#endif
#ifdef PRIO_PROCESS
	setpriority(PRIO_PROCESS, 0, priority);
#else
	nice(priority - nice(0));
#endif
}

int
main(int argc, char *argv[])
{
    int sel;
    struct timeval timeout;
    fd_set readfds;
    long tstamp = ticks();
    long ts;

    /* This fixes a problem with diald using UTC in log messages
     * rather than local time. I do not believe this call should
     * be necessary. It may be library version dependent.
     */
    tzset();

    if (argc > 1
    && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "-v")
    || !strcmp(argv[1], "--version"))) {
	printf("Diald version %s\n", VERSION);
	exit(0);
    }

    argc_save = argc;
    argv_save = argv;

    /* initialize system log interface */
    openlog("diald", LOG_PID | LOG_NDELAY,  LOG_LOCAL2);

    /* figure out clock granularity */
#ifdef _SC_CLK_TCK
    clk_tck = sysconf(_SC_CLK_TCK);
#endif
#ifdef CLK_TCK
    if (clk_tck <= 0)
	clk_tck = CLK_TCK;
#elif HZ
    if (clk_tck <= 0)
	clk_tck = HZ;
#endif

    /* initialize a firewall unit so we can store our options */
    /* If I get things into a device this should be an "open" */
    fwunit = ctl_firewall(IP_FW_OPEN,0);

    parse_init();

    /* Get an internet socket for doing socket ioctls. */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
	syslog(LOG_ERR, "Couldn't create IP socket: %m");
	die(1);
    }
    fcntl(sockfd, F_SETFD, FD_CLOEXEC);

    if (debug&DEBUG_VERBOSE)
        syslog(LOG_INFO,"Starting diald version %s",VERSION);

    signal_setup();
    do_config();

    become_daemon();

    FD_ZERO(&ctrl_fds);
    open_fifo();
    filter_setup();

    proxy_init(&proxy, proxyif);
    if (proxy.start) proxy.start(&proxy);
    idle_filter_proxy();

    /* We are a session manager and currently have no controlling
     * terminal (this will be the modem tty when open).
     */
    setpgid(0, getppid());
    setsid();

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_INFO,"Diald initial setup completed.");

    /* main loop */
    while (!terminate) {
	/* wait up to a second for an event */
        readfds = ctrl_fds;
        if (proxy.fd >= 0) FD_SET(proxy.fd, &readfds);
        if (snoopfd >= 0) FD_SET(snoopfd, &readfds);
	/* Compute the likely timeout for the next second boundary */
	ts = tstamp + PAUSETIME*clk_tck - ticks();
	if (ts < 0) ts = 0;
    	timeout.tv_sec = ts/clk_tck;
    	timeout.tv_usec = 1000*(ts%clk_tck)/clk_tck;
	sel = select(256,&readfds,0,0,&timeout);
	if (sel < 0 && errno == EBADF) {
	    PIPE *p;
	    /* Yuk, one of the pipes is probably broken. It seems to
	     * happen on unnamed pipes created with pipe(). Named
	     * pipes used by dctrl etc. seem ok.
	     * Is this correct select behaviour or is it a bug either
	     * in the kernel or glibc?
	     */
	    p = pipes;
	    while (p) {
		PIPE *tmp = p->next;
		if (!(p->access & ACCESS_CONTROL))
		    ctrl_read(p);
		p = tmp;
	    }
	} else if (sel > 0) {
	    PIPE *p;
	    if (tcp_fd != -1) {
		if (FD_ISSET(tcp_fd,&readfds)) {
		    struct sockaddr_in sa;
		    int flags, len, fd;
		    flags = fcntl(tcp_fd, F_GETFL, 0);
		    fcntl(tcp_fd, F_SETFL, flags|O_NONBLOCK);
		    len = sizeof(sa);
		    fd = accept(tcp_fd, (struct sockaddr *)&sa, &len);
		    fcntl(tcp_fd, F_SETFL, flags);
		    if (fd >= 0) {
			PIPE *p;
#if HAVE_LIBWRAP
			struct request_info rq;
			request_init(&rq,
				RQ_DAEMON, "diald",
				RQ_FILE, fd,
				0);
			fromhost(&rq);
			if (!hosts_access(&rq)) {
				close(fd);
				mon_syslog(LOG_WARNING,
				    "Connection from TCP %s:%d - DENIED",
				    inet_ntoa(sa.sin_addr), sa.sin_port);
			} else
#endif
			if ((p = malloc(sizeof(PIPE)))) {
			    char def[] = "simple default";
			    char buf[1024];
			    int n;
			    fcntl(fd, F_SETFD, FD_CLOEXEC);
			    n = snprintf(buf, sizeof(buf)-2, "TCP %s:%d",
					inet_ntoa(sa.sin_addr), sa.sin_port);
			    buf[n] = '\0';
			    pipe_init(strdup(buf), ctrl_access(def),
					fd, p, 0);
			    FD_SET(fd, &ctrl_fds);
			    mon_syslog(LOG_NOTICE, "Connection from %s", buf);
			} else {
			    close(fd);
			    mon_syslog(LOG_ERR, "malloc: %m");
			}
		    } else
			mon_syslog(LOG_ERR, "accept: %m");
		}
	    }

	    p = pipes;
	    while (p) {
		PIPE *tmp = p->next;
		if (FD_ISSET(p->fd, &readfds))
		    ctrl_read(p);
		p = tmp;
	    }

	    /* update the connection filters */
	    if (snoopfd >= 0
	    && FD_ISSET(snoopfd, &readfds))
		filter_read();

	    /* deal with packets coming into the pty proxy link */
	    if (proxy.fd >= 0
	    && FD_ISSET(proxy.fd, &readfds))
		proxy_read();
	}
	/* check if ticks() has advanced a second since last check.
	 * This is immune to wall clock skew because we use the ticks count.
	 */
	ts = tstamp + PAUSETIME*clk_tck - ticks();
	if (ts <= 0) {
	    tstamp = ticks();
	    fire_timers();
	    /* Advance a second on state machine timeouts.
	     * Under high load this can get stretched out.
	     * Even under low load it is likely to have 1% error.
	     * This doesn't bother me enough to bother changing things.
	     */
	    if (state_timeout > 0) state_timeout--;
	    if (debug&DEBUG_TICK)
	        mon_syslog(LOG_DEBUG,"--- tick --- state %d block %d state_timeout %d",state,blocked,state_timeout);
	    monitor_queue();
	}
	change_state();
    }
    die(0);

    return 0;
}

/*
 * Change into a daemon.
 * Get rid of the stdio streams, and disassociate from the original
 * controling terminal, and become a group leader.
 */

void become_daemon()
{
    int pid;
    FILE *fp;
    if (daemon_flag) {
        close(0);
        close(1);
        close(2);
	/* go into the background */
	if ((pid = fork()) < 0) {
	    syslog(LOG_ERR,"Could not fork into background: %m");
	    die(1);
	}
	/* parent process is finished */
	if (pid != 0) exit(0);
    }
    pidfile = malloc(strlen(run_prefix) + strlen(pidlog) + 2);
    sprintf(pidfile,"%s/%s",run_prefix,pidlog);
    if ((fp = fopen(pidfile,"w")) != NULL) {
        fprintf(fp,"%d\n",getpid());
        fclose(fp);
    } else {
	syslog(LOG_ERR,"Unable to create run file %s: %m",pidfile);
    }
}

/* Open the command fifo, if any */

void open_fifo()
{
    struct stat sbuf;

    if (fifoname) {
	if (stat(fifoname,&sbuf) < 0 || !(sbuf.st_mode&S_IFIFO)) {
	    syslog(LOG_INFO,"Creating FIFO");
	    /* Create the fifo. */
	    mknod(fifoname, S_IFIFO|0277, 0);
	    chmod(fifoname, 0600);
	}
	/* We need to open this RDWR to make select() work the
         * way we want in kernels after 1.3.81. In particular
	 * we don't want select() to return 1 whenever there
	 * are no writers on the remote side of the command fifo.
	 * This guarantees that there is always at least one writer...
         */
	if ((fifo_fd = open(fifoname, O_RDWR)) >= 0) {
	    fcntl(fifo_fd, F_SETFD, FD_CLOEXEC);
            fifo_pipe = (PIPE *)malloc(sizeof(PIPE));
            if (fifo_pipe) {
	        if (debug&DEBUG_VERBOSE)
	   	    syslog(LOG_INFO,"Using fifo %s",fifoname);
	        pipe_init("FIFO", 0x7fffffff, fifo_fd, fifo_pipe, 1);
		FD_SET(fifo_fd, &ctrl_fds);
            } else {
	        syslog(LOG_ERR,"Could not open fifo pipe %m");
	        fifo_fd = -1;
            }
	} else {
	    syslog(LOG_ERR,"Could not open fifo file %s",fifoname);
	    fifo_fd = -1;
	}
    } else {
	/* make sure to invalidate the fifo_fd if we don't open one. */
	fifo_fd = -1;
    }

    if (tcpport) {
	if ((tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
	    struct sockaddr_in sa;
	    int opt = 1;
	    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR,
		(void *)&opt, sizeof(opt));
	    fcntl(tcp_fd, F_SETFD, FD_CLOEXEC);
	    sa.sin_family = AF_INET;
	    sa.sin_addr.s_addr = INADDR_ANY;
	    sa.sin_port = htons(tcpport);
	    if (!bind(tcp_fd, (struct sockaddr *)&sa, sizeof(sa))
	    && !listen(tcp_fd, 5)) {
		if (debug&DEBUG_VERBOSE)
	   	    syslog(LOG_INFO,"Using TCP port %d", tcpport);
		FD_SET(tcp_fd, &ctrl_fds);
	    } else {
		close(tcp_fd);
		tcp_fd = -1;
	    }
	}
	if (tcp_fd < 0) {
	    syslog(LOG_ERR,"Could not open TCP socket: %m");
	    tcp_fd = -1;
	}
    } else {
	tcp_fd = -1;
    }
}


/*
 * Set up the signal handlers.
 */
static sigset_t sig_mask;


void signal_setup()
{
    struct sigaction sa;
    /* set up signal handlers */

    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGHUP);
    sigaddset(&sig_mask, SIGINT);
    sigaddset(&sig_mask, SIGTERM);
    sigaddset(&sig_mask, SIGUSR1);
    sigaddset(&sig_mask, SIGUSR2);
    sigaddset(&sig_mask, SIGCHLD);
    sigaddset(&sig_mask, SIGPIPE);

#define SIGNAL(s, handler)      { \
        sa.sa_handler = handler; \
        if (sigaction(s, &sa, NULL) < 0) { \
            mon_syslog(LOG_ERR, "sigaction(%d): %m", s); \
            die(1); \
        } \
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_mask = sig_mask;
    sa.sa_flags = 0;

    SIGNAL(SIGHUP, sig_hup);            /* Hangup: modem went down. */
    SIGNAL(SIGINT, sig_intr);           /* Interrupt: take demand dialer down */
    SIGNAL(SIGUSR1, linkup);            /* User requests the link to go up */
    SIGNAL(SIGUSR2, print_filter_queue); /* dump the packet queue to the log */
    SIGNAL(SIGPIPE, SIG_IGN);
    SIGNAL(SIGTERM, sig_term);          /* Terminate: user take link down */
    SIGNAL(SIGCHLD, sig_chld);		/* reap dead kids */
    SIGNAL(SIGTTOU, SIG_IGN);
}

static int signal_block_depth = 0;

void block_signals()
{
    if (signal_block_depth++ == 0)
	sigprocmask(SIG_BLOCK, &sig_mask, NULL);
}

void unblock_signals()
{
    if (--signal_block_depth == 0)
	sigprocmask(SIG_UNBLOCK, &sig_mask, NULL);
}

void default_sigacts()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_mask = sig_mask;
    sa.sa_flags = 0;

    SIGNAL(SIGHUP, SIG_DFL);
    SIGNAL(SIGINT, SIG_DFL);
    SIGNAL(SIGTERM, SIG_DFL);
    SIGNAL(SIGUSR1, SIG_DFL);
    SIGNAL(SIGUSR2, SIG_DFL);
    SIGNAL(SIGCHLD, SIG_DFL);
    SIGNAL(SIGPIPE, SIG_DFL);
    SIGNAL(SIGTTOU, SIG_DFL);
}

#ifndef HAVE_PTY_H
/*
 * Get a pty and open both the slave and master sides.
 */

int openpty(int *mfd, int *sfd, void *name, void *termios, void *win)
{
    char *ptys = "0123456789abcdef";
    int i, c;
    static char buf[128];

    for (c = 'p'; c <= 's'; c++)
        for (i = 0; i < 16; i++) {
	    sprintf(buf,"/dev/pty%c%c",c,ptys[i]);
	    if ((*mfd = open(buf,O_RDWR)) >= 0) {
	    	sprintf(buf,"/dev/tty%c%c",c,ptys[i]);
		if ((*sfd = open(buf,O_RDWR|O_NOCTTY|O_NDELAY)) < 0) {
		    syslog(LOG_ERR,"Can't open slave side of pty: %m");
		    return -1;
		}
		return 0;
	    }
        }
    syslog(LOG_ERR,"No pty found in range pty[p-s][0-9a-f]\n");
    return -1;
}
#endif

/* Read a request from the command pipe.
 * Valid requests are:
 *	config		- modify diald configuration.
 *	block		- block diald from calling out.
 *	unblock		- unblock diald from calling out.
 *	down		- bring the link down.
 *	up		- bring the link up.
 *	delayed-quit	- quit next time diald is idle.
 *	quit		- stop diald in its tracks.
 *	queue		- dump the filter queue.
 *	debug level	- set the debug level.
 *	force		- force diald to put the connection up and keep it up.
 *	unforce		- remove the forced up requirement.
 *	connect pid dev	- go up on a connection to the named port.
 *			  We assume the connection negotiations are
 *			  already finished and any lock files are in place.
 *			  When the connection should be killed we send a
 *			  SIGTERM to the given pid.
 *	dynamic <lip> <rip> - pass back dynamic IP config info to diald.
 *	message <txt>	- set the message text from the connect script.
 *	monitor file	- start a monitoring program.
 *      reset		- reread the configuration information.
 */

void ctrl_read(PIPE *pipe)
{
    int i;
    int pid, dev, j,k,l = 0;
    char *buf, *tail;

    i = pipe_read(pipe);
    buf = tail = pipe->buf;
    if (i < 0) {
	PIPE **tmp;
	FD_CLR(pipe->fd, &ctrl_fds);
	close(pipe->fd);
        tmp = &pipes;
        while (*tmp) {
            if (pipe == *tmp) {
                *tmp = pipe->next;
                free(pipe);
		break;
            }
            tmp = &(*tmp)->next;
        }
	return;
    }
    if (i == 0) return;

    while (i--) {
        if (*tail == '\n' || *tail == '\r') {
            *tail = '\0';
	    /* Ok, we've got a line, now we need to "parse" it. */
	    if (!*buf) {
		/* Empty line. Probably \r\n? */
	    } else if (!(pipe->access & ACCESS_CONTROL)) {
		/* Not a control pipe - just messages from a script */
		mon_syslog(LOG_INFO, "%s: %s", pipe->name, buf);
	    } else if (strncmp(buf, "auth ", 5) == 0) {
	    	if (!(pipe->access & ACCESS_AUTH)) {
		    mon_syslog(LOG_NOTICE, "%s: ignored auth request",
			pipe->name);
		} else {
		    pipe->access = ctrl_access(buf+5);
		    mon_syslog(LOG_NOTICE, "%s: new access 0x%08x",
			pipe->name, pipe->access);
		}
	    } else if ((pipe->access & ACCESS_CONFIG)
	    && strncmp(buf, "config ", 7) == 0) {
		mon_syslog(LOG_NOTICE, "%s: %s", pipe->name, buf);
		parse_options_line(buf+7);
	    } else if ((pipe->access & ACCESS_DEMAND)
	    && strcmp(buf,"demand") == 0) {
		mon_syslog(LOG_NOTICE, "%s: demand enable request",
			pipe->name);
		parse_options_line(buf);
	    } else if ((pipe->access & ACCESS_NODEMAND)
	    && strcmp(buf,"nodemand") == 0) {
		mon_syslog(LOG_NOTICE, "%s: demand disable request",
			pipe->name);
		parse_options_line(buf);
	    } else if ((pipe->access & ACCESS_BLOCK)
	    && strcmp(buf,"block") == 0) {
		mon_syslog(LOG_NOTICE, "%s: block request", pipe->name);
		parse_options_line(buf);
		request_down = 1;
		request_up = 0;
	    } else if ((pipe->access & ACCESS_UNBLOCK)
	    && strcmp(buf,"unblock") == 0) {
		mon_syslog(LOG_NOTICE, "%s: unblock request", pipe->name);
		parse_options_line(buf);
	    } else if ((pipe->access & ACCESS_FORCE)
	    && strcmp(buf,"force") == 0) {
		mon_syslog(LOG_NOTICE, "%s: force request", pipe->name);
		forced = 1;
	    } else if ((pipe->access & ACCESS_UNFORCE)
	    && strcmp(buf,"unforce") == 0) {
		mon_syslog(LOG_NOTICE, "%s: unforce request", pipe->name);
		forced = 0;
	    } else if ((pipe->access & ACCESS_DOWN)
	    && strcmp(buf,"down") == 0) {
		mon_syslog(LOG_NOTICE, "%s: link down request", pipe->name);
    		request_down = 1;
    		request_up = 0;
	    } else if ((pipe->access & ACCESS_UP)
	    && strcmp(buf,"up") == 0) {
    		mon_syslog(LOG_NOTICE, "%s: link up request", pipe->name);
    		request_down = 0;
    		request_up = 1;
	    } else if ((pipe->access & ACCESS_DELQUIT)
	    && strcmp(buf,"delayed-quit") == 0) {
    		mon_syslog(LOG_NOTICE, "%s: delayed termination request", pipe->name);
    		delayed_quit = 1;
	    } else if ((pipe->access & ACCESS_QUIT)
	    && strcmp(buf,"quit") == 0) {
    		mon_syslog(LOG_NOTICE, "%s: termination request", pipe->name);
    		terminate = 1;
	    } else if ((pipe->access & ACCESS_RESET)
	    && strcmp(buf,"reset") == 0) {
    		mon_syslog(LOG_NOTICE, "%s: reset request received - re-reading configuration", pipe->name);
		do_config();
	    } else if ((pipe->access & ACCESS_QUEUE)
	    && strcmp(buf,"queue") == 0) {
    		struct firewall_req req;
    		mon_syslog(LOG_NOTICE,"%s: user requested dump of firewall queue", pipe->name);
    		mon_syslog(LOG_DEBUG,"--------------------------------------");
    		req.unit = fwunit;
    		ctl_firewall(IP_FW_PCONN,&req);
    		mon_syslog(LOG_DEBUG,"--------------------------------------");
	    } else if ((pipe->access & ACCESS_DEBUG)
	    && sscanf(buf,"debug %i", &pid) == 1) {
    		mon_syslog(LOG_NOTICE,"%s: changing debug flags to 0x%x",
		    pipe->name, pid);
		debug = pid;
	    } else if ((pipe->access & ACCESS_DYNAMIC)
	    && (sscanf(buf,"dynamic %n%*s%n %n",&j,&k,&l) >= 0) && l) {
		buf[k] = 0;
		if (inet_addr(buf+j) == (unsigned long)0xffffffff
		||  inet_addr(buf+l) == (unsigned long)0xffffffff) {
		    mon_syslog(LOG_ERR,"%s: bad parameters '%s' and '%s' to dynamic command ignored",
			pipe->name, buf+j, buf+l);
		} else {
		    if (local_ip) free(local_ip);
		    local_ip = strdup(buf+j);
		    if (remote_ip) free(remote_ip);
		    remote_ip = strdup(buf+l);
		    force_dynamic = 1;
		}
	    } else if ((pipe->access & ACCESS_MONITOR)
	    && strncmp(buf,"monitor", 7) == 0) {
    		struct stat sbuf;
		int fd;
		MONITORS *new;

		k = 0;
		if (sscanf(buf,"monitor %i %n",&j,&k) == 1) {
		    /* Use the most advanced flags we know */
		    if ((j & MONITOR_QUEUE2))
			j &= (~MONITOR_QUEUE);
		    mon_syslog(LOG_NOTICE, "%s: log level 0x%08x", buf + k, j);
		} else if (buf[7] != 0 && buf[7] == ' ') {
		    mon_syslog(LOG_NOTICE, "%s: full monitor connection", buf+8);
		    j = 0x060000ff;	/* Heavy weight connection requested */
		    k = 8;
		}
		if (k >= 8) {
		    /* Check list to see if this is just a status change */
		    block_signals();	/* don't let anything mess up the data */
		    new = monitors;
		    while (new) {
			if (strcmp(new->name,buf+k) == 0) {
			    new->level = j;
			    output_state();
			    break;
			}
			new = new->next;
		    }
		    if (!new) {
			if (pipe == fifo_pipe
			&& (stat(fifoname,&sbuf) < 0 || !sbuf.st_mode&S_IFIFO)) {
			    mon_syslog(LOG_ERR, "%s: %s not a pipe",
				pipe->name, buf+k);
			} else if ((pipe != fifo_pipe && (fd=dup(pipe->fd)) < 0)
			|| (pipe == fifo_pipe && (fd = open(buf+k,O_WRONLY|O_NDELAY))<0)) {
			    mon_syslog(LOG_ERR, "%s: could not open pipe %s: %m",
				pipe->name, buf+k);
			} else {
			    struct firewall_req req;
			    fcntl(fd, F_SETFD, FD_CLOEXEC);
			    new = (MONITORS *)malloc(sizeof(MONITORS));
			    new->name = strdup(buf+k);
			    new->is_pipe = (pipe == fifo_pipe);
			    new->next = monitors;
			    new->fd = fd;
			    new->level = j;
			    if (!monitors) ctl_firewall(IP_FW_MCONN_INIT,&req);
			    monitors = new;
			    req.unit = fwunit;
			    output_state();
			}
		    }
		    unblock_signals();
		} else {
		    mon_syslog(LOG_INFO, "%s: empty monitor request ignored",
			pipe->name);
		}
	    } else if ((pipe->access & ACCESS_MESSAGE)
	    && strncmp(buf,"message ",8) == 0) {
		/* pass a message from the connector on to the monitor */
		if (monitors) {
		    mon_write(MONITOR_MESSAGE,"MESSAGE\n",8);
		    mon_write(MONITOR_MESSAGE,buf+8,strlen(buf+8));
		    mon_write(MONITOR_MESSAGE,"\n",1);
		}
            } else if ((pipe->access & ACCESS_CONNECT)
	    && sscanf(buf,"connect %d %n", &pid, &dev) == 1) {
#if 0
/* XXX */mon_syslog(LOG_INFO,"%s: up request on %s state=%d, dial=%d, dev=%s", pipe->name, buf+dev, state, dial_pid, current_dev ? current_dev : "none");
#endif
		/* Damn ISDN has no blocking dial. If we get a request up
		 * where the request device matches the current device we
		 * ignore it. (Perhaps we should take it as a dial
		 * completion?)
		 */
		if (state == STATE_CONNECT && current_dev
		&& !strcmp(current_dev, buf+dev)) {
		    mon_syslog(LOG_INFO, "%s: link up request on current device ignored",
			pipe->name);
		} else if ((state != STATE_DOWN && state != STATE_CLOSE
		    && !give_way)
		|| state==STATE_UP || req_pid) {
                    /* somebody else already has this diald, tell 'em */
                    if (pid) kill(pid, SIGTERM);
		    mon_syslog(LOG_INFO, "%s: link up requested but denied",
			pipe->name);
                } else {
                    req_pid = pid;
                    req_dev = (char *)malloc(tail-(buf+dev)+1);
                    if (req_dev == 0) {
                        req_pid = 0;
                        mon_syslog(LOG_ERR, "%s: no memory to store requested devce!",
			    pipe->name);
                    } else {
                        strcpy(req_dev, buf+dev);
                        request_down = 0;
                        request_up = 1;
                        mon_syslog(LOG_INFO, "%s: link up requested on device %s",
			    pipe->name, req_dev);
                    }
                }
            } else {
		mon_syslog(LOG_ERR,"%s: Ignored request '%s'",
		    pipe->name, buf);
	    }
	   buf = tail+1;
       }
       tail++;
    }

    pipe_flush(pipe, buf-pipe->buf);
}

/*
 * Deal with master side packet on the SLIP link.
 */
void proxy_read()
{
    int len;
    char buffer[4096];

    /* read the SLIP packet */
    len = recv_packet(buffer,4096);
    if (len == 0)
	return;

    /* If we get here with the link up and fwdfd not -1,
     * and we are rerouting, then it must be
     * that the external interface has gone down without
     * taking the link with it, and as a result our route
     * to the external interface got lost. (This CAN legally
     * happen with PPP). In this case we buffer the packet so
     * we can retransmit it when the link comes back up.
     * OR
     * the kernel is retransmitting something through sl0, despite
     * the existance of a route through another device...
     */

    /* if the external iface is up then probably we can send it on */
    if (link_iface != -1 && fwdfd != -1) {
	int dlen;
	struct sockaddr_pkt sp;
#ifdef HAVE_AF_PACKET
	struct sockaddr_ll sl;
#endif
	struct sockaddr *to;
	size_t to_len;

	/* Make sure we try to restore the link to working condition now... */
	if (current_mode == MODE_PPP) {
	    /* Check if a route exists at this point through the ppp device. */
	    /* If not then we must be half dead. */
	    if (!ppp_route_exists()) {
		/* The external iface is down, buffer the packet so we can
	 	 * forward it when the iface comes up.
	  	 */
	        ppp_half_dead = 1;
		if (buffer_packets)
	    	    buffer_packet(len,buffer);
		return;
	    }
	}

	/* Ok, the interface is there, and the route is up,
  	 * so just send it on. This can happen when routing is switched
	 * in the middle of a retransmission sequence. (There is a race
	 * between the route switching and the forwarding I think.)
	 */

#ifdef HAVE_AF_PACKET
	if (af_packet) {
	    memset(&sl, 0, sizeof(sl));
	    sl.sll_family = AF_PACKET;
	    sl.sll_protocol = *(unsigned short *)buffer;
	    sl.sll_ifindex = snoop_index;
	    to = (struct sockaddr *)&sl;
	    to_len = sizeof(sl);
	} else
#endif
	{
	    memset(&sp, 0, sizeof(sp));
	    sp.spkt_family = AF_INET;
	    strcpy(sp.spkt_device, snoop_dev);
	    sp.spkt_protocol = *(unsigned short *)buffer;
	    to = (struct sockaddr *)&sp;
	    to_len = sizeof(sp);
	}

	dlen = len - sizeof(unsigned short);

	if (debug&DEBUG_VERBOSE)
	    mon_syslog(LOG_DEBUG,"Forwarding packet of length %d", dlen);
	if (sendto(fwdfd, buffer+sizeof(unsigned short), dlen, 0, to, to_len) < 0) {
	    mon_syslog(LOG_ERR,
		"Error forwarding data packet to physical device: %m");
	}
    } else {
	/* If the link isn't up, then we better buffer the packets */
	if (buffer_packets)
	    buffer_packet(len,buffer);
    }
}

/*
 * Terminate diald gracefully.
 */

static int in_die = 0;

void die(int i)
{
    int count;

    if (!in_die) {
	in_die = 1;
        mon_syslog(LOG_NOTICE, "Diald is dieing with code %d", i);
	/* We're killing without a care here. Uhggg. */
	if (link_pid) kill(link_pid,SIGINT);
	if (dial_pid)
	    if (kill(-dial_pid, SIGINT) == -1)
		kill(dial_pid, SIGINT);
	if (running_pid) kill(running_pid,SIGINT);
	/* Wait up to 30 seconds for them to die */
        for (count = 0; (link_pid || dial_pid) && count < 30; count++)
	    sleep(1);
	/* If they aren't dead yet, kill them for sure */
	if (link_pid) kill(link_pid,SIGKILL);
	if (dial_pid)
	    if (kill(-dial_pid, SIGKILL) == -1)
		kill(dial_pid, SIGKILL);
	if (running_pid) kill(running_pid,SIGKILL);
	/* Give the system a second to send the signals */
	if (link_pid || dial_pid || running_pid) sleep(1);

	close_modem();
	interface_down();
	proxy_stop();
	proxy_release();

	if (deinitializer) {
		if (devices && devices[0])
			setenv("MODEM", devices[0], 1);
		run_shell(SHELL_WAIT, "deinit", deinitializer, -1);
	}

	if (tcp_fd >= 0)
		close(tcp_fd);

	unlink(pidfile);
    	exit(i);
    }
}

/*
 * Signal handlers.
 */

/*
 * Modem link went down.
 */
void sig_hup(int sig)
{
    mon_syslog(LOG_NOTICE, "SIGHUP: modem got hung up on.");
    modem_hup = 1;
}

/*
 * User wants the link to go down.
 * (Perhaps there should be a 10 second delay? Configurable????)
 */
void sig_intr(int sig)
{
    mon_syslog(LOG_NOTICE, "SIGINT: Link down request received.");
    request_down = 1;
    request_up = 0;
}

/*
 *  The user has requested that the link be put up.
 */
void linkup(int sig)
{
    mon_syslog(LOG_NOTICE, "SIGUSR1. External link up request received.");
    request_down = 0;
    request_up = 1;
}

/*
 * A child process died. Find out which one.
 */
void sig_chld(int sig)
{
    int pid, status;
    static int seq = 0;
    ++seq;
    while ((pid = waitpid(-1,&status,WNOHANG)) > 0) {
        if (debug&DEBUG_VERBOSE)
	    mon_syslog( LOG_DEBUG, "SIGCHLD[%d]: pid %d %s, status %d", seq, pid,
		    pid == link_pid ? "link"
		   	: pid == dial_pid ? "dial"
			: pid == running_pid ? "system"
			: "other",
		    status);
	if (pid == link_pid) link_pid = 0;
	else if (pid == dial_pid) { dial_status = status; dial_pid = 0; }
	else if (pid == running_pid) { running_status = status; running_pid = 0; }
	else if (!WIFEXITED(status))
   	    mon_syslog(LOG_ERR,"Abnormal exit (status %d) on pid %d",status,pid);
	else if (WEXITSTATUS(status) != 0)
	    mon_syslog(LOG_ERR,"Nonzero exit status (%d) on pid %d",
		WEXITSTATUS(status),pid);
	if (pid > 0) {
	    if (WIFSIGNALED(status)) {
		mon_syslog(LOG_WARNING, "child process %d terminated with signal %d",
		       pid, WTERMSIG(status));
	    }
	}
    }
    if (pid && errno != ECHILD)
	mon_syslog(LOG_ERR, "waitpid: %m");
    return;
}

/*
 * User wants diald to be terminated.
 */
void sig_term(int sig)
{
    mon_syslog(LOG_NOTICE, "SIGTERM. Termination request received.");
    terminate = 1;
}


void mon_cork(int onoff)
{
#ifdef __linux__
#  ifndef TCP_CORK
#    define TCP_CORK 3
#  endif
#endif
#ifdef TCP_CORK
    MONITORS *mon = monitors;
    while (mon) {
	if (!mon->is_pipe) {
	    setsockopt(mon->fd, SOL_TCP, TCP_CORK,
		(void *)&onoff, sizeof(onoff));
	}
	mon = mon->next;
    }
#endif
}


/*
 * UGH. Pulling stuff out of the monitors list is full of races.
 */
void mon_write(unsigned int level, char *message, int len)
{
    int pri = 6<<24;
    MONITORS *c = monitors, *p = 0, *cn;
    if ((level & MONITOR_MESSAGE)
    && len > 3 && message[0] == '<' && message[2] == '>') {
	pri = (message[1] - '0')<<24;
	message += 3;
	len -= 3;
    }
    block_signals();	/* don't let anything mess up the data */
    while (c) {
	cn = c->next;
	if ((c->level & level) == level
	&& (!(level & MONITOR_MESSAGE) || pri <= (c->level & 0xff000000))) {
	    if (write(c->fd,message,len) < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
#if 0
		    syslog(LOG_INFO,"Writing error on pipe %s: %m.",c->name);
#endif
		    /* Write error. The reader probably got swapped out
		     * or something and the pipe flooded. We'll just "loose"
		     * the data.
		     */
		     p = c;
		     c = cn;
		     continue;
		}
		close(c->fd);
		if (p) p->next = c->next;
		else monitors = c->next;
		mon_syslog(LOG_NOTICE,"Monitor pipe %s closed.",c->name);
		free(c->name);
		free(c);
	    } else {
		p = c;
	    }
	}
	c = cn;
    }
    unblock_signals();	/* don't let anything mess up the data */
}
