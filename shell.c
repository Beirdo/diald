/*
 * shell.c - Call external programs via the shell.
 *
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <diald.h>


int
run_shell(int mode, const char *name, const char *buf, int d)
{
    int d2, p[2];
    pid_t pid;
    FILE *fd;

    block_signals();
    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG,"running '%s'",buf);

    if (pipe(p))
	p[0] = p[1] = -1;

    pid = fork();

    if (pid < 0) {
	unblock_signals();
        mon_syslog(LOG_ERR, "failed to fork and run '%s': %m",buf);
	return -1;
    }

    if (pid == 0) {
	if (d >= 0) {
	    /* Run in a new process group and foreground ourselves
	     * on the tty (SIGTTOU is ignored).
	     * N.B. If we are in dev mode we have /dev/null and
	     * not a serial line...
	     */
	    setpgrp();
	    if (tcsetpgrp(d, getpid()) < 0 && errno != ENOTTY)
		mon_syslog(LOG_ERR, "dial: failed to set pgrp: %m");
	} else {
	    setsid();    /* No controlling tty. */
	    umask (S_IRWXG|S_IRWXO);
	    chdir ("/"); /* no current directory. */
	}

        /* change the signal actions back to the defaults, then unblock them. */
        default_sigacts();
	unblock_signals();

#if 0
	proxy_close();
#endif
	/* make sure the stdin, stdout and stderr get directed to /dev/null */
	if (p[0] >= 0) close(p[0]);
	d2 = open("/dev/null", O_RDWR);
        if (d >= 0) {
            if (p[1] != 2) dup2((p[1] >= 0 ? p[1] : d2), 2);
	    close(d2);
	    if (d != 0) {
	    	dup2(d, 0);
		close(d);
	    } else {
		fcntl(d, F_SETFD, 0);
	    }
	    dup2(0, 1);
        } else {
	    if (d2 != 0) {
	    	dup2(d2, 0);
		close(d2);
	    }
	    if (p[1] != 1) dup2((p[1] >= 0 ? p[1] : 0), 1);
            if (p[1] != 2) dup2((p[1] >= 0 ? p[1] : 0), 2);
	}
	if (p[1] > 2) close(p[1]);

	/* set the current device (compat) */
	if (current_dev)
	    setenv("MODEM", current_dev, 1);

	/* set the current command FIFO (if any) */
	if (fifoname)
	    setenv("FIFO", fifoname, 1);

	if (current_dev)
	    setenv("DIALD_DEVICE", current_dev, 1);
	if (link_name)
	    setenv("DIALD_LINK", link_name, 1);

        execl("/bin/sh", "sh", "-c", buf, (char *)0);
        mon_syslog(LOG_ERR, "could not exec /bin/sh: %m");
        _exit(127);
        /* NOTREACHED */
    }

    if (p[1] >= 0) close(p[1]);

    if (mode & SHELL_WAIT) {
	running_pid = pid;

	if (p[0] >= 0 && (fd = fdopen(p[0], "r"))) {
	    char buf[1024];

	    while (fgets(buf, sizeof(buf)-1, fd)) {
		buf[sizeof(buf)-1] = '\0';
		mon_syslog(LOG_INFO, "%s: %s", name, buf);
	    }

	    fclose(fd);
	}

	unblock_signals();

	while (running_pid)
	    pause();
	return running_status;
    }

    if (p[0] >= 0) {
	PIPE *ctrl_p;

	if ((ctrl_p = malloc(sizeof(PIPE)))) {
	    pipe_init((char *)name, 0, p[0], ctrl_p, 0);
	    FD_SET(p[0], &ctrl_fds);
	} else
	    close(p[0]);
    }

    unblock_signals();
    return pid;
}


void
run_state_script(char *name, char *script, int background)
{
    char buf[1024];

    snprintf(buf, sizeof(buf)-1, "%s '%s' '%s' '%s' '%s'",
	script,
	snoop_dev,
	netmask ? netmask : "255.255.255.255",
	local_ip,
	remote_ip);
    buf[sizeof(buf)-1] = '\0';

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_INFO,"running %s script '%s'", name, buf);

    if (background)
	running_pid = run_shell(SHELL_NOWAIT, name, buf, -1);
    else
	run_shell(SHELL_WAIT, name, buf, -1);
}
