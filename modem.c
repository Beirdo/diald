/*
 * modem.c - Modem control functions.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
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

#include "diald.h"

static int rotate_offset = 0;

char *current_dev = 0;
int current_mode;
int current_slip_encap;

/* local variables */

static struct termios inittermios;      /* Initial TTY termios */
static int restore_term = 0;

#if B9600 == 9600
/*
 * XXX assume speed_t values numerically equal bits per second
 * (so we can ask for any speed).
 */
#define translate_speed(bps)	(bps)

#else
/*
 * List of valid speeds.
 */
struct speed {
    int speed_int, speed_val;
} speeds[] = {
#ifdef B50
    { 50, B50 },
#endif
#ifdef B75
    { 75, B75 },
#endif
#ifdef B110
    { 110, B110 },
#endif
#ifdef B134
    { 134, B134 },
#endif
#ifdef B150
    { 150, B150 },
#endif
#ifdef B200
    { 200, B200 },
#endif
#ifdef B300
    { 300, B300 },
#endif
#ifdef B600
    { 600, B600 },
#endif
#ifdef B1200
    { 1200, B1200 },
#endif
#ifdef B1800
    { 1800, B1800 },
#endif
#ifdef B2000
    { 2000, B2000 },
#endif
#ifdef B2400
    { 2400, B2400 },
#endif
#ifdef B3600
    { 3600, B3600 },
#endif
#ifdef B4800
    { 4800, B4800 },
#endif
#ifdef B7200
    { 7200, B7200 },
#endif
#ifdef B9600
    { 9600, B9600 },
#endif
#ifdef B19200
    { 19200, B19200 },
#endif
#ifdef B38400
    { 38400, B38400 },
#endif
#ifdef EXTA
    { 19200, EXTA },
#endif
#ifdef EXTB
    { 38400, EXTB },
#endif
#ifdef B57600
    { 57600, B57600 },
#endif
#ifdef B115200
    { 115200, B115200 },
#endif
#ifdef B230400
    { 230400, B230400 },
#endif
#ifdef B460800
    { 460800, B460800 },
#endif
    { 0, 0 }
};

/*
 * Translate from bits/second to a speed_t.
 */
int translate_speed(int bps)
{
    struct speed *speedp;

    if (bps == 0)
	return 0;
    for (speedp = speeds; speedp->speed_int; speedp++)
	if (bps == speedp->speed_int)
	    return speedp->speed_val;
    mon_syslog(LOG_WARNING, "speed %d not supported", bps);
    return 0;
}
#endif

/*
 * set_up_tty: Set up the serial port on `fd' for 8 bits, no parity,
 * at the requested speed, etc.  If `local' is true, set CLOCAL
 * regardless of whether the modem option was specified.
 */
void set_up_tty(int fd, int local, int spd)
{
    int speed, i;
    struct termios tios;

    if (tcgetattr(fd, &tios) < 0) {
	mon_syslog(LOG_ERR, "could not get initial terminal attributes: %m");
    }

    tios.c_cflag = CS8 | CREAD | HUPCL;
    if (local || !modem) tios.c_cflag |= CLOCAL;
    if (crtscts == 1) tios.c_cflag |= CRTSCTS;
    tios.c_iflag = IGNBRK | IGNPAR;
    tios.c_oflag = 0;
    tios.c_lflag = 0;
    for (i = 0; i < NCCS; i++)
	tios.c_cc[i] = 0;
    tios.c_cc[VMIN] = 1;
    tios.c_cc[VTIME] = 0;

    speed = translate_speed(spd);
    if (speed) {
	cfsetospeed(&tios, speed);
	cfsetispeed(&tios, speed);
    } else {
	speed = cfgetospeed(&tios);
    }

    if (tcsetattr(fd, TCSAFLUSH, &tios) < 0) {
	mon_syslog(LOG_ERR, "failed to set terminal attributes: %m");
    }
}

/*
 * setdtr - control the DTR line on the serial port.
 * This is called from die(), so it shouldn't call die().
 */
void setdtr(int fd, int on)
{
    int modembits = TIOCM_DTR;

    ioctl(fd, (on? TIOCMBIS: TIOCMBIC), &modembits);
}


/*
 * fork_dialer - run a program to connect/disconnect the device.
 */
void fork_dialer(char *prog_type, char *program, int fd)
{
    int p[2];
    PIPE *ctrl_p;

    block_signals();

    if (pipe(p))
	p[0] = p[1] = -1;

    dial_pid = fork();

    if (dial_pid < 0) {
	unblock_signals();
        mon_syslog(LOG_ERR, "failed to fork %s: %m", prog_type);
	/* FIXME: Probably this should not be fatal */
        die(1);
    }

    if (dial_pid == 0) {
	/* Run in a new process group and foreground ourselves
	 * on the tty (SIGTTOU is ignored).
	 * N.B. If we are in dev mode we have /dev/null and
	 * not a serial line...
	 */
	setpgrp();
	if (tcsetpgrp(modem_fd, getpid()) < 0 && errno != ENOTTY)
	    mon_syslog(LOG_ERR, "dial: failed to set pgrp: %m");

        /* change the signal actions back to the defaults, then unblock them. */
        default_sigacts();
	unblock_signals();

        /* make sure the child doesn't inherit any extra file descriptors */
	close(proxy_mfd);      /* close the master pty endpoint */
	close(proxy_sfd);      /* close the slave pty endpoint */
	if (fifo_fd != -1) close(fifo_fd);
	if (tcp_fd != -1) close(tcp_fd);
	if (pipes) {
	    PIPE *p = pipes;
	    while (p) {
		close(p->fd);
		p = p->next;
	    }
	}
	if (monitors) {
	    MONITORS *c = monitors;
	    while (c) {
	    	close(c->fd);
		c = c->next;
	    }
	}

	/* make sure the stdin and stdout get directed to the modem */
        if (fd != 0) { dup2(fd, 0); close(fd); }
        dup2(0, 1);

	dup2(p[1] >= 0 ? p[1] : 0, 2);
	if (p[0] >= 0) close(p[0]);

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

        execl("/bin/sh", "sh", "-c", program, (char *)0);
        mon_syslog(LOG_ERR, "could not exec /bin/sh: %m");
        _exit(127);
        /* NOTREACHED */
    }

    if (p[1] >= 0) close(p[1]);

    if (p[0] >= 0) {
	if ((ctrl_p = malloc(sizeof(PIPE)))) {
	    pipe_init(prog_type, 0, p[0], ctrl_p, 0);
	    FD_SET(p[0], &ctrl_fds);
	} else
	    close(p[0]);
    }

    unblock_signals();
    mon_syslog(LOG_INFO,"Running %s (pid = %d).", prog_type, dial_pid);
}

/*
 * Open up a modem and set up the desired parameters.
 */
int open_modem()
{
    int i;

    /*
     * Open the serial device and set it up.
     */

    modem_hup = 0;
    modem_fd = -1;
    dial_status = 0;

    /* If this is a request for diald to take over management of an
     * interface that we didn't bring up ourselves there is little
     * to do here except note what we are taking on.
     */
    if (req_pid) {
	current_dev = req_dev;
	use_req=1;

	/* FIXME: If we are locking devices and the requested device
	 * is not already locked we should probably lock it to prevent
	 * anyone else trying it. This is a particular problem with
	 * non-modem devices such as isdn? and ippp?.
	 *   Possibly we should also inherit existing locks?
	 */

	modem_fd = open(current_dev[0] != '/' ? current_dev : "/dev/null",
			O_RDWR | O_NDELAY);
	if (modem_fd < 0) {
	    mon_syslog(LOG_ERR, "Can't open requested device '%s'", req_dev);
	    if (current_dev[0] != '/')
		req_pid = 0;
	    else {
	    	killpg(req_pid, SIGKILL);
	    	kill(req_pid, SIGKILL);
	    }
	    dial_status = -1;
	    return 1;
	}
    } else {
	for (i = 0; i < device_count; i++) {
	    current_dev = devices[(i+rotate_offset)%device_count];

	    if (lock_dev && lock(current_dev))
		continue;

	    /* OK. Locked one, try to open it */
	    modem_fd = open(current_dev[0] == '/' ? current_dev : "/dev/null",
			    O_RDWR | O_NDELAY);
	    if (modem_fd >= 0)
		break;

	    /* That didn't work, get rid of the lock */
	    mon_syslog(LOG_ERR,"Error opening device %s: %m",current_dev);
	    if (lock_dev) unlock();
	}
	if (modem_fd < 0) {
	    mon_syslog(LOG_WARNING,"No devices free to call out on.");
	    current_dev = 0;
	    dial_status = -1;
	    return 2;
	}

	if (rotate_devices)
	    rotate_offset = (rotate_offset+1)%device_count;
    }

    if (current_dev[0] != '/')
	current_mode = MODE_DEV;
    else {
	current_mode = mode;
	current_slip_encap = slip_encap;
    }

    if (current_mode == MODE_DEV) {
	/* If we have a connector we may need to run it to set up the
	 * real interface.
	 */
	if (!req_pid && connector)
		fork_dialer("connector", connector, modem_fd);
	req_pid = 0;
	return 0;
    }


    /* set device to be controlling tty */
    /* FIXME: we should not die here. If we go round again we may
     * be able to use the next device in the list.
     */
    /* If this is outgoing this should have become our controlling
     * tty when we opened it. If it is incoming it belongs to
     * another session so we have to steal it.
     */
    if (ioctl(modem_fd, TIOCSCTTY, 1) < 0) {
	mon_syslog(LOG_ERR, "failed to set modem to controlling tty: %m");
	die(1);
    }

    if (tcsetpgrp(modem_fd, getpgrp()) < 0) {
	mon_syslog(LOG_ERR, "open: failed to set tty process group: %m");
	die(1);
    }

    /* Get rid of any initial line noise */
    tcflush(modem_fd, TCIOFLUSH);

    if (tcgetattr(modem_fd, &inittermios) < 0) {
	mon_syslog(LOG_ERR, "failed to get initial modem terminal attributes: %m");
    }

    /* So we don't try to restore if we die before this */
    restore_term = 1;

    /* Clear the NDELAY flag now */
    if (fcntl(modem_fd,F_SETFL,fcntl(modem_fd,F_GETFL)&~(O_NDELAY)) < 0)
	mon_syslog(LOG_ERR, "failed to clear O_NDELAY flag: %m"), die(1);

    if (!req_pid) {
	int line_disc;

	/* hang up and then start again */
	set_up_tty(modem_fd, 1, inspeed);
	if (ioctl(modem_fd, TIOCGETD, &line_disc) < 0 || line_disc != N_TTY) {
	    line_disc = N_TTY;
	    ioctl(modem_fd, TIOCSETD, &line_disc);
	}
	set_up_tty(modem_fd, 1, 0);
	sleep(1);
	set_up_tty(modem_fd, 1, inspeed);

	/* Get rid of any initial line noise after the hangup */
	tcflush(modem_fd, TCIOFLUSH);
	fork_dialer("connector", connector, modem_fd);
    } else {
	/* someone else opened the line, we just set the mode */
	set_up_tty(modem_fd, 0, inspeed);
    }
    return 0;
}

/*
 * Reopen up a modem that closed on a sighup and set up the desired parameters.
 */
void reopen_modem()
{
    if (current_mode == MODE_DEV)
	return;

    if(debug&DEBUG_VERBOSE)
	mon_syslog(LOG_INFO,"Reopening modem device");

    close(modem_fd);
    sleep(1);
    if ((modem_fd = open(current_dev, O_RDWR | O_NDELAY)) < 0) {
	mon_syslog(LOG_ERR,"Can't reopen device '%s'",current_dev);
    } else {
	/* set device to be controlling tty */
	if (ioctl(modem_fd, TIOCSCTTY, 1) < 0) {
	    mon_syslog(LOG_ERR, "reopen: failed to set modem to controlling tty: %m");
	    die(1);
	}

	if (tcsetpgrp(modem_fd, getpgrp()) < 0) {
	    mon_syslog(LOG_ERR, "reopen: failed to set process group: %m");
	    die(1);
	}

	set_up_tty(modem_fd, 1, inspeed);
	/* Clear the NDELAY flag now */
	if (fcntl(modem_fd,F_SETFL,fcntl(modem_fd,F_GETFL)&~(O_NDELAY)) < 0)
	    mon_syslog(LOG_ERR, "failed to clear O_NDELAY flag: %m"), die(1);
    }
}

void finish_dial()
{
    if (current_mode == MODE_DEV)
	return;

    if (!req_pid) {
	if (tcsetpgrp(modem_fd, getpgrp()) < 0)
	    mon_syslog(LOG_ERR, "finish: failed to set pgrp: %m");
        set_up_tty(modem_fd, 0, inspeed);
    }
}

/*
 * Close the modem, making sure it hangs up properly!
 */
void close_modem()
{
    if (current_dev && debug&DEBUG_VERBOSE)
        mon_syslog(LOG_INFO,"Closing %s", current_dev);

    current_dev = 0;
    if (modem_fd < 0)
 	return;

    if (current_mode != MODE_DEV) {
	tcsetpgrp(modem_fd, getpgrp());

	/* Get rid of what ever might be waiting to go out still */
	tcflush(modem_fd, TCIOFLUSH);

	/*
	 * Restore the initial termio settings.
	 */

	if (restore_term) {
	    tcsetattr(modem_fd, TCSANOW, &inittermios);
	}

	/*
	 * Hang up the modem up by dropping the DTR.
	 * We do this because the initial termio settings
	 * may not have set HUPCL. This forces the issue.
	 * We need the sleep to give the modem a chance to hang
	 * up before we get another program asserting the DTR.
	 */
	setdtr(modem_fd, 0);
	sleep(1);
    }

    close(modem_fd);
    modem_fd = -1;

    if (use_req) {
	if (req_pid) {
	    if (debug&DEBUG_VERBOSE)
		mon_syslog(LOG_INFO, "Killing requesting shell pid %d",req_pid);
	    killpg(req_pid, SIGKILL);
	    kill(req_pid, SIGKILL);
	    req_pid = 0;
	}
    } else if (lock_dev) unlock();
}
