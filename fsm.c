/*
 * fsm.c - Control Finite State Machine for diald main loop.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

#define STATE(name,timeout,tstate) \
        { timeout, act_ ## name, trans_ ## name, STATE_ ## tstate, #name }

/* Protocol control structure */
struct {
	void (*start)();
	int (*set_addrs)();
	int (*dead)();
	void (*stop)();
	void (*reroute)();
	void (*kill)();
	void (*zombie)();
} pcontrol[3] = {
    {slip_start,slip_set_addrs,slip_dead,slip_stop,slip_reroute,slip_kill,slip_zombie},
    {ppp_start,ppp_set_addrs,ppp_dead,ppp_stop,ppp_reroute,ppp_kill,ppp_zombie},
    {dev_start,dev_set_addrs,dev_dead,dev_stop,dev_reroute,dev_kill,dev_zombie},
};

/*
 * Some cruft to try and catch the mysterios disappearing diald.
 */

void validate_mode()
{
	if (mode < 0 || mode > 2) {
		mon_syslog(LOG_ERR, "Mode value strayed to %d. Tell Eric.\n",mode);
		die(1);
	}
	if (pcontrol[0].start != slip_start
	|| pcontrol[0].set_addrs != slip_set_addrs
	|| pcontrol[0].dead != slip_dead
	|| pcontrol[0].stop != slip_stop
	|| pcontrol[0].reroute != slip_reroute
	|| pcontrol[0].kill != slip_kill
	|| pcontrol[0].zombie != slip_zombie
	|| pcontrol[1].start != ppp_start
	|| pcontrol[1].set_addrs != ppp_set_addrs
	|| pcontrol[1].dead != ppp_dead
	|| pcontrol[1].stop != ppp_stop
	|| pcontrol[1].reroute != ppp_reroute
	|| pcontrol[1].kill != ppp_kill
	|| pcontrol[1].zombie != ppp_zombie
	|| pcontrol[2].start != dev_start
	|| pcontrol[2].set_addrs != dev_set_addrs
	|| pcontrol[2].dead != dev_dead
	|| pcontrol[2].stop != dev_stop
	|| pcontrol[2].reroute != dev_reroute
	|| pcontrol[2].kill != dev_kill
	|| pcontrol[2].zombie != dev_zombie) {
		mon_syslog(LOG_ERR, "Corrupt FSM table. Tell Eric.\n");
		die(1);
	}
}

void control_start() { validate_mode(); (*pcontrol[mode].start)(); }
int control_set_addrs() { validate_mode(); return (*pcontrol[mode].set_addrs)(); }
int control_dead() { validate_mode(); return (*pcontrol[mode].dead)(); }
void control_stop() { validate_mode(); (*pcontrol[mode].stop)(); }
void control_reroute() { validate_mode(); (*pcontrol[mode].reroute)(); }
void control_kill() { validate_mode(); (*pcontrol[mode].kill)(); }
void control_zombie() { validate_mode(); (*pcontrol[mode].zombie)(); }

int state = STATE_DOWN;		/* DFA state */
int current_retry_count = 0;	/* current retry count */
int no_redial_delay = 0;

void GOTO(int);

/*
 * Actions and transition rules for the FSM.
 */

void act_DOWN(void)
{
    current_retry_count = retry_count;
}
void trans_DOWN(void)
{
    request_down = 0;
    use_req = 0;
    if (request_up /* && (req_pid || !blocked) */) {
	request_up = 0; GOTO(STATE_CONNECT);
    }
    else if ((forced || !queue_empty()) && !blocked) GOTO(STATE_CONNECT);
    else if (delayed_quit && queue_empty() && !forced) {
	mon_syslog(LOG_NOTICE,"Carrying out delayed termination request.");
	terminate = 1;
    }
}

void act_CONNECT(void)
{
    if (!req_pid) {
	mon_syslog(LOG_NOTICE, "Calling site %s\n", remote_ip);
	if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
	    fprintf(acctfp, "%s: Calling site %s.\n",
		cdate(time(0)), remote_ip);
	    fclose(acctfp);
	}
    }
    txtotal = rxtotal = 0;
    dial_status = 0;
    force_dynamic = 0;
    no_redial_delay = 0;
    if (open_modem() == 2)
	no_redial_delay = 2;
}
void trans_CONNECT(void)
{
    if (dial_pid == 0) {
	if (dial_status == 0) {
	    dial_failures = 0;
	    redial_rtimeout = redial_timeout;
	    finish_dial(); /* go into a CLOCAL connection */
	    GOTO(STATE_START_LINK);
	} else {
	    mon_syslog(LOG_NOTICE,"Connect script failed.");
	    dial_failures++;
	    if (redial_rtimeout == -1) redial_rtimeout = redial_timeout;
	    if (redial_backoff_start >= 0 && dial_failures > redial_backoff_start) {
		redial_rtimeout *= 2;
		if (redial_rtimeout > redial_backoff_limit)
		    redial_rtimeout = redial_backoff_limit;
	    }
	    if (dial_fail_limit != 0 && dial_failures > dial_fail_limit) {
		/* want to block connection until the user comes back...*/
		blocked = 1;
		dial_failures = 0;
		redial_rtimeout = redial_timeout;
		current_retry_count = 0;
		mon_syslog(LOG_NOTICE,"Too many dialing failures in a row. Blocking connection.");
	    }
	    GOTO(STATE_CLOSE);
	}
    } else if (state_timeout == 0) {
	mon_syslog(LOG_NOTICE,"Connect script timed out. Killing script.");
	GOTO(STATE_STOP_DIAL);
    } else if (req_pid && !use_req) {
        /* we never get here on a connect FIFO request anyway */
        mon_syslog(LOG_NOTICE,"Cancelling connect script in favour of request.");
	GOTO(STATE_STOP_DIAL);
    }
}

void act_STOP_DIAL(void)
{
    if (dial_pid) {
#if 0
        if (debug&DEBUG_VERBOSE)
#endif
            mon_syslog(LOG_DEBUG,"Sending SIGINT to (dis)connect process %d",
		dial_pid);
	if (kill(dial_pid,SIGINT) == -1 && errno == ESRCH) {
	    dial_pid = 0;
	    dial_status = -1;
	}
    }
}
void trans_STOP_DIAL(void)
{
    if (dial_pid == 0) GOTO(STATE_CLOSE);
}


void act_KILL_DIAL(void)
{
    if (dial_pid) {
#if 0
        if (debug&DEBUG_VERBOSE)
#endif
            mon_syslog(LOG_DEBUG,"Sending SIGKILL to (dis)connect process %d",
		dial_pid);
	if (kill(dial_pid,SIGKILL) == -1 && errno == ESRCH) {
	    dial_pid = 0;
	    dial_status = -1;
	}
    }
}
void trans_KILL_DIAL(void)
{
    if (dial_pid == 0) GOTO(STATE_CLOSE);
}

void act_START_LINK(void)
{
    time(&call_start_time);
    mon_syslog(LOG_NOTICE,
	use_req ? "Connect request from %s\n" : "Connected to site %s\n",
	remote_ip);

    if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
        fprintf(acctfp,"%s: %s %s.\n",
	    cdate(call_start_time),
	    use_req ? "Connect request from" : "Connected to site",
	    remote_ip);
	fclose(acctfp);
    }

    validate_mode();
    control_start();
}
void trans_START_LINK(void)
{
    if (control_dead()) {
	/* link protocol died before we really got going */
	/* We must reroute, just in case we got so far as to change routing */
	control_reroute();
	GOTO(STATE_DISCONNECT);
    } else if (control_set_addrs()) {
	/* Ok, we're up and running. */
	GOTO(STATE_UP);
    }

    /* If we fall through then we haven't finished the setup yet. */
    if (state_timeout == 0) {
	/* If we time out, then we're going to stop. We need to reroute
         *  just in case the routes got changed before we timed out.
	 */
	mon_syslog(LOG_NOTICE,"pppd startup timed out. Check your pppd options. Killing pppd.");
	control_reroute();
    }
}

void act_STOP_LINK(void)
{
    control_stop();
}
void trans_STOP_LINK(void)
{
    if (control_dead()) GOTO(STATE_DISCONNECT);
}

void act_KILL_LINK(void)
{
    control_kill();
}
void trans_KILL_LINK(void)
{
    if (control_dead()) GOTO(STATE_DISCONNECT);
}

void act_UP(void)
{
    idle_filter_init();
    flush_timeout_queue();
    interface_up();
    ppp_half_dead = 0;
    if (buffer_packets)
   	 forward_buffer();
    if (use_req) {
	mon_syslog(LOG_NOTICE, "Connected to site %s\n", remote_ip);

	if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
	    fprintf(acctfp, "%s: Connected to site %s.\n",
		cdate(time(0)), remote_ip);
	    fclose(acctfp);
	}
    }
    /* Once we get here, we might as well kill off any outstanding
     * FIFO requests */
    if (!use_req && req_pid) {
        killpg(req_pid, SIGKILL);
        kill(req_pid, SIGKILL);
	req_pid=0;
        mon_syslog(LOG_NOTICE,"Cancelling link up request in favour of existing link.");
    }
}

void trans_UP(void)
{
    request_up = 0;
    if (/* blocked || */ request_down) {
	request_down = 0;
	goto take_link_down;
    }
    if (state_timeout == 0) {
	if (!forced && queue_empty()) {  /* the link may be forced up. */
	    mon_syslog(LOG_NOTICE,"%s %d %s",
	    	"Failed to received first packet within",
	    	first_packet_timeout,
	    	"seconds. Closing Link down.");
	    goto take_link_down;
	}
	state_timeout = -1;
    }
    if (!forced && queue_empty() && state_timeout == -1) {
	mon_syslog(LOG_NOTICE,"Closing down idle link.");
take_link_down:
	current_retry_count = 0;
	flush_timeout_queue();
	/* WARNING: You MUST do this before calling idle_filter_proxy(),
           or the snoop socket will not bind properly! */
	control_reroute();
	idle_filter_proxy();
	GOTO(STATE_STOP_LINK);
	return;
    }
    if (ppp_half_dead) {
	mon_syslog(LOG_ERR,"PPP network layer died, but link did not. Probable configuration error.");
	GOTO(STATE_HALF_DEAD);
	return;
    }
    if (control_dead() || modem_hup) {
	mon_syslog(LOG_NOTICE,"Link died on remote end.");
    	if (two_way) flush_timeout_queue();
	no_redial_delay = 1;
	current_retry_count = died_retry_count;
	/* WARNING: You MUST do this before calling idle_filter_proxy(),
           or the snoop socket will not bind properly! */
   	control_reroute();
	idle_filter_proxy();
	GOTO(STATE_DISCONNECT);
	return;
    }
}

void act_HALF_DEAD(void)
{
    /* We're half dead, make sure we monitor the correct device... */
    control_reroute();
    idle_filter_proxy();
}

void trans_HALF_DEAD(void)
{
    if ((control_dead)()) {
	/* link protocol died and did not come back */
   	control_reroute();
	GOTO(STATE_DISCONNECT);
    } else if (control_set_addrs()) {
	/* Ok, we're up and running. */
	GOTO(STATE_UP);
    }
    /* If we fall through then we haven't finished the setup yet. */
    if (state_timeout == 0) {
	/* If we time out, then we're going to stop. We need to reroute
         *  just in case the routes got changed before we timed out.
	 */
	mon_syslog(LOG_NOTICE,"pppd restart timed out. Killing pppd.");
	control_reroute();
    }
}

void act_DISCONNECT(void)
{
    dial_status = 0;
    if (disconnector) {
	reopen_modem();
        fork_dialer("disconnector", disconnector, modem_fd);
    }
}
void trans_DISCONNECT(void)
{
    if (dial_pid == 0) {
	if (dial_status != 0)
	    mon_syslog(LOG_WARNING,"Disconnect script failed");
	GOTO(STATE_CLOSE);
    } else if (state_timeout == 0) {
	mon_syslog(LOG_NOTICE,"Disconnect script timed out. Killing script.");
    }
}

void act_CLOSE(void)
{
    if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
	int duration = -call_start_time;
	char *tm;
	tm = cdate(time(&call_start_time));
	duration += call_start_time;
	mon_syslog(LOG_NOTICE,
	    "Disconnected. Call duration %d seconds.\n",
	    duration);
        fprintf(acctfp,"%s: Disconnected. Call duration %d seconds.\n",
	    tm, duration);
        fprintf(acctfp,"      IP transmitted %d bytes and received %d bytes.\n",
	    txtotal, rxtotal);
	fclose(acctfp);
	mon_syslog(LOG_NOTICE,
	    "IP transmitted %d bytes and received %d bytes.\n",
	    txtotal, rxtotal);
    }
    close_modem();
    interface_down();
    if (no_redial_delay == 0) {
	if (redial_rtimeout == -1)
	    redial_rtimeout = redial_timeout;
        mon_syslog(LOG_NOTICE,"Delaying %d seconds before clear to dial.",
	    redial_rtimeout);
	state_timeout = redial_rtimeout;
    } else if (no_redial_delay == 2) {
        mon_syslog(LOG_NOTICE,"Delaying %d seconds before clear to dial.",
	    nodev_retry_timeout);
	state_timeout = nodev_retry_timeout;
    }
}
void trans_CLOSE(void)
{
    if (request_up) GOTO(STATE_DOWN); /* STATE_DOWN handles the link-up-request */
    if (no_redial_delay == 1) {
	no_redial_delay = 0;
	GOTO(STATE_RETRY);
    }
}

void act_RETRY(void)
{
    current_retry_count--;
}
void trans_RETRY(void)
{
    if (request_up) GOTO(STATE_DOWN);
    if (current_retry_count >= 0) GOTO(STATE_CONNECT);
    else GOTO(STATE_DOWN);
}


void act_ERROR(void)
{
    mon_syslog(LOG_ERR,"Subprocess sent SIGKILL still alive after %d seconds. Reaping zombie.",kill_timeout);
    control_zombie();	/* deal with the zombie */
}
void trans_ERROR(void) {
    if (control_dead()) GOTO(STATE_DISCONNECT);
}

void act_ZOMBIE(void)
{
    mon_syslog(LOG_ERR,"Subprocess sent SIGKILL still alive after %d seconds. Reaping zombie.",kill_timeout);

    sig_chld(SIGKILL);	/* try to reap the zombie */
    if (dial_pid) {
	/* If the zombie didn't get reaped, forget it exists */
	dial_pid = 0;
    	dial_status = -1;
    }
}
void trans_ZOMBIE(void) {
    if (dial_pid == 0) GOTO(STATE_CLOSE);
}

/*
 * State definitions and actions for the control DFA.
 * The routine change_state handles transitions.
 */

struct {
    int *timeout;
    void (*action)(void);
    void (*trans)(void);
    int timeout_state;
    char *name;
} trans[] = {
    STATE(DOWN ,0, DOWN),
    STATE(CONNECT, &connect_timeout, STOP_DIAL),
    STATE(STOP_DIAL, &stop_dial_timeout, KILL_DIAL),
    STATE(KILL_DIAL, &kill_timeout, ZOMBIE),
    STATE(START_LINK, &start_pppd_timeout, STOP_LINK),
    STATE(STOP_LINK, &stop_pppd_timeout, KILL_LINK),
    STATE(KILL_LINK, &kill_timeout, ERROR),
    STATE(UP, &first_packet_timeout, UP),
    STATE(DISCONNECT, &disconnect_timeout, STOP_DIAL),
    STATE(CLOSE, 0, RETRY),
    STATE(RETRY, 0, RETRY),
    STATE(ERROR, 0, ERROR),
    STATE(ZOMBIE, 0, ZOMBIE),
    STATE(HALF_DEAD, &start_pppd_timeout, STOP_LINK)
};

void output_state()
{
    if (monitors) {
	if (link_name) {
	    mon_write(MONITOR_VER2|MONITOR_STATE, "TITLE\n", 6);
	    mon_write(MONITOR_VER2|MONITOR_STATE, link_name, strlen(link_name));
	    mon_write(MONITOR_VER2|MONITOR_STATE, "\n", 1);
	}
	mon_write(MONITOR_STATE,"STATE\n",6);
	mon_write(MONITOR_STATE,trans[state].name,strlen(trans[state].name));
	mon_write(MONITOR_STATE,"\n",1);
    }
}

void GOTO(int new_state)
{
    state_timeout = (trans[new_state].timeout)
                     ? *trans[new_state].timeout : -1;
    if (debug&DEBUG_STATE_CONTROL)
    	mon_syslog(LOG_DEBUG,"new state %s action %p timeout %d",
	    trans[new_state].name,trans[new_state].action,state_timeout);
    state = new_state;
    output_state();
    (*trans[new_state].action)();
}

/*
 * Change the state according to the current state and events.
 */

void change_state()
{
    /* Change state from the current state if conditions warrent */
    (*trans[state].trans)();
    /* Check if the current state timed out */
    if (state_timeout == 0) GOTO(trans[state].timeout_state);
}
