/*
 * route.c - diald routing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <diald.h>

static void
add_routes(char *desc, char *iface, char *lip, char *rip, int metric)
{
    char win[32];
    char buf[1024];

    /* FIXME: Should not report an error if the error was just that the
     *        route we tried to add already exists.
     *        (A new error reported by more recent kernels.)
     */

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG, "%s: Establishing routes for %s", desc, iface);

    if (window == 0)
	win[0] = 0;
    else
    	sprintf(win,"window %d",window);

#if 1
    /* FIXME: this is only needed for 2.0 kernels. 2.2 and beyond
     * create routes automatically when the interface is configured.
     * On 2.2 and later kernels this just creates some annoying
     * duplicate routes. But if the metric is non-zero we can,
     * and should, get rid of the original zero metric route.
     */
    if (rip) {
	if (path_ip && *path_ip) {
	    sprintf(buf,"%s route replace %s dev %s scope link%s%s metric %d %s",
		path_ip, rip, iface,
		lip ? " src " : "",
		lip ? lip : "",
		metric, win); 
	} else {
	    sprintf(buf,"%s add %s metric %d %s dev %s",
		path_route, rip, metric, win, iface);
	}
	run_shell(SHELL_WAIT, desc, buf, -1);

	if (metric) {
	    if (path_ip && *path_ip) {
		sprintf(buf,"%s route del %s dev %s scope link%s%s metric 0 %s",
		    path_ip, rip, iface,
		    lip ? " src " : "",
		    lip ? lip : "",
		    win); 
	    } else {
		sprintf(buf,"%s del %s metric 0 %s dev %s",
		    path_route, rip, win, iface); 
	    }
	    run_shell(SHELL_WAIT, desc, buf, -1);
	}
    }
#endif

    /* Add in a default route for the link if required. */
    if (default_route) {
	if (path_ip && *path_ip) {
	    sprintf(buf, "%s route replace default dev %s scope link%s%s metric %d %s",
		path_ip, iface,
		lip ? " src " : "",
		lip ? lip : "",
		metric, win); 
	} else {
	    sprintf(buf,"%s add default metric %d %s netmask 0.0.0.0 dev %s",
		path_route, metric, win, iface);
	}
        run_shell(SHELL_WAIT, desc, buf, -1);
    }

    /* call addroute script */
    if (addroute) {
        sprintf(buf,"%s %s %s \"%s\" \"%s\" %d %d",
	    addroute, iface, (netmask)?netmask:"default",
	    lip, rip, metric, window);
	run_shell(SHELL_WAIT, desc, buf, -1);
    }

    if (proxyarp && rip) set_proxyarp(inet_addr(rip));
}


static void
del_routes(char *desc, char *iface, char *lip, char *rip, int metric)
{
    char buf[1024];

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG, "%s: Removing routes for %s", desc, iface);

    if (proxyarp && rip) clear_proxyarp(inet_addr(rip));

    if (delroute) {
	/* call delroute <iface> <netmask> <local> <remote> */
        sprintf(buf, "%s %s %s \"%s\" \"%s\" %d",
	    delroute, iface,
	    (netmask) ? netmask : "default",
	    lip, rip, metric);
        run_shell(SHELL_WAIT, desc, buf, -1);
    }

    if (default_route) {
	if (path_ip && *path_ip) {
	    sprintf(buf, "%s route del default dev %s scope link%s%s metric %d",
		path_ip, iface,
		lip ? " src " : "",
		lip ? lip : "",
		metric); 
	} else {
	    sprintf(buf, "%s del default metric %d netmask 0.0.0.0 dev %s",
		path_route, metric, iface);
	}
        run_shell(SHELL_WAIT, desc, buf, -1);
    }
}


void
iface_start(char *mode, char *iftype, int ifunit,
    char *lip, char *rip, char *bip, int metric)
{
    char *iface, desc[32], buf[1024];

    strcpy(desc, "start ");
    snprintf(desc+6, sizeof(desc)-6-1, "%s%d", iftype, ifunit);
    iface = desc+6;

    if (monitors) {
	sprintf(buf, "INTERFACE\n%s\n%s\n%s\n", desc+6, lip, rip);
	mon_write(MONITOR_INTERFACE, buf, strlen(buf));
    }

    /* mark the interface as up */
    if (ifsetup) {
	sprintf(buf, "%s start %s %s",
	    ifsetup, mode, iface);
	run_shell(SHELL_WAIT, desc, buf, -1);
	return;
    }

    /* With no ifsetup script we have to do it all ourselves. */
    if (lip) {
	sprintf(buf,"%s %s %s%s%s%s%s netmask %s metric %d mtu %d up",
	    path_ifconfig, iface, lip,
	    rip ? " pointopoint " : "",
	    rip ? rip : "",
	    bip ? " broadcast " : "",
	    bip ? bip : "",
	    netmask ? netmask : "255.255.255.255",
	    metric, mtu);
	run_shell(SHELL_WAIT, desc, buf, -1);
    }

    add_routes(desc, iface, lip, rip, metric);
}


void
iface_stop(char *mode, char *iftype, int ifunit,
    char *lip, char *rip, char *bip, int metric)
{
    char *iface, desc[32], buf[128];

    strcpy(desc, "stop ");
    snprintf(desc+5, sizeof(desc)-5-1, "%s%d", iftype, ifunit);
    iface = desc+5;

    if (ifsetup) {
	sprintf(buf, "%s stop %s %s",
	    ifsetup, mode, iface);
	run_shell(SHELL_WAIT, desc, buf, -1);
	return;
    }

    /* With no ifsetup script we have to do it all ourselves. */

    /* Deleting the addresses has the effect of deleting routes as well
     * on 2.1 and later kernels but we still call del_routes first
     * because the user delroutes scripts may have been abused to do
     * something "special".
     * 2.0.x kernels have a different behaviour when the address is
     * set to 0.0.0.0 so we use 127.0.0.1 as a "safe" local address.
     */
    del_routes(desc, iface, lip, rip, metric);

    sprintf(buf, "%s %s %s",
	path_ifconfig, iface,
#ifdef HAVE_AF_PACKET
	af_packet ? "0.0.0.0" : "127.0.0.1"
#else
	"127.0.0.1"
#endif
    );
    run_shell(SHELL_WAIT, desc, buf, -1);
}


void
iface_down(char *mode, char *iftype, int ifunit,
    char *lip, char *rip, char *bip, int metric)
{
    char *iface, desc[32], buf[128];

    strcpy(desc, "down ");
    snprintf(desc+5, sizeof(desc)-5-1, "%s%d", iftype, ifunit);
    iface = desc+5;

    sprintf(buf, "%s %s down",
	path_ifconfig, iface
    );
    run_shell(SHELL_WAIT, desc, buf, -1);
}
