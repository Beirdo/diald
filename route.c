/*
 * route.c - diald routing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

static void
add_routes(char *iftype, int ifunit, char *lip, char *rip)
{
    char win[32];
    char buf[1024];

    /* FIXME: Should not report an error if the error was just that the
     *        route we tried to add already exists.
     *        (A new error reported by more recent kernels.)
     */

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG,"Establishing routes for %s%d", iftype, ifunit);

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
	    sprintf(buf,"%s route add %s dev %s%d scope link%s%s metric %d %s",
		path_ip, rip, iftype, ifunit,
		lip ? " src " : "",
		lip ? lip : "",
		metric, win); 
	} else {
	    sprintf(buf,"%s add %s metric %d %s dev %s%d",
		path_route, rip, metric, win, iftype, ifunit); 
	}
	run_shell(SHELL_WAIT, "add route", buf, -1);

	if (metric) {
	    if (path_ip && *path_ip) {
		sprintf(buf,"%s route del %s dev %s%d scope link%s%s metric 0 %s",
		    path_ip, rip, iftype, ifunit,
		    lip ? " src " : "",
		    lip ? lip : "",
		    win); 
	    } else {
		sprintf(buf,"%s del %s metric 0 %s dev %s%d",
		    path_route, rip, win, iftype, ifunit); 
	    }
	    run_shell(SHELL_WAIT, "del route", buf, -1);
	}
#endif
    }

    /* Add in a default route for the link if required. */
    if (default_route) {
	if (path_ip && *path_ip) {
	    sprintf(buf, "%s route add default dev %s%d scope link%s%s metric %d %s",
		path_ip, iftype, ifunit,
		lip ? " src " : "",
		lip ? lip : "",
		metric, win); 
	} else {
	    sprintf(buf,"%s add default metric %d %s netmask 0.0.0.0 dev %s%d",
		path_route, metric, win, iftype, ifunit);
	}
        run_shell(SHELL_WAIT, "add default route", buf, -1);
    }

    /* call addroute script */
    if (addroute) {
        sprintf(buf,"%s %s%d %s \"%s\" \"%s\" %d %d",
	    addroute, iftype, ifunit, (netmask)?netmask:"default",
	    lip, rip, metric, window);
	run_shell(SHELL_WAIT, "addroute", buf, -1);
    }

    if (proxyarp && rip) set_proxyarp(inet_addr(rip));
}


static void
del_routes(char *iftype, int ifunit, char *lip, char *rip)
{
    char buf[1024];

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG, "Removing routes for %s%d", iftype, ifunit);

    if (proxyarp && rip) clear_proxyarp(inet_addr(rip));

    if (delroute) {
	/* call delroute <iface> <netmask> <local> <remote> */
        sprintf(buf, "%s %s%d %s \"%s\" \"%s\" %d",
	    delroute, iftype, ifunit,
	    (netmask) ? netmask : "default",
	    lip, rip, metric);
        run_shell(SHELL_WAIT, "delroute", buf, -1);
    }

    if (default_route) {
	if (path_ip && *path_ip) {
	    sprintf(buf, "%s route del default dev %s%d scope link%s%s metric %d",
		path_ip, iftype, ifunit,
		lip ? " src " : "",
		lip ? lip : "",
		metric); 
	} else {
	    sprintf(buf, "%s del default metric %d netmask 0.0.0.0 dev %s%d",
		path_route, metric, iftype, ifunit);
	}
        run_shell(SHELL_WAIT, "del default route", buf, -1);
    }
}


void
iface_start(char *mode, char *iftype, int ifunit, char *lip, char *rip)
{
    char buf[1024];

    /* mark the interface as up */
    if (ifsetup) {
	sprintf(buf, "%s start %s %s%d",
	    ifsetup, mode, iftype, ifunit);
	run_shell(SHELL_WAIT, "iface start", buf, -1);
	return;
    }

    /* With no ifsetup script we have to do it all ourselves. */
    if (lip) {
	sprintf(buf,"%s %s%d %s%s%s%s%s netmask %s metric %d mtu %d up",
	    path_ifconfig, iftype, ifunit, lip,
	    rip ? " pointopoint " : "",
	    rip ? rip : "",
	    rip ? " broadcast " : "",
	    rip ? rip : "",
	    netmask ? netmask : "255.255.255.255",
	    metric, mtu);
	run_shell(SHELL_WAIT, "iface start", buf, -1);
    }

    add_routes(iftype, ifunit, lip, rip);

    if (monitors) {
	sprintf(buf, "INTERFACE\n%s%d\n%s\n%s\n", iftype, ifunit, lip, rip);
	mon_write(MONITOR_INTERFACE, buf, strlen(buf));
    }
}


void
iface_stop(char *mode, char *iftype, int ifunit, char *lip, char *rip)
{
    char buf[128];

    if (ifsetup) {
	sprintf(buf, "%s stop %s %s%d",
	    ifsetup, mode, iftype, ifunit);
	run_shell(SHELL_WAIT, "iface stop", buf, -1);
	return;
    }

    /* With no ifsetup script we have to do it all ourselves. */

    /* We do not simply down the interface because it may be required
     * to up (ISDN, for instance, will not answer an incoming call if
     * there is not up interface). Instead we delete the address
     * which has much the same effect of stopping traffic through it.
     * Deleting the addresses has the effect of deleting routes as well
     * but we still call del_routes first because the user delroutes
     * scripts may have been abused to do something "special".
     */
    del_routes(iftype, ifunit, lip, rip);

    sprintf(buf, "%s %s%d 0.0.0.0",
	path_ifconfig, iftype, ifunit);
    run_shell(SHELL_WAIT, "iface stop", buf, -1);
}
