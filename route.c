/*
 * route.c - diald routing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

static void
add_routes(char *iftype, int ifunit, char *lip, char *rip)
{
    int res;
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

    if (path_ip) {
	sprintf(buf,"%s route add %s dev %s%d scope link src %s metric %d %s",
	    path_ip, rip, iftype, ifunit, lip, metric, win); 
    } else {
	sprintf(buf,"%s add %s metric %d %s dev %s%d",
	    path_route, rip, metric, win, iftype, ifunit); 
    }
    res = system(buf);
    report_system_result(res, buf);

    /* Add in a default route for the link if required. */
    if (default_route) {
	if (path_ip) {
	    sprintf(buf, "%s route add default dev %s%d scope link src %s metric %d %s",
		path_ip, iftype, ifunit, lip, metric, win); 
	} else {
	    sprintf(buf,"%s add default metric %d %s netmask 0.0.0.0 dev %s%d",
		path_route, metric, win, iftype, ifunit);
	}
        res = system(buf);
    	report_system_result(res, buf);
    }

    /* call addroute script */
    if (addroute) {
        sprintf(buf,"%s %s%d %s %s %s %d %d",
	    addroute, iftype, ifunit, (netmask)?netmask:"default",
	    lip, rip, metric, window);
	res = system(buf);
    	report_system_result(res, buf);
    }

    if (proxyarp) set_proxyarp(inet_addr(rip));
}


void
iface_config(char *iftype, int ifunit, char *lip, char *rip)
{
    char buf[128];
    int res;

    /* mark the interface as up */
    sprintf(buf,"%s %s%d %s pointopoint %s netmask %s metric %d mtu %d up",
	path_ifconfig, iftype, ifunit, lip, rip,
	netmask ? netmask : "255.255.255.255",
	metric, mtu);
    res = system(buf);
    report_system_result(res,buf);

    add_routes(iftype, ifunit, lip, rip);

    if (monitors) {
	sprintf(buf, "INTERFACE\n%s%d\n%s\n%s\n", iftype, ifunit, lip, rip);
	mon_write(MONITOR_INTERFACE, buf, strlen(buf));
    }
}


void
iface_down(char *iftype, int ifunit)
{
    char buf[128];
    int res;

    /* Downing an interface drops all routes through it. */
    sprintf(buf, "%s %s%d down",
	path_ifconfig, iftype, ifunit);
    res = system(buf);
    report_system_result(res,buf);
}
