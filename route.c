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
	res = system(buf);
	report_system_result(res, buf);

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
	    res = system(buf);
	    report_system_result(res, buf);
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
        res = system(buf);
    	report_system_result(res, buf);
    }

    /* call addroute script */
    if (addroute) {
        sprintf(buf,"%s %s%d %s \"%s\" \"%s\" %d %d",
	    addroute, iftype, ifunit, (netmask)?netmask:"default",
	    lip, rip, metric, window);
	res = system(buf);
    	report_system_result(res, buf);
    }

    if (proxyarp && rip) set_proxyarp(inet_addr(rip));
}


static void
del_routes(char *iftype, int ifunit, char *lip, char *rip)
{
    int res;
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
        res = system(buf);
        report_system_result(res, buf);
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
        system(buf);
    }
}


void
iface_start(char *iftype, int ifunit, char *lip, char *rip)
{
    int res;
    char buf[128];

    /* mark the interface as up */
    if (lip) {
	sprintf(buf,"%s %s%d %s%s%s netmask %s metric %d mtu %d up",
	    path_ifconfig, iftype, ifunit, lip,
	    rip ? " pointopoint " : "",
	    rip ? rip : "",
	    netmask ? netmask : "255.255.255.255",
	    metric, mtu);
	res = system(buf);
	report_system_result(res,buf);
    }

    add_routes(iftype, ifunit, lip, rip);

    if (monitors) {
	sprintf(buf, "INTERFACE\n%s%d\n%s\n%s\n", iftype, ifunit, lip, rip);
	mon_write(MONITOR_INTERFACE, buf, strlen(buf));
    }
}


void
iface_stop(char *iftype, int ifunit, char *lip, char *rip)
{
    char buf[128];
    int res;

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
    res = system(buf);
    report_system_result(res,buf);
}
