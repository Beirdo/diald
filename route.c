/*
 * route.c - diald routing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

/* set up a point to point route for a device */
void
set_ptp(char *itype, int iface, char *lip, char *rip, int metric)
{
    char win[32];
    char buf[1024];

    if (window == 0)
	win[0] = 0;
    else
    	sprintf(win,"window %d",window);

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG, "Setting pointopoint route for %s%d",itype,iface);

    /* If metric changes changed routes instead of adding duplicates
     * (except for the metric) this would not be necessary.
     * We do the delete first because if the following replace does
     * a replace rather than an add a following delete would delete
     * the _only_ route and not one of a pair. (Yeah, I lack confidence)
     * This may open a routeless window sometimes...
     * N.B. This is not needed for Linux 2.0 which did not auto add
     * routes when interfaces were configured. Deleting non-existent
     * routes is not a problem however.
     */
    if (metric || !path_ip) {
	if (path_ip) {
	    sprintf(buf,"%s route del %s dev %s%d scope link src %s metric 0",
		path_ip, rip, itype, iface, lip); 
	} else {
	    sprintf(buf,"%s del %s metric 0 dev %s%d",
		path_route, rip, itype, iface); 
	}

	system(buf);
    }

    if (path_ip) {
	sprintf(buf,"%s route replace %s dev %s%d scope link src %s metric %d %s",
	    path_ip, rip, itype, iface, lip, metric, win); 
    } else {
	sprintf(buf,"%s add %s metric %d %s dev %s%d",
	    path_route, rip, metric, win, itype, iface); 
    }

    system(buf);
}

/* delete a point to point route for a device */
void del_ptp(char *itype, int iface, char *lip, char *rip, int metric)
{
    char buf[1024];

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG, "Deleting pointopoint route for %s%d",itype,iface);
    if (path_ip) {
	sprintf(buf,"%s route del %s dev %s%d scope link src %s metric %d",
	    path_ip, rip, itype, iface, lip, metric); 
    } else {
	sprintf(buf,"%s del %s dev %s%d",
	    path_route, rip, itype, iface); 
    }

    system(buf);
}

/*
 * Add in a direct and default route to the slip link.
 * The default route is only added if the "default" option was
 * requested by the user.
 */

void add_routes(char *itype, int iface, char *lip, char *rip, int metric)
{
    int res;
    char win[32];
    char buf[1024];

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG,"Establishing routes for %s%d",itype,iface);

    if (window == 0)
	win[0] = 0;
    else
    	sprintf(win,"window %d",window);

    if (monitors) {
	sprintf(buf, "INTERFACE\n%s%d\n%s\n%s\n", itype, iface, lip, rip);
	mon_write(MONITOR_INTERFACE, buf, strlen(buf));
    }

    /* Add in a default route for the link */
    /* FIXME: should this refuse to add if a default route exists? */
    /* FIXME: Should not report an error if the error was just that the
     *        route we tried to add already exists.
     *        (A new error reported by more recent kernels.)
     */
    if (default_route) {
	if (path_ip) {
	    sprintf(buf, "%s route add default dev %s%d scope link src %s metric %d %s",
		path_ip, itype, iface, lip, metric, win); 
	} else {
	    sprintf(buf,"%s add default metric %d %s netmask 0.0.0.0 dev %s%d",
		path_route, metric, win, itype, iface);
	}
        res = system(buf);
    	report_system_result(res,buf);
    }

    /* call addroute script */
    if (addroute) {
        sprintf(buf,"%s %s%d %s %s %s %d %d",
	    addroute,itype,iface,(netmask)?netmask:"default",
	    lip,rip,metric,window);
	res = system(buf);
    	report_system_result(res,buf);
    }

    if (proxyarp) set_proxyarp(inet_addr(rip));
}

/*
 * Call the delroute script.
 */
void del_routes(char *itype, int iface, char *lip, char *rip, int metric)
{
    int res;
    char buf[1024];

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_DEBUG,"Removing routes for %s%d",itype,iface);

    if (proxyarp) clear_proxyarp(inet_addr(rip));

    /* FIXME: should delete routes be added here?
     * We may be bringing a connection "down" that always has an up interface.
     * Question: should we just delete all routes through the interface?
     * That might be the best thing. On the other hand it confuses the
     * whole question of the need for a delroute script.
     */
    if (default_route) {
	if (path_ip) {
	    sprintf(buf, "%s route del default dev %s%d scope link src %s metric %d",
		path_ip, itype, iface, lip, metric); 
	} else {
	    sprintf(buf, "%s del default metric %d netmask 0.0.0.0 dev %s%d",
		path_route,metric,itype,iface);
	}
        system(buf);
    }

    if (delroute) {
	/* call delroute <iface> <netmask> <local> <remote> */
        sprintf(buf,"%s %s%d %s %s %s %d",
	    delroute,itype,iface,(netmask)?netmask:"default",lip,rip,metric);
        res = system(buf);
        report_system_result(res,buf);
    }

    del_ptp(itype, iface, lip, rip, metric);
}
