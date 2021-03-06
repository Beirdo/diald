/*
 * options.c - Option parsing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <diald.h>


#define MAXLINELEN 1024
#define MAXARGS 512


/* Configuration variables */
char **devices = 0;
int device_count = 0;
int inspeed = DEFAULT_SPEED;
int window = 0;
int mtu = DEFAULT_MTU;
int mru = DEFAULT_MTU;
int metric = DEFAULT_METRIC;
char *link_name = 0;
char *link_desc = 0;
char *authsimple = 0;
#if HAVE_LIBPAM
char *authpam = 0;
#endif
char *initializer = 0;
char *deinitializer = 0;
char *connector = 0;
char *disconnector = 0;
char *proxyif = 0;
char *orig_local_ip = 0;
char *orig_remote_ip = 0;
char *orig_broadcast_ip = 0;
char *orig_netmask = 0;
char *local_ip = 0;
unsigned long local_addr = 0;
char *remote_ip = 0;
char *netmask = 0;
char *ifsetup = 0;
char *addroute = 0;
char *delroute = 0;
char *ip_up = 0;
char *ip_down = 0;
char *ip_goingdown = 0;
char *acctlog = 0;
char *pidlog = 0;
char *fifoname = 0;
int tcpport = 0;
int demand = 1;
int blocked = 0;
int blocked_route = 1;
char *lock_prefix = 0;
int pidstring = PIDSTRING;
char *run_prefix = 0;
char *path_ip = 0;
char *path_route = 0;
char *path_ifconfig = 0;
char *path_bootpc = 0;
char *path_pppd = 0;
int buffer_packets = BUFFER_PACKETS;
int buffer_size = BUFFER_SIZE;
int buffer_fifo_dispose = BUFFER_FIFO_DISPOSE;
int buffer_timeout = BUFFER_TIMEOUT;
FILE *acctfp = 0;
int mode = MODE_SLIP;
int scheduler = DEFAULT_SCHEDULER;
int priority = DEFAULT_PRIORITY;
int debug = 0;
int modem = 0;
int crtscts = 0;
int daemon_flag = 1;
int slip_encap = 0;
int lock_dev = 0;
int default_route = 0;
int dynamic_addrs = 0;
int strict_forwarding = 0;
int dynamic_mode = DMODE_REMOTE_LOCAL;
int rotate_devices = 0;
int two_way = 0;
int give_way = 0;
int proxyarp = 0;
#ifdef __linux__
int demasq = 0;
#endif
int route_wait = 0;

int connect_timeout = 60;
int disconnect_timeout = 60;
int redial_timeout = DEFAULT_DIAL_DELAY;
int nodev_retry_timeout = 1;
int stop_dial_timeout = 60;
int kill_timeout = 60;
int start_pppd_timeout = 60;
int stop_pppd_timeout = 60;
int first_packet_timeout = DEFAULT_FIRST_PACKET_TIMEOUT;
int retry_count = 0;
int died_retry_count = 1;
int redial_backoff_start = -1;
int redial_backoff_limit = 600;
int dial_fail_limit = 0;

#ifdef SIOCSKEEPALIVE
int keepalive = 0;
#endif
#ifdef SIOCSOUTFILL
int outfill = 0;
#endif

struct {
    char *str;
    char *uargs;
    char args;
    void *var;
    void (*parser)();
} commands[] = {
    {"-f","<file>",1,0,read_config_file},
    {"-file","<file>",1,0,read_config_file},
    {"include","<file>",1,0,read_config_file},
/* Mode options */
    {"-m","[ppp|slip|cslip|slip6|cslip6|aslip|dev]",1,0,set_mode},
    {"mode","[ppp|slip|cslip|slip6|cslip6|aslip|dev]",1,0,set_mode},
/* Debugging options */
    {"debug","<debugmask>",1,&debug,set_int},
    {"-daemon","",0,&daemon_flag,clear_flag},
/* general options */
    {"accounting-log","<f>",1,&acctlog,set_str},
    {"pidfile","<f>",1,&pidlog,set_str},
    {"fifo","<f>",1,&fifoname,set_str},
    {"tcpport","<n>",1,&tcpport,set_int},
    {"demand","",0,&demand,set_flag},
    {"-demand","",0,&demand,clear_flag},
    {"nodemand","",0,&demand,clear_flag},
    {"blocked","",0,&blocked,set_blocked},
    {"-blocked","",0,&blocked,clear_blocked},
    {"block","",0,&blocked,set_blocked},
    {"unblock","",0,&blocked,clear_blocked},
    {"blocked-route","",0,&blocked_route,set_blocked_route},
    {"-blocked-route","",0,&blocked_route,clear_blocked_route},
    {"linkname","<name>",1,&link_name,set_str},
    {"linkdesc","<description>",1,&link_desc,set_str},
    {"authsimple","<file>",1,&authsimple,set_str},
#if HAVE_LIBPAM
    {"authpam","<file>",1,&authpam,set_str},
#endif
    {"initializer","<script>",1,&initializer,set_str},
    {"deinitializer","<script>",1,&deinitializer,set_str},
    {"proxy","<interface>",1,&proxyif,set_str},
/* scheduling */
    {"scheduler","[fifo|rr|other]",1,0,set_scheduler},
    {"priority","<n>",1,&priority,set_int},
/* Networking addressing and control options */
    {"window","<n>",1,&window,set_int},
    {"mtu","<m>",1,&mtu,set_int},
    {"mru","<m>",1,&mru,set_int},
    {"metric","<metric>",1,&metric,set_int},
    {"local","<ip-address>",1,&local_ip,set_str},
    {"remote","<ip-address>",1,&remote_ip,set_str},
    {"broadcast","<ip-address>",1,&broadcast_ip,set_str},
    {"netmask","<ip-address>",1,&netmask,set_str},
    {"dynamic","",0,&dynamic_addrs,set_flag},
    {"sticky","",0,&dynamic_addrs,set_flag2},
    {"strict-forwarding","",0,&strict_forwarding,set_flag},
    {"dslip-mode","<mode>",1,0,set_dslip_mode},
    {"defaultroute","",0,&default_route,set_flag},
    {"ifsetup","<script>",1,&ifsetup,set_str},
    {"addroute","<script>",1,&addroute,set_str},
    {"delroute","<script>",1,&delroute,set_str},
    {"proxyarp","",0,&proxyarp,set_flag},
#ifdef __linux__
    {"demasq","",0,&demasq,set_flag},
    {"-demasq","",0,&demasq,clear_flag},
#endif
    {"ip-up","<script>",1,&ip_up,set_str},
    {"ip-down","<script>",1,&ip_down,set_str},
    {"ip-goingdown","<script>",1,&ip_goingdown,set_str},
#ifdef SIOCSKEEPALIVE
    {"keepalive","<0-255>",1,&keepalive,set_int},
#endif
#ifdef SIOCSOUTFILL
    {"outfill","<0-255>",1,&outfill,set_int},
#endif
/* Modem options */
    {"device","<device>",1,0,add_device},
    {"connect","<script>",1,&connector,set_str},
    {"disconnect","<script>",1,&disconnector,set_str},
    {"lock","",0,&lock_dev,set_flag},
    {"speed","<baudrate>",1,&inspeed,set_int},
    {"modem","",0,&modem,set_flag},
    {"crtscts","",0,&crtscts,set_flag},
    {"rotate-devices","",0,&rotate_devices,set_flag},
/* Configuration options */
    {"lock-prefix","<path>",1,&lock_prefix,set_str},
    {"pidstring","",0,&pidstring,set_flag},
    {"-pidstring","",0,&pidstring,clear_flag},
    {"run-prefix","<path>",1,&run_prefix,set_str},
    {"path-ip","<path>",1,&path_ip,set_str},
    {"path-route","<path>",1,&path_route,set_str},
    {"path-ifconfig","<path>",1,&path_ifconfig,set_str},
    {"path-bootpc","<path>",1,&path_bootpc,set_str},
    {"path-pppd","<path>",1,&path_pppd,set_str},
    {"buffer-packets","",0,&buffer_packets,set_flag},
    {"-buffer-packets","",0,&buffer_packets,clear_flag},
    {"buffer_size","<n>",1,&buffer_size,buffer_init},
    {"buffer-fifo-dispose","",0,&buffer_fifo_dispose,set_flag},
    {"-buffer-fifo-dispose","",0,&buffer_fifo_dispose,clear_flag},
    {"buffer-timeout","<n>",1,&buffer_timeout,set_int},
/* Timeouts and connection policy control */
    {"route-wait","",0,&route_wait,set_flag},
    {"two-way","",0,&two_way,set_flag},
    {"give-way","",0,&give_way,set_flag},
    {"connect-timeout","<timeout>",1,&connect_timeout,set_int},
    {"disconnect-timeout","<timeout>",1,&disconnect_timeout,set_int},
    {"redial-timeout","<timeout>",1,&redial_timeout,set_int},
    {"nodev-retry-timeout","<timeout>",1,&nodev_retry_timeout,set_int},
    {"stop-dial-timeout","<timeout>",1,&stop_dial_timeout,set_int},
    {"kill-timeout","<timeout>",1,&kill_timeout,set_int},
    {"start-pppd-timeout","<timeout>",1,&start_pppd_timeout,set_int},
    {"stop-pppd-timeout","<timeout>",1,&stop_pppd_timeout,set_int},
    {"first-packet-timeout","<timeout>",1,&first_packet_timeout,set_int},
    {"retry-count","<count>",1,&retry_count,set_int},
    {"died-retry-count","<count>",1,&died_retry_count,set_int},
    {"redial-backoff-start","<count>",1,&redial_backoff_start,set_int},
    {"redial-backoff-limit","<time>",1,&redial_backoff_limit,set_int},
    {"dial-fail-limit","<count>",1,&dial_fail_limit,set_int},
/* Filter rules */
    {"proto","<name> <protocol> <len> <nxt proto> <spec>",5,0,&parse_proto},
    {"subproto","<protocol> <protocol>[,<protocol>...]",2,0,&parse_subproto},
    {"describe","<spec>",1,0,&parse_describe},
    {"var","<name> <spec>",2,0,&parse_var},
    {"restrict","<start-time> <end-time> <weekday> <day> <month>",5,0,&parse_restrict},
    {"or-restrict","<start-time> <end-time> <weekday> <day> <month>",5,0,&parse_or_restrict},
    {"bringup","<protocol-rule> <timeout> <packet-rule>",3,0,&parse_bringup},
    {"keepup","<protocol-rule> <timeout> <packet-rule>",3,0,&parse_keepup},
    {"accept","<protocol-rule> <timeout> <packet-rule>",3,0,&parse_accept},
    {"ignore","<protocol-rule> <packet-rule>",2,0,&parse_ignore},
    {"impulse","[<duration>,<fuzz>|<duration1>,<duration2>,<fuzz>]",1,0,&parse_impulse},
    {"up","",0,0,&parse_up},
    {"down","",0,0,&parse_down},
    {"flushfilters","",0,0,&flush_filters},
    {"flushprules","",0,0,&flush_prules},
    {"flushvars","",0,0,&flush_vars},
    {0,0,0,0}
};

void init_vars()
{
    int i;

    if (device_count) {
	for (i=0; i<device_count; i++)
	    free(devices[i]);
	free(devices);
    }
    devices = 0;
    device_count = 0;
    inspeed = DEFAULT_SPEED;
    window = 0;
    mtu = DEFAULT_MTU;
    mru = DEFAULT_MTU;
    metric = DEFAULT_METRIC;
    if (link_name) free(link_name);
    link_name = 0;
    if (link_desc) free(link_desc);
    link_desc = 0;
    if (authsimple) free(authsimple);
    authsimple = 0;
#if HAVE_LIBPAM
    if (authpam) free(authpam);
    authpam = 0;
#endif
    if (initializer) free(initializer);
    initializer = 0;
    if (deinitializer) free(deinitializer);
    deinitializer = 0;
    if (connector) free(connector);
    connector = 0;
    if (disconnector) free(disconnector);
    disconnector = 0;
    if (proxyif) free(proxyif);
    proxyif = 0;
    if (local_ip) free(local_ip);
    local_ip = 0;
    local_addr = 0;
    if (orig_local_ip) free(orig_local_ip);
    orig_local_ip = 0;
    if (netmask) free(netmask);
    netmask = 0;
    if (broadcast_ip) free(broadcast_ip);
    broadcast_ip = 0;
    if (orig_netmask) free(orig_netmask);
    orig_netmask = 0;
    if (orig_broadcast_ip) free(orig_broadcast_ip);
    orig_broadcast_ip = 0;
    if (remote_ip) free(remote_ip);
    remote_ip = 0;
    if (orig_remote_ip) free(orig_remote_ip);
    orig_remote_ip = 0;
    if (ifsetup) free(ifsetup);
    ifsetup = 0;
    if (addroute) free(addroute);
    addroute = 0;
    if (delroute) free(delroute);
    delroute = 0;
    if (ip_up) free(ip_up);
    ip_up = 0;
    if (ip_down) free(ip_down);
    ip_down = 0;
    if (ip_goingdown) free(ip_goingdown);
    ip_goingdown = 0;
    if (acctlog) free(acctlog);
    acctlog = 0;
    if (pidlog) free(pidlog);
    pidlog = strdup("diald.pid");
    if (fifoname) free(fifoname);
    fifoname = 0;
    acctfp = 0;
    mode = MODE_SLIP;
    scheduler = DEFAULT_SCHEDULER;
    priority = DEFAULT_PRIORITY;
    debug = 0;
    modem = 0;
    crtscts = 0;
    daemon_flag = 1;
    slip_encap = 0;
    lock_dev = 0;
    default_route = 0;
    strict_forwarding = 0;
    dynamic_addrs = 0;
    dynamic_mode = DMODE_REMOTE_LOCAL;
    rotate_devices = 0;
    two_way = 0;
    proxyarp = 0;
#ifdef __linux__
    demasq = 0;
#endif
    route_wait = 0;
    connect_timeout = 60;
    disconnect_timeout = 60;
    redial_timeout = DEFAULT_DIAL_DELAY;
    nodev_retry_timeout = 1;
    stop_dial_timeout = 60;
    kill_timeout = 60;
    start_pppd_timeout = 60;
    stop_pppd_timeout = 60;
    first_packet_timeout = DEFAULT_FIRST_PACKET_TIMEOUT;
    retry_count = 0;
    died_retry_count = 1;
    redial_backoff_start = -1;
    redial_backoff_limit = 600;
    dial_fail_limit = 0;
    if (lock_prefix) free(lock_prefix);
    lock_prefix = strdup(LOCK_PREFIX);
    pidstring = PIDSTRING;
    if (run_prefix) free(run_prefix);
    run_prefix = strdup(RUN_PREFIX);
    if (path_ip) free(path_ip);
#ifdef PATH_IP
    path_ip = strdup(PATH_IP);
#else
    if (!access("/sbin/ip", X_OK))
	path_ip = strdup("/sbin/ip");
    else if (!access("/usr/sbin/ip", X_OK))
	path_ip = strdup("/usr/sbin/ip");
    else if (!access("/bin/ip", X_OK))
	path_ip = strdup("/bin/ip");
    else if (!access("/usr/bin/ip", X_OK))
	path_ip = strdup("/usr/bin/ip");
    else
	path_ip = NULL;
#endif
    if (path_route) free(path_route);
#ifdef PATH_ROUTE
    path_route = strdup(PATH_ROUTE);
#else
    if (!access("/sbin/route", X_OK))
	path_route = strdup("/sbin/route");
    else if (!access("/usr/sbin/route", X_OK))
	path_route = strdup("/usr/sbin/route");
    else if (!access("/bin/route", X_OK))
	path_route = strdup("/bin/route");
    else if (!access("/usr/bin/route", X_OK))
	path_route = strdup("/usr/bin/route");
    else
	path_route = NULL;
#endif
    if (path_ifconfig) free(path_ifconfig);
#ifdef PATH_IFCONFIG
    path_ifconfig = strdup(PATH_IFCONFIG);
#else
    if (!access("/sbin/ifconfig", X_OK))
	path_ifconfig = strdup("/sbin/ifconfig");
    else if (!access("/usr/sbin/ifconfig", X_OK))
	path_ifconfig = strdup("/usr/sbin/ifconfig");
    else if (!access("/bin/ifconfig", X_OK))
	path_ifconfig = strdup("/bin/ifconfig");
    else if (!access("/usr/bin/ifconfig", X_OK))
	path_ifconfig = strdup("/usr/bin/ifconfig");
    else
	path_ifconfig = NULL;
#endif
    if (path_bootpc) free(path_bootpc);
#ifdef PATH_BOOTPC
    path_bootpc = strdup(PATH_BOOTPC);
#else
    if (!access("/sbin/bootpc", X_OK))
	path_bootpc = strdup("/sbin/bootpc");
    else if (!access("/usr/sbin/bootpc", X_OK))
	path_bootpc = strdup("/usr/sbin/bootpc");
    else if (!access("/bin/bootpc", X_OK))
	path_bootpc = strdup("/bin/bootpc");
    else if (!access("/usr/bin/bootpc", X_OK))
	path_bootpc = strdup("/usr/bin/bootpc");
    else
	path_bootpc = NULL;
#endif
    if (path_pppd) free(path_pppd);
#ifdef PATH_PPPD
    path_pppd = strdup(PATH_PPPD);
#else
    if (!access("/sbin/pppd", X_OK))
	path_pppd = strdup("/sbin/pppd");
    else if (!access("/usr/sbin/pppd", X_OK))
	path_pppd = strdup("/usr/sbin/pppd");
    else if (!access("/bin/pppd", X_OK))
	path_pppd = strdup("/bin/pppd");
    else if (!access("/usr/bin/pppd", X_OK))
	path_pppd = strdup("/usr/bin/pppd");
    else
	path_pppd = NULL;
#endif
    buffer_packets = BUFFER_PACKETS;
    buffer_size = BUFFER_SIZE;
    buffer_fifo_dispose = BUFFER_FIFO_DISPOSE;
    buffer_timeout = BUFFER_TIMEOUT;
#ifdef SIOCSKEEPALIVE
    keepalive = 0;
#endif
#ifdef SIOCSOUTFILL
    outfill = 0;
#endif

    if (pppd_argv) {
	for (i = 0; i < pppd_argc; i++)
	    free(pppd_argv[i]);
	free(pppd_argv);
    }
}

void set_int(int *var, char **argv)
{
    *var = strtol(*argv, NULL, 0);
}

void set_str(char **var, char **argv)
{
    if (*var) free (*var);
    *var = strdup(*argv);
}

void set_scheduler(char **var, char **argv)
{
#ifdef SCHED_FIFO
    if (strcmp(argv[0],"fifo") == 0)
	scheduler = SCHED_FIFO;
    else
#endif
#ifdef SCHED_RR
    if (strcmp(argv[0],"rr") == 0)
	scheduler = SCHED_RR;
    else
#endif
    if (strcmp(argv[0],"other") == 0)
#ifdef SCHED_OTHER
	scheduler = SCHED_OTHER;
#else
	scheduler = DEFAULT_SCHEDULER;
#endif
    else
    {
	mon_syslog(LOG_ERR, "Unknown scheduling class %s", argv[0]);
	mon_syslog(LOG_ERR, "Valid classes may be: fifo, rr, or other.", argv[0]);
    }
}

void parse_mode(char *s, int *mode, int *slip_encap)
{
    if (strcmp(s, "ppp") == 0)
	*mode = MODE_PPP;
    else if (strcmp(s, "dev") == 0)
	*mode = MODE_DEV;
    else if (strcmp(s, "slip") == 0)
	*mode = MODE_SLIP, *slip_encap = 0;
    else if (strcmp(s, "cslip") == 0)
	*mode = MODE_SLIP, *slip_encap = 1;
    else if (strcmp(s, "slip6") == 0)
	*mode = MODE_SLIP, *slip_encap = 2;
    else if (strcmp(s, "cslip6") == 0)
	*mode = MODE_SLIP, *slip_encap = 3;
    else if (strcmp(s, "aslip") == 0)
	*mode = MODE_SLIP, *slip_encap = 8;
    else {
	mon_syslog(LOG_ERR, "Unknown mode %s", s);
	mon_syslog(LOG_INFO,
	    "Valid modes are: dev, ppp, slip, cslip, slip6, cslip6, or aslip");
    }
}

void set_mode(char **var, char **argv)
{
    parse_mode(argv[0], &mode, &slip_encap);
}

void set_dslip_mode(char **var, char **argv)
{
    if (strcmp(argv[0],"remote") == 0)
	dynamic_mode = DMODE_REMOTE;
    else if (strcmp(argv[0],"local") == 0)
	dynamic_mode = DMODE_LOCAL;
    else if (strcmp(argv[0],"remote-local") == 0)
	dynamic_mode = DMODE_REMOTE_LOCAL;
    else if (strcmp(argv[0],"local-remote") == 0)
	dynamic_mode = DMODE_LOCAL_REMOTE;
    else if (strcmp(argv[0],"bootp") == 0)
	dynamic_mode = DMODE_BOOTP;
    else {
	mon_syslog(LOG_ERR, "Unknown dynamic slip mode %s", argv[0]);
	mon_syslog(LOG_ERR, "Valid modes are: remote, local, remote-local, local-remote or bootp.", argv[0]);
    }
}

void set_flag(int *var, char **argv)
{
    *var = 1;
}

void set_flag2(int *var, char **argv)
{
    *var = 2;
}

void clear_flag(int *var, char **argv)
{
    *var = 0;
}

void set_blocked(int *var, char **argv)
{
    if (!blocked_route && proxy.stop && state == STATE_DOWN && *var == 0)
	proxy.stop(&proxy);
    *var = 1;
}

void clear_blocked(int *var, char **argv)
{
    if (!blocked_route && proxy.start && state == STATE_DOWN && *var == 1)
	proxy.start(&proxy);
    *var = 0;
}

void set_blocked_route(int *var, char **argv)
{
    if (blocked && proxy.start && state == STATE_DOWN && *var == 0)
	proxy.start(&proxy);
    *var = 1;
}

void clear_blocked_route(int *var, char **argv)
{
    if (blocked && proxy.stop && state == STATE_DOWN && *var == 1)
	proxy.stop(&proxy);
    *var = 0;
}

void read_config_file(int *var, char **argv)
{
    parse_options_file(argv[0]);
}

void usage(void)
{
    int i;
    mon_syslog(LOG_ERR,"usage: diald [modem-device1] [modem-device2 ...] [options...] [-- [pppd options...]]\n");
    mon_syslog(LOG_ERR,"where valid options are:");
    for (i = 0; commands[i].str; i++)
        mon_syslog(LOG_ERR,"    %s %s",commands[i].str,commands[i].uargs);
    exit(1);
}

void copy_pppd_args(int argc, char *argv[])
{
    int i;

    pppd_argv = malloc(sizeof(char **)*argc);
    for (i = 0; i < argc; i++) {
	pppd_argv[i] = strdup(argv[i]);
    }
    pppd_argc = argc;
}

void add_device(void *var, char **argv)
{
    device_count++;
    if (device_count == 1)
    	devices = (char **)malloc(sizeof(char *));
    else
	devices = (char **)realloc(devices,sizeof(char *)*device_count);

    devices[device_count-1] = strdup(argv[0]);
}


void parse_args(int argc, char *argv[])
{
    int i;
    struct stat st;

    /* Get any tty devices from the initial arguments */
    for (i = 0; argc > 0 && stat(*argv,&st) == 0 && S_ISCHR(st.st_mode); i++) {
	add_device(0,argv);
	argc--, argv++;
    }
    
    /*
     * Ok, parse the options list now,
     * command line options override/augment defaults
     */
    while (argc-- > 0) {
	if (strcmp(*argv,"--") == 0) {
	    argv++;
	    argc--;
	    break;
	}
	for (i = 0; commands[i].str; i++)
	    if (strcmp(commands[i].str,*argv) == 0)
		break;
	if (commands[i].parser) {
	    argc -= commands[i].args;
	    if (argc < 0) {
		mon_syslog(LOG_ERR,"Insufficient arguments to option '%s'",*argv);
		usage();
	    }
	    (commands[i].parser)(commands[i].var,++argv);
	    argv += commands[i].args;
	} else {
	    mon_syslog(LOG_ERR,"Unknown option '%s'",*argv);
	    usage();
	}
    }
    /* Any remaining options are food for pppd */
    if (++argc > 0)
    	copy_pppd_args(argc,argv);
}

void trim_whitespace(char *s)
{
    int i;
    for (i = strlen(s)-1; i >= 0; i--) {
	if (!isspace(s[i]))
	    break;
	s[i] = 0;
    }
}

/* Parse the given options line */
void parse_options_line(char *line)
{
    char *argv[MAXARGS];
    char *s;
    char *t1,*t2;

    int argc, i;

    trim_whitespace(line);
    argc = 0;
    for (s = line, argc = 0; *s && argc < MAXARGS; s++) {
	if (*s == ' ' || *s == '\t')
	    *s = 0;
	else if (*s == '#' && argc == 0) /* the line is a comment */
	    return;
	else if (*s == '\"' || *s == '\'') {
	    char delim = *s;
	    /* start of a quoted argument */
	    s++;
	    argv[argc] = s;
	    while (*s) {
		if (*s == delim) { *s++ = 0; break; }
		if (*s == '\\' && s[1] != 0) s++;
		s++;
	    }
	    s--;
	    /* go back and fix up "quoted" characters */
	    t1 = t2 = argv[argc++];
	    while (*t1) {
		if (*t1 == '\\') {
		    t1++;
		    /* do a translation */
		    switch (*t1) {
		    case 'a': *t1 = '\a'; break;
		    case 'b': *t1 = '\b'; break;
		    case 'f': *t1 = '\f'; break;
		    case 'n': *t1 = '\n'; break;
		    case 'r': *t1 = '\r'; break;
		    case 's': *t1 = ' '; break;
		    case 't': *t1 = '\t'; break;
		    default:
			if (*t1 >= '0' && *t1 <= '8') {
			    int val = 0, n;
			    for (n = 0;
			    n < 3 && (*t1 >= '0' && *t1 <= '8');
			    ++n) {
				val = (val << 3) + (*t1 & 07);
				t1++;
			    }
			    *(--t1) = val;
			    break;
			}
			if (*t1 == 'x') {
			    int val = 0, n, digit;
			    t1++;
			    for (n = 0; n < 2 && isxdigit(*t1); ++n) {
				digit = toupper(*t1) -'0';
				if (digit > 10)
				    digit += '0' + 10 - 'A';
				val = (val << 4) + digit;
				t1++;
			    }
			    *(--t1) = val;
			    break;
			}
			/* character is itself, don't muck with it. */
		    }
		}
		*t2++ = *t1++;
	    }
	    *t2++ = 0;
	} else { /* just a normal word */
	    argv[argc++] = s;
	    while (*s) {
		if (*s == ' ' || *s == '\t') break;
		if (*s == '\"' || *s == '\'') {
		    char delim = *s;
		    /* start of a quoted sub-string */
		    s++;
		    while (*s && *s != delim) {
			if (*s == '\\' && s[1] != 0) s++;
			s++;
		    }
		    if (!*s) break;
		}
		s++;
	    }
	    s--;
	}
    }
    *s = 0;
    if (argc == 0)
        return;

    for (i = 0; commands[i].str; i++)
        if (strcmp(commands[i].str,argv[0]) == 0)
	    break;
    if (commands[i].parser) {
        argc -= commands[i].args;
        if (argc < 0) {
	    mon_syslog(LOG_ERR,"Insufficient arguments to option '%s'",argv[0]);
        } else {
	    (commands[i].parser)(commands[i].var,&argv[1]);
        }
    } else if (strcmp("pppd-options",argv[0]) == 0) {
	copy_pppd_args(argc-1,&argv[1]);
    } else {
	mon_syslog(LOG_ERR,"Unknown option '%s'",*argv);
    }
}

/* Parse the given options file */
void parse_options_file(char *file)
{
    char line[MAXLINELEN];

    FILE *fp = fopen(file,"r");

    if (fp == NULL) {
	mon_syslog(LOG_ERR,"Unable to open options file %s: %m",file);
	return;	/* no options file */
    }
    while (getsn(fp,line,1024) != EOF) {
	parse_options_line(line);
    }
    fclose(fp);
}

void check_setup()
{
    int flag = 0;

    if (!ifsetup || !*ifsetup) {
	if (!path_ifconfig || !*path_ifconfig)
	    flag = 1, mon_syslog(LOG_ERR, "No ifconfig program found.");
	if ((!path_ip || !*path_ip) && (!path_route || !*path_route))
	    flag = 1, mon_syslog(LOG_ERR,"No ip or route programs found.");
	else if (broadcast_ip && inet_addr(broadcast_ip) == -1)
	    flag = 1, mon_syslog(LOG_ERR,"Bad broadcast ip address specification.");
	else if (netmask && inet_addr(netmask) == -1)
	    flag = 1, mon_syslog(LOG_ERR,"Bad netmask specification.");
	else if (!netmask && broadcast_ip)
	    flag = 1, mon_syslog(LOG_ERR,"Netmask required with broadcast.");
	else if (remote_ip && inet_addr(remote_ip) == -1)
	    flag = 1, mon_syslog(LOG_ERR,"Bad remote ip address specification.");
	else if (local_ip) {
	    if (inet_addr(local_ip) == -1)
		flag = 1, mon_syslog(LOG_ERR,"Bad local ip address specification.");
	    else
    		local_addr = inet_addr(local_ip);
	}
    }

    if (acctlog) {
	if ((acctfp = fopen(acctlog,"a")) == NULL)
	    mon_syslog(LOG_ERR, "Can't open accounting log file %s: %m",
		acctlog);
	else
	    fclose(acctfp);
    }
    
    if (flag) {
	mon_syslog(LOG_ERR,"Terminating due to damaged reconfigure.");
	exit(1);
    }

    if (!broadcast_ip && remote_ip)
	broadcast_ip = strdup("0.0.0.0");
    if (!netmask)
	netmask = strdup("255.255.255.255");

    current_retry_count = retry_count;

    /* If we are running in "dynamic" or "sticky" address mode
     * make sure ip_dynaddr is non-zero.
     */
    if (dynamic_addrs) {
	int d;

	if ((d = open("/proc/sys/net/ipv4/ip_dynaddr", O_RDWR)) >= 0) {
	    char c;

	    if (read(d, &c, 1) == 1 && c == '0') {
		c = '1';
		write(d, &c, 1);
	    }
	    close(d);
	}
    }
}
