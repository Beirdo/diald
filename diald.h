/*
 * diald.h - Main header file.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#if HAVE_UNISTD_H
#  include <unistd.h>
#endif
#include <string.h>
#if HAVE_DIRENT_h
#  include <dirent.h>
#endif
#if HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#include <ctype.h>
#include <errno.h>
#if HAVE_SYSLOG_H
#  include <syslog.h>
#endif
#include <signal.h>
#include <time.h>
#if HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#ifdef _POSIX_PRIORITY_SCHEDULING
#  include <sched.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#include <sys/socket.h>
#include <sys/termios.h>
/* #include <sys/bitypes.h> */
#include <net/if.h>
#include <netdb.h>
/*
#include <netinet/ip_tcp.h>
#include <netinet/ip_udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
*/
#include <netinet/in.h>
/* #include <asm/byteorder.h> */
/* Shut up gcc about a redefinition that is harmless */
#undef LITTLE_ENDIAN
#ifndef __GLIBC__
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#else
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>
/* Hmm. Should there be a netinet pointer to these??? */
#ifndef __GLIBC__ 
#  include <linux/if_ether.h>
#  include <linux/if_slip.h>
#  include <linux/if_packet.h>
#else
#  include <net/ethernet.h>
#  include <net/if_packet.h>
#  if __GLIBC_MINOR__ >= 1
#    include <netpacket/packet.h>
#    include <netinet/ip6.h>
     typedef struct ip6_hdr ip6hdr_t;
#  endif
#endif

#if defined(AF_PACKET) && defined(PACKET_OUTGOING)
#  define HAVE_AF_PACKET
   typedef struct sockaddr_ll sockaddr_ll_t;
#else
   typedef struct { int sll_protocol; } sockaddr_ll_t;
#endif

#include <access.h>
#include <fsm.h>
#include <timer.h>
#include <firewall.h>
#include <bufio.h>
#include <proxy.h>

#define LOG_DDIAL	LOG_LOCAL2

/* SLIP special character codes */
#define END             0300    /* indicates end of packet */
#define ESC             0333    /* indicates byte stuffing */
#define ESC_END         0334    /* ESC ESC_END means END data byte */
#define ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */

/* Operation modes */
#define MODE_SLIP 0
#define MODE_PPP 1
#define MODE_DEV 2


/* Dynamic slip interpretation modes */
#define DMODE_REMOTE 0
#define DMODE_LOCAL 1
#define DMODE_REMOTE_LOCAL 2
#define DMODE_LOCAL_REMOTE 3
#define DMODE_BOOTP 4

/* Define DEBUG flags */
#define DEBUG_FILTER_MATCH	0x0001
#define DEBUG_PROXYARP		0x0004
#define DEBUG_VERBOSE		0x0008
#define DEBUG_STATE_CONTROL	0x0010
#define DEBUG_TICK		0x0020
#define DEBUG_CONNECTION_QUEUE	0x0040

/* Define MONITOR flags
 * 0x??????nn - status request flags, default on
 * 0x??nnnn?? - status request flags, default off
 * 0xnn?????? - syslog level
 */
#define MONITOR_STATE		0x00000001
#define MONITOR_INTERFACE	0x00000002
#define MONITOR_STATUS		0x00000004
#define MONITOR_LOAD		0x00000008
#define MONITOR_MESSAGE		0x00000010
#define MONITOR_QUEUE		0x00000020
#define MONITOR_VER1		0x00000080
#define MONITOR_VER2		0x00000100
#define MONITOR_QUEUE2		0x00010000

/*
 * Originally diald just threw away any packets it received when
 * the link was down. This is OK because IP is an unreliable protocol,
 * so applications will resend packets when the link comes back up.
 * On the other hand the kernel doubles the timeout for TCP packets
 * every time a send fails. If you define BUFFER_PACKETS diald
 * will store packets that come along when the link is down and
 * send them as soon as the link comes up. This should speed up
 * the initial connections a bit.
 */

#define BUFFER_PACKETS 1	/* turn on packet buffering code. */
#define BUFFER_SIZE 65536	/* size of buffer to store packets */
#define BUFFER_FIFO_DISPOSE 1	/* dispose of old packets to make room
				 * for new packets if the buffer becomes
				 * full. Without this option new packets
				 * are discarded if there is no room.
				 */
#define BUFFER_TIMEOUT 600	/* Maximum number of seconds to keep a
				 * packet in the buffer. Don't make this
				 * too large or you will break IP.
				 * (Something on the order of 1 hour
				 * probably the maximum safe value.
				 * I expect that the 10 minutes defined
				 * by default should be plenty.
				 */

/*
 * Various timeouts and times used in diald.
 */

#define PAUSETIME 1	/* how many seconds should diald sleep each time
			   it checks to see what's happening. Note that
			   this is a maximum time and that a packet
			   arriving will cut the nap short. */
#define DEFAULT_FIRST_PACKET_TIMEOUT 120
#define DEFAULT_DIAL_DELAY 30
#define DEFAULT_MTU 1500
#define DEFAULT_METRIC 0
#define DEFAULT_SPEED 38400

#ifdef SCHED_OTHER
#  define DEFAULT_SCHEDULER SCHED_OTHER
#else
#  define DEFAULT_SCHEDULER 0
#endif
#define DEFAULT_PRIORITY -5

typedef struct monitors {
    struct monitors *next;
    int is_pipe;		/* is this a pipe? Or TCP? */
    int fd;			/* monitor output fp. */
    unsigned int level;		/* Information level requested */
    char *name;
} MONITORS;


#define SHELL_NOWAIT	0
#define SHELL_WAIT	1
extern int run_shell(int mode, const char *name, const char *buf, int fd);

/* Configuration variables */

char **devices;
int device_count;
int inspeed;
int window;
int mtu;
int mru;
int metric;
char *link_name;
char *link_desc;
char *authsimple;
#if HAVE_LIBPAM
char *authpam;
#endif
char *initializer;
char *deinitializer;
char *connector;
char *disconnector;
char *proxyif;
char *orig_local_ip;
char *orig_remote_ip;
char *orig_broadcast_ip;
char *orig_netmask;
char *local_ip;
unsigned long local_addr;
char *remote_ip;
char *broadcast_ip;
char *netmask;
char *ifsetup;
char *addroute;
char *delroute;
char *ip_up;
char *ip_down;
char *ip_goingdown;
char *acctlog;
char *pidlog;
char *fifoname;
int tcpport;
int demand;			/* enables demand dialling */
int blocked;			/* user has blocked the link */
int blocked_route;		/* blocked link has routes through it */
char *lock_prefix;
int pidstring;
char *run_prefix;
char *diald_config_file;
char *diald_defs_file;
char *path_ip;
char *path_route;
char *path_ifconfig;
char *path_bootpc;
char *path_pppd;
int buffer_packets;
int buffer_size;
int buffer_fifo_dispose;
int buffer_timeout;
FILE *acctfp;
int mode;
int scheduler;
int priority;
int debug;
int modem;
int rotate_devices;
int crtscts;
int daemon_flag;
int strict_forwarding;
int dynamic_addrs;
int dynamic_mode;
int slip_encap;
int current_slip_encap;
int lock_dev;
int default_route;
int pppd_argc;
char **pppd_argv;
int connect_timeout;
int disconnect_timeout;
int redial_timeout;
int nodev_retry_timeout;
int stop_dial_timeout;
int kill_timeout;
int start_pppd_timeout;
int stop_pppd_timeout;
int first_packet_timeout;
int retry_count;
int died_retry_count;
int redial_backoff_start;
int redial_backoff_limit;
int redial_backoff;
int dial_fail_limit;
int two_way;
int give_way;
int proxyarp;
#ifdef __linux__
int demasq;
#endif
int route_wait;

#ifdef SIOCSKEEPALIVE
extern int keepalive;
#endif

#ifdef SIOCSOUTFILL
extern int outfill;
#endif

/* Global variables */

int clk_tck;			/* clock ticks per second */
int af_packet;			/* kernel has AF_PACKET sockets */
int fifo_fd;			/* FIFO command pipe. */
int tcp_fd;			/* TCP listener. */
fd_set ctrl_fds;		/* TCP command/monitor connections. */
PIPE *pipes;			/* List of control/monitor pipes. */
MONITORS *monitors;		/* List of monitor pipes. */
int modem_fd;			/* modem device fp (for slip links) */
int modem_hup;			/* have we seen a modem HUP? */
int sockfd;			/* socket for doing interface ioctls */
int request_down;		/* has the user requested link down? */
int request_up;			/* has the user requested link up? */
int forced;			/* has the user requested the link forced up? */
int link_pid;			/* current pppd command pid */
int dial_pid;			/* current dial command pid */
int running_pid;		/* current system command pid */
int running_status;		/* status of last system command */
int dial_status;		/* status from last dial command */
int state_timeout;		/* state machine timeout counter */
int state;			/* DFA state */
int current_retry_count;	/* current retry count */
proxy_t proxy;			/* Proxy interface */
int link_iface;			/* Interface number for ppp line */
int orig_disc;			/* original PTY line disciple */
int fwdfd;			/* control socket for packet forwarding */
int snoopfd;			/* snooping socket fd */
int fwunit;			/* firewall unit for firewall control */
int req_pid;			/* pid of process that made "request" */
char *current_dev;		/* name of the current device */
int current_mode;		/* mode of the current link */
char *req_dev;			/* name of the device file requested to open */
int use_req;			/* are we actually using the FIFO link-up request device? */
char snoop_dev[10];		/* The interface name we are listening on */
int snoop_index;		/* The index of the interface */
int txtotal,rxtotal;		/* transfer stats for the link */
int itxtotal, irxtotal;		/* instantaneous transfer stats */
int delayed_quit;		/* has the user requested delayed termination?*/
int terminate;			/* has the user requested termination? */
int impulse_time;		/* time for current impulses */
int impulse_init_time;		/* initial time for current impulses */
int impulse_fuzz;		/* fuzz for current impulses */
char *pidfile;			/* full path filename of pid file */
int force_dynamic;		/* 1 if the current connect passed back addrs */
int redial_rtimeout;		/* current real redial timeout */
int dial_failures;		/* number of dial failures since last success */
int ppp_half_dead;		/* is the ppp link half dead? */

/* function prototypes */
void init_vars(void);
void parse_init(void);
void parse_options_line(char *);
void parse_options_file(char *);
void parse_args(int, char *[]);
void check_setup(void);
void signal_setup(void);
void default_sigacts(void);
void block_signals(void);
void unblock_signals(void);
void filter_setup(void);
void proxy_start(void);
void proxy_stop(void);
void proxy_close(void);
void proxy_up(void);
void proxy_down(void);
void proxy_release(void);
void dynamic_slip(void);
void idle_filter_proxy(void);
void open_fifo(void);
void filter_read(void);
void ctrl_read(PIPE *);
void proxy_read(void);
void modem_read(void);
void advance_filter_queue(void);
void fire_timers(void);
int recv_packet(unsigned char *, size_t);
int send_packet(unsigned short, unsigned char *, size_t);
void sig_hup(int);
void sig_intr(int);
void sig_term(int);
void sig_io(int);
void sig_chld(int);
void sig_pipe(int);
void linkup(int);
void die(int);
void print_filter_queue(int);
void monitor_queue(void);
void become_daemon(void);
void change_state(void);
void output_state(void);
void add_device(void *, char **);
void set_str(char **, char **);
void set_scheduler(char **, char **);
void set_int(int *, char **);
void set_flag(int *, char **);
void set_flag2(int *, char **);
void clear_flag(int *, char **);
void set_blocked(int *, char **);
void clear_blocked(int *, char **);
void set_blocked_route(int *, char **);
void clear_blocked_route(int *, char **);
void set_mode(char **, char **);
void set_dslip_mode(char **, char **);
void read_config_file(int *, char **);
void add_filter(void *var, char **);
int insert_packet(unsigned char *, int);
char *lock(char *);
void unlock(char *);
void fork_dialer(char *, char *, int);
void fork_connect(char *);
void flush_timeout_queue(void);
void set_up_tty(int, int, int);
void flush_prules(void);
void flush_filters(void);
void flush_vars(void);
void parse_impulse(void *var, char **argv);
void parse_restrict(void *var, char **argv);
void parse_or_restrict(void *var, char **argv);
void parse_bringup(void *var, char **argv);
void parse_keepup(void *var, char **argv);
void parse_accept(void *var, char **argv);
void parse_ignore(void *var, char **argv);
void parse_wait(void *var, char **argv);
void parse_up(void *var, char **argv);
void parse_down(void *var, char **argv);
void parse_proto(void *var, char **argv);
void parse_subproto(void *var, char **argv);
void parse_describe(void *var, char **argv);
void parse_var(void *var, char **argv);
void iface_start(char *, char *, int, char *, char *, char *, int);
void iface_stop(char *, char *, int, char *, char *, char *, int);
void iface_down(char *, char *, int, char *, char *, char *, int);
void close_modem(void);
int open_modem (void);
void reopen_modem (void);
void finish_dial(void);
void ppp_start(void);
int ppp_set_addrs(void);
int ppp_dead(void);
int ppp_route_exists(void);
void ppp_stop(void);
void ppp_reroute(void);
void ppp_kill(void);
void ppp_zombie(void);
int ppp_rx_count(void);
void slip_start(void);
int slip_set_addrs(void);
int slip_dead(void);
void slip_stop(void);
void slip_reroute(void);
void slip_kill(void);
void slip_zombie(void);
int slip_rx_count(void);
void dev_start(void);
int dev_set_addrs(void);
int dev_dead(void);
void dev_stop(void);
void dev_reroute(void);
void dev_kill(void);
void dev_zombie(void);
int dev_rx_count(void);
void idle_filter_init(void);
void interface_up(void);
void interface_down(void);
void buffer_init(int *, char **);
int queue_empty(void);
int fw_wait(void);
int fw_reset_wait(void);
int next_alarm(void);
void buffer_packet(unsigned int,unsigned char *);
void forward_buffer(void);
void run_state_script(char *name, char *script, int background);
void pipe_init(char *, int, int, PIPE *, int);
int pipe_read(PIPE *);
void pipe_flush(PIPE *, int);
int set_proxyarp (unsigned int);
int clear_proxyarp (unsigned int);
int report_system_result(int,char *);
void mon_syslog(int pri, char *fmt, ...);
void mon_cork(int);
void mon_write(unsigned int,char *,int);
void block_timer();
void unblock_timer();
char *cdate(time_t);
int getservice(const char *name, const char *proto);
int getprotocol(const char *name);
char *getprotonumber(int proto);
int getsn(FILE *fp,char *buf,int len);
void del_impulse(FW_unit *unit);
void del_connection(FW_Connection *c);
void slip_start_fail(void * data);
