/*
 * config.h - Configuration options for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * These are the compile time defaults for various system files.
 * You may want to edit these to match your system before you compile diald.
 * However, if you didn't, don't panic. Almost all of these locations can be
 * configured at run time if necessary. The only thing you can't configure
 * at run time is the location of the main diald configuration files.
 *
 */

/*
 * Diald needs to be able to find its default configuration files.
 * These paths should match the installation path in the Makefile!
 * THIS MUST BE CONFIGURED AT COMPILE TIME IF YOU WANT TO CHANGE IT!
 */
#define DIALD_CONFIG_FILE "/etc/diald.conf"
#define DIALD_DEFS_FILE "/usr/lib/diald/diald.defs"

/*
 * The default access to be allowed on monitor connections. Note
 * that connections on the control fifo can always do anything
 * because there is no way to determine who asked. This only
 * applies to TCP monitor connections. The full list of access
 * flags can be found in access.h.
 *   N.B. If ACCESS_CONTROL is not set then *anything* received
 * on the pipe is treated as a message and no command are possible.
 * If ACCESS_ACCESS is not set then the "access" command may not
 * be used to get other than the default access capabilities.
 */
#define CONFIG_DEFAULT_ACCESS \
	(ACCESS_CONTROL | ACCESS_AUTH \
	| ACCESS_MONITOR)

#if 0
/* This is not needed. See the TODO file. */

/* The PORT_MASQ_BEGIN and PORT_MASQ_END defines specify the range
 * of ports which may be used by the kernel masquerade code under Linux.
 * Some sites that need to masquerade many connections at once may have
 * increased this range. If so you should change the defines here. For a
 * truely general diald you should leave both undefined but this adds some
 * usually unnecessary overhead.
 *  N.B. The demasquerading needs to be enabled using the "demasq" option.
 * FIXME: This probably isn't a big killer unless you have lots of
 * short lived connections?
 */
#define PORT_MASQ_BEGIN	61000
#define PORT_MASQ_END	(PORT_MASQ_BEGIN + 4096)
#endif


/* If defined then a fatal signal will print the eip that it
 * ocurred at. This may or may not be useful.
 */
#define CONFIG_FATAL_EIP


/*****************************************************************************
 * EVERYTHING BELOW HERE IS RUN TIME CONFIGURABLE
 * You can change these things if you want to save yourself some
 * entries in your configuration files.
 ****************************************************************************/

/*
 * Your lock files are probably somewhere else unless you
 * happen to be running a newer distribution that is compiliant
 * the the Linux File System Standard. On older distributions
 * you will usually find them in /var/spool/uucp or /usr/spool/uucp.
 */
#define LOCK_PREFIX	"/var/lock/LCK.."

/*
 * If your lock files should contain binary PID's then
 * set the following to 0. I think most linux
 * distributions want ASCII PID's in the lock files.
 */
#define PIDSTRING 1

/*
 * Define where to put the diald.pid file. Under the FSSTD this 
 * should be in /var/run, but you're system might have them
 * elsewhere. Check and be sure.
 */

#define RUN_PREFIX	"/var/run"

/*
 * Diald needs to use the route and ifconfig binaries to set up
 * routing tables and to bring up the proxy device. Check where
 * these executables are on your system and set these paths to match.
 */
#define PATH_ROUTE	"/sbin/route"
#define PATH_IFCONFIG	"/sbin/ifconfig"

/*
 * Diald needs to know where to find the bootpc binary in order to
 * use the bootp protocol for dynamic slip address determination.
 */

#define PATH_BOOTPC	"/usr/sbin/bootpc"

/*
 * If you're never going to use pppd don't worry if this is wrong.
 * Otherwise, find your pppd executable and set this path to match its
 * location.
 */
#define PATH_PPPD	"/usr/sbin/pppd"
