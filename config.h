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
 * If you want to be able to reconfigure a running diald by sending
 * options prefixed with "config " down the control pipe you can
 * enable this.
 * WARNING: THERE IS NO SECURITY ON THIS AT THE MOMENT
 *          IF YOU ENABLE THIS ANYONE WHO CAN CONNECT TO DIALD CAN
 *          DO *ANYTHING* - INCLUDING CHANGING PROGRAM PATHS TO
 *          THEIR OWN SCRIPTS (AND, YES, DIALD IS PROBABLY ROOT)
 */
#undef CONFIG_REMOTE_CONFIG


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
