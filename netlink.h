#include <linux/types.h>


/* This is ripped directly from the kernel netlink.h file... */

#define NETLINK_TAPBASE		16	/* 16 to 31 are ethertap */


struct sockaddr_nl
{
	sa_family_t	nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	__u32		nl_pid;		/* process pid	*/
       	__u32		nl_groups;	/* multicast groups mask */
};
