/*
 * firewall.h - Firewall headers.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#define FW_MAX_ADDR_BYTES 16		/* max bytes in an addr */
#define FW_MAX_ADDR_UINTS (FW_MAX_ADDR_BYTES/sizeof(unsigned int))
#define FW_ID_HDRS 4			/* max headers in a packet */
#define FW_ID_LEN 64			/* max bytes in a header id */
#define FW_MAX_DESCVARS 16		/* max vars in a connection desc */
#define FW_MAX_DESCLEN 128		/* max length of a connection desc */
#define FW_OFFSET(x) ((x)&0x0fff)	/* offset into a header */
#define FW_HDR_OFFSET(x) ((x)&0x7fff)	/* header offset */
#define FW_DATA_OFFSET(x) (0x8000|(x))	/* data offset */
#define FW_SRC_OFFSET(x) (0x4000|(x))	/* src ident offset */
#define FW_DST_OFFSET(x) (0x2000|(x))	/* dest ident offset */
#define FW_IN_HDR(x) (((x)&0x8000)==0)	/* in header segment */
#define FW_IN_DATA(x) ((x)&0x8000)	/* in data segment */
#define FW_IN_SRC(x) ((x)&0x4000)	/* src ident offset */
#define FW_IN_DST(x) ((x)&0x2000)	/* dest ident offset */
#define FW_TCP_STATE(x) ((x)==0x0fff)	/* test tcp_state variable */
#define FW_PROTO_ALL(x) ((x)==0xffff)	/* any protocol */

/* Direction indicators */
#define FW_DIR_IN 0
#define FW_DIR_OUT 1
#define FW_DIR_BOTH 2

/* Comparision operators */
#define FW_EQ 0
#define FW_NE 1
#define FW_GE 2
#define FW_LE 3

#define FW_MAX_TERMS 10			/* Max terms per filter struct */
#define FW_MAX_PRULES 255
#define FW_MAX_DESCS 64
#define FW_NRUNIT 16			/* max # of unit's FW can monitor */

/*
 * Externally visible structures.
 */

#define FW_VAR_NUMERIC	0
#define FW_VAR_STRING	1
#define FW_VAR_PROTOCOL	2
#define FW_VAR_PORT	3
#define FW_VAR_TCPPORT	4
#define FW_VAR_UDPPORT	5
#define FW_VAR_DOTQUAD	6
#define FW_VAR_HEX	7
#define FW_VAR_INET6	8

struct var {
    unsigned char valid:2;
    unsigned char type:6;
    unsigned char prule;

    union {
	struct {
	    signed char shift;		/* +/- left/right shift 0-31 */
	    unsigned char width;	/* n bytes */
	    unsigned short offset;
	    unsigned int value[FW_MAX_ADDR_UINTS];
	    unsigned int mask[FW_MAX_ADDR_UINTS];
	    unsigned int cval[FW_MAX_ADDR_UINTS];	/* constant */
	} n;
	char *s;
    } u;

    struct var *next_dirty;
    struct var *next;
    unsigned int refs;
    char *name;
};

typedef struct firewall_prule {
    unsigned char *hdr;
    unsigned char *data;
    struct var *nxt_offset;		/* Offset of next header */
    struct var *nxt_proto;		/* Protocol of next header */
    struct var *var_dirty;		/* List of cached vars */
    unsigned short protocol;		/* Protocol/packet type */
    unsigned char next_dirty;		/* Next used prule for packet */
    unsigned char nsubs;		/* no. sub protocols */
    unsigned char sub[FW_MAX_PRULES];	/* Sub protocols possible */
    unsigned int clen;			/* coding rule length */
    unsigned short codes[FW_ID_LEN];	/* coding rule, byte offsets */
} FW_ProtocolRule;

typedef struct firewall_term {
    struct var *var;
    struct var *mask;
    unsigned char op;		/* operation: =, !=, >=, <= */
    struct var *test;		/* test value */
} FW_Term;


typedef struct firewall_desc {
    struct var *vars[FW_MAX_DESCVARS];
    char *fmt[FW_MAX_DESCVARS];
} FW_Desc;

/*
 * Times that a rule should be applied.
 */
typedef struct FW_Timeslot {
    unsigned int start;			/* first minute of day in slot */
    unsigned int end;			/* last minute of day in slot */
    unsigned int wday:7;                /* days of the week slot applies */
    unsigned int mday:31;               /* days of the month slot applies */
    unsigned short month:12;            /* month of the year slot applies */
    struct FW_Timeslot *next;		/* next slot in disjunct */
} FW_Timeslot;

#define FW_TYPE_BRINGUP 0		/* bring the link up */
#define FW_TYPE_KEEPUP	1		/* keep the link active */
#define FW_TYPE_ACCEPT	2		/* bring up and active */
#define FW_TYPE_IGNORE	3		/* ignore this packet */
#define FW_TYPE_UP	4
#define FW_TYPE_DOWN	5
#define FW_TYPE_IMPULSE 6
#define FW_TYPE_WAIT	7		/* use packet to mark start of
					 * active transmissions. Generally
					 * a routing packet of some kind.
					 */

/*
 * Firewall filter.
 */
typedef struct firewall_rule {
    FW_Timeslot *times;		/* chain of times the filter can be applied */
    unsigned char prule;	/* protocol rule, 0-FW_MAX_PRULES-1. */
    unsigned char type;		/* link type */
    unsigned char count:7;	/* number of terms. maximum FW_MAX_TERMS */
    unsigned char log:1;	/* log matches to this rule */
    unsigned int timeout;	/* timeout in seconds. Max approx 136 years */
    unsigned int fuzz;		/* fuzz to apply to impulse rules */
    unsigned int timeout2;	/* impulse timeout after first used */
    unsigned int conn_hold;	/* how long to remember idle connection */
    FW_Term terms[FW_MAX_TERMS];	/* terms in the rule */
} FW_Filter;

/*
 * Firewall request structure for ioctl's.
 */

struct firewall_req {
    unsigned char unit;			/* firewall unit */
    union {
        char ifname[16];		/* FIXME! */
	FW_Filter filter;
	FW_ProtocolRule rule;
	FW_Desc desc;
	int vals[2];
	int value;
    } fw_arg;
};

/*
 * Firewall IOCTL's
 */

#define IP_FW_QFLUSH	1	/* flush the timeout queue */
#define IP_FW_QCHECK	2	/* is the queue empty or not */
#define IP_FW_FFLUSH	3	/* flush the filters */
#define IP_FW_PFLUSH	4	/* flush the protocol rules */
#define IP_FW_AFILT     5	/* add a filter rule */
#define IP_FW_APRULE	6	/* add a protocol rule */
#define IP_FW_APSUB	7	/* add a sub protocol */
#define IP_FW_ADESC	8	/* add a connection description */
#define IP_FW_PCONN	9	/* print the connections */
#define IP_FW_PPRULE	10	/* print the rules */
#define IP_FW_PFILT	11	/* print the filters */
#define IP_FW_OPEN	12	/* print the filters */
#define IP_FW_CLOSE	13	/* print the filters */
#define IP_FW_UP	14	/* mark the interface as up */
#define IP_FW_DOWN	15	/* mark the interface as down */
#define IP_FW_MCONN	16	/* print the connections to monitor */
#define IP_FW_WAIT	17	/* check if we are done waiting for
				 * routing packet */
#define IP_FW_RESET_WAITING 18
#define IP_FW_MCONN_INIT 19	/* initialize connection monitoring */

/*
 * Internal data structures.
 */

/*
 * List of filters.
 */
typedef struct fw_filters {
    struct fw_filters *next;	/* next filter in the firewall chain */
    FW_Filter filt;
} FW_Filters;

/*
 * Identifier structure.
 */
typedef struct {
    unsigned char nhdrs;		/* number of headers */
    struct {
	unsigned char prule;		/* prule for this header */
	unsigned short len;		/* id length */
	unsigned char id[FW_ID_LEN];	/* identifier for this header */
    } hdr[FW_ID_HDRS];
} FW_ID;

/*
 * TCP State structure.
 */
typedef struct tcp_state {
    unsigned char tcp_flags:2;		/* TCP liveness flags */
    unsigned char saw_fin:2;		/* directions we saw a FIN in */
    unsigned long fin_seq[2];		/* sequence numbers for FIN packets */
} TCP_STATE;

/*
 * Connection entry;
 */
typedef struct fw_connection {
    struct timer_lst timer;		/* timer for this connection */
    int conn_hold;			/* time to remember after time out */
    FW_ID id;				/* identifier for this connection */
    unsigned long packets[2];		/* packet counts out/in */
    unsigned long bytes[2];		/* byte count out/in */
    unsigned long bytes_total[2];	/* total byte count out/in */
    TCP_STATE tcp_state;		/* TCP state information */
    struct fw_unit *unit;		/* Unit this connection is in */
    struct fw_connection *next,*prev;	/* queue chain pointers */
    unsigned char desc_len;		/* length of description */
    char description[FW_MAX_DESCLEN];	/* description of this connection */
} FW_Connection;

typedef struct fw_unit {
    FW_ProtocolRule prules[FW_MAX_PRULES];	/* prules */
    FW_Desc descs[FW_MAX_DESCS];	/* connection descriptions */
    FW_Filters *filters;		/* list of filters */
    FW_Filters *last;			/* last filter in the list */
    FW_Connection *connections;		/* connection queue */
    int live;				/* number of live connections in queue */
    struct timer_lst impulse;		/* impulse timer */
    unsigned long force_etime;		/* time of next forcing event */
    unsigned long impulse_etime;	/* time of next impulse change event */
    char used;				/* is this unit free */
    unsigned char up:1;			/* Is the line currently up or down? */
    unsigned char force:2;		/* 0 = queue only, 1 = force up,
   					 * 2 = force down */
    unsigned char impulse_mode:1;	/* impulse mode 0 = on, 1 = fuzz */
    unsigned char waiting:1;		/* waiting for routing packet */
    unsigned char nrules;		/* how many rules are assigned */
    unsigned char ndescs;		/* how many descriptions are assigned */
    unsigned short nfilters;		/* how many filters are assigned */
} FW_unit;

int ctl_firewall(int, struct firewall_req *);
int check_firewall(int, sockaddr_ll_t *, unsigned char *, int);
