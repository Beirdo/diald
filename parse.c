/*
 * parse.c - Options parsing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <setjmp.h>

#include <diald.h>


#define TOK_LE 256
#define TOK_GE 257
#define TOK_NE 258
#define TOK_INET 259
#define TOK_STR 260
#define TOK_NUM 261
#define TOK_ERR 262
#define TOK_EOF 263
#define TOK_LSHIFT 264
#define TOK_RSHIFT 265
#define TOK_QSTR 266
#define TOK_HEX 267
#define TOK_INET6 268
#define ADVANCE token = token->next

struct prule {
    char *name;
} prules[FW_MAX_PRULES];
static int nprules = 0;

static struct var *vars = 0;

typedef struct token {
    int offset;
    int type;
    char *str;
    struct token *next;
} Token;

static FW_Timeslot *cslot,*tslot;

char *errstr;
Token *tlist;
Token *token;
char *context;

static jmp_buf unwind;

void parse_init()
{
    cslot = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
    cslot->next = 0;
    cslot->start = 0;
    cslot->end = 24*60*60-1;
    cslot->wday = 0x7f;
    cslot->mday = 0x7fffffff;
    cslot->month = 0xfff;
}

void parse_error(char *s)
{
    mon_syslog(LOG_ERR,"%s parsing error. Got token '%s'. %s",context,token->str,s);
    mon_syslog(LOG_ERR,"parse string: '%s'",errstr);
    longjmp(unwind,1);
}

void tokenize(char *cntxt, int argc, char **argv)
{
    char *s, *t;
    int i, len;
    Token *prev = 0, *new;

    context = cntxt;
    /* merge the arguments into one string */

    for (len = i = 0; i < argc; i++)
	len += strlen(argv[i])+1;
    t = errstr = malloc(len);
    if (errstr == 0) { mon_syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    strcpy(errstr,argv[0]);
    for (i = 1; i < argc; i++) { strcat(errstr," "); strcat(errstr,argv[i]); }

    tlist = 0;

    for (s = errstr; *s;) {
	new = malloc(sizeof(Token));
	if (new == 0) { mon_syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
        if (prev == 0) tlist = new; else prev->next = new;
	prev = new;
	new->next = 0;
	new->offset = s-errstr;
	if (*s == '<' && s[1] == '=') {
	    new->type = TOK_LE; s += 2;
	} else if (*s == '>' && s[1] == '=') {
	    new->type = TOK_GE; s += 2;
	} else if (*s == '!' && s[1] == '=') {
	    new->type = TOK_NE; s += 2;
	} else if (*s == '<' && s[1] == '<') {
	    new->type = TOK_LSHIFT; s += 2;
	} else if (*s == '>' && s[1] == '>') {
	    new->type = TOK_RSHIFT; s += 2;
	} else if (*s == '"') {
	    new->type = TOK_QSTR;
	    s++;
	    while (*s && *s != '"') {
		if (*s == '\\' && s[1] != 0) s++;
		s++;
	    };
	    if (*s) s++;
	} else if (isalpha(*s) || *s == '.' || *s == '_') {
	    new->type = TOK_STR;
	    while (isalnum(*s) || *s == '.' || *s == '_' || *s == '-') s++;
	} else if (*s == '0' && s[1] == 'x' && isxdigit(s[2])) {
	    new->type = TOK_NUM;
	    s += 2;
	    while (isxdigit(*s)) s++;
	    len = (s-errstr)-new->offset;
	    if (len > sizeof(((struct var*)0)->u.n.value[0])<<1)
		new->type = TOK_HEX;
	} else if (*s == '0' && isdigit(s[1])) {
	    new->type = TOK_NUM;
	    s++;
	    while (isdigit(*s)) s++;
	} else if (isxdigit(*s)) {
	    new->type = TOK_NUM;
	    while (isxdigit(*s) || *s == ':') {
		if (*s == ':')
		    new->type = TOK_INET6;
		else if (!isdigit(*s))
		    new->type = TOK_HEX;
		s++;
	    }
	    if ((new->type == TOK_NUM
	    || new->type == TOK_INET6)
	    && *s == '.') {
	        if (new->type == TOK_NUM)
		    new->type = TOK_INET;
		s++;
		if (!isdigit(*s)) goto tokerr;
		while (isdigit(*s)) s++;
		if (*s != '.') goto tokerr;
		s++;
		if (!isdigit(*s)) goto tokerr;
		while (isdigit(*s)) s++;
		if (*s != '.') goto tokerr;
		s++;
		if (!isdigit(*s)) goto tokerr;
		while (isdigit(*s)) s++;
	        if (*s == '.') s++;
	        goto done;
tokerr:
		new->type = TOK_ERR;
	    }
	} else {
	    new->type = *s++;
	}
done:
	len = (s-errstr)-new->offset;
	if (new->type == TOK_QSTR) len = (len > 2 ? len - 2 : 0);
	new->str = malloc(len+1);
	if (new->str == 0) { mon_syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
	if (new->type == TOK_QSTR)
	    strncpy(new->str,errstr+new->offset+1,len);
	else
	    strncpy(new->str,errstr+new->offset,len);
	new->str[len] = 0;
    }
    new = malloc(sizeof(Token));
    if (new == 0) { mon_syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    if (prev == 0) tlist = new; else prev->next = new;
    prev = new;
    new->next = 0;
    new->offset = s-errstr;
    new->type = TOK_EOF;
    new->str = strdup("");
    token = tlist;
}

void free_tokens(void)
{
    Token *next;
    if (token && token->type != TOK_EOF)
	mon_syslog(LOG_ERR,
	    "Parsing error. Got token '%s' when end of parse was expected.",
	    token->str);
    while (tlist) {
	next = tlist->next;
	free(tlist->str);
	free(tlist);
	tlist = next;
    }
    tlist = 0;
    free(errstr);
}


void init_prule(FW_ProtocolRule *rule)
{
    memset(rule,0,sizeof(*rule));
}

void init_filter(FW_Filter *filter)
{
    memset(filter,0,sizeof(*filter));
    filter->times = cslot;
}

void eat_whitespace(void)
{
    if (token->type == ' ') { ADVANCE; }
}

void parse_whitespace(void)
{
    if (token->type != ' ') parse_error("Expecting whitespace");
    ADVANCE;
}

static void set_start(int i)
{
    if (i == -1)
   	tslot->start = 0;
    else
    	tslot->start = i;
}

static void set_end(int i)
{
    if (i == -1)
	tslot->end = 24*60*60-1;
    else
        tslot->end = i;
    if (tslot->end < tslot->start) {
	parse_error("End of time slot must be later than start.");
    }
}

static void set_weekdays(int i)
{
    if (i < 0) {
	tslot->wday = 0x7f;
    } else if (i < 7) {
	tslot->wday |= (1<<i);
    } else {
	parse_error("Weekday specification must be in range 0-6.");
    }
}


static void set_days(int i)
{
    if (i < 0) {
	tslot->mday = 0x7fffffff;
    } else if (i > 0 && i < 32) {
	tslot->mday |= (1<<(i-1));
    } else {
	parse_error("Month day specification must be in range 1-31.");
    }
}

static void set_month(int i)
{
    if (i < 0) {
	tslot->month = 0xfff;
    } else if (i > 0 && i < 13) {
	tslot->month |= (1<<(i-1));
    } else {
	parse_error("Month specification must be in range 1-12.");
    }
}

static void parse_time(void (*set_func)(int))
{
    int hour, min, sec;

    if (token->type == '*') {
	(*set_func)(-1);
	ADVANCE;
    } else {
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number for hours.");
	sscanf(token->str,"%d",&hour);
	if (hour < 0 || hour > 23)
	    parse_error("Hours value must be between 0 and 23");
	ADVANCE;
	if (token->type != ':')
	    parse_error("Expecting a ':'.");
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number for minutes.");
	sscanf(token->str,"%d",&min);
	if (min < 0 || min > 59)
	    parse_error("Minutes value must be between 0 and 59");
	ADVANCE;
	if (token->type != ':')
	    parse_error("Expecting a ':'.");
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number for seconds.");
	sscanf(token->str,"%d",&sec);
	if (sec < 0 || sec > 59)
	    parse_error("Seconds value must be between 0 and 59");
	ADVANCE;
	(*set_func)(hour*60*60+min*60+sec);
    }
}

static void parse_times(void (*set_func)(int))
{
    int i,j;

    if (token->type == '*') {
	(*set_func)(-1);
	ADVANCE;
    } else {
	while (1) {
	    if (token->type != TOK_NUM)
		parse_error("Expecting a number.");
	    sscanf(token->str,"%i",&i);
	    (*set_func)(i);
	    ADVANCE;
	    if (token->type == '-') {
		ADVANCE;
		if (token->type != TOK_NUM)
		    parse_error("Expecting a number.");
		sscanf(token->str,"%i",&j);
		for (; i <= j; i++)
		    (*set_func)(i);
		ADVANCE;
	    }
	    if (token->type != ',') break;
	    ADVANCE;
	}
    }
}

void parse_restrict_disjunct()
{
    /* clear the current settings */
    tslot->start = 0;
    tslot->end = 0;
    tslot->wday = 0;
    tslot->mday = 0;
    tslot->month = 0;
    tslot->next = 0;
    eat_whitespace();
    parse_time(set_start);
    parse_whitespace();
    parse_time(set_end);
    parse_whitespace();
    parse_times(set_weekdays);
    parse_whitespace();
    parse_times(set_days);
    parse_whitespace();
    parse_times(set_month);
    eat_whitespace();
}

void parse_restrict(void *var, char **argv)
{
    tslot = cslot = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
    tokenize("restrict",5,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_restrict_disjunct();

    while (token->type == ',') {
	ADVANCE;
    	tslot->next = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
	tslot = tslot->next;
	parse_restrict_disjunct();
    }
    free_tokens();
}


void parse_or_restrict(void *var, char **argv)
{
    tokenize("restrict",5,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    tslot->next = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
    tslot = tslot->next;
    parse_restrict_disjunct();
    free_tokens();
}

void parse_new_prule_name(void)
{
    int i;
    if (token->type != TOK_STR) parse_error("Expecting a string.");
    for (i = 0; i < nprules; i++)
	if (strcmp(token->str,prules[i].name) == 0)
	    parse_error("Rule name already defined.");
    prules[nprules].name = strdup(token->str);
    ADVANCE;
}

void parse_protocol_name(FW_ProtocolRule *prule)
{
    int proto;
    if (token->type == TOK_STR) {
	if (strcmp(token->str,"any") == 0)
	    { prule->protocol = 0xffff; ADVANCE; return; }
        if ((proto = getprotocol(token->str)))
	    { prule->protocol = proto; ADVANCE; return; }
	parse_error("Expecting a protocol name or 'any'.");
    } else if (token->type == TOK_NUM) {
	int p;
	sscanf(token->str,"%i",&p);
	prule->protocol = p;
	ADVANCE;
    } else
        parse_error("Expecting a string or a number.");
}

int parse_offset(void)
{
    int v;
    int flag = 0;
    if (token->type == '+') { flag = 1; ADVANCE; }
    if (token->type == TOK_NUM) {
	sscanf(token->str,"%i",&v);
	ADVANCE;
	if (FW_OFFSET(v) != v) parse_error("Offset definition out of range.");
	return ((flag) ? FW_DATA_OFFSET(v) : FW_HDR_OFFSET(v));
    }
    parse_error("Expecting an offset definition: <num> or +<num>.");
    return 0; /* NOTREACHED */
}

int parse_width(void)
{
    if (token->type == TOK_STR) {
	if (!strcmp(token->str, "b")) { /* b(yte) */
	    ADVANCE; return 1;
	} else if (!strcmp(token->str, "w")) { /* w(ord) */
	    ADVANCE; return 2;
	} else if (!strcmp(token->str, "t")) { /* t(riple) */
	    ADVANCE; return 3;
	} else if (!strcmp(token->str, "q")) { /* q(uad) */
	    ADVANCE; return 4;
	}
	parse_error("Expecting a width: b, w, t, q or [<n>]");
    } else if (token->type == TOK_NUM) {
	    int width = 0;
	    sscanf(token->str, "%i", &width);
	    if (width <= 0
	    || width > FW_MAX_ADDR_UINTS*sizeof(unsigned int))
		parse_error("Width value must be 1-16.");
	    ADVANCE;
	    return width;
    }
    return 1; /* default to 1 byte */
}

void parse_prule_spec(FW_ProtocolRule *prule)
{
    prule->clen = 0;
    if (token->type == '-') {
	ADVANCE; return;
    }
    while (prule->clen < FW_ID_LEN) {
	char flag;
	unsigned int offset, width;

	flag = ' ';
	if (token->type == '<' || token->type == '>') {
	    flag = token->type;
	    ADVANCE;
	}

	offset = parse_offset();
	if (flag == '<')
	    offset = FW_SRC_OFFSET(offset);
	else if (flag == '>')
	    offset = FW_DST_OFFSET(offset);

	width = 1;
	if (token->type == '[') {
	    ADVANCE;
	    width = parse_width();
	    if (token->type != ']') parse_error("Expecting a ']'.");
	    ADVANCE;
	}

	while (width-- > 0) {
	    prule->codes[prule->clen++] = offset++;
	    if (prule->clen == FW_ID_LEN)
		parse_error("ID specification too long.");
	}

	if (token->type == TOK_EOF) return;
	if (token->type != ',') parse_error("Expecting ','");
	ADVANCE;
    }
}

int parse_prule_name()
{
    int i;
    if (token->type != TOK_STR) parse_error("Expecting a string.");
    for (i = 0; i < nprules; i++)
	if (strcmp(token->str,prules[i].name) == 0) {
	    ADVANCE;
	    return i;
	}
    parse_error("Not a known protocol rule.");
    return 0; /* NOTREACHED */
}

void parse_timeout(FW_Filter *filter)
{
    int to;
    if (token->type != TOK_NUM) parse_error("Expecting a number.");
    sscanf(token->str,"%i",&to);
    if (to < 0)
	parse_error("Out of acceptable range for a timeout.");
    filter->timeout = to;
    ADVANCE;
}

/* <rvalue> ::= <num> | <name> | <inet> */
void parse_rvalue(unsigned char *type, unsigned int *v)
{
    memset(v, 0, sizeof(v));

    if (token->type == TOK_NUM) {
	/* A "simple" number, possibly with a 0 or 0x prefix for
	 * octal or hex, no bigger than an int.
	 */
	sscanf(token->str,"%i", &v[FW_MAX_ADDR_UINTS-1]);
	*type = FW_VAR_NUMERIC;
	ADVANCE; return;
    } else if (token->type == TOK_HEX) {
	char *p;
	int i;

	i = 0;
	p = token->str;
	if (p[0] == '0' && p[1] == 'x') p += 2;
	while (*p) {
	    /* Hex strings can have colons separating terms but if
	     * so all digits *must* be specified because we do not
	     * know how wide each term is.
	     */
	    if (p[0] == ':')
		continue;

	    for (i=0; i<FW_MAX_ADDR_UINTS-2; i++)
		v[i] = (v[i] << 4) | (v[i+1] >> (8*sizeof(v[0])-4));
	    if (isdigit(p[0]))
		v[i] = (v[i] << 4) | (p[0] - '0');
	    else
		v[i] = (v[i] << 4) | (toupper(p[0]) - 'A' + 10);

	    p++;
	}
#if 0
mon_syslog(LOG_INFO, "hex val: %08x:%08x:%08x:%08x", v[0], v[1], v[2], v[3]);
#endif
	*type = FW_VAR_HEX;
	ADVANCE; return;
    } else if (token->type == TOK_INET) {
	unsigned int ipa, ipb, ipc, ipd;
	if (sscanf(token->str, "%u.%u.%u.%u", &ipa, &ipb, &ipc, &ipd) != 4)
	    parse_error("Bad inet address specification.");
	v[FW_MAX_ADDR_UINTS-1] = (ipa<<24)|(ipb<<16)|(ipc<<8)|ipd;
	*type = FW_VAR_DOTQUAD;
	ADVANCE; return;
    } else if (token->type == TOK_INET6) {
	char *p;
	int i, j, k, split = -1;
	unsigned short ip6[128/16];

	i = 0;
	p = token->str;
	if (*p == ':' && *(++p) != ':')
	    parse_error("Leading ':' should be leading '::'?");
	while (*p) {
	    char *q = p;

	    ip6[i] = 0;
	    while (isxdigit(*p)) {
		ip6[i] = (ip6[i] << 4)
		    | (*p <= '9' ? *p-'0' : toupper(*p)-'A'+10);
		p++;
	    }
	    if (p != q) {
		if (*p == '.') {
		    unsigned int ipa, ipb, ipc, ipd;
		    if (sscanf(q, "%u.%u.%u.%u", &ipa, &ipb, &ipc, &ipd) != 4)
			parse_error("Bad inet address specification.");
		    ip6[i++] = (ipa<<8)|ipb;
		    ip6[i++] = (ipc<<8)|ipd;
		    break;
		}
		i++;
		if (*p == ':') p++;
		continue;
	    }

	    if (*p != ':')
		parse_error("Trailing garbage?");

	    split = i;
	    p++;
	}
	if (split < 0) split = i;

	j = 0;
	k = FW_MAX_ADDR_UINTS
	    - (sizeof(ip6) + sizeof(v[0])-1) / sizeof(v[0]);
	while (j < split) {
	    v[k] |= ip6[j]
		<< (16 * ((sizeof(v[0])/sizeof(ip6[0]) - 1)
			- (j % (sizeof(v[0])/sizeof(ip6[0])))));
	    if ((++j % (sizeof(v[0])/sizeof(ip6[0]))) == 0)
		k++;
	}

	j = split;
	k = FW_MAX_ADDR_UINTS
	    - ((i-split)*sizeof(ip6[0]) + sizeof(v[0])-1) / sizeof(v[0]);
	while (j < i) {
	    v[k] |= ip6[j]
		<< (16 * ((sizeof(v[0])/sizeof(ip6[0]) - 1)
			- ((i-j) % (sizeof(v[0])/sizeof(ip6[0])))));
	    if (((i-(++j)) % (sizeof(v[0])/sizeof(ip6[0]))) == 0)
		k++;
	}

	*type = FW_VAR_INET6;
	ADVANCE; return;
    } else if (token->type == TOK_STR) {
	if (strncmp("udp.",token->str,4) == 0) {
	    if ((v[FW_MAX_ADDR_UINTS-1] = getservice(token->str+4,"udp"))) {
		*type = FW_VAR_UDPPORT;
	 	ADVANCE; return;
	    }
	    parse_error("Not a known udp service port.");
	} else if (strncmp("tcp.",token->str,4) == 0) {
	    if ((v[FW_MAX_ADDR_UINTS-1] = getservice(token->str+4,"tcp"))) {
		*type = FW_VAR_TCPPORT;
	 	ADVANCE; return;
	    }
	    parse_error("Not a known tcp service port.");
	} else if ((v[FW_MAX_ADDR_UINTS-1] = getprotocol(token->str))) {
	    *type = FW_VAR_PROTOCOL;
	    ADVANCE; return;
	}
	parse_error("Not a known value name.");
    } else {
	parse_error("Expecting an <rvalue> specification.");
    }
}


unsigned char parse_vartype()
{
    static struct {
	char *name;
	unsigned char val;
    } types[] = {
	{ "protocol",	FW_VAR_PROTOCOL },
	{ "port",	FW_VAR_PORT },
	{ "tcpport",	FW_VAR_TCPPORT },
	{ "udpport",	FW_VAR_UDPPORT },
	{ "dotquad",	FW_VAR_DOTQUAD },
	{ "ipv4",	FW_VAR_DOTQUAD },
	{ "ip",		FW_VAR_DOTQUAD },
	{ "ipv6",	FW_VAR_INET6 },
	{ "ip6",	FW_VAR_INET6 }
    };
    int i;

    if (token->type != TOK_STR)
	parse_error("Expecting a var type.");
    for (i=0; i<sizeof(types)/sizeof(types[0]); i++) {
	if (!strcmp(types[i].name, token->str)) {
	    ADVANCE;
	    return types[i].val;
	}
    }
    parse_error("Expecting a var type.");
    return 0; /* NOTREACHED */
}

/* <varspec> ::= [<constant>]
 *             | [{proto} @[+]<offset> \[[bwtq]\] [[<<>>]<shift>]
 *               [&<mask>] [+<const>] [?<type>]
 */
void parse_varspec(struct var *variable)
{
    int is_first = 1;

    variable->valid = 1;
    variable->type = FW_VAR_NUMERIC;
    variable->next_dirty = NULL;
    memset(variable->u.n.mask, ~0, sizeof(variable->u.n.mask));
    memset(variable->u.n.cval, 0, sizeof(variable->u.n.cval));
    variable->u.n.offset = 0;
    variable->u.n.width = 0;
    variable->u.n.shift = 0;

    while (token->type != TOK_EOF
    && token->type != ' '
    && token->type != ',') {
	if (token->type == '?') {
	    ADVANCE;
	    variable->type = parse_vartype();
	} else if (token->type == '{') {
	    ADVANCE;
	    variable->prule = parse_prule_name();
	    if (token->type != '}') parse_error("Expecting a '}'.");
	    ADVANCE;
	    variable->valid |= 2;
	} else if (token->type == '@') {
	    ADVANCE;
	    variable->u.n.offset = parse_offset();
	    variable->valid &= 2;
	} else if (token->type == '[') {
	    ADVANCE;
	    variable->u.n.width = parse_width();
	    if (token->type != ']') parse_error("Expecting a ']'.");
	    ADVANCE;
	} else if (token->type == TOK_LSHIFT) {
	    int shift;
	    ADVANCE;
	    if (token->type != TOK_NUM)
		parse_error("Expecting a bit shift value.");
	    sscanf(token->str, "%i", &shift);
	    if (shift > 31) parse_error("Shift value must be 0-31.");
	    variable->u.n.shift = shift;
	    ADVANCE;
	} else if (token->type == TOK_RSHIFT) {
	    int shift;
	    ADVANCE;
	    if (token->type != TOK_NUM)
		parse_error("Expecting a bit shift value.");
	    sscanf(token->str, "%i", &shift);
	    if (shift > 31) parse_error("Shift value must be 0-31.");
	    variable->u.n.shift = -shift;
	    ADVANCE;
        } else if (token->type == '&') {
	    unsigned char type;
	    ADVANCE;
	    parse_rvalue(&type, variable->u.n.mask);
	    variable->type = type;
	} else if (token->type == '+') {
	    unsigned char type;
	    ADVANCE;
	    parse_rvalue(&type, variable->u.n.cval);
	    variable->type = type;
	} else
	    break;
	is_first = 0;
    }

    if (is_first
    && token->type != TOK_EOF
    && token->type != ' '
    && token->type != ',') {
	if (token->type == TOK_QSTR) {
	    variable->type = FW_VAR_STRING;
	    variable->u.s = strdup(token->str);
	    ADVANCE;
	} else {
	    unsigned char type;
	    parse_rvalue(&type, variable->u.n.cval);
	    variable->type = type;
	}
    }

    /* If it is still valid we have a simple constant so assign
     * the value now.
     */
    if (variable->type != FW_VAR_STRING
    && (variable->valid & 1)) {
	memcpy(variable->u.n.value, variable->u.n.cval,
	    sizeof(variable->u.n.value));
    }
}

void parse_var_name(struct var *variable)
{
    struct var *cvar;

    if (token->type == TOK_STR) {
	for (cvar = vars; cvar; cvar = cvar->next) {
	    if (strcmp(cvar->name,token->str) == 0)
		parse_error("Expecting a new variable name");
	}
	variable->name = strdup(token->str);
	ADVANCE;
    } else
       parse_error("Expecting a variable name.");
}

/* <varref> ::= <name> | <varspec> */
struct var *
parse_varref()
{
    struct var *cvar;

    if (token->type == TOK_STR) {
	for (cvar = vars; cvar; cvar = cvar->next) {
	    if (strcmp(cvar->name,token->str) == 0) {
		cvar->refs++;
		ADVANCE;
		return cvar;
	    }
	}
    }

    cvar = malloc(sizeof(struct var));
    if (cvar == 0) { mon_syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    cvar->name = NULL;
    parse_varspec(cvar);
    cvar->refs = 1;
    cvar->name = NULL;
    return cvar;
}

/* <lvalue> ::= <varref> | <varref>&<rvalue> */
void parse_lvalue(FW_Term *term)
{
    term->var = parse_varref();
    term->mask = NULL;
    if (token->type == '&') {
	ADVANCE;
	term->mask = parse_varref();
    }
}

int parse_op(FW_Term *term)
{
    if (token->type == TOK_NE) term->op = FW_NE;
    else if (token->type == '=') term->op = FW_EQ;
    else if (token->type == TOK_GE) term->op = FW_GE;
    else if (token->type == TOK_LE) term->op = FW_LE;
    else return 0;
    ADVANCE;
    return 1;
}

/* <term> ::= <lvalue> | !<lvalue> | <lvalue> <op> <rvalue> */
void parse_term(FW_Filter *filter)
{
    if (token->type == '!') {
	ADVANCE;
	parse_lvalue(&filter->terms[filter->count]);
	filter->terms[filter->count].op = FW_EQ;
	filter->terms[filter->count].test = NULL;
    } else {
	parse_lvalue(&filter->terms[filter->count]);
	if (parse_op(&filter->terms[filter->count])) {
	    filter->terms[filter->count].test = parse_varref();
	} else {
	    filter->terms[filter->count].op = FW_NE;
	    filter->terms[filter->count].test = NULL;
	}
    }
    filter->count++;
}

void parse_terms(FW_Filter *filter)
{
    if (token->type == TOK_STR && strcmp(token->str,"any") == 0)
	{ ADVANCE; return; }
    parse_term(filter);
    while (token->type == ',') { ADVANCE; parse_term(filter); }
}

void parse_proto(void *var, char **argv)
{
    FW_ProtocolRule prule;
    struct firewall_req req;
    tokenize("proto",5,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    prule.hdr = prule.data = NULL;
    prule.var_dirty = NULL;
    prule.next_dirty = 0;
    prule.nsubs = 0;
    parse_new_prule_name();
    parse_whitespace();
    parse_protocol_name(&prule);
    parse_whitespace();
    prule.nxt_offset = parse_varref();
    if (prule.nxt_offset->type == FW_VAR_STRING)
	parse_error("Expecting a numeric variable type");
    parse_whitespace();
    prule.nxt_proto = parse_varref();
    if (prule.nxt_proto->type == FW_VAR_STRING)
	parse_error("Expecting a numeric variable type");
    parse_whitespace();
    parse_prule_spec(&prule);
    free_tokens();
    nprules++;
    /* Save the prule in the kernel */
    req.unit = fwunit;
    req.fw_arg.rule = prule;
    ctl_firewall(IP_FW_APRULE,&req);
}

void parse_sub_proto(int proto)
{
    struct firewall_req req;
    req.unit = fwunit;
    req.fw_arg.vals[0] = proto;
    req.fw_arg.vals[1] = parse_prule_name();
    ctl_firewall(IP_FW_APSUB, &req);
}

void parse_subproto(void *var, char **argv)
{
    int proto;
    tokenize("subproto",2,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    proto = parse_prule_name();
    parse_whitespace();
    parse_sub_proto(proto);
    while (token->type == ',') { ADVANCE; parse_sub_proto(proto); }
    free_tokens();
}

/* <describe> ::= <varref> ["<fmt>"] */
void parse_describe(void *var, char **argv)
{
    FW_Desc desc;
    int i;
    struct firewall_req req;
    tokenize("describe",1,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    desc.vars[0] = parse_varref();
    desc.fmt[0] = NULL;
    if (token->type == TOK_QSTR)
	{ desc.fmt[0] = strdup(token->str); ADVANCE; }
    i = 1;
    while (token->type == ',') {
	ADVANCE;
	desc.vars[i] = parse_varref();
	desc.fmt[i] = NULL;
	if (token->type == TOK_QSTR)
	    { desc.fmt[i] = strdup(token->str); ADVANCE; }
	if (++i == FW_MAX_DESCVARS)
	    parse_error("Too many vars in description.");
    }
    desc.vars[i] = NULL;
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.desc = desc;
    ctl_firewall(IP_FW_ADESC,&req);
}

void parse_bringup(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_BRINGUP;
    tokenize("bringup",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    filter.prule = parse_prule_name();
    parse_whitespace();
    parse_timeout(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_keepup(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_KEEPUP;
    tokenize("keepup",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    filter.prule = parse_prule_name();
    parse_whitespace();
    parse_timeout(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_accept(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_ACCEPT;
    tokenize("accept",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    filter.prule = parse_prule_name();
    parse_whitespace();
    parse_timeout(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_ignore(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_IGNORE;
    tokenize("ignore",2,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    filter.prule = parse_prule_name();
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_up(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_UP;
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_down(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_DOWN;
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_impulse(void *var, char **argv)
{
    int t1,t2;

    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_IMPULSE;
    tokenize("impulse",1,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }

    if (token->type != TOK_NUM)
	parse_error("Expecting a number.");
    sscanf(token->str,"%i",&t1);
    ADVANCE;
    if (token->type != ',')
	parse_error("Expecting a ','");
    ADVANCE;
    if (token->type != TOK_NUM)
	parse_error("Expecting a number.");
    sscanf(token->str,"%i",&t2);
    ADVANCE;
    if (token->type == ',') {
	filter.timeout2 = t1;
	filter.timeout = t2;
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number.");
	sscanf(token->str,"%i",&filter.fuzz);
	ADVANCE;
    } else {
	filter.timeout = t1;
	filter.timeout2 = t1;
	filter.fuzz = t2;
    }

    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_var(void *var, char **argv)
{
    struct var *variable = malloc(sizeof(struct var));
    if (variable == 0) { mon_syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    tokenize("var",2,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_var_name(variable);
    parse_whitespace();
    parse_varspec(variable);
    free_tokens();
    /* add the new variable to the linked list */
    variable->refs = 1;
    variable->next = vars;
    vars = variable;
}

void flush_prules(void)
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_PFLUSH,&req);
    nprules = 0;
}

void flush_vars(void)
{
    struct var *next;
    for (; vars; vars = next) {
	next = vars->next;
	if (!--vars->refs) {
	    if (vars->name) free(vars->name);
	    free(vars);
	}
    }
    vars = 0;
}

void flush_filters(void)
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_FFLUSH,&req);
}
