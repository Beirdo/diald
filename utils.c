#include <config.h>

#include <diald.h>


/* Grumble. Attempt to generate a nicely formatted ascii date without
 * a built in newline.
 */
char *cdate(time_t now)
{
    static char dt[128];
    int len;

    len = strftime(dt, 128, "%c %Z", localtime(&now));
    if (len == 128) dt[len] = 0;
    return dt;
}

int getsn(FILE *fp,char *buf,int len)
{
    int c;
    int i = 0;
    while ((c = fgetc(fp)) != EOF) {
	if (c == '\n') {
	    buf[i] = 0;
	    return i;
	}
	if (i < len-1) {
	    buf[i++] = c;
	}
    }
    if (i == 0)
    	return EOF;
    buf[i] = 0;
    return i;
}


struct proto {
	char *name;
	int proto;
};

static struct proto *protos = NULL;
static int proto_init = 0;
static int proto_lines = 0;


static void
init_protos(void)
{
	char **alias;
	struct protoent *proto_entry;

	setprotoent(1);
	while ((proto_entry = getprotoent())) {
		proto_lines++;
		alias = proto_entry->p_aliases;
		/* also count any aliases listed in /etc/protocols */
		while (*alias) {
			proto_lines++;
			alias++;
		}
	}
	endprotoent();

	setprotoent(1);
	protos = malloc(sizeof(struct proto) * proto_lines);
	proto_lines = 0;
	while ((proto_entry = getprotoent())) {
		protos[proto_lines].name = strdup(proto_entry->p_name);
		protos[proto_lines].proto = proto_entry->p_proto;
		proto_lines++;
		alias = proto_entry->p_aliases;
		while (*alias) {
			protos[proto_lines].name = strdup(*alias);
			protos[proto_lines].proto = proto_entry->p_proto;
			proto_lines++;
			alias++;
		}
	}
	endprotoent();

	proto_init=1;
}


int
getprotocol(const char *name)
{
	int i;

	if (!proto_init)
		init_protos();

	for (i = 0; i < proto_lines; i++)
		if (strcmp(protos[i].name,name) == 0)
			return protos[i].proto;
	return 0;
}


char *
getprotonumber(int proto)
{
	static char buf[16];
	int i;

	if (!proto_init)
		init_protos();

	for (i = 0; i < proto_lines; i++)
		if (protos[i].proto == proto)
			return protos[i].name;

	sprintf(buf, "%d", proto);
	return buf;
}


struct serv {
	char *name;
	char *proto;
	int serv;
};

static struct serv *servs = NULL;
static int serv_init = 0;
static int serv_lines = 0;


static void
init_servs(void)
{
	char **alias;
	struct servent *serv_entry;

	setservent(1);
	while ((serv_entry = getservent())) {
		serv_lines++;
		alias = serv_entry->s_aliases;
		/* also count any aliases listed in /etc/services */
		while (*alias){
			serv_lines++;
			alias++;
		}
	}
	endservent();
  
	setservent(1);
	servs = malloc(sizeof(struct serv) * serv_lines);
	serv_lines = 0;
	while ((serv_entry = getservent())) {
		servs[serv_lines].name = strdup(serv_entry->s_name);
		servs[serv_lines].proto = strdup(serv_entry->s_proto);
		servs[serv_lines].serv = serv_entry->s_port;
		serv_lines++;
		alias = serv_entry->s_aliases;
		while (*alias) {
			servs[serv_lines].name = strdup(*alias);
			servs[serv_lines].proto = strdup(serv_entry->s_proto);
			servs[serv_lines].serv = serv_entry->s_port;
			serv_lines++;
			alias++;
		}
	}
	endservent();

	serv_init=1;
}


int
getservice(const char *name, const char *proto)
{
	int i;

	if (!serv_init)
		init_servs();

	for (i = 0; i < serv_lines; i++)
		if (strcmp(servs[i].name,name) == 0
		&& strcmp(servs[i].proto,proto) == 0)
			return servs[i].serv;

	return 0;
}
