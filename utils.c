#include "diald.h"

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
static int proto_init=0;
static int proto_lines=0;

static void init_protos()
{
    FILE *fp;
    char line[1024];
    char name[20];
    int proto;

    if ((fp = fopen("/etc/protocols","r"))) {
	while (getsn(fp,line,1024) != EOF) {
	    if (sscanf(line,"%s %d",name,&proto) == 2)
		proto_lines++;
	}
	fclose(fp);
    	if ((fp = fopen("/etc/protocols","r"))) {
	    protos = malloc(sizeof(struct proto)*proto_lines);
	    proto_lines = 0;
	    while (getsn(fp,line,1024) != EOF) {
		if (sscanf(line,"%s %d",name,&proto) == 2) {
		    protos[proto_lines].name = strdup(name);
		    protos[proto_lines].proto = proto;
		    proto_lines++;
		}
	    }
	    fclose(fp);
	}
    }
    proto_init=1;
}

int getprotocol(const char *name)
{
    int i;
    if (!proto_init)
	init_protos();
    for (i = 0; i < proto_lines; i++)
	if (strcmp(protos[i].name,name) == 0)
	    return protos[i].proto;
    return 0;
}

char *getprotonumber(int proto)
{
    int i;
    if (!proto_init)
	init_protos();
    for (i = 0; i < proto_lines; i++)
	if (protos[i].proto == proto)
	    return protos[i].name;
    return 0;
}

struct serv {
	char *name;
	char *proto;
	int serv;
};

static struct serv *servs = NULL;
static int serv_init=0;
static int serv_lines=0;

static void init_servs()
{
    FILE *fp;
    char line[1024];
    char name[20];
    char proto[20];
    int serv;

    if ((fp = fopen("/etc/services","r"))) {
	while (getsn(fp,line,1024) != EOF) {
	    if (sscanf(line,"%s %d/%s",name,&serv,proto) == 3)
		serv_lines++;
	}
	fclose(fp);
    	if ((fp = fopen("/etc/services","r"))) {
	    servs = malloc(sizeof(struct serv)*serv_lines);
	    serv_lines = 0;
	    while (getsn(fp,line,1024) != EOF) {
	    	if (sscanf(line,"%s %d/%s",name,&serv,proto) == 3) {
		    servs[serv_lines].name = strdup(name);
		    servs[serv_lines].proto = strdup(proto);
		    servs[serv_lines].serv = serv;
		    serv_lines++;
		}
	    }
	    fclose(fp);
	}
    }
    serv_init=1;
}

int getservice(const char *name, const char *proto)
{
    int i;
    if (!serv_init)
	init_servs();
    for (i = 0; i < serv_lines; i++)
	if (strcmp(servs[i].name,name) == 0
	&& strcmp(servs[i].proto,proto) == 0) {
	    return servs[i].serv;
        }
    return 0;
}

#if 0
/* Stuff needed because to keep checker happy,
 * because the fast versions of these address memory in four
 * byte blocks, which are often outside of permitted ranges.
 */
int strlen(const char *s)
{
   int i = 0;
   while (*s++)
	i++;
   return i;
}

char *strdup(const char *s)
{
     char *t = malloc(strlen(s)+1);
     char *t2 = t;
     while ((*t++ = *s++));
     return t2;
}

char *strrchr(const char *s, int c)
{
    int i;
    for (i = strlen(s)-1; i >= 0; i--)
	if (s[i] == c) return (char *)&s[i];
    return 0;
}

char *strcat(char *dest, const char *src)
{
	char *p = dest;
	while ((*p++));
	p--;
	while ((*p++ = *src++));
	return dest;
}
#endif
