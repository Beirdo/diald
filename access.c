#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "diald.h"


/* FIXME: this should be a config option... */
#define DIALD_ACC_SIMPLE_FILE	"/usr/lib/diald/auth"


static struct {
	char *name;
	int value;
} acc_name[] = {
	{ "none",	0		},
	{ "control",	ACCESS_CONTROL	},
	{ "config",	ACCESS_CONFIG	},
	{ "block",	ACCESS_BLOCK	},
	{ "unblock",	ACCESS_UNBLOCK	},
	{ "force",	ACCESS_FORCE	},
	{ "unforce",	ACCESS_UNFORCE	},
	{ "down",	ACCESS_DOWN	},
	{ "up",		ACCESS_UP	},
	{ "delquit",	ACCESS_DELQUIT	},
	{ "quit",	ACCESS_QUIT	},
	{ "reset",	ACCESS_RESET	},
	{ "queue",	ACCESS_QUEUE	},
	{ "debug",	ACCESS_DEBUG	},
	{ "dynamic",	ACCESS_DYNAMIC	},
	{ "monitor",	ACCESS_MONITOR	},
	{ "message",	ACCESS_MESSAGE	},
	{ "connect",	ACCESS_CONNECT	},
	{ "demand",	ACCESS_DEMAND	},
	{ "nodemand",	ACCESS_NODEMAND	},
	{ "auth",	ACCESS_AUTH	}
};


static int
acc_strtovec(char *buf)
{
	int n;
	char *p;

	if (buf[0] == '0' && buf[1] == 'x')
		return strtoul(buf, NULL, 16);

	n = 0;
	p = strtok(buf, ", ");
	while (p) {
		if (*p) {
			int i;
			for (i=0; i<sizeof(acc_name)/sizeof(acc_name[0]); i++) {
				if (!strcmp(acc_name[i].name, p)) {
					n |= acc_name[i].value;
					break;
				}
			}
		}
		p = strtok(NULL, ", ");
	}

	return n;
}


static int
acc_simple(char *buf)
{
	int new_access = CONFIG_DEFAULT_ACCESS;
	FILE *fd;
	char line[1024];

	if (!(fd = fopen(DIALD_ACC_SIMPLE_FILE, "r")))
		return new_access;

	while (fgets(line, sizeof(line), fd)) {
		char *p;

		/* Comments have a '#' in the first column. */
		if (line[0] == '#') continue;

		for (p=line+strlen(line)-1; p >= line && *p == '\n'; p--)
			*p = '\0';
		for (p=line; *p && *p != ' ' && *p != '\t'; p++);
		if (*p) *(p++) = '\0';
		while (*p == ' ' || *p == '\t') p++;

		if (!strcmp(line, buf) || !strcmp(line, "*")) {
			new_access = acc_strtovec(p);
			break;
		}
	}
	fclose(fd);

	return new_access;
}


int
ctrl_access(char *buf)
{
	int new_access = CONFIG_DEFAULT_ACCESS;

	if (buf && *buf) {
		if (!strncmp(buf, "simple ", 7)) {
			new_access = acc_simple(buf+7);
		}
	}

	return new_access;
}
