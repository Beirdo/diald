/*
 * access.c - Monitor access stuff.
 *
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#if HAVE_SYSLOG_H
#  include <syslog.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>

#if HAVE_LIBPAM
#include <security/pam_appl.h>
#endif

#include <diald.h>


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

	if (!(fd = fopen(authsimple, "r")))
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


#if HAVE_LIBPAM

static char *acc_pam_user;
static char *acc_pam_pass;

static int acc_pam_conv(int num_msg,
		const struct pam_message **msg,
		struct pam_response **resp,
		void *appdata_ptr)
{
	struct pam_response *reply = malloc(sizeof(struct pam_response)*num_msg);
	int i;
	
	if (!reply)
		return PAM_CONV_ERR;
	
	for (i = 0 ; i < num_msg ; i++)
	{
		switch (msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_ON:
				reply[i].resp_retcode = PAM_SUCCESS;
				reply[i].resp = (acc_pam_user ? strdup(acc_pam_user) : NULL);
				break;
				
			case PAM_PROMPT_ECHO_OFF:
				reply[i].resp_retcode = PAM_SUCCESS;
				reply[i].resp = (acc_pam_pass ? strdup(acc_pam_pass) : NULL);
				break;			
			
			case PAM_TEXT_INFO:
			case PAM_ERROR_MSG:
				reply[i].resp_retcode = PAM_SUCCESS;
				reply[i].resp = NULL;
				break;
			
			default:
				free(reply);
				return PAM_CONV_ERR;
		}
	}
	*resp = reply;
	return PAM_SUCCESS;
}


static int acc_pam_auth(char *user, char *pass)
{
	pam_handle_t *pamh;
	struct pam_conv acc_pam_conv_d = { acc_pam_conv, NULL};
	int ret;
	
	acc_pam_user = user;
	acc_pam_pass = pass;

	if ((ret = pam_start("diald", user, &acc_pam_conv_d,&pamh))			!= PAM_SUCCESS)
		mon_syslog(LOG_WARNING, "PAM initialisation for user %s (error %d)", user, ret);

	if (ret == PAM_SUCCESS &&
	    (ret = pam_authenticate(pamh, PAM_SILENT)) != PAM_SUCCESS)
		mon_syslog(LOG_WARNING, "Failed to authenticate user %s (error %d)", user, ret);

	if (pam_end(pamh, ret != PAM_SUCCESS))
		mon_syslog(LOG_WARNING, "PAM cleanup failed (error %d)", ret);

	if (ret != PAM_SUCCESS)
		return 1;
	else
		return 0;
}


static int
acc_pam(char *buf)
{
	FILE *fd;
	char line[1024];

	char *pass;
	for (pass=buf+strlen(buf)-1; pass >= buf && (*pass == '\n' ||
	*pass == ' ' || *pass == '\t'); pass--)
		*pass = '\0';
	for (pass=buf; *pass && *pass != ' ' && *pass != '\t'; pass++);
	if (*pass) *(pass++) = '\0';
	while (*pass == ' ' || *pass == '\t') pass++;

	if (acc_pam_auth(buf, pass))
		return CONFIG_DEFAULT_ACCESS;


	if (!(fd = fopen(authpam, "r")))
		return CONFIG_DEFAULT_ACCESS;

	while (fgets(line, sizeof(line), fd)) {
		char *p;
		struct group *grp = NULL;
		/* Comments have a '#' in the first column. */
		if (line[0] == '#') continue;

		for (p=line+strlen(line)-1; p >= line && *p == '\n'; p--)
			*p = '\0';
		for (p=line; *p && *p != ' ' && *p != '\t'; p++);
		if (*p) *(p++) = '\0';
		while (*p == ' ' || *p == '\t') p++;

                {
                	if (!strcmp(line, "*"))
                	{
                		fclose(fd);
                		return acc_strtovec(p);
                	}
			else if ((grp = getgrnam(line)))
			{
				while (*(grp->gr_mem))
				{
					if (!strcmp(*grp->gr_mem, buf))
					{
						fclose(fd);
						return acc_strtovec(p);
					}
					grp->gr_mem++;
				}
			}
		}
	}
	fclose(fd);

	return CONFIG_DEFAULT_ACCESS;
}
#endif


int
ctrl_access(char *buf)
{
	int new_access = CONFIG_DEFAULT_ACCESS;

	if (buf && *buf) {
		if (!strncmp(buf, "simple ", 7)) {
			new_access = acc_simple(buf+7);
		}
#if HAVE_LIBPAM
		else if (!strncmp(buf, "pam ", 4)) {
			new_access = acc_pam(buf+4);
		}
#endif
	}

	return new_access;
}
