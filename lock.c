/*
 * lock.c - lock/unlock the serial device.
 *
 * This code is derived from chat.c.
 */

#include "diald.h"

static char *lock_file;

/*
 *	Create a lock file for the named lock device
 */
int lock(char *dev)
{
    char hdb_lock_buffer[12];
    int fd, pid, n;
    char *p;

    if ((p = strrchr(dev, '/')) != NULL)
	dev = p + 1;
    lock_file = malloc(strlen(lock_prefix) + strlen(dev) + 1);
    if (lock_file == NULL)
	return -1;
    strcat(strcpy(lock_file, lock_prefix), dev);

    while ((fd = open(lock_file, O_EXCL | O_CREAT | O_RDWR, 0644)) < 0) {
	if (errno == EEXIST
	    && (fd = open(lock_file, O_RDONLY, 0)) >= 0) {
	    /* Read the lock file to find out who has the device locked */
	    if (pidstring) {
		n = read(fd, hdb_lock_buffer, 11);
		if (n > 0) {
		    hdb_lock_buffer[n] = 0;
		    pid = atoi(hdb_lock_buffer);
		}
	    } else {
		n = read(fd, &pid, sizeof(pid));
	    }
	    if (n <= 0) {
		syslog(LOG_ERR, "Can't read pid from lock file %s", lock_file);
		close(fd);
	    } else {
		if (kill(pid, 0) == -1 && errno == ESRCH) {
		    /* pid no longer exists - remove the lock file */
		    if (unlink(lock_file) == 0) {
			close(fd);
			syslog(LOG_NOTICE, "Removed stale lock on %s (pid %d)",
			       dev, pid);
			continue;
		    } else
			syslog(LOG_WARNING, "Couldn't remove stale lock on %s",
			       dev);
		} else
		    syslog(LOG_NOTICE, "Device %s is locked by pid %d",
			   dev, pid);
	    }
	    close(fd);
	} else
	    syslog(LOG_ERR, "Can't create lock file %s: %m", lock_file);
	free(lock_file);
	lock_file = NULL;
	return -1;
    }

    if (pidstring) {
    	sprintf(hdb_lock_buffer, "%10d\n", getpid());
    	write(fd, hdb_lock_buffer, 11);
    } else {
    	pid = getpid();
    	write(fd, &pid, sizeof pid);
    }

    close(fd);
    return 0;
}

/*
 *	Remove our lockfile
 */
void unlock()
{
    if (lock_file) {
	unlink(lock_file);
	free(lock_file);
	lock_file = NULL;
    }
}

