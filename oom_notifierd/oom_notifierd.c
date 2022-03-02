/* 
 * Description:
 * This program notifies a user when the oom-killer kills a process in that
 * user's cgroup.  This should be run per ssh session and will exit within
 * TIMEOUT_SECONDS seconds if the user's ssh connection is terminated. The
 * notification is only done for the pseudo-tty that is allocated for the
 * ssh connection from which the oom_notifierd is run.  The best place to
 * run this from is probably /etc/ssh/sshrc. This was not coded in a portable
 * fashion so minor changes may be necessary for different kernels/distros.
 *
 * See also: https://www.kernel.org/doc/Documentation/cgroups/memory.txt
 *
 * Note: Major changes were made in April 2016. Notification is now made to
 * a single TTY instead of all TTYs from a user. The program exits based on
 * availability of the TTY instead of counting processes from a user.
 *
 * Author:   Ryan Cox <ryan_cox@byu.edu>
 *
 * Copyright (C) 2013,2016 Brigham Young University
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *  
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* definition of uint64_t */
#include <string.h> /* strdup */
#include <time.h> /* time, ctime_r */
#include <sys/eventfd.h> /* eventfd */
#include <sys/types.h> /* fstat and others */
#include <sys/stat.h> /* fstat */
#include <fcntl.h> /* open */
#include <sys/time.h> /* {get,set}priority */
#include <sys/resource.h> /* {get,set}priority */
#include <poll.h> /* poll */
#ifndef NO_GPL
#include <libgen.h> /* basename */
#include <malloc.h> /* mallopt */
#include "setproctitle.h"
#endif

#define handle_error(msg) \
    do { perror(msg); exit(1); } while (0)

#define ERROR_MSG_TO_USER "You exceeded your memory limit on this host. The kernel invoked the oom-killer which killed a process of yours to free up memory. No further action is required.\nRun 'loginlimits' to see the current limits.\a"
#define TIMEOUT_SECONDS 15
/* This should never take much cputime away from people, so let's be nice */
#define TARGET_NICE 15

void daemonize() {

	/* This seems to be necessary on RHEL 8.5 at least, since the ssh connection does
	 * not exit if you keep the stderr open.  This is a workaround until we figure
	 * a better way. */
	struct stat statbuf;
	if(fstat(2, &statbuf) != -1) {
		if(S_ISFIFO(statbuf.st_mode)) { /* if stderr is a FIFO */
			/* Assume that we're running in a non-interactive shell, and we can safely exit. */
			exit(0);
		}
	}

	/* We will use stderr to communicate with the user. Close the others */
	close(0);
	close(1);
	chdir("/");
	if(fork())
		exit(0);
	setsid();
}

void writeToTTY() {
	ssize_t s;
	char msg[1024];
	time_t localtime;
	char localtime_str[26];

	time(&localtime);
	ctime_r(&localtime, localtime_str);
	sprintf(msg,
		"\e[31m\n\n<<<<<<<<<<<<<<\n%s\n%s\n>>>>>>>>>>>>>>\e[0m\n\n",
		localtime_str, ERROR_MSG_TO_USER);

	s = write(2, msg, strlen(msg));
	if((size_t)s != (size_t)strlen(msg))
		exit(1); /* Couldn't write to tty so we might as well exit */
}

int csv_contains_field(const char *csv, const char *searchstr) {
	char *token;
        char *orig, *rest;
        orig = rest = strdup(csv); //need to preserve the original pointer, to free later

        
	while ((token = strtok_r(rest, ",", &rest))) {
		if(strcmp(searchstr, token) == 0) {
                    if(orig != NULL)
                        free(orig);
                    return(1);
		}
	}
        if(orig != NULL)
            free(orig);
	return(0);
}

int get_memcg_self_path(char *path) {
	FILE *fp;
	int is_memory_cgroup_line, pos, retval = 0;
	char *strtok_ptr, *str1, *token, line[512], *tmppath;
	
	tmppath=NULL;
	
	fp = fopen("/proc/self/cgroup", "r");
	if(fp==NULL)
		handle_error("failed to open /proc/self/cgroup");
	while(fgets(line, 512, fp) != NULL) {
		is_memory_cgroup_line = 0;
		for (pos = 0, str1 = line; ; pos++, str1 = NULL) {
			token = strtok_r(str1, ":", &strtok_ptr);
			if(token == NULL)
				break;
			if(pos == 1 && strcmp(token, "memory") == 0)
				is_memory_cgroup_line = 1;
			else if(pos == 2 && is_memory_cgroup_line) {
				/* strip newline */
				strncpy(path, token, strlen(token));
				path[strlen(token)-1] = '\0';
				retval = 1;
			}
		}
	}
	fclose(fp);
	return retval;
}

int get_memcg_mount_path(char *path) {
	FILE *fp;
	int is_memory_cgroup_line, pos, retval = 0;
	char *strtok_ptr, *str1, *token, line[512], *tmppath;
	
	tmppath=NULL;
	
	fp = fopen("/proc/mounts", "r");
	if(fp==NULL) {
		printf("failed to open /proc/mounts");
		exit(1);
	}
	while(fgets(line, 512, fp) != NULL) {
		is_memory_cgroup_line = 0;
		for (pos = 0, str1 = line; ; pos++, str1 = NULL) {
			token = strtok_r(str1, " ", &strtok_ptr);
		       
			if(token == NULL) {
				tmppath=NULL;
				break;
			}
						
			if(pos == 1) {
				tmppath=token; //Save the current path for potential future use
			} else if (pos == 3 && csv_contains_field(token, "memory")) {
				strncpy(path, tmppath, (strlen(tmppath)+1)*sizeof(char));
				path[strlen(tmppath)] = '\0';
				retval = 1;
				break;
			}
		}
	}
	fclose(fp);
	return retval;
}

char * get_cgroup_path() {
	char *memcg_path;
	char mount_path[1024], self_path[1024], path[1024];
	if(!get_memcg_mount_path(mount_path))
		handle_error("Couldn't find memory cgroup mount point in /proc/mounts");
	if(!get_memcg_self_path(self_path))
		handle_error("Couldn't find memory cgroup path in /proc/self/cgroup. Am I in a cgroup yet?");
	memcg_path = (char *)malloc(sizeof(char) * (strlen(mount_path) + strlen(self_path) + 1));
	sprintf(path, "%s%s", mount_path, self_path);
	strcpy(memcg_path, path);
	return memcg_path;
}

int open_event_fd(char *memcg_path) {
	int efd, ecfd, oomfd;
	char ecfd_str[32];
	char *filename;
	ssize_t s;

	filename = malloc(sizeof(char) * (strlen(memcg_path) + 22));
	sprintf(filename, "%s/memory.oom_control", memcg_path);
	oomfd = open(filename, O_RDONLY);
	if(oomfd == -1)
		handle_error("open oomfd");

	efd = eventfd(0, 0);
	if(efd == -1)
		handle_error("open efd");

	sprintf(filename, "%s/cgroup.event_control", memcg_path);
	ecfd = open(filename, O_WRONLY);
	if(ecfd == -1)
		handle_error("open ecfd");

	free(filename);

	/* configure event_control with file descriptors */
	sprintf(ecfd_str, "%d %d", efd, oomfd);
	s = write(ecfd, &ecfd_str, strlen(ecfd_str));
	if((size_t)s != (size_t)strlen(ecfd_str))
		handle_error("writing to cgroup.event_control");

	return efd;
}

void usage(char *progname) {
	printf(	"usage: %s <path to memory cgroup directory>\n\n"
		"The path is optional. If none is provided, the current "
		"memory cgroup will be used. An invalid cgroup or path "
		"will result in a silent failure.\n", progname );
}

/* Check the hard link counter for stderr and check if it's writable using
 * poll().  These checks should handle it whether a tty is allocated or not.
 * We could detect which test to use, but doing both is probably better in
 * case there are edge conditions of which I am not aware. */
int pipe_alive() {
	struct stat statbuf;
	struct pollfd pfd;
	int retval;

	/* If number of hardlinks for the controlling tty (open through stderr)
	 * is 0, the tty is deleted, presumably because the ssh connection is
	 * now closed */

	fstat(2, &statbuf);
	if(statbuf.st_nlink < 1)
		return 0;

	/* If this isn't a TTY, the previous check won't help because the stderr
	 * pipe always exists. Check if we can write to it. */

	pfd.fd = 2;
	pfd.events = POLLERR|POLLHUP|POLLNVAL;

	retval =  poll(&pfd, 1, 0);

	if(retval == -1 || !!pfd.revents) {
		return 0;
	}
	return 1;
}

int main(int argc, char *argv[]) {
	int efd, retval, prio;
	uint64_t u;
	ssize_t s;
	uid_t uid;
	fd_set set;
	char *memcg_path;
	struct timeval timeout;
	#ifndef NO_GPL
	char *pathcopy, *progname, cmdline[1024], *tty;
	int istty = 1;
	pid_t pgid;
	#endif

	/* maybe save a tiny number of bytes, because we can */
	mallopt(M_MXFAST, 0);

	if(argc > 2) {
		usage(argv[0]);
		exit(1);
	} else if(argc > 1 && argv[1][0] == '-') {
		/* any attempt at -helpme, etc */
		usage(argv[0]);
		return 1;
	}
	

	uid = getuid();
	/* don't monitor root */
	if(uid == 0)
		return 0;

	/* used for cmdline when this is not a tty */
	pgid = getpgrp();

	daemonize();

	/* be nice */
	prio = getpriority(PRIO_PROCESS, getpid());
	if(prio < TARGET_NICE)
		setpriority(PRIO_PROCESS, getpid(), TARGET_NICE);

	if(argc == 2)
		memcg_path = strdup(argv[1]);
	else
		memcg_path = get_cgroup_path();

	/* set cmdline for ps, top, etc. if you're not concerned about GPL */
	#ifndef NO_GPL
	pathcopy = strdup(argv[0]);
	progname = basename(pathcopy);
	initproctitle(argc, argv);
	tty = getenv("SSH_TTY");
	if(tty == NULL) {
		istty = 0;
		tty = malloc(256);
		snprintf(tty, 256, "[notty: pgid=%d]", pgid);
	}
	snprintf(cmdline, 1024, "%s %s", tty, memcg_path);
	setproctitle(progname, cmdline);
	if(!istty)
		free(tty);
	free(pathcopy);
	#endif


	efd = open_event_fd(memcg_path);

	free(memcg_path);

	while(1) {
		/* Check periodically if the user has other processes.
		   Exit if none exist */
		timeout.tv_sec = TIMEOUT_SECONDS;
		timeout.tv_usec = 0;
		FD_ZERO(&set);
		FD_SET(efd, &set);

		/* check for data in efd (i.e. oom triggered) */
		retval = select(FD_SETSIZE, &set, NULL, NULL, &timeout);
		if(retval == -1) {
			handle_error("select returned -1");
		} else if(retval == 0) {
			if(!pipe_alive())
				return 0;
		} else {
			/* select() found data */
			s = read(efd, &u, sizeof(uint64_t));
			if (s != sizeof(uint64_t)) 
				handle_error("reading from event fd");

			/* Wait a moment for the oom-killer to take effect. */
			sleep(4);
			writeToTTY();
		}
	}
	return 2;
}
