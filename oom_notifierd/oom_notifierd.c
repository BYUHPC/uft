/* 
 * Description:
 * This program notifies a user when the oom-killer kills a process in that
 * user's cgroup.  It will only allow one copy of itself to run and exits if
 * another program of the same name by the same user exists.  It terminates
 * if the user has no other processes except this one within a certain amount
 * of time.  The notification is done to all of a user's ttys.  This was not
 * coded in a portable fashion so minor changes may be necessary for
 * different kernels/distros.
 * See also: https://www.kernel.org/doc/Documentation/cgroups/memory.txt
 *
 * Bugs:  (TODO)
 *     - Check for other user procs only checks if itself is not in the list.
 *     		-Needs to check if any of the others are the same type of prog
 *     		but monitoring a different directory
 *
 * Assumptions:
 *     - You want to notify all of a user's TTYs
 *     - TTYs are in /dev/pts/
 *         - Change DEV_TTY_GLOB if not
 *
 * Author:   Ryan Cox <ryan_cox@byu.edu>
 *
 * Copyright (C) 2013 Brigham Young University
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

#include <libgen.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>             /* Definition of uint64_t */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <glob.h>
#include <sys/stat.h>
#include <time.h>

#define handle_error(msg) \
    do { perror(msg); exit(1); } while (0)


#define ERROR_MSG_TO_USER "You exceeded your memory limit on this host. The kernel invoked the oom-killer which killed a process of yours to free up memory. No further action is required.\nRun 'loginlimits' to see the current limits.\a"
#define DEV_TTY_GLOB "/dev/pts/*"
#define TIMEOUT_SECONDS 60

void daemonize() {
	chdir("/");
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	if(fork())
		exit(0);
	setsid();
}

int walkUserProcesses(int (*cb)(char *, uid_t, pid_t, pid_t, char *), char *arg1) {
	int i, retval;
	glob_t globbuf;
	struct stat stat;
	char *bname;
	char path_temp[40];
	pid_t pid, examine_pid;
	uid_t uid;
	pid = getpid();
	uid = getuid();

	globbuf.gl_offs = 0;
	glob("/proc/[0-9]*", GLOB_NOSORT, NULL, &globbuf);
	for(i=0; i < globbuf.gl_pathc; i++) {
		if(lstat(globbuf.gl_pathv[i], &stat)==0) {
			if(stat.st_uid == uid) {
				strncpy(path_temp, globbuf.gl_pathv[i], 40);
				bname = (char *)basename(globbuf.gl_pathv[i]);
				examine_pid = atol(bname);
				if( (retval = cb((char *)globbuf.gl_pathv[i], (uid_t)uid, (pid_t)pid, (pid_t)examine_pid, (char *)arg1)) ) {
					globfree(&globbuf);
					return retval;
				}
			}
		}
	}
		
	globfree(&globbuf);
	return 0;
}

int findDuplicate(char *progname, uid_t uid) {
	char mycmdline[1024];
	int fd, bytes, i;

	fd = open("/proc/self/cmdline", O_RDONLY);
	if(fd == -1)
		handle_error("Couldn't open /proc/self/cmdline?!");
	bytes = read(fd, mycmdline, 1024);
	close(fd);
	/* args are separated by \0. replace with space */
	for(i = 0; i < bytes-1; i++)
		if(mycmdline[i] == '\0')
			mycmdline[i] = ' ';

	int findDuplicate_cb(char *path, uid_t uid, pid_t mypid, pid_t examine_pid, char *progname) {
		int fd, bytes, i;
		char filename[1024];
		char cmdline[1024];
		sprintf(filename, "%s/cmdline", path);
		fd = open(filename, O_RDONLY);
		if(fd != -1) {
			bytes = read(fd, cmdline, 1024);
			close(fd);
			for(i = 0; i < bytes-1; i++)
				if(cmdline[i] == '\0')
					cmdline[i] = ' ';
			if(strcmp(progname, cmdline)==0) {
				if(mypid != examine_pid)
					return 1;
			}
		}
		return 0;
	}
	return walkUserProcesses(&findDuplicate_cb, mycmdline);
}

int userHasOtherProcesses(uid_t uid) {
	int retval;
	int userHasOtherProcesses_cb(char *path, uid_t uid, pid_t mypid, pid_t examine_pid, char *progname) {
		return mypid!=examine_pid;
	}
	retval = walkUserProcesses(&userHasOtherProcesses_cb, NULL);
	return retval;
}

void writeToTTY(char *path, char *msg) {
	int ttyfd;
	ssize_t s;

	ttyfd = open(path, O_WRONLY);
	s = write(ttyfd, msg, strlen(msg));
	if(s != strlen(ERROR_MSG_TO_USER))
		printf("non-fatal: couldn't write to terminal: %s", path);
	close(ttyfd);
}

void writeToUserTTYs(uid_t uid) {
	glob_t globbuf;
	struct stat stat;
	int i;
	char msg[1024];
	time_t localtime;
	char localtime_str[26];

	time(&localtime);
	ctime_r(&localtime, localtime_str);
	sprintf(msg, "\e[31m\n\n<<<<<<<<<<<<<<\n%s\n%s\n>>>>>>>>>>>>>>\e[0m\n\n", localtime_str, ERROR_MSG_TO_USER);
	globbuf.gl_offs = 0;
	glob(DEV_TTY_GLOB, GLOB_NOSORT, NULL, &globbuf);
	for(i=0; i < globbuf.gl_pathc; i++) {
		if(lstat(globbuf.gl_pathv[i], &stat)==0) {
			if(stat.st_uid == uid) {
				writeToTTY(globbuf.gl_pathv[i], msg);
			}
		}
	}
	globfree(&globbuf);
}

int get_memcg_self_path(char *path) {
	FILE *fp;
	int is_memory_cgroup_line, pos, retval = 0;
	char *strtok_ptr, *str1, *token, line[512];
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
	char *strtok_ptr, *str1, *token, line[512];
	fp = fopen("/proc/mounts", "r");
	if(fp==NULL) {
		printf("failed to open /proc/mounts");
		exit(1);
	}
	while(fgets(line, 512, fp) != NULL) {
		is_memory_cgroup_line = 0;
		for (pos = 0, str1 = line; ; pos++, str1 = NULL) {
			token = strtok_r(str1, " ", &strtok_ptr);
			if(token == NULL)
				break;
			if(pos == 0 && strcmp(token, "memory") == 0)
				is_memory_cgroup_line = 1;
			else if(pos == 1 && is_memory_cgroup_line) {
				strcpy(path, token);
				retval = 1;
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
	if(s != strlen(ecfd_str))
		handle_error("writing to cgroup.event_control");

	return efd;
}

void usage(char *progname) {
	printf(	"usage: %s <path to memory cgroup directory>\n\n"
		"The path is optional. If none is provided, the current "
		"memory cgroup will be used. An invalid cgroup or path "
		"will result in a silent failure.\n", progname );
}

int main(int argc, char *argv[]) {
	int efd;
	uint64_t u;
	ssize_t s;
	uid_t uid;
	struct timeval timeout;
	int retval;
	fd_set set;
	char *memcg_path;

	if(argc > 2) {
		usage(argv[0]);
		exit(1);
	} else if(argc==2 && argv[1][0] == '-') {
		/* any attempt at -helpme, etc */
		usage(argv[0]);
		exit(0);
	}
	

	uid = getuid();
	/* don't monitor root */
	if(uid == 0)
		exit(0);
	if(findDuplicate(argv[0], uid))
		exit(0);

	daemonize();

	if(argc == 2)
		memcg_path = argv[1];
	else
		memcg_path = get_cgroup_path();

	efd = open_event_fd(memcg_path);

	if(argc != 2)
		free(memcg_path);
	while(1) {
		do {
			/* Check periodically if the user has other processes.
			   Exit if none exist */
			timeout.tv_sec = TIMEOUT_SECONDS;
			timeout.tv_usec = 0;
			FD_ZERO(&set);
			FD_SET(efd, &set);

			/* check for data in efd (i.e. oom condition triggered)  */
			retval = select(FD_SETSIZE, &set, NULL, NULL, &timeout);
			if(retval == 0) {
				/* select() timed out */
				if(userHasOtherProcesses(uid)==0)
					exit(0);
			} else {
				/* select() found data or it failed */
				s = read(efd, &u, sizeof(uint64_t));
			}
		} while(retval < 1);
		if (s != sizeof(uint64_t))
			handle_error("reading from event fd");

		/* Wait a moment for the oom-killer to take effect. */
		sleep(4);
		writeToUserTTYs(uid);
	}
	exit(0);
}
