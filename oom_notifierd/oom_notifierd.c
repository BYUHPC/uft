/* This program notifies a user when the oom-killer kills
 * a process in that user's cgroup.  It will only allow one
 * copy of itself to run and exits if another program of the
 * same name by the same user exists.  It terminates if the
 * user has no other processes except this one within a
 * certain amount of time.  The notification is done to the
 * most recently used tty.  This was not coded in a portable
 * fashion but should be relatively easy to port to other
 * Unix-like systems.
 *
 * Author:    Ryan Cox <ryan_cox@byu.edu>
 * 
 * Copyright (C) 2013, Brigham Young University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 *
 */
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>             /* Definition of uint64_t */
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <glob.h>
#include <sys/stat.h>

#define handle_error(msg) \
    do { perror(msg); exit(1); } while (0)


#define ERROR_MSG_TO_USER "\nYou exceeded your memory limit on this host. The kernel invoked the oom-killer which killed a process of yours to free up memory. No further action is required.\nRun 'loginlimits' to see the current limits.\n\n"


FILE *debugfd;

int getUsernameFromUid(uid_t uid, char *username) {
	struct passwd pwd;
	struct passwd *result;
	char *buf;
	size_t bufsize;
	int s;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)          /* Value was indeterminate */
		bufsize = 16384;        /* Should be more than enough */

	buf = malloc(bufsize);
	if (buf == NULL) {
		perror("malloc");
		return 0;
	}

	s = getpwuid_r(uid, &pwd, buf, bufsize, &result);
	if (result == NULL) {
		if (s == 0) {
			/* DEBUG("Not found\n");*/
		} else {
			errno = s;
			perror("getpwnam_r");
		}
		return 0;
	}

	strcpy(username, pwd.pw_name);
	return 1;

}

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
	int fd;
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
				bname = basename(globbuf.gl_pathv[i]);
				examine_pid = atol(bname);
				if(retval = cb((char *)globbuf.gl_pathv[i], (uid_t)uid, (pid_t)pid, (pid_t)examine_pid, (char *)arg1)) {
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
	int findDuplicate_cb(char *path, uid_t uid, pid_t mypid, pid_t examine_pid, char *progname) {
		int fd;
		char filename[255];
		char cmdline[255];
		sprintf(filename, "%s/cmdline", path);
		fd = open(filename, O_RDONLY);
		if(fd != -1) {
			read(fd, cmdline, 255);
			if(strcmp(progname, cmdline)==0) {
				if(mypid != examine_pid) {
					return 1;
				}
			}
			close(fd);
		}
		return 0;
	}
	return walkUserProcesses(&findDuplicate_cb, progname);
}

int userHasOtherProcesses(uid_t uid) {
	int retval;
	int userHasOtherProcesses_cb(char *path, uid_t uid, pid_t mypid, pid_t examine_pid, char *progname) {
		return mypid!=examine_pid;
	}
	retval = walkUserProcesses(&userHasOtherProcesses_cb, NULL);
	return retval;
}

int findActiveTty(uid_t uid, char *path) {
	glob_t globbuf;
	char most_recent_tty[255];
	time_t most_recent_time;
	struct stat stat;
	int i;

	most_recent_time = 0;
	globbuf.gl_offs = 0;
	glob("/dev/pts/*", GLOB_NOSORT, NULL, &globbuf);
	for(i=0; i < globbuf.gl_pathc; i++) {
		if(lstat(globbuf.gl_pathv[i], &stat)==0) {
			if(stat.st_uid == uid) {
				if(stat.st_mtime > most_recent_time) {
					strncpy(most_recent_tty, globbuf.gl_pathv[i], 255);
					most_recent_time = stat.st_mtime;
				}
			}
		}
	}
	globfree(&globbuf);
	strncpy(path, most_recent_tty, 255);
	return most_recent_time;
}

void writeToActiveTty(uid_t uid) {
	char path[255];
	int most_recent_time;
	int ttyfd;
	ssize_t s;
	most_recent_time = findActiveTty(uid, path);
	if(most_recent_time == 0)
		return;
	ttyfd = open(path, O_WRONLY);
        if(ttyfd == -1) {
		return;
	}

        s = write(ttyfd, ERROR_MSG_TO_USER, strlen(ERROR_MSG_TO_USER));
	/* if it didn't write, there's not much we can do about it */
	close(ttyfd);
}

int get_memcg_self_path(char *path) {
	FILE *fp;
	int is_memory_cgroup_line, pos, retval = 0;
	char *strtok_ptr, *str1, *token, line[512];
	fp = fopen("/proc/self/cgroup", "r");
	if(fp==NULL) {
		printf("failed to open /proc/self/cgroup");
		exit(1);
	}
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

int get_cgroup_path(char *memcg_path) {
	char mount_path[256], self_path[256];
	if(!get_memcg_mount_path(mount_path))
		return 1;
	if(!get_memcg_self_path(self_path))
		return 1;
	sprintf(memcg_path, "%s%s", mount_path, self_path);
	return 0;
}

int main(int argc, char *argv[]) {
	int efd, ecfd, oomfd;
	uint64_t u;
	ssize_t s;
	char ecfd_str[32];
	uid_t uid;
	struct passwd pwd;
	char username[32];
	char filename[255];
	FILE *write_pipe;
	struct timeval timeout;
	int retval;
	fd_set set;
	char memcg_path[255];

	uid = getuid();
	/* don't monitor root */
	if(uid == 0)
		exit(0);
	if(findDuplicate(argv[0], uid))
		exit(0);
	daemonize();
	getUsernameFromUid(uid, username);	

	get_cgroup_path(memcg_path);

	sprintf(filename, "%s/memory.oom_control", memcg_path);


	oomfd = open(filename, O_RDONLY);
	if(oomfd == -1)
		handle_error("oomfd");

	efd = eventfd(0, 0);
	if(efd == -1)
		handle_error("efd");

	sprintf(filename, "%s/cgroup.event_control", memcg_path);
	ecfd = open(filename, O_WRONLY);
	if(ecfd == -1)
		handle_error("ecfd");

	sprintf(ecfd_str, "%d %d", efd, oomfd);
	s = write(ecfd, &ecfd_str, strlen(ecfd_str));
	if(s != strlen(ecfd_str))
		handle_error("writing to cgroup.event_control");


	while(1) {
		do {
			timeout.tv_sec = 30;
			timeout.tv_usec = 0;

			FD_ZERO(&set);
			FD_SET(efd, &set);
			retval = select(FD_SETSIZE, &set, NULL, NULL, &timeout);
			if(retval == 0) {
				if(userHasOtherProcesses(uid)==0)
					exit(0);
			} else {
				s = read(efd, &u, sizeof(uint64_t));
			}
		} while(retval < 1);
		if (s != sizeof(uint64_t))
			handle_error("read");

		/* Wait a moment for the oom-killer to take effect. */
		sleep(2);
		writeToActiveTty(uid);
	}
	exit(0);
}
