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
 * Date:      September 2013
 * Copyright: Brigham Young University
 * License:   GNU GPL Version 2
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

//#define DEBUG(args...) printf("DEBUG: "); printf(args); printf("\n");
//#define DEBUG(args...) fprintf(debugfd, "DEBUG: "); fprintf(debugfd, ##args); fprintf(debugfd, "\n"); fflush(debugfd);
#define DEBUG(args...) errno == 1;

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
			DEBUG("Not found\n");
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

/*int findDuplicate(char *argv[]) {
	DIR *procdir;
	int name_max, len;
	struct dirent *entryp;
	struct dirent *result;
	name_max = pathconf(dirpath, _PC_NAME_MAX);
	if (name_max == -1)         /* Limit not defined, or error */
/*		name_max = 255;         /* Take a guess */
/*	len = offsetof(struct dirent, d_name) + name_max + 1;
	entryp = malloc(len);

	procdir = opendir("/proc");
	
}*/


int walkUserProcesses(int (*cb)(char *, uid_t, pid_t, pid_t, char *), char *arg1) {
//int findDuplicate(char *progname, uid_t uid) {
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
		//	DEBUG("  Owner is %d\n", stat.st_uid);
			if(stat.st_uid == uid) {
				DEBUG("11\n");
				strncpy(path_temp, globbuf.gl_pathv[i], 40);
				DEBUG("14\n");
				bname = basename(globbuf.gl_pathv[i]);
				DEBUG("15  %s\n", path_temp);
				examine_pid = atol(bname);
				DEBUG("17\n");
				DEBUG("Calling callback for pid:%d, uid:%d, $$:%d\n", examine_pid, uid, pid);
				if(retval = cb((char *)globbuf.gl_pathv[i], (uid_t)uid, (pid_t)pid, (pid_t)examine_pid, (char *)arg1)) {
					DEBUG("callback returned > 0\n");
					globfree(&globbuf);
					return retval;
				}
			}
		}
	}
		

	//DEBUG("Done with walkUserProcesses. Freeing globbuf. return 0");
	globfree(&globbuf);
	DEBUG("Freed.\n");
	//DEBUG("Couldn't find match for '%s'\n", progname);
	return 0;
}

//int findDuplicate_cb(char *progname, uid pid_t pid) {
int findDuplicate(char *progname, uid_t uid) {
	int findDuplicate_cb(char *path, uid_t uid, pid_t mypid, pid_t examine_pid, char *progname) {
	  //int (*cb)(char *path, uid_t uid, pid_t pid) = {
	//  int cb (char *path, uid_t uid, pid_t pid) {
		int fd;
		char filename[255];
		char cmdline[255];
		sprintf(filename, "%s/cmdline", path);
		DEBUG("Will open '%s'\n", filename);
		fd = open(filename, O_RDONLY);
		if(fd != -1) {
		DEBUG("    Did open '%s'\n", filename);
			read(fd, cmdline, 255);
			DEBUG("TESTING '%s': %s.\n", progname, path);
			if(strcmp(progname, cmdline)==0) {
				if(mypid != examine_pid) {
					DEBUG("Found match for '%s': %s.\n", progname, path);
					return 1;
				}
				DEBUG("Found match for '%s': %s. Ignoring because it's me!\n", progname, path);
			}
			close(fd);
		}
		return 0;
	  //}
	//  walkUserProcesses(&cb);

	}
	return walkUserProcesses(&findDuplicate_cb, progname);
}

/*int findDuplicate(char *progname, uid_t uid) {



	walkUserProcesses(uid, &findDuplicate_cb);
}
*/
int userHasOtherProcesses(uid_t uid) {
	int retval;
	int userHasOtherProcesses_cb(char *path, uid_t uid, pid_t mypid, pid_t examine_pid, char *progname) {
		if(mypid!=examine_pid) {
			DEBUG("Found. %d\n", examine_pid);
			return 1;
		}
		else {
			DEBUG("Clean. %d\n", examine_pid);
			return 0;
		}
//		return mypid!=examine_pid;
	}
	retval = walkUserProcesses(&userHasOtherProcesses_cb, NULL);
	DEBUG("userHasOtherProcesses returning '%d'", retval);
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
					DEBUG("TIME FOR %s:  %ld > %ld\n", globbuf.gl_pathv[i], stat.st_mtime, most_recent_time);
					DEBUG("About to strncpy(most_recent_tty, globbuf.gl_pathv[i], 255);\n");
					strncpy(most_recent_tty, globbuf.gl_pathv[i], 255);
					DEBUG("Success\n");
					most_recent_time = stat.st_mtime;
				}
			}
		}
	}
	DEBUG("About to free in findActiveTty\n");
	globfree(&globbuf);
	strncpy(path, most_recent_tty, 255);
	return most_recent_time;
}

void writeToActiveTty(uid_t uid) {
	char path[255];
	int most_recent_time;
	int ttyfd;
	ssize_t s;
	DEBUG("Finding most recent tty\n");
	most_recent_time = findActiveTty(uid, path);
	DEBUG("FOUND most recent tty\n");
	if(most_recent_time == 0)
		return;
	DEBUG("Will open tty '%s' with time %ld.\n", path, most_recent_time);
	ttyfd = open(path, O_WRONLY);
        if(ttyfd == -1) {
                DEBUG("Could not open ttyfd '%s'\n", path);
		return;
	}

        DEBUG("Will write to tty '%s'\n", path);
        s = write(ttyfd, ERROR_MSG_TO_USER, strlen(ERROR_MSG_TO_USER));
        if(s != strlen(ERROR_MSG_TO_USER))
               	DEBUG("Error writing to %s\n", path);
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
	DEBUG("Will daemonize\n");
	//exit(19);
	daemonize();
	getUsernameFromUid(uid, username);	

	get_cgroup_path(memcg_path);
	DEBUG("memcg_path: '%s'\n", memcg_path);

	//sprintf(filename, "/cgroup/memory/users/user_%s/memory.oom_control", username);
	sprintf(filename, "%s/memory.oom_control", memcg_path);


	DEBUG("Will open filename '%s'\n", filename);	
	oomfd = open(filename, O_RDONLY);
	if(oomfd == -1)
		handle_error("oomfd");

	efd = eventfd(0, 0);
	if(efd == -1)
		handle_error("efd");

	sprintf(filename, "%s/cgroup.event_control", memcg_path);
	DEBUG("Will open filename '%s'\n", filename);
	ecfd = open(filename, O_WRONLY);
	if(ecfd == -1)
		handle_error("ecfd");

	sprintf(ecfd_str, "%d %d", efd, oomfd);
	DEBUG("Will write to cgroup.event_control:  %s\n", ecfd_str);
	s = write(ecfd, &ecfd_str, strlen(ecfd_str));
	if(s != strlen(ecfd_str))
		handle_error("writing to cgroup.event_control");


	while(1) {
		DEBUG("About to read");
		do {
			timeout.tv_sec = 30;
			timeout.tv_usec = 0;

			FD_ZERO(&set);
			FD_SET(efd, &set);
			retval = select(FD_SETSIZE, &set, NULL, NULL, &timeout);
			if(retval == 0) {
				DEBUG("No data. Checking if the user has other processes");
				if(userHasOtherProcesses(uid)==0)
					exit(0);
			} else {
				DEBUG("Found data");
				s = read(efd, &u, sizeof(uint64_t));
			}
			DEBUG("Looping");
		} while(retval < 1);
		DEBUG("Exited loop");
		if (s != sizeof(uint64_t))
			handle_error("read");
		DEBUG("Parent read %llu (0x%llx) from efd\n",
			(unsigned long long) u, (unsigned long long) u);

		/* Wait a moment for the oom-killer to take effect. */
		sleep(2);
		writeToActiveTty(uid);
	}
	exit(0);
}
