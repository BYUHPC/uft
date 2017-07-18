/* pam_cgroup_per_user */

/*
 * Author: Ryan Cox <ryan_cox@byu.edu>
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
 */

/*
 * TODO:
 * 	- More cleanup
 * 	- Separate definitions to a .h file
 * 	- Error handling for malloc()
 * 	- Error handling for some other functions
 * 	- Unified config file instead of just options in multiple pam files
 * 	- Documentation
 * 	- Set other (generic?) cgroup settings
 * 	- Submit to Linux-PAM if others find this useful?
 *	- Create a cleaner get_user_cg_path()
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <pwd.h>
/*#include <stdint.h> */ /* INT64_MAX */

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

/* don't change these unless the kernel does */
#define MAX_MEMORY_BYTES	"9223372036854775807" /* 2^63-1 */
#define NUMERIC_STRING_BYTES	24 /* should hold ascii 2^63-1 + '\0' */

/* default values in the kernel. change if you want these to be different */
#define DEFAULT_MEMORY_LIMIT_IN_BYTES		MAX_MEMORY_BYTES
#define DEFAULT_MEMORY_MEMSW_LIMIT_IN_BYTES	MAX_MEMORY_BYTES
#define DEFAULT_CPU_SHARES			"1024"

/* what directory do you want to do place user cgroups in? */
#define DEFAULT_CPU_PREFIX			"/cgroup/cpu/users"
#define DEFAULT_MEM_PREFIX			"/cgroup/memory/users"

/* TODO:  separate definitions to .h */

typedef struct limits {
	char memory_limit_in_bytes[NUMERIC_STRING_BYTES];
	char memory_memsw_limit_in_bytes[NUMERIC_STRING_BYTES];
	char cpu_shares[NUMERIC_STRING_BYTES];	
} limits;

typedef struct cg_path {
	char *cpuset;
	char *cpu;
	char *cpuacct;
	char *memory;
	char *devices;
	char *freezer;
	char *net_cls;
	char *blkio;
	char *perf_event;
} cg_path;

int debug;

void initialize_cgroup_struct(cg_path *cg) {
	cg->cpuset = NULL;
	cg->cpu = NULL;
	cg->cpuacct = NULL;
	cg->memory = NULL;
	cg->devices = NULL;
	cg->freezer = NULL;
	cg->net_cls = NULL;
	cg->blkio = NULL;
	cg->perf_event = NULL;
}

void initialize_limits_struct(limits *limits)  {
	strcpy(limits->memory_limit_in_bytes, DEFAULT_MEMORY_LIMIT_IN_BYTES);
	strcpy(limits->memory_memsw_limit_in_bytes, DEFAULT_MEMORY_MEMSW_LIMIT_IN_BYTES);
	strcpy(limits->cpu_shares, DEFAULT_CPU_SHARES);
}

int cgroup_write_setting(pam_handle_t *pamh, char *cg_path, char *file, char *value) {
	int fd;
	char *path;

	path = malloc(sizeof(char) * (strlen(cg_path) + 1 + strlen(file)));
	strcpy(path, cg_path);
	strcat(path, "/");
	strcat(path, file);
	/* pam_syslog(pamh, LOG_ERR, "cgroup_write_setting %s > %s", value, path); */
	fd = open(path, O_WRONLY);
	free(path);
	if(fd) {
		write(fd, value, strlen(value));
		close(fd);
		return 1;
	}
	else {
		return 0;
	}
}

int cgroup_assign_pid(pam_handle_t *pamh, char *cg_path, pid_t pid) {
	int fd, retval;
	ssize_t wrote;
	char *path, pid_str[16];

	path = malloc(sizeof(char) * (strlen(cg_path) + 6));
	strcpy(path, cg_path);
	strcat(path, "/tasks");
	
	fd = open(path, O_WRONLY);
	if(fd) {
		snprintf(pid_str, 16, "%d", pid);
		wrote = write(fd, pid_str, strlen(pid_str));
		close(fd);
		if(wrote == strlen(pid_str)) {
			pam_syslog(pamh, LOG_ERR, "Assigned %d to %s", pid, path);
			free(path);
			return 1;
		} else
			pam_syslog(pamh, LOG_ERR, "Couldn't assign pid %ld to cg %s: Failed to write to tasks", pid, cg_path);
	}
	else
		pam_syslog(pamh, LOG_ERR, "Couldn't assign pid %ld to cg %s: Failed to open tasks", pid, cg_path);
	free(path);
	return 0;
}

char *get_user_cg_path(pam_handle_t *pamh, char *cg_global_path, char *user_name) {
	int global_len, user_len;
	char *cg_user_path;

	if(strcmp(user_name,"root")==0)
		return cg_global_path;

	global_len = strlen(cg_global_path);
	user_len = strlen(user_name);

	/* pretend there is no '/' */
	if(cg_global_path[global_len] == '/')
		--global_len;
	cg_user_path = malloc(sizeof(char) * (global_len + 6 + user_len + 1));
	if(!cg_user_path)
		return NULL;
	strcpy(cg_user_path, cg_global_path);
	strcat(cg_user_path, "/user_");
	strcat(cg_user_path, user_name);
	return cg_user_path;
}

char *get_root_cg_path(pam_handle_t *pamh, char *cg_global_path, char *subsys) {
	/* example global:  /cgroup/cpu/users */
	char *search, *pos, *buf;
	int bufsize;
	
	search = malloc(sizeof(char) * (strlen(subsys) + 2));
	sprintf(search, "/%s/", subsys);
	pos = strstr(cg_global_path, search);
	if(pos == NULL)
		return NULL;
	bufsize = strlen(search) + pos - cg_global_path - 1;
	buf = malloc(sizeof(char) * bufsize);
	strncpy(buf, cg_global_path, bufsize);
	buf[bufsize] = '\0';
	return buf;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval = PAM_IGNORE, fd;
	pid_t pid;
	char *user_name;
	cg_path cg_user, cg_global;
	limits limits;

	initialize_cgroup_struct(&cg_user);
	initialize_cgroup_struct(&cg_global);
	initialize_limits_struct(&limits);

        debug = 0; //default false
        
	/* get user or fail */
	retval = pam_get_item(pamh, PAM_USER, (void *) &user_name);
	if (user_name == NULL || retval != PAM_SUCCESS)  {
		pam_syslog(pamh, LOG_ERR, "No username in PAM_USER? Fail!");
		return PAM_SESSION_ERR;
	}

	/* parse arguments */
	for (; argc-- > 0; ++argv) {
		if (!strncmp(*argv,"user_mem_dir=",13)) {
			cg_global.memory = (char *)(13 + *argv);
			if (*cg_global.memory != '\0') {
				/* ignore the blank path provided via module arg */
				cg_global.memory = NULL;
			}
		}
		else if (!strncmp(*argv,"user_cpu_dir=",13)) {
			cg_global.cpu = (char *)(13 + *argv);
			if (*cg_global.cpu == '\0') {
				/* ignore the blank path provided via module arg */
				cg_global.cpu = NULL;
			}
		}
		/* make this more dynamic in the future ? */
		else if (!strncmp(*argv,"memory.memsw.limit_in_bytes=",28))
			strncpy(limits.memory_memsw_limit_in_bytes, 28 + *argv, NUMERIC_STRING_BYTES);
		else if (!strncmp(*argv,"memory.limit_in_bytes=",22))
			strncpy(limits.memory_limit_in_bytes, 22 + *argv, NUMERIC_STRING_BYTES);
		else if (!strncmp(*argv,"cpu.shares=",11))
			strncpy(limits.cpu_shares, 11 + *argv, NUMERIC_STRING_BYTES);
		else if (!strncmp(*argv,"debug",5))
			debug=1;
		else
			pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
	}
	/* end parse arguments */

        if (debug) {
                pam_syslog(pamh, LOG_ERR, "DEBUGGING: memory.memsw.limit_in_bytes=%s", limits.memory_memsw_limit_in_bytes);
                pam_syslog(pamh, LOG_ERR, "DEBUGGING: memory.limit_in_bytes=%s", limits.memory_limit_in_bytes);
                pam_syslog(pamh, LOG_ERR, "DEBUGGING: cpu.shares=%s", limits.cpu_shares);
        }


	/* default cgroup settings */
	if (cg_global.cpu == NULL) {
		cg_global.cpu = malloc(sizeof(char) * strlen(DEFAULT_CPU_PREFIX) + 1);
		strcpy(cg_global.cpu, DEFAULT_CPU_PREFIX);
	}
	if (cg_global.memory == NULL) {
		cg_global.memory = malloc(sizeof(char) * strlen(DEFAULT_MEM_PREFIX) + 1);
		strcpy(cg_global.memory, DEFAULT_MEM_PREFIX);
	}

       	/* if it's root, assign it to the root cg.
	   this is important for sudo, su, etc to remove the process from a user cgroup.
	   TODO: this should be a uid==0 check instead. */
	if(strcmp(user_name, "root")==0) {
                if (debug)
                    pam_syslog(pamh, LOG_ERR, "DEBUGGING: Found root user");
            
		cg_user.cpu = get_root_cg_path(pamh, cg_global.cpu, "cpu");
		cg_user.memory = get_root_cg_path(pamh, cg_global.memory, "memory");
	} else {
                if (debug)
                    pam_syslog(pamh, LOG_ERR, "DEBUGGING: found non-root user: %s", user_name);
            
		/* create directories if they don't exist. ignore errors */
		mkdir(cg_global.cpu, 0755);
		mkdir(cg_global.memory, 0755);

		/* assemble cg paths */
		cg_user.cpu = get_user_cg_path(pamh, cg_global.cpu, user_name);
		cg_user.memory = get_user_cg_path(pamh, cg_global.memory, user_name);

		/* create user-specific cg */
		mkdir(cg_user.cpu, 0755);
		mkdir(cg_user.memory, 0755);

		/* write cgroup settings */
		cgroup_write_setting(pamh, cg_user.cpu, "cpu.shares", limits.cpu_shares);
		/* write memory.limit_in_bytes AFTER memsw or it may fail since memsw must me >= mem */
		cgroup_write_setting(pamh, cg_user.memory, "memory.memsw.limit_in_bytes", limits.memory_memsw_limit_in_bytes);
		cgroup_write_setting(pamh, cg_user.memory, "memory.limit_in_bytes", limits.memory_limit_in_bytes);
	}
	/* assign process to cgroup */
	pid = getpid();
	cgroup_assign_pid(pamh, cg_user.cpu, pid);
	cgroup_assign_pid(pamh, cg_user.memory, pid);

	return retval;
}

PAM_EXTERN int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	 return PAM_IGNORE;
}

#ifdef PAM_STATIC
struct pam_module _pam_cgroup_per_user_modstruct = {
	 "pam_cgroup_per_user",
	 NULL,
	 NULL,
	 NULL,
	 pam_sm_open_session,
	 pam_sm_close_session,
	 NULL,
};
#endif
