#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define PATH_TO_CGROUP_MGT_SCRIPT "/fslhome/ryancox/cgroups/manage_cgroup.pl"

#define UID_STR_BUF 10

int errno = 0;

int main(int argc, char *argv[]) {
	struct stat sb;
	char uid[UID_STR_BUF];
	
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <PID> <JOBID>\n", argv[0]);
		exit(1);
	}

	execl(
		PATH_TO_CGROUP_MGT_SCRIPT,
		PATH_TO_CGROUP_MGT_SCRIPT,
		"-p",
		argv[1],
		"-j",
		argv[2],
		NULL
	);
	fprintf(stderr, "%0: exec errno=%d\n", argv[0], errno);
	
	return 0;
}
