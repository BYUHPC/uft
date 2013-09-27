#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>             /* Definition of uint64_t */
#include <stdio.h>

#define handle_error(msg) \
    do { perror(msg); exit(1); } while (0)


int main() {
	int efd, ecfd, oomfd;
	uint64_t u;
	ssize_t s;
	char ecfd_str[32];

	oomfd = open("/cgroup/memory/users/user_ryancox/memory.oom_control", O_RDONLY);
	if(oomfd == -1)
		handle_error("oomfd");

	efd = eventfd(0, 0);
	if(efd == -1)
		handle_error("efd");

	ecfd = open("/cgroup/memory/users/user_ryancox/cgroup.event_control", O_WRONLY);
	if(ecfd == -1)
		handle_error("ecfd");

	sprintf(ecfd_str, "%d %d", efd, oomfd);
	printf("Will write to cgroup.event_control:  %s\n", ecfd_str);
	s = write(ecfd, &ecfd_str, strlen(ecfd_str));
	if(s != strlen(ecfd_str))
		handle_error("writing to cgroup.event_control");

	printf("About to read\n");
	s = read(efd, &u, sizeof(uint64_t));
	if (s != sizeof(uint64_t))
		handle_error("read");
	printf("Parent read %llu (0x%llx) from efd\n",
		(unsigned long long) u, (unsigned long long) u);
	//exit(EXIT_SUCCESS);
	exit(0);
}
