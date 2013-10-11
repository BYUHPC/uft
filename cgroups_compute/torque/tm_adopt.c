#include <tm.h>
#include <stdio.h>
#include <sys/types.h> /* pid_t */
#include <stdlib.h> /* atoi */

/* Ryan Cox. BYU. July 2010 */

/* gcc `/usr/local/bin/pbs-config --libs` -o tm_adopt tm_adopt.c */

int main(int argc, char **argv)
{
	int retval;
	if(argc!=3)
	{
		printf("usage: tm_adopt <jobid.the.full.job.id.edu> <pid>");
		return 1;
	}
	retval = tm_adopt(argv[1], TM_ADOPT_JOBID, (pid_t)atoi(argv[2]));
	return retval;
}
