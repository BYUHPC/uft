This collection of scripts and programs is designed to improve the stability of shared nodes, whether login or compute, in an HPC setting.  It may work in other scenarios but is not tested for anything but HPC.  The tools were developed by Ryan Cox at BYU's Fulton Supercomputing Lab in order to limit the ability of users to negatively affect each others' work on shared nodes.  These tools work to control memory and CPU usage, keep /tmp and /dev/shm clean through cgroups, namespaces, process limits, and a polling mechanism if cgroups aren't available.

These tools are grouped into different categories and can generally be used separately.

cgroups_compute/
	Ideally your scheduler will have support for cgroups.  This directory contains scripts that catch ssh-launched tasks (i.e. tasks not launched through the scheduler) for SLURM (once 13.12 is released) and Torque.  Some incomplete code is included that may help in the development of a prologue-based mechanism for cgroups in Torque or other schedulers.  cgroups on compute nodes are probably only necessary if you allow node sharing (multiple jobs can run on the same node).

cgroups_login/
	DEPRECATED by pam_cgroup_per_user.  This contains files intended to control login node usage, specifically memory usage and CPU sharing.  It uses the memory and cpu (not cpuset) cgroups to provide hard memory limits and soft core limits on a per-user basis.

cputime_controls/
	Make sure that login nodes are only used as login nodes.  Prohibit long processing tasks but optionally allow long-running data movement processes such as scp and rsync.

loginlimits/
	Contains a script that reads certain cgroup information from the current cgroup as well as cputime limits.  It very verbosely explains some ofthe cgroup information.

loginmemlimitenforcer/
	Enforce a memory usage threshold on a login node by killing a process if a user exceeds the limit.  Uses a polling mechanism.  Use cgroups if possible but this if nothing else.

namespaces/
	Create a separate /tmp and /dev/shm per user on login and compute nodes.  Each user will have no idea anything is different but it greatly assists in cleanup of user data after the user exits the node.

oom_notifierd/
	An out-of-memory notification tool for users.  It listens for events in the current or specified cgroup and writes to a user's ttys when OOM occurs.

pam_cgroup_per_user/
	Create a cgroup per user with admin-specified CPU, memory, and swap limits.  Intended for login nodes, not compute nodes.


RECOMMENDED SOFTWARE

Login nodes:
* pam_cgroup_per_user
* oom_notifierd
* loginlimits
* cputime_controls
* namespaces

Compute nodes (shared nodes allowed):
* a resource manager with cgroups support (not provided)
* cgroups_compute
* namespaces

Compute nodes (exclusive node access):
* namespaces

Note that cgroups aren't particularly useful on compute nodes if shared access is prohibited.
