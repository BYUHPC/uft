#!/usr/bin/perl -w

#  ###   #     #  #####  ####### #     # ######  #       ####### ####### #######
#   #    ##    # #     # #     # ##   ## #     # #       #          #    #
#   #    # #   # #       #     # # # # # #     # #       #          #    #
#   #    #  #  # #       #     # #  #  # ######  #       #####      #    #####
#   #    #   # # #       #     # #     # #       #       #          #    #
#   #    #    ## #     # #     # #     # #       #       #          #    #
#  ###   #     #  #####  ####### #     # #       ####### #######    #    #######

#  This script was never completed by Ryan.  Due to the anticipated and eventual switch to SLURM, it was never completed though it was really close.  Use at your own risk.  This is provided so that others can have an idea of how to start adding support to Torque or other schedulers.  One immediate observation is that it uses cpu.shares to control CPU usage.  That may or may not be better than cpusets since the user isn't pinned to only the requested number of CPUs, though it should approximate it.  Using cpusets would require intelligence in knowing which CPUs to allocate to do NUMA layout, etc.

# Author:  Ryan Cox <ryan_cox@byu.edu>
#
# Copyright (C) 2012, Brigham Young University
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



use strict;
use Getopt::Std;
use File::Path qw(mkpath);

# require "/fslhome/ryancox/cgroups/BYUFSLCgroups.pm";

sub printUsage(;$);
sub validateOption_integer(\%$);

sub CGROUPPATH { "/cgroup" }

sub getValue($$);
sub setValue($$$);
sub countCpus();
sub updateCgroup($$$$);
sub recalculateUserSetting($$);
sub createCgroup($);
sub modifyCgroupAllocation($);
sub recalculateAllocations($);
sub assignPid($);
sub ownerOfPid($);

my $cpus = countCpus();

#special case: if there is only one argument and it is the cgroup, release it and recalculate
if($#ARGV == 0 && -d CGROUPPATH . $ARGV[0]) {
	my $cgroup = CGROUPPATH . $ARGV[0];
	if($cgroup =~ /\/users\/user_(\w+)\/job_(\w*)/) {
		rmdir($cgroup);
		my %opts = ( 'u' => $1 );
		print "Will recalculate for user $1\n";
		recalculateAllocations(\%opts);
	} else {
		die("Malformed path: \"$cgroup\".\n");
	}
	exit;
}

my %opts;
getopts('c:m:s:j:u:p:rh', \%opts);

########## test options

if(exists $opts{'u'} and $opts{'u'} =~ /^\d+/) {
	#convert uid to username. keep it as uid if we can't find the username
	$opts{'u'} = getpwuid($opts{'u'}) || $opts{'u'};
}

if(exists $opts{'u'} and exists $opts{'j'}) {
#
# Create/modify cgroup
#
	if(exists $opts{'r'} or exists $opts{'p'}) {
		printUsage("Cannot specify \"-r\" or \"-p\" when adding/modifying a cgroup");
		exit(1);
	}
	createCgroup(\%opts);
	modifyCgroupAllocation(\%opts);
} elsif(exists $opts{'p'} and exists $opts{'j'}) {
#
# Assign PID to a cgroup
#

	my @o = keys %opts;

	# (Perl)1 == (ANYTHING_ELSE)2
	if($#o != 1) {
		printUsage("Cannot specify other options when adding a process to a cgroup");
		exit(1);
	}

	#ugly way of doing it, but it works
 	$opts{'u'} = ownerOfPid($opts{'p'});
 	assignPid(\%opts);
} elsif(exists $opts{'r'} and exists $opts{'u'}) {
#
# Recalculate allocation for user
#

	my @o = keys %opts;
	if($#o != 1) {
		printUsage("Cannot specify other options when recalculating a user's allocation");
		exit(1);
	}
 	recalculateAllocations(\%opts);
} elsif(exists $opts{'h'}) {
#
# Show usage
#

	printUsage();
	exit(0);
} else {
#
# Invalid
#

	printUsage("Invalid set of options specified");
	exit(1);
}

######### done testing options

# if(not exists $opts{'j'}) {
# 	my @invalid_without_jobid = qw( c m s );
# 	foreach my $key(@invalid_without_jobid) {
# 		if(exists $opts{$key}) {
# 			printUsage("option $key invalid requires -j");
# 			exit(1);
# 		}
# 	}
# } else {
# 	$opts{'j'} = "job_$opts{'j'}";
# }


my @opts_require_integer = qw( c m s );
foreach my $opt(@opts_require_integer) {
	validateOption_integer(%opts, $opt);
}

#my @types;
#loop through types
#if(exists $opts{'r'} and $opts{'r'} ne "ALL") {
#	@types = ($opts{'r'});
#} else {
#	opendir(CGROUPDIR, CGROUPPATH());
#	@types = readdir(CGROUPDIR);
#	closedir(CGROUPDIR);
#}


sub cgroupPathUser($) {
	my $opts = shift;
	return CGROUPPATH() . "/users/user_$$opts{'u'}";
}

sub cgroupPathJob($) {
	my $opts = shift;
	return  cgroupPathUser($opts) . "/job_$$opts{'j'}";
}

# createCgroup(\%opts):
# This creates or modifies a cgroup to match the allocation amounts specified in %opts.  It will create the hierarchy users/user_username/jobs_jobname if it doesn't already exist.  The values are then set to those specified.
# The following must exist in %opts: j, u
# The following are optional in %opts: c, m, s
#
sub createCgroup($) {
	my $opts = shift;
	#just to mitigate the already low chance of collisions between usernames and values, prepend "user_"
# 	my $cgroup_user = CGROUPPATH . "/users/user_$$opts{'u'}";

# 	mkpath($cgroup_user);
# 	my $cgroup_job = "$cgroup_user/$$opts{'j'}";
	my $cgroup_user = cgroupPathUser($opts);
	my $cgroup_job = cgroupPathJob($opts);
	if( ! -e $cgroup_job ) {
		mkpath($cgroup_job);
		setValue($cgroup_job, "notify_on_release", 0);

# 	my @jobs = glob("$cgroup_user/job_*");
# 	if($#jobs > -1) {
# 	setValue($cgroup_user, "notify_on_release", 1);
	setValue($cgroup_user, "memory.use_hierarchy", 1);
# 	setValue($cgroup_job, "notify_on_release", 1);
	setValue($cgroup_job, "memory.use_hierarchy", 1);
# 	} else {
# 		setValue($cgroup_user, "notify_on_release", 0);
# 	}
	}
}

# modifyCgroupAllocation(\%opts):
# This modifies an existing cgroup to match the allocation amounts specified in %opts.
#
sub modifyCgroupAllocation($) {
	my $opts = shift;
	my $cgroup_user = cgroupPathUser($opts);
	if(exists $$opts{'c'}) {
		my $shares = int( (1024 * $$opts{'c'} ) / countCpus() );
		updateCgroup($cgroup_user, $$opts{'j'}, "cpu.shares", $shares);
	}

	if(exists $$opts{'m'}) {
		updateCgroup($cgroup_user, $$opts{'j'}, "memory.limit_in_bytes", $$opts{'m'});
	}

	if(exists $$opts{'s'}) {
		updateCgroup($cgroup_user, $$opts{'j'}, "memory.memsw.limit_in_bytes", $$opts{'s'});
	}

	recalculateAllocations($opts);
}

sub recalculateAllocations($) {
	#aggregate the job_* values for the user's root
	my $opts = shift;
	my $cgroup_user = cgroupPathUser($opts);
	recalculateUserSetting($cgroup_user, "cpu.shares");
	recalculateUserSetting($cgroup_user, "memory.limit_in_bytes");
	recalculateUserSetting($cgroup_user, "memory.memsw.limit_in_bytes");
}

# assignPid(\%opts)
# Assign process to a cgroup
sub assignPid($) {
	my $opts = shift;
	my $cgroup_target;
	my $cgroup_user = cgroupPathUser($opts);

	# $cgroup_target is the cgroup the process will be added to.  If a job is specified, it will be added to that group.  If a job is not specified or if a specified job cgroup doesn't exist, the process will be added to the user's top level cgroup

	if(exists $$opts{'j'}) {
		$cgroup_target = cgroupPathJob($opts);
		if( ! -e $cgroup_target) {
			$cgroup_target = $cgroup_user;
		}
	} else {
		$cgroup_target = $cgroup_user;
	}

	# This adds the process to the cgroup. It does not remove existing processes.
	setValue($cgroup_target, "tasks", $$opts{'p'});
	# Call the notification script on release
	setValue($cgroup_target, "notify_on_release", 1);
}

# ownerOfPid($pid)
# Figure out who $pid is running as. Return the username
# Maybe there's a module that does this, but I haven't looked yet. It's easy enough this way.
sub ownerOfPid($) {
	my $pid = shift;
	my $pid_file = "/proc/$pid";
	if(! -e $pid_file) {
		die("Process $pid does not exist\n"); # or /proc doesn't work the same on your system
	}
	my @stat = stat($pid_file);
	my $owner = getpwuid($stat[4]) || $stat[4];
	return $owner;
}

sub printUsage(;$) {
	if($#_ == 0) {
		print STDERR $_[0] . "\n";
	}
	print <<"EOF";

Options:
	-h   this message
	-r   recalculate user allocation (useful after deletion of a job)
	-j   job ID
	-u   username

Limits:
	-c   soft number of CPUs to allocate (uses "shares")
	-m   hard memory limit in bytes
	-s   hard mem+swap limit in bytes

USAGE:
  Create/modify cgroup (also recalculates aggregate allocation for user):
	$0 -u USERNAME -j JOBID [ -c CPUCOUNT ] [ -m MEMORY ] [ -s MEMPLUSSWAP ]

  Assign a process to a cgroup:
	$0 -p PID -j JOBID

  Recalculate aggregate allocation for user (useful after a job completes):
	$0 -u USERNAME -r

  #FUTURE: Kill user's jobs/processes and remove group

EOF

# Examples:
# 	# Create or modify user12's 8675309.My.Job.ID cgroup
# 	$0 -u user12 -j 8675309.My.Job.ID -c 2 -m 10485760 -s 20971520
# 
# 	# Assign pid 1234 to 8675309.My.Job.ID cgroup for pid 1234's owner
# 	$0 -j 8675309.My.Job.ID -p 1234
# 
# 	# Recalculate allocation for user12
# 	$0 -u user12 -r
# 
# Notes:
# 	When assigning a PID to a cgroup, username is determined by owner of PID. If specified JOBID is non-existent, PID is attached to the root cgroup for the owner of PID.
# 
# 
# EOF

}

sub recalculateUserSetting($$) {
	my ($cgroup_user, $setting) = @_;
	setValue($cgroup_user, $setting, sumJobValues($cgroup_user, $setting));
}

sub validateOption_integer(\%$) {
	my ($opts, $opt) = @_;
	if(exists $$opts{$opt} and $$opts{$opt} !~ /^\d+$/) {
		printUsage("-$opt must be an integer");
		exit(1);
	}
	return 1;
}

sub updateCgroup($$$$) {
	my ($cgroup_user, $job, $setting, $value) = @_;
	setValue("$cgroup_user/job_$job", $setting, $value);
# 	setValue($cgroup_user, $setting, sumJobValues($cgroup_user, $setting)); #aggregate the job_* values for the user's root
}

sub sumJobValues($$) {
	my ($dir, $setting) = @_;
	my @jobs = glob("$dir/job_*/");
	my $sum = 0;
	foreach my $job(@jobs) {
		$sum += getValue($job, $setting);
	}
	return $sum;
}

sub setValue($$$) {
	my ($dir, $setting, $value) = @_;
	open(FILE, ">", $dir . "/" . $setting) or warn $!;
	print FILE "$value\n";
	# close() complains if the particular cgroup isn't set up properly, so ignore. e.g. cpuset has to be set up first
	if(close(FILE)) {
		print "Wrote $value to $dir/$setting\n";
	} else {
		warn "Error writing $value to $dir/$setting: $!\n";
sleep(300);
	}
}

sub getValue($$) {
	my ($dir, $setting) = @_;
	my $ret;
	open(FILE, $dir . "/" . $setting) or return undef;
	$ret = <FILE>;
	chomp $ret;
	close(FILE);
	return $ret;
}

sub countCpus() {
	#use Unix::Processors, Sys::Info, or Sys::CPU to make this more portable. We only have x86_64 Linux, so this isn't an issue for us... one of these days. Could also do glob of /sys/devices/system/cpu/cpu[0-9]* on linux
	my $cpus = 0;
	open(CPUINFO, "/proc/cpuinfo");
	while(<CPUINFO>) {
		$cpus++ if($_ =~ /^processor/i);
	}
	close(CPUINFO);
	return $cpus;
}
