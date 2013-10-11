#!/bin/bash

#Ryan Cox. Nov 2011

# IMPORTANT:  This file MUST be either saved as or linked to memory, cpu, cpuset, etc so that $1 is properly set. Or you can just change the $1 to memory, etc for each script

CGROUPPATH=/cgroup
#type=$(basename $0)
type=""
user=$(echo $1 | awk -F users/user_ '{print $2}' | cut -d/ -f1)

#sleep 20
#exit


echo "NOTICE: '$0 $*'" | wall

rmdir "$CGROUPPATH/$type$1"
#very ugly....
#/fslhome/ryancox/cgroups/manage_cgroup.pl -r $type -u $(echo $1 | awk -F users/user_ '{print $2}' | cut -d/ -f1)
/fslhome/ryancox/cgroups/manage_cgroup.pl -u $(echo $1 | awk -F users/user_ '{print $2}' | cut -d/ -f1) 2>&1 | wall
#echo "Should have run stuff for '$user'"
