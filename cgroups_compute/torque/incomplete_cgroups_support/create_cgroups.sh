#!/bin/sh -e

#add the ones you need
mount -tcgroup -o cpu,memory cgroup /cgroup
echo 1 > "/cgroup/memory.use_hierarchy"
echo 0 > "/cgroup/notify_on_release"
echo 1 > "/cgroup/cgroup.clone_children"
echo /fslhome/ryancox/cgroups/release_cgroup.sh > "/cgroup/release_agent"

exit





CGROUPPATH=/cgroup

mkdir -p "$CGROUPPATH"
awk 'NR>1 {print $1}' /proc/cgroups |
while read -r type
do
	path="$CGROUPPATH/$type"
	mkdir -p "$path"
	mount -tcgroup -o"$type" "cgroup:$type" "$path"
	echo /fslhome/ryancox/cgroups/release_cgroup.sh > "$path/release_agent"
	echo 0 > "$path/notify_on_release"
	if [ -e "$path/cgroup.clone_children" ]
	then
		echo 1 > "$path/cgroup.clone_children"
	fi
done 

echo 1 > "$CGROUPPATH/memory/memory.use_hierarchy"
