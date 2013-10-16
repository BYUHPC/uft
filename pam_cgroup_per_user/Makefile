all:
	gcc -fPIC -shared -lpam -xc -c pam_cgroup_per_user.c
	ld -x --shared -o pam_cgroup_per_user.so pam_cgroup_per_user.o
#	gcc -shared -o pam_cgroup_per_user.so pam_cgroup_per_user.o -lpam


#/bin/sh ../../libtool --tag=CC   --mode=compile gcc -DHAVE_CONFIG_H -g -O2 -MT pam_cgroup_per_user.lo -MD -MP -MF .deps/pam_cgroup_per_user.Tpo -c -o pam_cgroup_per_user.lo pam_cgroup_per_user.c
#gcc -DHAVE_CONFIG_H -g -O2 -MT pam_cgroup_per_user.lo -MD -MP -MF .deps/pam_cgroup_per_user.Tpo -c pam_cgroup_per_user.c  -fPIC -DPIC -o pam_cgroup_per_user.o
#mv -f .deps/pam_cgroup_per_user.Tpo .deps/pam_cgroup_per_user.Plo
#/bin/sh ../../libtool --tag=CC   --mode=link gcc -I../../libpam/include -I../../libpamc/include -g -O2 -no-undefined -avoid-version -module -Wl,--version-script=./../modules.map -Wl,--as-needed -Wl,--no-undefined -Wl,-O1 -o pam_cgroup_per_user.la -rpath /lib64/security pam_cgroup_per_user.lo ../../libpam/libpam.la 
#libtool: link: rm -fr  .libs/pam_cgroup_per_user.la .libs/pam_cgroup_per_user.lai .libs/pam_cgroup_per_user.so
#libtool: link: gcc -shared  .libs/pam_cgroup_per_user.o   -Wl,-rpath -Wl,/fslhome/ryancox/pam/libpam/.libs ../../libpam/.libs/libpam.so -laudit -ldl  -Wl,--version-script=./../modules.map -Wl,--as-needed -Wl,--no-undefined -Wl,-O1   -Wl,-soname -Wl,pam_cgroup_per_user.so -o .libs/pam_cgroup_per_user.so
#libtool: link: ( cd ".libs" && rm -f "pam_cgroup_per_user.la" && ln -s "../pam_cgroup_per_user.la" "pam_cgroup_per_user.la" )

