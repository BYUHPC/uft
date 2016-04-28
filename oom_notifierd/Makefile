all:
	cc ${CFLAGS} -Os -o oom_notifierd oom_notifierd.c setproctitle.c

pedantic:
	gcc ${CFLAGS} -Wpedantic -Wunused  -Wunused-function -Wunused-label  -Wunused-local-typedefs -Wunused-parameter -Wno-unused-result -Wunused-value  -Wunused-variable -Wunused-but-set-parameter -Wunused-but-set-variable -Wall  -Wextra -o oom_notifierd oom_notifierd.c setproctitle.c

clean:
	rm -f oom_notifierd
