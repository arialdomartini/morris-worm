/* Magic numbers the program uses to identify other copies of itself. */

#define REPORT_PORT 0x2c5d
#define MAGIC_1 0x00148898
#define MAGIC_2 0x00874697
extern int pleasequit;		/* This stops the program after one
				 * complete pass if set.  It is incremented
				 * inside of checkother if contact with another
				 * happens. */

/* There are pieces of "stub" code, presumably from something like this to
   get rid of error messages */
#define error()

/* This appears to be a structure unique to this program.  It doesn't seem that
 * the blank slots are really an array of characters for the hostname, but
 * maybe they are.
 */
struct hst {
    char *hostname;
    int l4, l8, l12, l16, l20, l24, o28, o32, o36, o40, o44;
    int o48[6];					/* used */
    int flag;					/* used */
#define HST_HOSTEQUIV	8
#define HST_HOSTFOUR	4
#define HST_HOSTTWO	2
    struct hst *next;				/* o76 */
};

typedef struct {
    char *name;
    unsigned long size;
    char *buf;
} object;

extern struct ifses {
    int if_l0, if_l4, if_l8, if_l12; /* unused */
    int if_l16;			/* used */
    int if_l20;			/* unused */
    int if_l24;			/* used */
    short if_l28;		/* unused */
} ifs[];
extern nifs;

extern int ngateways;

extern object objects[], *getobjectbyname();
extern int nobjects;

/* Only used for a2in().  Why?  I don't know. */
struct bar {int baz;};
extern struct bar *a2in();

