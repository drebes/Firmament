#ifndef _FIRMVM_H
#define _FIRMVM_H
#include "firm_global.h"

#define F_DFT_TO (20)

struct f_timer {
    uint8_t reg;
    unsigned long period;
    struct timer_list tl;
    struct f_flow *flow;
    char started;
};

struct f_flow {
    char *name;			/* rule name as shown to the user */
    int hook;			/* netfilter hook */
    int pf;			/* protocol family */
    int priority;		/* netfilter hook priority */
    unsigned short protocol;	/* protocol number (ethertype) */
    char started;		/* flow is active? */
    char *faultlet;		/* faultlet storage */
    uint32_t fsize;		/* faultlet size */
    int32_t reg[F_MAXREG];	/* flow registers */
    struct nf_hook_ops nfh;	/* netfilter hook parameters */
    struct proc_dir_entry *pdir;	/* proc_dir_entry for rule file */
    struct f_timer timer[F_MAXREG];
    unsigned long delay;

};

static struct f_flow f_flowtable[] = {
    {"ipv4_in", NF_IP_PRE_ROUTING, PF_INET, NF_IP_PRI_FIRST, 0x0800},
    {"ipv6_in", NF_IP6_PRE_ROUTING, PF_INET6, NF_IP6_PRI_FIRST, 0x86DD},
    {"ipv4_out", NF_IP_POST_ROUTING, PF_INET, NF_IP_PRI_FIRST, 0x800},
    {"ipv6_out", NF_IP6_POST_ROUTING, PF_INET6, NF_IP6_PRI_FIRST, 0x86DD},
    {NULL}
};

struct f_cmds {
    char *name;
    int (*func) (int argc, char *argv[]);
    int argcmin;
    char *argc_errmsg;
};

static int f_dostartflow(int argc, char *argv[]);
static int f_dostopflow(int argc, char *argv[]);
static int f_doshowreg(int argc, char *argv[]);
static int f_dosetto(int argc, char *argv[]);
static int f_doreset(int argc, char *argv[]);
static int f_doversion(int argc, char *argv[]);
static int f_doverbose(int argc, char *argv[]);

static struct f_cmds firmcmds[] = {
    {"startflow", f_dostartflow, 2, "startflow {flow|all}"},
    {"stopflow", f_dostopflow, 2, "stopflow {flow|all}"},
    {"showregister", f_doshowreg, 3, "showregister flow {register|all}"},
    {"settimeout", f_dosetto, 2, "settimeout value"},
    {"reset", f_doreset, 1, "reset"},
    {"version", f_doversion, 1, "version"},
    {"wdverbose", f_doverbose, 2, "wdverbose {yes|no}"},
    {NULL},
};

struct f_delayparms {
    struct sk_buff *skb;
    struct timer_list *timer;
    struct nf_queue_entry *entry;
};


#endif
