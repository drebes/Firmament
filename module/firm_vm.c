/*
 * FIRMAMENT kernel module
 * Copyright (c) 2005 Roberto Jung Drebes
 *                    Felipe Mobus
 *                    Leonardo Golob
 *
 * Portions of this code (in f_tokenize, f_docmd)
 * Copyright (c) 1991 Phil Karn, KA9Q
 *
 *
 *   This file is part of FIRMAMENT.
 *
 *   FIRMAMENT is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   FIRMAMENT is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with FIRMAMENT; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <asm/uaccess.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_queue.h>
#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/net_namespace.h> /* Correção para proc_net */
#define __KERNEL_
#include "firm_vm.h"
#include "firm_global.h"
#ifndef INT32_MAX
#define INT32_MAX              (2147483647)
/*#define proc_net NULL          Evitando redefinir proc_net */
#endif
#define f_faulterr(flow, format, arg...) { printk(KERN_ERR "firm_vm: " format "\n" , ## arg); f_stopflow(flow); return NF_ACCEPT;}
#define proc_net init_net.proc_net /* Redefinição do diretório */

/* Function prototypes */
static ssize_t f_read(struct file *, char *, size_t, loff_t *);
static ssize_t f_write(struct file *, const char *, size_t, loff_t *);
static ssize_t f_control_write(struct file *, const char *, size_t,
			       loff_t *);
static int f_open(struct inode *, struct file *);
static int f_close(struct inode *, struct file *);
static int f_permission(struct inode *, int, unsigned int);
static struct f_flow *f_findflow(int, unsigned short);
static int f_startflow(struct f_flow *);
static int f_stopflow(struct f_flow *);
static void f_reset(void);
static unsigned int
f_hook(unsigned int hook,
       struct sk_buff *,                                                                                /* Alterado */
       const struct net_device *,
       const struct net_device *, int (*)(struct sk_buff *));
static int
f_process_queued(struct nf_queue_entry *entry, unsigned int queuenum);
static int f_docmd(struct f_cmds *cmds, int argc, char *argv[]);
static void f_delaydeliver(struct f_delayparms *);
static int f_isanumber(char *, uint32_t *);
static uint32_t f_get_random_bytes(uint32_t *, uint32_t *, uint32_t *);


/* Module variables */
static struct file_operations f_fops = {
  read:f_read,
  write:f_write,
  open:f_open,
  release:f_close,
};

static struct file_operations f_cfops = {
  write:f_control_write,
};

static struct inode_operations f_iops = {
  permission:f_permission,
};

/* Default timeout for faultlet watchdog: 20 ms */
static uint32_t timeout = F_DFT_TO;

/* Be verbose when reporting warnings? */
static uint32_t f_verbose = 0;

/* Tausworthe Random Seeds */
static uint32_t seed1, seed2, seed3;

static struct proc_dir_entry *firm_proc_dir, *firm_rules_proc_dir,
    *proc_net_firm_action;

static struct nf_queue_handler nf_q_h = {         /* Alterado */
  .outfn = &f_process_queued,          		  /* Alterado */
  .name = "Processa_Fila",			  /* Alterado */
};

/*
 * Receive a null terminated string 'line' and fill argc with the
 * token count and argv[] with the list of tokens. maxargc is the
 * maximum number of tokens expected by the calling function.
 */
static void f_tokenize(char *line, int *argc, char *argv[], int maxargc)
{
    char *cp;

    /* Initialize token list */
    for (*argc = 0; *argc < maxargc; (*argc)++)
	argv[*argc] = '\0';

    for (*argc = 0; *argc < maxargc;) {

	/* Skip leading white space */
	while (*line == ' ' || *line == '\t')
	    line++;
	if (*line == '\0')
	    /* Line ended */
	    break;
	/* Start of token */
	argv[(*argc)++] = line;
	/* Find space or tab. If not present,
	 * then we've already found the last
	 * token.
	 */
	if ((cp = strchr(line, ' ')) == '\0' &&
	    (cp = strchr(line, '\t')) == '\0') {
	    break;
	}
	/* End of token */
	*cp++ = '\0';
	line = cp;
    }
}

static ssize_t
f_read(struct file *file, char *buffer, size_t length, loff_t * ppos)
{
    int ino, i;
    ino = file->f_dentry->d_inode->i_ino;

    for (i = 0; f_flowtable[i].name != NULL; i++) {
	if (ino == f_flowtable[i].pdir->low_ino) {
	    if (*ppos >= f_flowtable[i].fsize)
		return 0;
	    if (f_flowtable[i].fsize > 0) {
		if (length >= f_flowtable[i].fsize) {
		    if (copy_to_user(buffer,
				 f_flowtable[i].
				 faultlet, f_flowtable[i].fsize))
			return 0;
		    *ppos += f_flowtable[i].fsize;
		    return f_flowtable[i].fsize;
		} else {
		    if (copy_to_user(buffer, f_flowtable[i].faultlet, length))
			return 0;
		    *ppos += length;
		    return length;
		}
	    }
	}
    }
    printk(KERN_DEBUG "firm_vm: f_read called for an invalid file.\n");
    return 0;
}

static ssize_t
f_control_write(struct file *file, const char *buff, size_t len,
		loff_t * ppos)
{
    int ino;
    int argc;
    char *argv[4];
    char *command;

    /*
     * Writes are only permitted in the beggining of the file.
     */
    if (*ppos > 0)
	return -ESPIPE;
    ino = file->f_dentry->d_inode->i_ino;
    if (ino != proc_net_firm_action->low_ino) {
	printk(KERN_DEBUG
	       "firm_vm: f_control_write called for an invalid file.\n");
	return 0;
    }
    command = kmalloc(len, GFP_KERNEL);
    if (copy_from_user(command, buff, len - 1))
	return 0;
    command[len - 1] = '\0';
    f_tokenize(command, &argc, argv, 4);
    f_docmd(firmcmds, argc, argv);
    return len;
}

static ssize_t
f_write(struct file *file, const char *buff, size_t len, loff_t * ppos)
{

    int ino, i = 0;

    /*
     * Writes are only permitted in the beggining of the file.
     */
    if (*ppos > 0)
	return -ESPIPE;
    ino = file->f_dentry->d_inode->i_ino;
    for (i = 0; f_flowtable[i].name != NULL; i++) {
	if (ino == f_flowtable[i].pdir->low_ino) {
	    break;
	}
    }
    if (f_flowtable[i].name == NULL) {
	printk(KERN_DEBUG
	       "firm_vm: f_write called for an invalid file.\n");
	return 0;
    }
    if (f_flowtable[i].faultlet != NULL) {
	kfree(f_flowtable[i].faultlet);
	f_flowtable[i].faultlet = NULL;
    }
    if (len > 0) {
	f_flowtable[i].faultlet = kmalloc(len, GFP_KERNEL);
	if (copy_from_user(f_flowtable[i].faultlet, buff, len))
		return 0;
    }
    f_flowtable[i].fsize = f_flowtable[i].pdir->size = *ppos = len;
    return len;
}

static int f_open(struct inode *ino, struct file *filep)
{
    return 0;
}

static int f_close(struct inode *ino, struct file *file)
{
    return 0;
}

static int f_permission(struct inode *inode, int mask, unsigned int unused)
{
    int i;

    /* If not root, deny access */
    if (current_euid() != 0)
	return -EACCES;
    /* "control" file can only be written to */
    if (inode->i_ino == proc_net_firm_action->low_ino) {
	if (mask & MAY_WRITE)
	    return 0;
	else
	    return -EACCES;
    }
    /*
     * Test if it was any of the rule files. Always allows reading,
     * but writing only if the flow is not started.
     */
    for (i = 0; f_flowtable[i].name != NULL; i++) {
	if (inode->i_ino == f_flowtable[i].pdir->low_ino) {
	    if (mask & MAY_READ)
		return 0;
	    if ((mask & MAY_WRITE) && !f_flowtable[i].started)
		return 0;
	    else
		return -EACCES;
	}
    }
    /* For any other file. Should not reach this point. */
    printk(KERN_DEBUG
	   "firm_vm: f_permission called for an invalid file.\n");
    return -EACCES;
}

/*
 * Module initialization and cleanup
 */
static int __init f_init_module(void)
{

    int i;
    int retval = 0;

    get_random_bytes(&seed1, sizeof(seed1));
    get_random_bytes(&seed2, sizeof(seed2));
    get_random_bytes(&seed3, sizeof(seed3));
    firm_proc_dir = proc_mkdir("firmament", proc_net);
    if (!firm_proc_dir) {
	remove_proc_entry("firmament", proc_net);
	printk(KERN_ERR
	       "firmament error: could not create firmament directory\n");
	retval = -ENOMEM;
	goto exit;
    }
    firm_rules_proc_dir = proc_mkdir("rules", firm_proc_dir);
    if (!firm_rules_proc_dir) {
	remove_proc_entry("rules", firm_proc_dir);
	printk(KERN_ERR
	       "firmament error: could not create firmament/rules directory\n");
	retval = -ENOMEM;
	goto unreg_firm_proc;
    }

    proc_net_firm_action =
	create_proc_entry("control", S_IWUSR, firm_proc_dir);
    proc_net_firm_action->proc_iops = &f_iops;
    proc_net_firm_action->proc_fops = &f_cfops;
    if (!proc_net_firm_action) {
	remove_proc_entry("control", firm_proc_dir);
	printk(KERN_ERR
	       "firmament error: could not create control file\n");
	retval = -ENOMEM;
	goto unreg_rules_proc;
    }

    for (i = 0; f_flowtable[i].name != NULL; i++) {
	f_flowtable[i].pdir =
	    create_proc_entry(f_flowtable[i].name,
			      S_IRUSR | S_IWUSR, firm_rules_proc_dir);
	f_flowtable[i].pdir->proc_iops = &f_iops;
	f_flowtable[i].pdir->proc_fops = &f_fops;
	if (!f_flowtable[i].pdir) {
	    remove_proc_entry(f_flowtable[i].name, firm_rules_proc_dir);
	    printk(KERN_ERR
		   "firm_vm: could not create %s rule file.\n",
		   f_flowtable[i].name);
	    retval = -ENOMEM;
	    break;
	}
	/* Register the queue handler (delayed packets) */
        nf_register_queue_handler(f_flowtable[i].pf, &nf_q_h);  /* Alterado */

    }
    if (f_flowtable[i].name != NULL) {
	/* Not all rule files created. Unroll changes and quit */
	while (i >= 0) {
	    remove_proc_entry(f_flowtable[i--].name, firm_rules_proc_dir);
	}
    } else {
	/* Everything went well */
	printk(KERN_INFO "firm_vm: loaded\n");
	printk(KERN_INFO "firm_vm: random seeds are 0x%x 0x%x 0x%x\n",
	       seed1, seed2, seed3);
	return retval;
    }

    remove_proc_entry("control", firm_proc_dir);
  unreg_rules_proc:
    remove_proc_entry("rules", firm_proc_dir);
  unreg_firm_proc:
    remove_proc_entry("firmament", proc_net);
  exit:
    return retval;
}

static void __exit f_cleanup_module(void)
{
    int i;
    f_reset();
    for (i = 0; f_flowtable[i].name != NULL; i++) {
	remove_proc_entry(f_flowtable[i].name, firm_rules_proc_dir);
	/* Remove queue handler (delayed packets) */
        nf_unregister_queue_handler(f_flowtable[i].pf, &nf_q_h);                     /* Alterado */
    }
    remove_proc_entry("control", firm_proc_dir);
    remove_proc_entry("rules", firm_proc_dir);
    remove_proc_entry("firmament", proc_net);
    printk(KERN_INFO "firm_vm: unloaded\n");
}

struct f_flow *f_findflow(int hook, unsigned short protocol)
{
    int i;
    for (i = 0; f_flowtable[i].name != NULL; i++)
	if (f_flowtable[i].hook == hook
	    && f_flowtable[i].protocol == protocol) {
	    return &f_flowtable[i];
	}
    return NULL;
}


static struct f_flow *f_findflowbyname(char *flow)
{
    int i;
    for (i = 0; f_flowtable[i].name != NULL; i++)
	if (!strcmp(f_flowtable[i].name, flow))
	    return &f_flowtable[i];
    return NULL;
}

static void f_timerinc(struct f_timer *timer)
{
    timer->flow->reg[timer->reg]++;
    timer->tl.data = (unsigned long) timer;
    timer->tl.function = (void *) f_timerinc;
    timer->tl.expires = jiffies + timer->period * HZ /1000;
    add_timer(&(timer->tl));
}

static unsigned int
f_hook(unsigned int hook,
       struct sk_buff *pskb,                                                   /* Alterado */
       const struct net_device *in,
       const struct net_device *out, int (*okfn) (struct sk_buff *))
{
    struct sk_buff *skb, *dupskb;
    struct f_flow *flow;
    char *faultlet;
    char *event;
    uint32_t pc = 0;
    char code;
    uint32_t index1, index2, index3, size, i;
    int16_t shortaux;
    int32_t wordaux;
    unsigned long now, start;
    char *child_argv[4];

    start = jiffies;
    skb = pskb;                                                                /* Alterado */
    flow = f_findflow(hook, ntohs(skb->protocol));
    if (!flow)
	/* Called for an invalid hook */
	return NF_ACCEPT;
    /* Process faultlet */
    faultlet = flow->faultlet;
    while (pc < flow->fsize) {
	now = jiffies;
	if (timeout && now >= (start + timeout * HZ / 1000)) {
	    /* Watchdog timer expired */
	    printk(KERN_WARNING
		   "firm_vm: watchdog called for flow %s.\n", flow->name);
	    if (f_verbose) {
		child_argv[0] = kmalloc(13, GFP_ATOMIC);
		child_argv[2] = kmalloc(4, GFP_ATOMIC);
		child_argv[1] = flow->name;
		memcpy(child_argv[0], "showregister", 12);
		memcpy(child_argv[2], "all", 3);
		child_argv[0][12] = '\0';
		child_argv[2][3] = '\0';
		f_doshowreg(2, child_argv);
		kfree(child_argv[0]);
		kfree(child_argv[2]);
	    }
	    return NF_ACCEPT;
	}
	/* Evaluates instructions */
	code = faultlet[pc];
	switch (code) {
	case F_READB:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG)
		/* Invalid register */
		f_faulterr(flow, "invalid register.");
	    if (flow->reg[index1] < skb->len)
		flow->reg[index2] = skb->data[flow->reg[index1]];
	    else
		/* Access past the end of packet */
		printk(KERN_WARNING
		       "firm_vm: tried to read byte past the end of packet in flow %s.\n",
		       flow->name);
	    pc += 3;
	    break;
	case F_READS:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		/* Invalid register */
		f_faulterr(flow, "invalid register.");
	    }
	    if (flow->reg[index1] + 1 < skb->len) {
		memcpy(&shortaux,
		       &skb->data[flow->reg[index1]], sizeof(shortaux));
		flow->reg[index2] = ntohs(shortaux);
	    } else
		/* Access past the end of packet */
		printk(KERN_WARNING
		       "firm_vm: tried to read short past the end of packet in flow %s.\n",
		       flow->name);
	    pc += 3;
	    break;
	case F_READW:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		/* Invalid register */
		f_faulterr(flow, "invalid register.");
	    }
	    if (flow->reg[index1] + 3 < skb->len) {
		memcpy(&wordaux,
		       &skb->data[flow->reg[index1]], sizeof(wordaux));
		flow->reg[index2] = ntohl(wordaux);
	    } else
		/* Access past the end of packet */
		printk(KERN_WARNING
		       "firm_vm: tried to read word past the end of packet in flow %s.\n",
		       flow->name);
	    pc += 3;
	    break;
	case F_WRTEB:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		/* Invalid register */
		f_faulterr(flow, "invalid register.");
	    }
	    if (flow->reg[index1] < skb->len)
		skb->data[flow->reg[index1]] = flow->reg[index2] && 0x00ff;
	    else
		/* Access past the end of packet */
		printk(KERN_WARNING
		       "firm_vm: tried to write byte past the end of packet in flow %s.\n",
		       flow->name);
	    pc += 3;
	    break;
	case F_WRTES:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		/* Invalid register */
		f_faulterr(flow, "invalid register.");
	    }
	    if (flow->reg[index1] + 1 < skb->len) {
		shortaux = htons(flow->reg[index2]
				 && 0xffff);
		memcpy(&skb->data[flow->reg[index1]],
		       &shortaux, sizeof(shortaux));
	    } else
		/* Access past the end of packet */
		printk(KERN_WARNING
		       "firm_vm: tried to write short past the end of packet in flow %s.\n",
		       flow->name);
	    pc += 3;
	    break;
	case F_WRTEW:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		/* Invalid register */
		f_faulterr(flow, "invalid register.");
	    }
	    if (flow->reg[index1] + 3 < skb->len) {
		wordaux = htonl(flow->reg[index2]);
		memcpy(&skb->data[flow->reg[index1]],
		       &wordaux, sizeof(wordaux));
	    } else
		/* Access past the end of packet */
		printk(KERN_WARNING
		       "firm_vm: tried to write word past the end of packet in flow %s.\n",
		       flow->name);
	    pc += 3;
	    break;
	case F_SET:
	    index1 = faultlet[pc + 5];
	    /* Invalid register */
	    if (index1 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    memcpy(&wordaux, &faultlet[pc + 1], sizeof(wordaux));
	    flow->reg[index1] = ntohl(wordaux);
	    pc += 6;
	    break;
	case F_ADD:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index1] + flow->reg[index2];
	    pc += 3;
	    break;
	case F_SUB:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index2] - flow->reg[index1];
	    pc += 3;
	    break;
	case F_MUL:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index1] * flow->reg[index2];
	    pc += 3;
	    break;
	case F_DIV:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index2] / flow->reg[index1];
	    pc += 3;
	    break;
	case F_AND:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index1] & flow->reg[index2];
	    pc += 3;
	    break;
	case F_OR:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index1] | flow->reg[index2];
	    pc += 3;
	    break;
	case F_NOT:
	    index1 = faultlet[pc + 1];
	    /* Invalid register */
	    if (index1 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index1] = ~flow->reg[index1];
	    pc += 2;
	    break;
	case F_ACP:
	    return NF_ACCEPT;
	case F_DRP:
	    return NF_DROP;
	case F_DUP:
	    dupskb = skb_copy(pskb, GFP_ATOMIC);
	    if (dupskb) {
		okfn(dupskb);
	    }
	    return NF_ACCEPT;
	case F_DLY:
	    index1 = faultlet[pc + 1];
	    /* Invalid register */
	    if (index1 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->delay = flow->reg[index1];
	    return NF_QUEUE;
	case F_JMP:
	    memcpy(&shortaux, &faultlet[pc + 1], sizeof(shortaux));
	    pc = ntohs(shortaux);
	    /* Jump to invalid position */
	    if (pc >= flow->fsize)
		f_faulterr(flow, "JMP to invalid position %u.", pc);
	    break;
	case F_JMPZ:
	    index1 = faultlet[pc + 1];
	    if (index1 >= F_MAXREG) {
		printk(KERN_ERR "firm_vm: invalid register.\n");
		f_stopflow(flow);
		return NF_ACCEPT;
	    }
	    if (flow->reg[index1] == 0) {
		memcpy(&shortaux, &faultlet[pc + 2], sizeof(shortaux));
		pc = ntohs(shortaux);
		/* Jump to invalid position */
		if (pc >= flow->fsize) {
		    printk(KERN_ERR
			   "firm_vm: JMPZ to invalid position %u.\n", pc);
		    f_stopflow(flow);
		    return NF_ACCEPT;
		}
	    } else {
		pc += 4;
	    }
	    break;
	case F_AION:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		printk(KERN_ERR "firm_vm: invalid register.\n");
		f_stopflow(flow);
		return NF_ACCEPT;
	    }
	    /* Register to increment */
	    if (!flow->timer[index2].started) {
	        flow->timer[index2].started = 1;
	        flow->timer[index2].flow = flow;
	        flow->timer[index2].period = flow->reg[index1];
	        flow->timer[index2].reg = index2;
	        flow->timer[index2].tl.data =
		    (unsigned long) &(flow->timer[index2]);
	        flow->timer[index2].tl.function = (void *) f_timerinc;
	        flow->timer[index2].tl.expires =
		    jiffies + flow->timer[index2].period * HZ / 1000;
	        add_timer(&(flow->timer[index2].tl));
	    }
	    pc += 3;
	    break;
	case F_AIOFF:
	    index1 = faultlet[pc + 1];
	    if (index1 >= F_MAXREG) {
		printk(KERN_ERR "firm_vm: invalid register.\n");
		f_stopflow(flow);
		return NF_ACCEPT;
	    }
	    if (flow->timer[index1].started) {
	        flow->timer[index1].started = 0;
	        del_timer(&(flow->timer[index1].tl));
	    }
	    pc += 2;
	    break;
	case F_JMPN:
	    index1 = faultlet[pc + 1];
	    if (index1 >= F_MAXREG) {
		printk(KERN_ERR "firm_vm: invalid register.\n");
		f_stopflow(flow);
		return NF_ACCEPT;
	    }
	    if (flow->reg[index1] < 0) {
		memcpy(&shortaux, &faultlet[pc + 2], sizeof(shortaux));
		pc = ntohs(shortaux);
		/* Jump to invalid position */
		if (pc >= flow->fsize) {
		    printk(KERN_ERR
			   "firm_vm: JMPN to invalid position %u.\n", pc);
		    f_stopflow(flow);
		    return NF_ACCEPT;
		}
	    } else {
		pc += 4;
	    }
	    break;
	case F_CSTR:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    /* String length */
	    size = faultlet[pc + 3];
	    /* Assume equal */
	    flow->reg[index2] = 1;
	    for (i = 0; i < size; i++) {
		if ((flow->reg[index1] + i) < skb->len) {
		    if (faultlet[pc + 4 + i] !=
			skb->data[flow->reg[index1] + i]) {
			/* Different byte */
			flow->reg[index2] = 0;
			break;
		    }
		} else {
		    /* Compared through the end of packet */
		    flow->reg[index2] = 0;
		    break;
		}
	    }
	    pc += (size + 4);
	    break;
	case F_SSTR:
	    index1 = faultlet[pc + 1];
	    /* Invalid register */
	    if (index1 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    /* String length */
	    size = faultlet[pc + 2];
	    i = 0;
	    while ((i < size)
		   && (flow->reg[index1] + i < skb->len)) {
		skb->data[flow->reg[index1] + i] = faultlet[pc + 3 + i];
		i++;
	    }
	    pc += (size + 3);
	    break;
	case F_RND:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    wordaux = f_get_random_bytes(&seed1, &seed2, &seed3);
	    flow->reg[index2] =
		(wordaux) / (INT32_MAX / flow->reg[index1] + 1);
	    pc += 3;
	    break;
	case F_MOV:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    flow->reg[index2] = flow->reg[index1];
	    pc += 3;
	    break;
	case F_DMP:
	    index1 = skb->len;
	    printk(KERN_INFO "firm_vm: packet dump follows, %d bytes\n",
		   skb->len);
	    for (index1 = 0; index1 < skb->len; index1++) {
		if (index1 % 16 == 0)
		    printk(KERN_INFO "\t");
		printk("%02x ", skb->data[index1]);
		if (index1 % 16 == 15)
		    printk("\n");
	    }
	    if (index1 % 16 != 15)
		printk("\n");
	    pc++;
	    break;
	case F_DBG:
	    index1 = faultlet[pc + 1];
	    /* Invalid register */
	    if (index1 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    /* String length */
	    size = faultlet[pc + 2];
	    event = kmalloc(size + 1, GFP_ATOMIC);
	    memcpy(event, &faultlet[pc + 3], size);
	    event[size] = '\0';
	    printk(KERN_INFO "firm_vm: DBG event: ");
	    printk(event, flow->reg[index1]);
	    printk("\n");
	    kfree(event);
	    pc += (size + 3);
	    break;
	case F_VER:
	    index1 = faultlet[pc + 1];
	    if (index1 >= F_MAXREG) {
		printk(KERN_ERR "firm_vm: invalid register.\n");
		f_stopflow(flow);
		return NF_ACCEPT;
	    }
	    flow->reg[index1] = (F_MAJORVER << 16) + F_MINORVER;
	    pc += 2;
	    break;
	case F_SEED:
	    index1 = faultlet[pc + 1];
	    index2 = faultlet[pc + 2];
	    index3 = faultlet[pc + 3];
	    /* Invalid register */
	    if (index1 >= F_MAXREG || index2 >= F_MAXREG
		|| index3 >= F_MAXREG) {
		f_faulterr(flow, "invalid register.");
	    }
	    seed1 = flow->reg[index1];
	    seed2 = flow->reg[index2];
	    seed3 = flow->reg[index3];
	    printk(KERN_INFO "firm_vm: random seeds are 0x%x 0x%x 0x%x\n",
		   seed1, seed2, seed3);
	    pc += 4;
	    break;
	default:
	    printk(KERN_ERR
		   "firm_vm: invalid instruction 0x%x.\n", faultlet[pc]);
	    f_stopflow(flow);
	    return NF_ACCEPT;
	}
    }
    /* Faultlet ended */
    return NF_ACCEPT;
}

static int f_startflow(struct f_flow *flow)
{
    int i;

    if (flow->started) {
	/* Already started */
	printk(KERN_INFO "firm_vm: flow %s already started.\n",
	       flow->name);
	return 1;
    }
    printk(KERN_INFO "firm_vm: starting flow %s.\n", flow->name);
    if (flow->pf == PF_BRIDGE) {
	/*
	 * Bridge flows are not supported. Their packets
	 * do not have unique protocol numbers.
	 */
	printk(KERN_ERR
	       "firm_vm: bridge flow %s is unsupported.\n", flow->name);
	return 0;
    }
    /* Clear registers */
    for (i = 0; i < F_MAXREG; i++) {
	flow->reg[i] = 0;
    }
    /* Init timers */
    for (i = 0; i < F_MAXREG; i++) {
        flow->timer[i].tl.data = (unsigned long) &(flow->timer[i]);                    /* Alterado */
	flow->timer[i].tl.function = (void *) f_timerinc;                              /* Alterado */
	flow->timer[i].tl.expires = 0;                                                 /* Alterado */
	flow->timer[i].tl.base = &boot_tvec_bases;                                     /* Alterado */
	flow->timer[i].started = 0;
	init_timer(&(flow->timer[i].tl));
    }
    /* Start */
    flow->nfh.hook = &f_hook;
    flow->nfh.owner = THIS_MODULE;                               /*   Alterado */
    flow->nfh.hooknum = flow->hook;
    flow->nfh.pf = flow->pf;
    flow->nfh.priority = flow->priority;
    if (nf_register_hook(&flow->nfh)) {
	printk(KERN_ERR
	       "firm_vm: could not register hook for %s flow\n",
	       flow->name);
	return 0;
    }
    /* Make the rule file appear read only */
    flow->pdir->mode = S_IFREG | S_IRUSR;
    flow->started = 1;
    return 1;
}


static int f_stopflow(struct f_flow *flow)
{
    int i;
    if (!flow->started) {
	/* Already stopped */
	printk(KERN_INFO "firm_vm: flow %s already stopped.\n",
	       flow->name);
	return 1;
    }
    /* Stop */
    printk(KERN_INFO "firm_vm: stopping flow %s.\n", flow->name);
    /* Stop timers */
    for (i = 0; i < F_MAXREG; i++) {
	del_timer(&(flow->timer[i].tl));
    }
    /* Remove hook */
    nf_unregister_hook(&flow->nfh);
    flow->started = 0;
    flow->delay = 0;
    /* Make the rule file appear read/writeable */
    flow->pdir->mode = S_IFREG | S_IRUSR | S_IWUSR;
    return 1;
}

/* Stop all flows, clear faultlets, clear registers, reset timeout */
static void f_reset(void)
{
    int i, j;
    for (i = 0; f_flowtable[i].name != NULL; i++) {
	f_stopflow(&f_flowtable[i]);
	if (f_flowtable[i].faultlet != NULL) {
	    kfree(f_flowtable[i].faultlet);
	    f_flowtable[i].faultlet = NULL;
	    f_flowtable[i].fsize = 0;
	    f_flowtable[i].pdir->size = 0;
	}
	for (j = 0; j < F_MAXREG; j++) {
	    f_flowtable[i].reg[j] = 0;
	}
    }
    timeout = F_DFT_TO;
}

/* Start flow by name */
static int f_dostartflow(int argc, char *argv[])
{
    struct f_flow *flow;
    int i;
    if (argc > 2) {
	printk(KERN_WARNING "firm_vm: error, use: startflow {all|flow}\n");
	return 0;
    }
    if (!strcmp(argv[1], "all")) {
	for (i = 0; f_flowtable[i].name != NULL; i++) {
	    f_startflow(&f_flowtable[i]);
	}
	return 1;
    }
    flow = f_findflowbyname(argv[1]);
    if (flow) {
	f_startflow(flow);
	return 1;
    }
    printk(KERN_WARNING "firm_vm: error, bad flow: %s\n", argv[1]);
    return 0;
}


/* Stop flow by name */
static int f_dostopflow(int argc, char *argv[])
{
    struct f_flow *flow;
    int i;
    if (argc > 2) {
	printk(KERN_WARNING "firm_vm: error, use: stopflow {all|flow}\n");
	return 0;
    }
    if (!strcmp(argv[1], "all")) {
	for (i = 0; f_flowtable[i].name != NULL; i++) {
	    f_stopflow(&f_flowtable[i]);
	}
	return 1;
    }
    flow = f_findflowbyname(argv[1]);
    if (flow) {
	f_stopflow(flow);
	return 1;
    }
    printk(KERN_WARNING "firm_vm: error, bad flow: %s\n", argv[1]);
    return 0;
}

/* Print register value */
static int f_doshowreg(int argc, char *argv[])
{
    struct f_flow *flow;
    uint32_t reg;
    if (argc > 3) {
	printk(KERN_WARNING
	       "firm_vm: error, use: showregister flow {register|all}\n");
	return 0;
    }
    flow = f_findflowbyname(argv[1]);
    if (!flow) {
	printk(KERN_WARNING "firm_vm: error, bad flow: %s\n", argv[1]);
	return 0;
    }
    argv[2]++;
    if (argv[2][-1] == 'r' || argv[2][-1] == 'R') {
	if (f_isanumber(argv[2], &reg) && (reg < F_MAXREG)) {
	    printk(KERN_INFO "firm_vm: %s.r%d: 0x%02x\n", argv[1], reg,
		   flow->reg[reg]);
	    return 1;
	}
    } else {
	argv[2]--;
	if (!strcmp(argv[2], "all")) {
	    for (reg = 1; reg < F_MAXREG; reg++)
		printk(KERN_INFO "firm_vm: %s.r%d: 0x%02x\n", argv[1], reg,
		       flow->reg[reg]);
	    return 1;
	}
    }
    printk(KERN_WARNING "firm_vm: error, bad register: %s\n", argv[2]);
    return 0;
}

/* Set timeout value. */
static int f_dosetto(int argc, char *argv[])
{
    uint32_t mytimeout;
    if (argc > 2) {
	printk(KERN_WARNING "firm_vm: error, use: settimeout value\n");
	return 0;
    }
    if (f_isanumber(argv[1], &mytimeout)) {
	timeout = mytimeout;
	if (mytimeout)
	    printk(KERN_INFO "firm_vm: setting timeout to %ld\n",
		   (long int) mytimeout);
	else
	    printk(KERN_INFO "firm_vm: disabling timeout\n");
	return 1;
    } else {
	printk(KERN_WARNING "firm_vm: error, use: settimeout value\n");
	return 0;
    }
}

/* Reset firmament */
static int f_doreset(int argc, char *argv[])
{
    if (argc > 1) {
	printk(KERN_WARNING "firm_vm: error, use: reset\n");
	return 0;
    }
    printk(KERN_INFO "firm_vm: reset called\n");
    f_reset();
    return 1;
}

/* Display firm_vm version */
static int f_doversion(int argc, char *argv[])
{
    if (argc > 1) {
	printk(KERN_WARNING "firm_vm: error, use: version\n");
	return 0;
    }
    printk(KERN_INFO "firm_vm: version %d.%d\n", F_MAJORVER, F_MINORVER);
    return 1;
}


/* Set verbosity */
static int f_doverbose(int argc, char *argv[])
{
    if (argc > 2) {
	printk(KERN_WARNING "firm_vm: error, use: wdverbose {yes|now}\n");
	return 0;
    }
    if (!strcmp(argv[1], "yes")) {
	f_verbose = 1;
	printk(KERN_INFO "firm_vm: using verbose output for watchdog\n");
	return 1;
    }
    if (!strcmp(argv[1], "no")) {
	f_verbose = 0;
	printk(KERN_INFO
	       "firm_vm: using simplified output for watchdog\n");
	return 1;
    }
    printk(KERN_WARNING "firm_vm: error, use: wdverbose {yes|now}\n");
    return 0;
}

/* Perform command from argv using cmds as the command list */
static int f_docmd(struct f_cmds *cmds, int argc, char *argv[])
{
    struct f_cmds *cmdp;

    for (cmdp = cmds; cmdp->name; cmdp++) {
	if (!strncmp(argv[0], cmdp->name, strlen(argv[0])))
	    break;
    }
    if (!cmdp->name) {
	printk(KERN_WARNING "firm_vm: error, bad command: %s\n",
	       argv[0]);
	return 0;
    }
    if (argc < cmdp->argcmin) {
	/* Insufficient arguments */
	printk(KERN_WARNING "firm_vm: error, use: %s\n",
	       cmdp->argc_errmsg);
	return 0;
    }
    if (!cmdp->func)
	return 0;
    return (*cmdp->func) (argc, argv);

}


/* Add timer for queued packets for late delivery */
static int f_process_queued(struct nf_queue_entry *entry, unsigned int queuenum)
{
    struct timer_list *timer;
    struct f_delayparms *parms;
    struct f_flow *flow;

    flow = f_findflow(entry->hook, ntohs(entry->skb->protocol));
    if (!flow) {
	/* Called for an invalid flow */
	printk(KERN_ERR
	       "firm_vm: error, f_process_queued called for an invalid flow.\n");
	return 0;                                                                             /* Alterado */
    }

    parms = kmalloc(sizeof(struct f_delayparms), GFP_ATOMIC);
    timer = kmalloc(sizeof(struct timer_list), GFP_ATOMIC);
    parms->timer = timer;
    parms->entry = entry;
    parms->skb = entry->skb;
    timer->data = (unsigned long) parms;
    timer->function = (void *) f_delaydeliver;
    timer->expires = jiffies + flow->delay * HZ / 1000;
    timer->base = &boot_tvec_bases;                                                                        /* Alterado */
    /*DEFINE_TIMER( time, (void *) f_delaydeliver, jiffies + flow->delay, (unsigned long) parms );            Alterado */
    init_timer(timer);
    add_timer(timer);
    return 0;                                                                                  /* Alterado */
}

/* Reinject a packet in the protocol stack after the delay */
static void f_delaydeliver(struct f_delayparms *parms)
{
    nf_reinject(parms->entry, NF_ACCEPT);
    kfree(parms->timer);
    kfree(parms);
}

/* Convert string to long, return wether the conversion succeeded. */
static int f_isanumber(char *name, uint32_t * value)
{
    char *err;
    *value = simple_strtoul(name, &err, 10);
    if (*err != '\0')
	return 0;
    else
	return 1;
}

static uint32_t f_get_random_bytes(uint32_t * s1, uint32_t * s2,
				   uint32_t * s3)
{
    *s1 = (((*s1 & 0xFFFFFFFE) << 12) ^ (((*s1 << 13) ^ *s1) >> 19));
    *s2 = (((*s2 & 0xFFFFFFF8) << 4) ^ (((*s2 << 2) ^ *s2) >> 25));
    *s3 = (((*s3 & 0xFFFFFFF0) << 17) ^ (((*s3 << 3) ^ *s3) >> 11));
    return *s1 ^ *s2 ^ *s3;
}


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FIRMAMENT packet manipulation module");
MODULE_AUTHOR("Roberto Jung Drebes <drebes@hal.rcast.u-tokyo.ac.jp>");
module_init(f_init_module);
module_exit(f_cleanup_module);

