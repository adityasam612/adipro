#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROC_FILENAME "ipv6_counter"

static unsigned int ipv6_pkt_count = 0;
static struct nf_hook_ops nfho;
static struct proc_dir_entry *proc_file;

/* Netfilter hook function */
static unsigned int ipv6_packet_counter_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    /* Count IPv6 packets */
    if (skb->protocol == htons(ETH_P_IPV6)) {
        ipv6_pkt_count++;

        /* Log every 100 packets */
        if (ipv6_pkt_count % 100 == 0) {
            printk(KERN_INFO "IPv6 packets counted: %u\n", ipv6_pkt_count);
        }
    }

    return NF_ACCEPT;
}

/* /proc file read function */
static int proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%u\n", ipv6_pkt_count);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_file_ops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Module init */
static int __init ipv6_counter_init(void)
{
    printk(KERN_INFO "IPv6 Counter Module Loaded.\n");

    /* Register Netfilter hook */
    nfho.hook = ipv6_packet_counter_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = NFPROTO_IPV6;
    nfho.priority = NF_IP6_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    /* Create /proc file */
    proc_file = proc_create(PROC_FILENAME, 0, NULL, &proc_file_ops);
    if (!proc_file) {
        nf_unregister_net_hook(&init_net, &nfho);
        printk(KERN_ERR "Failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }

    return 0;
}

/* Module exit */
static void __exit ipv6_counter_exit(void)
{
    printk(KERN_INFO "IPv6 Counter Module Unloaded.\n");

    proc_remove(proc_file);
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(ipv6_counter_init);
module_exit(ipv6_counter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("IPv6 Packet Counter with /proc export and printk logging");
