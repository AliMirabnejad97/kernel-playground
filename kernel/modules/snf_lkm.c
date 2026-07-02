#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netns/generic.h>

#define MAX_PORTS 65536
#define LIMIT 10

/* Dynamic registration ID for network namespace data */
static unsigned int lkm_net_id;
/* Global arrays to keep track of per-port packet counts */
static unsigned int tcp_count[MAX_PORTS];
static unsigned int udp_count[MAX_PORTS];
/* Structure to hold Netfilter hook operations per network namespace */
struct lkm_netns_data {
        struct nf_hook_ops nf_hops;
};

/* * =====================================================================================
 * Netfilter Packet Hook Callback (Core Logic)
 * =====================================================================================
 * This callback functions as the core traffic inspector. It intercepts IPv4 packets, 
 * parses transport headers (TCP/UDP), increments port statistics, and triggers alerts.
 */

static unsigned int nf_callback(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
        struct iphdr *iph;
        struct tcphdr *tcph;
        struct udphdr *udph;
        unsigned int ip_header_len;
        unsigned int src_port, dst_port;

/* 1. Sanity Check & Linearization */
        if (!skb || !pskb_may_pull(skb, sizeof(*iph))) {
                printk(KERN_INFO "M2: weird skb?! Accept it\n");
                return NF_ACCEPT;
        }
// Fetch the IPv4 header from the socket buffer
        iph = ip_hdr(skb);

        if (!iph)
                return NF_ACCEPT;
// Calculate exact IP header length (IHL field holds length in 32-bit words)
        ip_header_len = iph->ihl * 4;

/* 2. TCP Traffic Classification */
        if (iph->protocol == IPPROTO_TCP) {
                if (!pskb_may_pull(skb, ip_header_len + sizeof(*tcph)))
                        return NF_ACCEPT;

                tcph = (struct tcphdr *)((unsigned char *)iph + ip_header_len);
// Convert network byte order (Big Endian) to host byte order (Little Endian)
                src_port = ntohs(tcph->source);
                dst_port = ntohs(tcph->dest);
// Track traffic by incrementing the destination port counter
                tcp_count[dst_port]++;

                printk(KERN_INFO "M2 TCP packet: src_port=%u dst_port=%u count=%u\n",
                       src_port, dst_port, tcp_count[dst_port]);
// Trigger a system alert exactly when the threshold LIMIT is hit
                if (tcp_count[dst_port] == LIMIT) {
                        printk(KERN_WARNING "M2 ALERT: TCP port %u reached limit %d\n",
                               dst_port, LIMIT);
                }
/* * 3. UDP Traffic Classification
         * If the protocol field indicates UDP, apply identical extraction and counting logic.
         */
        } else if (iph->protocol == IPPROTO_UDP) {
                if (!pskb_may_pull(skb, ip_header_len + sizeof(*udph)))
                        return NF_ACCEPT;
// Move the pointer past the IP header to access the UDP layer
                udph = (struct udphdr *)((unsigned char *)iph + ip_header_len);
// Convert network byte order to host byte order
                src_port = ntohs(udph->source);
                dst_port = ntohs(udph->dest);
// Track traffic by incrementing the destination port counter
                udp_count[dst_port]++;

                printk(KERN_INFO "M2 UDP packet: src_port=%u dst_port=%u count=%u\n",
                       src_port, dst_port, udp_count[dst_port]);
// Trigger a system alert exactly when the threshold LIMIT is hit
                if (udp_count[dst_port] == LIMIT) {
                        printk(KERN_WARNING "M2 ALERT: UDP port %u reached limit %d\n",
                               dst_port, LIMIT);
                }
        }
// Allow all packets to pass through smoothly (Logging mode only)
        return NF_ACCEPT;
}

static const struct nf_hook_ops lkm_nf_hook_ops_template = {
        .hook           = nf_callback,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops *lkm_nf_hook_ops(struct net *net)
{
        struct lkm_netns_data *netns_data = net_generic(net, lkm_net_id);

        return &netns_data->nf_hops;
}
/* * =====================================================================================
 * Network Namespace Initialization & Hook Registration
 * =====================================================================================
 */

static int __net_init netns_init(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);
        int rc;

        memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));

        rc = nf_register_net_hook(net, ops);
        if (rc) {
                printk(KERN_ERR "M2: cannot register netfilter hook\n");
                return rc;
        }

        printk(KERN_INFO "M2: netfilter hook registered\n");
        return 0;
}

static void __net_exit netns_exit(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);

        nf_unregister_net_hook(net, ops);

        printk(KERN_INFO "M2: netfilter hook unregistered\n");
}

static struct pernet_operations lkm_netns_ops = {
        .init = netns_init,
        .exit = netns_exit,
        .id = &lkm_net_id,
        .size = sizeof(struct lkm_netns_data),
};
/* * =====================================================================================
 * Module Initialization Entrypoint (insmod)
 * =====================================================================================
 */

static int __init lkm_init(void)
{
        int rc;

        rc = register_pernet_subsys(&lkm_netns_ops);
        if (rc) {
                printk(KERN_ERR "M2: cannot register the pernet ops\n");
                return rc;
        }

        printk(KERN_INFO "M2: TCP vs UDP classifier module registered\n");
        return 0;
}

static void __exit lkm_exit(void)
{
        unregister_pernet_subsys(&lkm_netns_ops);

        printk(KERN_INFO "M2: TCP vs UDP classifier module unregistered\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ali Mirab Nejad");
MODULE_DESCRIPTION("M2 TCP vs UDP Classifier using Netfilter");
MODULE_VERSION("1.0.0");
