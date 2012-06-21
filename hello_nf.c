
#define __KERNEL__
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>


static struct nf_hook_ops nfho;      //struct holding set of hook function options
static struct sk_buff *sock_buff;
static struct udphdr *udp_header;
static struct iphdr *ip_header;

//function to be called by hook
unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *))
{
    sock_buff = *skb; 
    ip_header = (struct iphdr *)skb_network_header(sock_buff);    
    if(!sock_buff){
        return NF_ACCEPT;
    }
    if(ip_header->protocol == 17) {
        udp_header = (struct udphdr *)skb_transport_header(sock_buff);
        printk(KERN_INFO "got udp packet.\n");
        return NF_DROP;
    }else{
        printk(KERN_INFO "packet accept.\n");
        return NF_ACCEPT;
    }
}

int init_module(void)
{
    printk(KERN_INFO "register hello netfilter module.\n");
    nfho.hook = hook_func;
    nfho.hooknum = 0 ; // NF_IP_PRE_ROUTING
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "cleanup hello netfilter module.\n");
    nf_unregister_hook(&nfho); 
}
