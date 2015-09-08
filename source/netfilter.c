/*************************************************************************
	> File Name: netfilter.c
	> Author: 
	> Mail:yawenok@126.com 
	> Created Time: 二  9/ 8 11:04:52 2014
 ************************************************************************/

// 内核模块包含头文件
#include <linux/init.h>
#include <linux/module.h>
// netfilter框架包含头文件
#include <linux/netfilter.h>
#include <linux/socket.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>

// 模块说明
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Awendemo");
MODULE_DESCRIPTION("Netfilter module");
MODULE_ALIAS("A simplest module");

// 记录钩子函数的结构体
static struct nf_hook_ops nfhoin; 
static struct nf_hook_ops nfhoout; 

// 网络包接受截获函数
unsigned int filter_in(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;

    if(skb == NULL)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if(iph == NULL)
        return NF_ACCEPT;

    switch(iph->protocol)
    {

        case IPPROTO_TCP:
        {
            // 获取tcp头
            tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
            if(tcph == NULL)
                return NF_ACCEPT;

            printk(KERN_INFO "TCP In Port [%u]-->[%u]\n", ntohs(tcph->source), ntohs(tcph->dest));
        }
        break;

        case IPPROTO_UDP:
        {
            // 获取udp头
            udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
            if(udph == NULL)
                return NF_ACCEPT;

            printk(KERN_INFO "UDP In Port [%u]-->[%u]\n", ntohs(udph->source), ntohs(udph->dest));
        }
        break;

        case IPPROTO_ICMP:
        {}
        break;

    }

    return NF_ACCEPT;
}

// 网络包发送截获函数
unsigned int filter_out(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;

    if(skb == NULL)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if(iph == NULL)
        return NF_ACCEPT;

    switch(iph->protocol)
    {

        case IPPROTO_TCP:
        {
            tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
            if(tcph == NULL)
                return NF_ACCEPT;

            printk(KERN_INFO "TCP Out Port [%u]-->[%u]\n", ntohs(tcph->source), ntohs(tcph->dest));
        }
        break;

        case IPPROTO_UDP:
        {
            udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
            if(udph == NULL)
                return NF_ACCEPT;

            printk(KERN_INFO "UDP Out Port [%u]-->[%u]\n", ntohs(udph->source), ntohs(udph->dest));
        }
        break;

        case IPPROTO_ICMP:
        {}
        break;

    }

    return NF_ACCEPT;
}

// 模块初始化函数
static int __init filter_init(void)
{
    printk(KERN_INFO "filter_init\n");

    // 注册钩子函数
    nfhoin.hook = filter_in;         
    nfhoin.hooknum = NF_INET_LOCAL_IN; 
    nfhoin.pf = PF_INET;
    nfhoin.priority = NF_INET_LOCAL_IN;  

    if(nf_register_hook(&nfhoin) < 0)
    {
        printk(KERN_INFO "nf_register_hook nfhoin failed!\n");
    }

    nfhoout.hook = filter_out;         
    nfhoout.hooknum = NF_INET_LOCAL_OUT; 
    nfhoout.pf = PF_INET;
    nfhoout.priority = NF_INET_LOCAL_OUT;  

    if(nf_register_hook(&nfhoout) < 0)
    {
        printk(KERN_INFO "nf_register_hook nfhoout failed!\n");
    }
        
    return 0;
}

// 模块清理函数
static void __exit filter_exit(void)
{
    // 注销钩子函数
    nf_unregister_hook(&nfhoin);
    nf_unregister_hook(&nfhoout);

    printk(KERN_INFO "filter_exit\n");
}

// 注册函数
module_init(filter_init);
module_exit(filter_exit);
