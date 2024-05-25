//Import necessary libraries
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/ip.h>

// callback function to block ping to VM machine 10.9.0.1
unsigned int block_ping(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct icmphdr *icmph;
	
	u32 ip_addr;
	char ip[16] = "10.9.0.1";

	// Convert the IPv4 address from dotted decimal to a 32-bit number
	in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL); 
	
	iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_ICMP) 
	{
		icmph = icmp_hdr(skb);
		if (iph->daddr == ip_addr && icmph->type == ICMP_ECHO)
		{ 
			printk(KERN_DEBUG "****Dropping %pI4 (ICMP)\n", &(iph->daddr));
			return NF_DROP; 
		}
	}
	
	return NF_ACCEPT;
}

// callback function to block telnet to VM machine 10.9.0.1
unsigned int block_telnet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	
	u16 port = 23; //telnet port
	
	u32 ip_addr;
	char ip[16] = "10.9.0.1";

	// Convert the IPv4 address from dotted decimal to a 32-bit number
	in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL); 
	
	iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_TCP) 
	{
		tcph = tcp_hdr(skb);
		if (iph->daddr == ip_addr && ntohs(tcph->dest) == port)
		{ 
			printk(KERN_DEBUG "****Dropping %pI4 (TCP), port%d\n", &(iph->daddr), port);
			return NF_DROP; 
		}
	}
	
	return NF_ACCEPT;
}



static struct nf_hook_ops ping_hook, telnet_hook;


int setupFilter(void)
{
	printk(KERN_INFO "Blocking module: Register filters \n");

	//Register ping_hook
	ping_hook.hook = block_ping; //callback function of ping_hook
	ping_hook.hooknum = NF_INET_PRE_ROUTING;
	ping_hook.pf = PF_INET; 
	ping_hook.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &ping_hook);
	
	//Register telnet hook
	telnet_hook.hook = block_telnet; //callback function of telnet_hook
	telnet_hook.hooknum = NF_INET_PRE_ROUTING;
	telnet_hook.pf = PF_INET; 
	telnet_hook.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &telnet_hook);
    
    return 0;
}

void removeFilter(void)
{
	printk(KERN_INFO "Blocking module: Remove filters \n");
	nf_unregister_net_hook(&init_net, &ping_hook);
	nf_unregister_net_hook(&init_net, &telnet_hook);
}

module_init(setupFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
