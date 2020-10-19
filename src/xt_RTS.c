/*
 * (C) 2017 Mathew Heard <mheard@x4b.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "libxt_rts.h"
#include <net/netfilter/nf_conntrack.h>

/*
Clone SKB ethernet header
*/
static void build_ethhdr(const struct sk_buff *skb_source, struct sk_buff *skb_target){
	const struct ethhdr *eth;
	unsigned char srcaddr[6];
	__be16 proto;
	
	eth = eth_hdr(skb_source);
	memcpy(srcaddr, eth->h_source, ETH_ALEN);
	proto = ntohs(eth->h_proto);
	eth_header(skb_target, skb_source->dev, proto, srcaddr, 0, proto);
}

static unsigned int
xt_rts_target(struct sk_buff *inskb, const struct xt_action_param *par)
{
	const struct xt_rts *info = (void *) par->targinfo;
	struct iphdr *iphdst, *iphsrc = ip_hdr(inskb);
	struct net* net = dev_net(inskb->dev);
	u8* pdst;
	int err;
	struct sk_buff *skb;
	u16 pkt_size;

	if(iphsrc == NULL){
		pr_warn("was not ip src");
		return XT_CONTINUE;
	}

	pkt_size = LL_MAX_HEADER + ntohs(iphsrc->tot_len) + sizeof(struct iphdr);
	if(pkt_size > 1600){
		pr_warn("pkt too big", pkt_size);
		return XT_CONTINUE;
	}

	skb = alloc_skb(pkt_size, GFP_ATOMIC);
	if(skb == NULL){
		pr_warn("could not allocate skb for %d bytes", pkt_size);
		return XT_CONTINUE;
	}
	skb->dev = inskb->dev;
	skb->protocol = inskb->protocol;
	
	skb_reserve(skb, LL_MAX_HEADER);

	skb_reset_network_header(skb);
	iphdst = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
	if(iphdst == NULL){
		pr_warn("could not put ip");
	}
	skb_reset_transport_header(skb);
	pdst = (u8 *)skb_put(skb, ntohs(iphsrc->tot_len));
	if(pdst == NULL){
		pr_warn("could not put payload");
	}

	build_ethhdr(inskb, skb);

	memcpy(pdst, iphsrc, ntohs(iphsrc->tot_len));

	memset(iphdst, 0, sizeof(*iphdst));
	iphdst->version = 4;
	iphdst->ihl = sizeof(struct iphdr)/4;
	iphdst->id = iphsrc->id;
	iphdst->protocol = 4;
	iphdst->saddr = iphsrc->daddr;	
	if(info->dst_override){
		iphdst->daddr = info->dst_override;
	}else{
		iphdst->daddr = iphsrc->saddr;
	}
	iphdst->tot_len = htons(ntohs(iphsrc->tot_len) + sizeof(struct iphdr));
	iphdst->ttl     = 100;
	ip_send_check (iphdst); /* handles check = 0 */


	nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
	skb->pkt_type = PACKET_OUTGOING;
	/*err = ip_local_out(net, skb->sk, skb);
	if (unlikely(err > 0)){
		err = net_xmit_errno(err);
		pr_debug("ip_local_out: return with error %d\n", err);
		return XT_CONTINUE;
	}*/
	err = dev_queue_xmit(skb);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		net_warn_ratelimited("dev_queue_xmit returned error: %d unable to send SYN cookie\n", err);
		return XT_CONTINUE;
	}
	
	return XT_CONTINUE;
}

static struct xt_target xt_nat_target_reg[] __read_mostly = {
	{
		.name		= "RTS",
		.revision	= 0,
		.target		= xt_rts_target,
		.targetsize	= sizeof(struct xt_rts),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	}
};

static int __init xt_nat_init(void)
{
	return xt_register_targets(xt_nat_target_reg,
				   ARRAY_SIZE(xt_nat_target_reg));
}

static void __exit xt_nat_exit(void)
{
	xt_unregister_targets(xt_nat_target_reg, ARRAY_SIZE(xt_nat_target_reg));
}

module_init(xt_nat_init);
module_exit(xt_nat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_ALIAS("ipt_RTS");;
MODULE_ALIAS("ip6t_RTS");