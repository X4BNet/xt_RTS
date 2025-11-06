#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter/nf_nat.h>
#include <arpa/inet.h>
#include "libxt_rts.h"

enum {
	O_DST
};


static const struct xt_option_entry rts_opts[] = {
	{.name = "rts-dst", .id = O_DST, .type = XTTYPE_STRING},
	XTOPT_TABLEEND
};

static void rts_help(void)
{
	printf(
"RTS target options:\n"
"--rts-dst <ip>	 : override destination`\n"
);
}

static void rts_parse(struct xt_option_call *cb)
{
	struct xt_rts *info = cb->data;
	const struct in_addr *ip;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_DST:
		{
			ip = xtables_numeric_to_ipaddr(cb->arg);
			info->dst_override = ip->s_addr;
			break;
		}
	}
}

static void rts_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	const struct xt_rts *info = (void *) target->data;
	printf(" RTS");
	if(info->dst_override){
		printf(" %s", inet_ntoa(*(struct in_addr *)&info->dst_override));
	}
}

static void rts_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_rts *info = (void *) target->data;

	if(info->dst_override){
		printf(" --rts-dst %s", inet_ntoa(*(struct in_addr *)&info->dst_override));
	}
}

static struct xtables_target rts_tg_reg = {
	.name		= "RTS",
    .revision      = 0,
	.version       = XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct xt_rts)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_rts)),
	.print		= rts_print,
	.help = rts_help,
	.x6_parse	= rts_parse,
	.x6_options	= rts_opts,
	.save = rts_save
};

#ifndef _init
#define _init __attribute__((constructor)) _INIT
#endif
void _init(void)
{
	xtables_register_target(&rts_tg_reg);
}
