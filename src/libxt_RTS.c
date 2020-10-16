#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter/nf_nat.h>


static void RTS_help(void)
{
	printf(
"RTS target options: [none]\n");
}


static void RTS_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	printf(" RTS");
}

static struct xtables_target rts_tg_reg = {
	.name		= "RTS",
    .revision      = 0,
	.version       = XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= 0,
	.userspacesize	= 0,
	.print		= RTS_print,
	.help = RTS_help
};

void _init(void)
{
	xtables_register_target(&rts_tg_reg);
}