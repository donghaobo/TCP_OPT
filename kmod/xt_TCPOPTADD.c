#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/netfilter/x_tables.h>
#include "xt_TCPOPTADD.h"

static int opt_no_eol_len(u8 *opt, int len)
{
    int i = 0;
    int optlen;
    while (i < len) {
        if (opt[i] == TCPOPT_EOL) {
            break;
        }
        if (opt[i] == TCPOPT_NOP) {
            i++;
            continue;
        }
        optlen = opt[i+1];
        if (optlen < 2 || i + optlen > len) {
            break;
        }
        i += optlen;
    }
    return i;
}

static int
tcpoptadd_mangle_packet(struct sk_buff *skb,
              const struct xt_action_param *par,
              unsigned int tcphoff, int *pexpand)
{
    const struct xt_tcpoptadd_info *info = par->targinfo;
    struct tcphdr *tcph;
    int len, tcp_hdrlen, newlen;
    int optlen;
    int new_optlen;
    unsigned int i;
    int expand = 0;
    __be16 oldval;
    __be16 newval;
    u8 *opt, *payload;
    u8 *new_opt;
    int no_eol_len;

    *pexpand = 0;
    /* This is a fragment, no TCP header is available */
    if (par->fragoff != 0)
        return 0;

    if (!skb_make_writable(skb, skb->len))
        return -1;

    len = skb->len - tcphoff;
    if (len < (int)sizeof(struct tcphdr))
        return -1;
    tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
    tcp_hdrlen = tcph->doff * 4;
    optlen = tcp_hdrlen - sizeof(struct tcphdr);

    if (len < tcp_hdrlen || tcp_hdrlen < sizeof(struct tcphdr))
        return -1;

    opt = (u_int8_t *)tcph + sizeof(struct tcphdr);
    new_opt = opt;
    no_eol_len = optlen;
    if (info->replace) {
        new_optlen = info->opt_len;
        if (new_optlen < optlen) {
            new_optlen = optlen;
        }
    } else {
        no_eol_len = opt_no_eol_len(opt, optlen);
        new_opt = opt + no_eol_len;
        new_optlen = no_eol_len + info->opt_len;
    }
    if (new_optlen & 0x3) {
        new_optlen |= 0x3;
        new_optlen++;
    }
    if (new_optlen > 40) {
        new_optlen = 40;
    }
    expand = new_optlen - optlen;

    newlen = len;
    if (expand > 0) {
        if (skb_tailroom(skb) < expand) {
            if (pskb_expand_head(skb, 0,
                         expand - skb_tailroom(skb),
                         GFP_ATOMIC))
                return -1;
            tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
        }
        skb_put(skb, expand);
        payload = (u_int8_t *)tcph + tcp_hdrlen;
        memmove(payload + expand, payload, len - tcp_hdrlen);
    }
    opt = (u_int8_t *)tcph + sizeof(struct tcphdr);
    if (info->replace) {
        for (i = 0; i < new_optlen && i < info->opt_len; i += 2) {
            oldval = 0;
            if (i < optlen) {
                oldval = *(__be16*)(&opt[i]);
            }
            if (i < info->opt_len) {
                opt[i] = info->opt[i];
            }
            if (i+1 < info->opt_len) {
                opt[i+1] = info->opt[i+1];
            }
            newval = *(__be16*)(&opt[i]);
            if (oldval != newval) {
                inet_proto_csum_replace2(&tcph->check, skb,
                        oldval, newval, false);
            }
        }
    } else {
        i = no_eol_len &~ 0x1; // for checksum be16 align
        for (; i < new_optlen; i += 2) {
            oldval = 0;
            if (i < optlen) {
                oldval = *(__be16*)(&opt[i]);
            }
            if (i < no_eol_len) {
                // keep pre opt byte
            } else if (i < no_eol_len + info->opt_len) {
                opt[i] = info->opt[i - no_eol_len];
            } else {
                opt[i] = 0; // unaligned space pad with EOL
            }
            // i+1 always >= no_eol_len
            if (i+1 < no_eol_len + info->opt_len) {
                opt[i+1] = info->opt[i+1 - no_eol_len];
            } else {
                opt[i+1] = 0; // unaligned space pad with EOL
            }
            newval = *(__be16*)(&opt[i]);
            if (oldval != newval) {
                inet_proto_csum_replace2(&tcph->check, skb,
                        oldval, newval, false);
            }
        }
    }

    if (expand < 0) {
        if (info->shrink) {
            payload = (u_int8_t *)tcph + tcp_hdrlen;
            memmove(payload + expand, payload, len - tcp_hdrlen);
            pskb_trim(skb, skb->len + expand);
        } else {
            expand = 0;
        }
    }
    if (expand) {
        tcp_hdrlen += expand;
        newlen += expand;
        if (par && par->state && par->state->out && skb->len > par->state->out->mtu) {
            if (!skb_shinfo(skb)->gso_size || skb_shinfo(skb)->gso_size == GSO_BY_FRAGS) {
                skb_shinfo(skb)->gso_size = par->state->out->mtu - tcphoff - tcp_hdrlen;
            } else {
                skb_shinfo(skb)->gso_size -= expand;
            }
            skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len - tcphoff - tcp_hdrlen, skb_shinfo(skb)->gso_size);
            if (skb_shinfo(skb)->gso_segs == 1) {
                skb_shinfo(skb)->gso_size = 0;
            }
        }
        inet_proto_csum_replace2(&tcph->check, skb,
                     htons(len), htons(newlen), true);

        oldval = ((__be16 *)tcph)[6];
        tcph->doff += expand/4;
        inet_proto_csum_replace2(&tcph->check, skb,
                     oldval, ((__be16 *)tcph)[6], false);
    }
    // test code for force pad MTU
    if (!new_optlen && skb->len >= 1500) {
        struct rtable *rt = (struct rtable *) skb_dst(skb);
        skb_shinfo(skb)->gso_size = 1460;
        skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len - tcphoff - tcp_hdrlen, skb_shinfo(skb)->gso_size);
        if (skb_shinfo(skb)->gso_segs == 1) {
            skb_shinfo(skb)->gso_size = 0;
        }
        if (rt && rt->rt_pmtu) {
            rt->rt_pmtu = 1500;
        }
    }
    *pexpand = expand;
    return 0;
}

static unsigned int
tcpoptadd_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *iph = ip_hdr(skb);
    __be16 newlen;
    int ret;
    int expand;
    ret = tcpoptadd_mangle_packet(skb, par, ip_hdrlen(skb), &expand);
    if (ret < 0)
        return NF_DROP;
    if (expand) {
        iph = ip_hdr(skb);
        newlen = htons(ntohs(iph->tot_len) + expand);
        csum_replace2(&iph->check, iph->tot_len, newlen);
        iph->tot_len = newlen;
    }
    return XT_CONTINUE;
}

static int tcpoptadd_tg_check(const struct xt_tgchk_param *par)
{
    const struct xt_tcpoptadd_info *info = par->targinfo;

    if (info->opt_len < 0 || info->opt_len > 40) {
        pr_info_ratelimited("tcp opt len MUST be 1~40\n");
        return -EINVAL;
    }
    return 0;
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static unsigned int
tcpoptadd_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct ipv6hdr *ipv6h = ipv6_hdr(skb);
    u8 nexthdr;
    __be16 frag_off, oldlen, newlen;
    int tcphoff;
    int ret;
    int expand;

    nexthdr = ipv6h->nexthdr;
    tcphoff = ipv6_skip_exthdr(skb, sizeof(*ipv6h), &nexthdr, &frag_off);
    if (tcphoff < 0)
        return NF_DROP;
    ret = tcpoptadd_mangle_packet(skb, par, tcphoff, &expand);
    if (ret < 0)
        return NF_DROP;
    if (expand) {
        ipv6h = ipv6_hdr(skb);
        oldlen = ipv6h->payload_len;
        newlen = htons(ntohs(oldlen) + expand);
        if (skb->ip_summed == CHECKSUM_COMPLETE)
            skb->csum = csum_add(csum_sub(skb->csum, oldlen),
                         newlen);
        ipv6h->payload_len = newlen;
    }
    return XT_CONTINUE;
}
#endif

static struct xt_target tcpoptadd_tg_reg[] __read_mostly = {
    {
        .name       = "TCPOPTADD",
        .family     = NFPROTO_IPV4,
        .checkentry    = tcpoptadd_tg_check,
        .proto      = IPPROTO_TCP,
        .target     = tcpoptadd_tg4,
        .targetsize = sizeof(struct xt_tcpoptadd_info),
        .me         = THIS_MODULE,
    },
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    {
        .name       = "TCPOPTADD",
        .family     = NFPROTO_IPV6,
        .checkentry    = tcpoptadd_tg_check,
        .proto      = IPPROTO_TCP,
        .target     = tcpoptadd_tg6,
        .targetsize = sizeof(struct xt_tcpoptadd_info),
        .me         = THIS_MODULE,
    },
#endif
};

static int __init tcpoptadd_tg_init(void)
{
    return xt_register_targets(tcpoptadd_tg_reg,
                   ARRAY_SIZE(tcpoptadd_tg_reg));
}

static void __exit tcpoptadd_tg_exit(void)
{
    xt_unregister_targets(tcpoptadd_tg_reg,
                  ARRAY_SIZE(tcpoptadd_tg_reg));
}

module_init(tcpoptadd_tg_init);
module_exit(tcpoptadd_tg_exit);
MODULE_DESCRIPTION("Xtables: TCP option add");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TCPOPTADD");
MODULE_ALIAS("ip6t_TCPOPTADD");
