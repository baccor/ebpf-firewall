#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800 
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct keyc {
    __u32 src;
    __u32 dst;
    __u16 sprt;
    __u16 dprt;
    __u8  prtcl;
    __u8 pad[3];   
};

struct kssd {
    __u32 ip;
    __u16 prt;
    __u8 prtcl;
    __u8 pad;
};

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct keyc);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} ips;

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct kssd);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipss;

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct kssd);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipsd;



SEC("tc")
int frwll(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_SHOT;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_SHOT;

    __u32 ihl = iph->ihl * 4;
    if ((void *)iph + ihl > data_end)
        return TC_ACT_SHOT;

    if (iph->protocol != IPPROTO_TCP && iph ->protocol != IPPROTO_UDP)
        return TC_ACT_SHOT;


    __u16 sprt = 0;
    __u16 dprt = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ihl;
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_SHOT;

        sprt = tcph->source;
        dprt = tcph->dest;

    } else {
        struct udphdr *udph = (void *)iph + ihl;
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_SHOT;

        sprt = udph->source;
        dprt = udph->dest;
    }

    __u32 src = iph->saddr;
    __u32 dst = iph->daddr;

    struct keyc kc = {
        .src   = src,
        .dst   = dst,
        .sprt = sprt,
        .dprt = dprt,
        .prtcl = iph->protocol,
    };

    struct kssd ksrc = {
        .ip   = src,
        .prt = sprt,
        .prtcl = iph->protocol,
    };

    struct kssd kdst = {
        .ip   = dst,
        .prt = dprt,
        .prtcl = iph->protocol,
    };

    __u32 *res = bpf_map_lookup_elem(&ips, &kc);
    if (res) {
        return TC_ACT_OK;
    }

    res = bpf_map_lookup_elem(&ipss, &ksrc);
    if (res) {
        return TC_ACT_OK;
    }

    res = bpf_map_lookup_elem(&ipsd, &kdst);
    if (res) {
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}


char LICENSE[] SEC("license") = "GPL";

