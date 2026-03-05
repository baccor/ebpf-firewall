#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800 
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct lpm_v4 {
    __u32 pfxlen;
    __u32 ipv4;
};

struct logev {
    __u64 fid;
    __u32 srcip;
    __u32 dstip;
    __u16 sprt;
    __u16 dprt;
    __u8  prtcl;
    __u8  act;
};

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct lpm_v4);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_dst;

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct lpm_v4);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_src;

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_islogs;

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16384); // 4096 * 4 as per docs
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_logs;

struct rulekey {
    __u64 id;
    __u16 sprt;
    __u16 dprt;
    __u8  prtcl;
    __u8  wc;
};

static const __u8 keyi = 1;

#define wcrdp (__u8)1
#define wcrds (__u8)2
#define wcrdd (__u8)4

SEC(".maps") struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct rulekey);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_rles;

static __always_inline int lkup(__u64 idd, __u8 prtcll, __u16 sprtt, __u16 dprtt)
{
    struct rulekey k;

    k = (struct rulekey){ .id=idd, .prtcl=prtcll, .wc=(__u8)0, .sprt=sprtt, .dprt=dprtt };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    k = (struct rulekey){ .id=idd, .prtcl=prtcll, .wc=wcrdd, .sprt=sprtt, .dprt=0 };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    k = (struct rulekey){ .id=idd, .prtcl=prtcll, .wc=wcrds, .sprt=0, .dprt=dprtt };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    k = (struct rulekey){ .id=idd, .prtcl=prtcll, .wc=wcrds|wcrdd, .sprt=0, .dprt=0 };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1; 

    k = (struct rulekey){ .id=idd, .prtcl=0, .wc=wcrdp, .sprt=sprtt, .dprt=dprtt };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    k = (struct rulekey){ .id=idd, .prtcl=0, .wc=wcrdp|wcrdd, .sprt=sprtt, .dprt=0 };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    k = (struct rulekey){ .id=idd, .prtcl=0, .wc=wcrdp|wcrds, .sprt=0, .dprt=dprtt };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    k = (struct rulekey){ .id=idd, .prtcl=0, .wc=wcrdp|wcrds|wcrdd, .sprt=0, .dprt=0 };
    if (bpf_map_lookup_elem(&fw_rles, &k)) return 1;

    return 0;
}

static __always_inline void log(__u64 fid, __u32 srcip, __u16 sprt, __u32 dstip, __u16 dprt, __u8 prtcl, __u8 act) {


    struct logev k = {0};
    k.fid = fid;
    k.srcip = srcip;
    k.sprt = sprt;
    k.dstip = dstip;
    k.dprt = dprt;
    k.prtcl = prtcl;
    k.act = act;

    if (bpf_ringbuf_output(&fw_logs, &k, sizeof(k), 0) != 0) bpf_printk("error writing to ringbuf."); 

}


SEC("tc")
int frwll(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u8 *islogsv = bpf_map_lookup_elem(&fw_islogs, &keyi);
    __u8 dolog = (islogsv && *islogsv == 1) ? 1 : 0;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {

        if (dolog) log((__u64)0, (__u32)0, (__u16)0, (__u32)0, (__u16)0, (__u8)0, TC_ACT_SHOT);
        return TC_ACT_SHOT;

    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {

        if (dolog) log((__u64)0, (__u32)0, (__u16)0, (__u32)0, (__u16)0, (__u8)0, TC_ACT_SHOT);
        return TC_ACT_SHOT;

    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {

        if (dolog) log((__u64)0, (__u32)0, (__u16)0, (__u32)0, (__u16)0, (__u8)0, TC_ACT_SHOT);
        return TC_ACT_SHOT;
    }

    __u32 ihl = iph->ihl * 4;
    if ((void *)iph + ihl > data_end) {

        if (dolog) log((__u64)0, (__u32)0, (__u16)0, (__u32)0, (__u16)0, (__u8)0, TC_ACT_SHOT);
        return TC_ACT_SHOT;
    }

    if (iph->protocol != IPPROTO_TCP && iph ->protocol != IPPROTO_UDP) {

        if (dolog) log((__u64)0, bpf_ntohl(iph->saddr), (__u16)0, bpf_ntohl(iph->daddr), (__u16)0, iph->protocol, TC_ACT_SHOT);
        return TC_ACT_SHOT;
    }


    __u16 sprt = 0;
    __u16 dprt = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ihl;
        if ((void *)(tcph + 1) > data_end) {

            if (dolog) log((__u64)0, bpf_ntohl(iph->saddr), sprt, bpf_ntohl(iph->daddr), dprt, iph->protocol, TC_ACT_SHOT);
            return TC_ACT_SHOT;
    
        }

        sprt = bpf_ntohs(tcph->source);
        dprt = bpf_ntohs(tcph->dest);

    } else {
        struct udphdr *udph = (void *)iph + ihl;
        if ((void *)(udph + 1) > data_end) {

            if (dolog) log((__u64)0, bpf_ntohl(iph->saddr), sprt, bpf_ntohl(iph->daddr), dprt, iph->protocol, TC_ACT_SHOT);
            return TC_ACT_SHOT;
        }

        sprt = bpf_ntohs(udph->source);
        dprt = bpf_ntohs(udph->dest);
    }

    struct lpm_v4 lpmd = {
        .ipv4 = bpf_ntohl(iph->daddr),
        .pfxlen = 32,
    };

    struct lpm_v4 lpms = {
        .ipv4 = bpf_ntohl(iph->saddr),
        .pfxlen = 32,
    };

    __u32 *dstid = bpf_map_lookup_elem(&fw_dst, &lpmd);
    if (!dstid) {

        if (dolog) log((__u64)0, lpms.ipv4, sprt, lpmd.ipv4, dprt, iph->protocol, TC_ACT_SHOT);
        return TC_ACT_SHOT;


    }

    __u32 *srcid = bpf_map_lookup_elem(&fw_src, &lpms);
    if (!srcid) {

        if (dolog) log((__u64)0, lpms.ipv4, sprt, lpmd.ipv4, dprt, iph->protocol, TC_ACT_SHOT);
        return TC_ACT_SHOT;

    }

    __u64 fid = ((__u64)(*srcid) << 32) | (*dstid);


    if (lkup(fid, iph->protocol, sprt, dprt)) {

        if (dolog) log(fid, lpms.ipv4, sprt, lpmd.ipv4, dprt, iph->protocol, TC_ACT_OK);
        return TC_ACT_OK;
    }

    if (dolog) log(fid, lpms.ipv4, sprt, lpmd.ipv4, dprt, iph->protocol, TC_ACT_SHOT);
    return TC_ACT_SHOT;
}


char LICENSE[] SEC("license") = "GPL";

