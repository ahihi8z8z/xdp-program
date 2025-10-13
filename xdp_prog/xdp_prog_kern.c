// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC 1000000000ULL

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================= MAPS ================= */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");

/* ================= PARSING ================= */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88CC))
        return -2;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        key->src_port = bpf_ntohs(tcph->source);
        key->dst_port = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        key->src_port = bpf_ntohs(udph->source);
        key->dst_port = bpf_ntohs(udph->dest);
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

static __always_inline fixed fixed_log2(__u64 x)
{
    if (x == 0)
        return 0;

    __u32 int_part = 63 - __builtin_clzll(x);
    // Scale x down to fit 32-bit
    __u64 y = (x >> (int_part - 8)); // normalize ~256 range
    __u32 frac_part = 0;

    for (int i = 0; i < 24; i++) {
        y = (y * y) >> 8;  // safe: y is small enough now
        if (y >= (2ULL << 8)) {
            y >>= 1;
            frac_part |= (1u << (23 - i));
        }
    }

    return (int_part << 24) | (frac_part & 0xFFFFFF);
}

static __always_inline void update_feature(data_point *dp){
    fixed flow_duration = fixed_log2(dp->flow_duration);
    dp->features[0] = flow_duration;
    dp->features[1] = fixed_log2(dp->total_pkts * 1000000) - flow_duration;
    dp->features[2] = fixed_log2(dp->total_bytes * 1000000) - flow_duration;
    dp->features[3] = fixed_log2(dp->sum_IAT) - fixed_log2(dp->total_pkts - 1);
    dp->features[4] = fixed_log2(dp->total_bytes) - fixed_log2(dp->total_pkts);
}

/* ================= UPDATE STATS ================= */
static __always_inline data_point *update_stats(struct flow_key *key,
                                                struct xdp_md *ctx)
{
    __u64 ts_ns = bpf_ktime_get_ns();
    __u64 ts_us = ts_ns / 1000; /* microseconds */
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) - (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts       = ts_us;
        zero.last_seen      = ts_us;
        zero.total_pkts     = 1;
        zero.total_bytes    = pkt_len;
        zero.is_normal      = 1;
        // zero.flow_bytes_per_s = 0;
        zero.flow_duration  = 0;
        zero.pkts_len_mean  = 0;
        // zero.flow_pkts_per_s = 0;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
        if (!dp) return NULL;

        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return dp;
    }

    __u64 current = ts_us;
    __u64 iat = (dp->last_seen > 0 && current >= dp->last_seen) ? (current - dp->last_seen) : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat > 0)
        dp->sum_IAT += iat;

    dp->last_seen = current;
    dp->flow_duration = dp->last_seen - dp->start_ts;

    update_feature(dp);
    return dp;
}

/* ================= XDP entry ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2) return XDP_DROP;
    if (ret < 0) return XDP_PASS;

    data_point *target = update_stats(&key, ctx);
    if (!target) return XDP_PASS;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
