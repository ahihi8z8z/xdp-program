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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * MAX_FEATURES + 2);
    __type(key, __u32);
    __type(value, fixed);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mlp_maps SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, mlp_params);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_mlp_params SEC(".maps");

/* ================= PACKET PARSING ================= */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88cc))
        return -2; // drop LLDP

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        key->src_port = tcph->source;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        key->src_port = udph->source;
    } else {
        key->src_port = 0;
    }

    key->src_port = bpf_ntohs(key->src_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

static __always_inline void apply_min_max_scale(data_point *dp, const mlp_params *params)
{
    if (!params)
        return;

// #pragma unroll
    for (int i = 0; i < MAX_FEATURES; i++) {
        fixed x = dp->features[i];
        fixed minv = params->min_vals[i];
        fixed maxv = params->max_vals[i];
        fixed range = maxv - minv;

        if (range <= 0)
            dp->features[i] = 0;
        else
            dp->features[i] = fixed_div((x - minv), range);
    }
}

/* ================= FEATURE UPDATE ================= */
static __always_inline void update_feature(data_point *dp, const mlp_params *params)
{
    if (dp->total_pkts > 1) {
        fixed flow_duration = fixed_log2(dp->flow_duration);
        __u64 mean_iat_us = dp->sum_IAT / (dp->total_pkts - 1);

        dp->features[0] = flow_duration;
        dp->features[1] = fixed_log2(dp->total_pkts * 1000000) - flow_duration;
        dp->features[2] = fixed_log2(dp->total_bytes * 1000000) - flow_duration;
        dp->features[3] = fixed_log2(mean_iat_us); // Log2(Mean IAT)
        dp->features[4] = fixed_log2(dp->total_bytes) - fixed_log2(dp->total_pkts);

        /* scale only if params provided */
        if (params)
            apply_min_max_scale(dp, params);
    }
}

/* ================= FLOW STATS ================= */
static __always_inline data_point *update_stats(struct flow_key *key,
                                                struct xdp_md *ctx)
{
    __u64 ts_us = bpf_ktime_get_ns() / 1000;
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                             (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts_us;
        zero.last_seen = ts_us;
        zero.total_pkts = 1;
        zero.total_bytes = pkt_len;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;
            
        return bpf_map_lookup_elem(&xdp_flow_tracking, key);
    }

    __u64 iat_ns = (dp->last_seen > 0 && ts_us >= dp->last_seen) ? ts_us - dp->last_seen : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;

    dp->last_seen = ts_us;
    dp->flow_duration = dp->last_seen - dp->start_ts;
    __u32 pkey = 0;
    mlp_params *params = bpf_map_lookup_elem(&xdp_mlp_params, &pkey);
    if (params) {
        /* verifier now knows params != NULL on the true branch */
        update_feature(dp, params);
    } else {
        /* No params: still update features without scaling (or early return) */
        update_feature(dp, NULL);
    }
    return dp;
}

// static __always_inline int inference_mlp(data_point *dp, mlp_params *params)

/* ================= XDP ENTRY ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2)
        return XDP_DROP;  // Drop LLDP
    if (ret < 0)
        return XDP_PASS;

    data_point *dp = update_stats(&key, ctx);
    if (!dp)
        return XDP_PASS;

    bpf_map_update_elem(&xdp_flow_tracking, &key, dp, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
