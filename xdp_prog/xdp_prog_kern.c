/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC     1000000000ULL
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
    __uint(max_entries, MAX_TREES * MAX_NODE_PER_TREE);
    __type(key, __u32);
    __type(value, iTreeNode);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_isoforest_nodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TRAINING_SET + 1); /* allow up to TRAINING_SET */
    __type(key, __u32);
    __type(value, __u32); /* scaled c(n) */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_isoforest_c SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct forest_params);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_isoforest_params SEC(".maps");

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

    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

/* ================= UPDATE FEATURE ================= */
static __always_inline void update_feature_in_datapoint(data_point *dp)
{
    dp->features[0] = (__u32)(dp->flow_duration);
    dp->features[1] = dp->flow_pkts_per_s;
    dp->features[2] = dp->pkt_len_mean;
    dp->features[3] = dp->flow_IAT_mean;
    dp->features[4] = dp->flow_bytes_per_s;
}

/* ================= UPDATE STATS ================= */
static __always_inline data_point *update_stats(struct flow_key *key,
                                                struct xdp_md *ctx,
                                                int is_fwd)
{
    __u64 ts_ns  = bpf_ktime_get_ns();
    __u64 ts_us  = ts_ns / 1000;  // convert ns -> µs
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts    = ts_us;
        zero.last_seen   = ts_us;
        zero.total_pkts  = 1;
        zero.total_bytes = pkt_len;
        zero.sum_IAT     = 0;
        zero.sum_pkt_len = pkt_len; /* initialize with first pkt length */

        #pragma unroll
        for (int i = 0; i < MAX_FEATURES; i++) {
            zero.features[i] = 0;
        }

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        /* tăng counter flow */
        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return bpf_map_lookup_elem(&xdp_flow_tracking, key);
    }

    __u64 current_us = ts_us;
    __u64 iat_us = (dp->last_seen > 0 && current_us >= dp->last_seen) ?
                   (current_us - dp->last_seen) : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);
    __sync_fetch_and_add(&dp->sum_pkt_len, pkt_len);

    if (iat_us > 0)
        dp->sum_IAT += iat_us;

    dp->last_seen = current_us;

    if (dp->total_pkts > 1){
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);  // µs
        dp->pkt_len_mean   = dp->sum_pkt_len / dp->total_pkts;
    }

    dp->flow_duration = dp->last_seen - dp->start_ts;  // µs
    if (dp->flow_duration > 0) {
        dp->flow_bytes_per_s = (dp->total_bytes * 1000000ULL) / dp->flow_duration;
        dp->flow_pkts_per_s  = (dp->total_pkts  * 1000000ULL) / dp->flow_duration;
    }
    update_feature_in_datapoint(dp);
    return dp;
}

// /* ================= SAFE FEATURE ACCESS ================= */
// static __always_inline __u32 get_feature_safe(data_point *dp, __u32 feat_idx)
// {
//     if (feat_idx < MAX_FEATURES)
//         return dp->features[feat_idx];
//     return 0;
// }

// /* ================= PATH LENGTH ================= */
// static __always_inline int compute_path_length(data_point *dp, __u32 tree_idx)
// {
//     __u32 base = tree_idx * MAX_NODE_PER_TREE;
//     __u32 key  = base;
//     int depth  = 0;

// #pragma unroll
//     for (int i = 0; i < MAX_NODE_PER_TREE; i++) {
//         iTreeNode *node = bpf_map_lookup_elem(&xdp_isoforest_nodes, &key);
//         if (!node)
//             break;

//         if (node->is_leaf) {
//             __u32 size = (node->num_points <= TRAINING_SET) ? node->num_points : TRAINING_SET;
//             __u32 c_key = size;
//             __u32 *c_scaled = bpf_map_lookup_elem(&xdp_isoforest_c, &c_key);
//             if (c_scaled) {
//                 int c_int = (int)((*c_scaled + (SCALE/2)) / SCALE);
//                 return depth + c_int;
//             }
//             return depth;
//         }

//         __u32 f_val = get_feature_safe(dp, node->feature_idx);

//         if (f_val <= node->split_value) {
//             if (node->left_idx == NULL_IDX) break;
//             key = base + node->left_idx;
//         } else {
//             if (node->right_idx == NULL_IDX) break;
//             key = base + node->right_idx;
//         }
//         depth++;
//     }
//     return depth;
// }

// /* ================= ANOMALY CHECK ================= */
// static __always_inline int is_anomaly(data_point *dp)
// {
//     __u32 key_params = 0;
//     struct forest_params *params = bpf_map_lookup_elem(&xdp_isoforest_params, &key_params);
//     if (!params) return 0;

//     __u32 n_trees = params->n_trees;
//     if (n_trees == 0) return 0;

//     int total_depth = 0;
//     for (__u32 t = 0; t < n_trees && t < MAX_TREES; t++)
//         total_depth += compute_path_length(dp, t);

//     __u32 avg_depth = ((__u32)total_depth * SCALE) / n_trees;
//     bpf_printk("AVG_DEPTH:%d", avg_depth);
//     return (avg_depth < params->threshold) ? 1 : 0;
// }

/* ================= XDP PROGRAM ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2) return XDP_DROP;
    if (ret < 0) return XDP_PASS;

    data_point *dp = update_stats(&key, ctx, 1);
    if (!dp) return XDP_PASS;

    // if (is_anomaly(dp)) {
    //     dp->label = 1;
    //     bpf_map_update_elem(&flow_dropped, &key, dp, BPF_ANY);
    // } else {
    //     dp->label = 0;
    // }
    // bpf_map_update_elem(&xdp_flow_tracking, &key, dp, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";