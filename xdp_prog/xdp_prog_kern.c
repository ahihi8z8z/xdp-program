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

/* ================= UPDATE STATS ================= */
static __always_inline data_point *update_stats(struct flow_key *key,
                                                struct xdp_md *ctx)
{
    __u64 ts_ns = bpf_ktime_get_ns();
    __u64 ts = ts_ns / 1000; /* microseconds */
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) - (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts;
        zero.last_seen = ts;
        zero.total_pkts = 1;
        zero.total_bytes = pkt_len;
        zero.is_normal = 1;
        zero.flow_bytes_per_s = 0;
        zero.flow_duration = 0;
        zero.pkts_len_mean = 0;
        zero.flow_pkts_per_s = 0;

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

    __u64 current = ts;
    __u64 iat = (dp->last_seen > 0 && current >= dp->last_seen) ? (current - dp->last_seen) : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat > 0)
        dp->sum_IAT += iat;

    dp->last_seen = current;

    if (dp->total_pkts > 1) {
        dp->flow_IAT_mean = fixed_div(uint_to_fixed(dp->sum_IAT), uint_to_fixed(dp->total_pkts - 1));
        dp->pkts_len_mean = fixed_div(uint_to_fixed(dp->total_bytes), uint_to_fixed(dp->total_pkts));
    }

    dp->flow_duration = dp->last_seen - dp->start_ts;
    if (dp->flow_duration > 0) {
        fixed total_bytes_fixed = fixed_mul(uint_to_fixed(dp->total_bytes), uint_to_fixed(1000000));
        fixed total_pkts_fixed = fixed_mul(uint_to_fixed(dp->total_pkts), uint_to_fixed(1000000));
        dp->flow_bytes_per_s = fixed_div(total_bytes_fixed, uint_to_fixed(dp->flow_duration));
        dp->flow_pkts_per_s  = fixed_div(total_pkts_fixed, uint_to_fixed(dp->flow_duration));
    }

    return dp;
}

/* ================= DISTANCE ================= */
// static __always_inline fixed euclidean_distance(const data_point *a, const data_point *b)
// {
//     /* differences (absolute) */
//     fixed dx = fixed_sub(a->flow_bytes_per_s, b->flow_bytes_per_s);
//     fixed dy = fixed_sub(a->flow_pkts_per_s, b->flow_pkts_per_s);
//     fixed dz = fixed_sub(a->pkts_len_mean, b->pkts_len_mean);
//     /* for durations stored as uint -> convert to fixed then subtract */
//     fixed da = uint_to_fixed(a->flow_duration);
//     fixed db = uint_to_fixed(b->flow_duration);
//     fixed dw = fixed_sub(da, db);
//     fixed dh = fixed_sub(a->flow_IAT_mean, b->flow_IAT_mean);

//     fixed sum = fixed_add(fixed_mul(dx, dx),
//                  fixed_add(fixed_mul(dy, dy),
//                  fixed_add(fixed_mul(dz, dz),
//                  fixed_add(fixed_mul(dw, dw), fixed_mul(dh, dh)))));

//     return fixed_sqrt(sum);
// }

static __always_inline fixed euclidean_distance(const data_point *a, const data_point *b)
{
    fixed dx = fixed_sub(a->flow_bytes_per_s, b->flow_bytes_per_s);
    fixed dy = fixed_sub(a->flow_pkts_per_s, b->flow_pkts_per_s);
    fixed dz = fixed_sub(a->pkts_len_mean, b->pkts_len_mean);

    fixed da = uint_to_fixed(a->flow_duration);
    fixed db = uint_to_fixed(b->flow_duration);
    fixed dw = fixed_sub(da, db);

    fixed dh = fixed_sub(a->flow_IAT_mean, b->flow_IAT_mean);

    fixed sum = fixed_add(fixed_mul(dx, dx),
                 fixed_add(fixed_mul(dy, dy),
                 fixed_add(fixed_mul(dz, dz),
                 fixed_add(fixed_mul(dw, dw), fixed_mul(dh, dh)))));

    return fixed_sqrt(sum);
}

/* ================= KNN helpers ================= */
static __always_inline void init_knn(fixed *knn_dist, struct flow_key *knn_keys)
{
    for (int i = 0; i < KNN; i++) {
        knn_dist[i] = (fixed)~(fixed)0ULL;
        knn_keys[i].src_ip = 0;
        knn_keys[i].src_port = 0;
        knn_keys[i].dst_ip = 0;
        knn_keys[i].dst_port = 0;
    }
}

static __always_inline void insert_knn(fixed *knn_dist, struct flow_key *knn_keys,
                                       fixed dist, const struct flow_key *neighbor_key)
{
    for (int i = 0; i < KNN; i++) {
        if (dist < knn_dist[i]) {
            for (int j = KNN - 1; j > i; j--) {
                knn_dist[j] = knn_dist[j - 1];
                knn_keys[j] = knn_keys[j - 1];
            }
            knn_dist[i] = dist;
            knn_keys[i] = *neighbor_key;
            break;
        }
    }
}

/* context for map iteration */
struct knn_ctx_local {
    const struct flow_key *target_key;
    data_point *target;
    fixed *knn_dist;
    struct flow_key *knn_keys;
    int neighbor_count;
};

static int knn_scan_cb(void *map, const void *key, void *value, void *ctx)
{
    struct knn_ctx_local *c = ctx;
    const struct flow_key *k = key;
    data_point *neighbor = value;

    if (!neighbor || !c->target) return 0;

    /* skip same flow (5-tuple) */
    if (k->src_ip == c->target_key->src_ip &&
        k->src_port == c->target_key->src_port &&
        k->dst_ip == c->target_key->dst_ip &&
        k->dst_port == c->target_key->dst_port &&
        k->proto == c->target_key->proto)
        return 0;

    c->neighbor_count++;
    fixed dist = euclidean_distance(c->target, neighbor);
    insert_knn(c->knn_dist, c->knn_keys, dist, k);
    return 0;
}

/* ================= K-DIST & LRD ================= */
static __always_inline void compute_k_distance_and_lrd(const struct flow_key *tkey,
                                                       data_point *target,
                                                       fixed *knn_dist,
                                                       struct flow_key *knn_keys)
{
    if (!target) return;

    init_knn(knn_dist, knn_keys);

    struct knn_ctx_local ctx = {
        .target_key = tkey,
        .target = target,
        .knn_dist = knn_dist,
        .knn_keys = knn_keys,
        .neighbor_count = 0,
    };

    long it = bpf_for_each_map_elem(&xdp_flow_tracking, knn_scan_cb, &ctx, 0);
    if (it < 0) return;

    target->k_distance = knn_dist[KNN - 1];

    fixed reach_sum = 0;
    for (int i = 0; i < KNN; i++) {
        if (knn_dist[i] == (fixed)~(fixed)0ULL || knn_keys[i].src_ip == 0) continue;
        data_point *o = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!o) continue;
        fixed dist = knn_dist[i];
        fixed reach = dist;
        if (o->k_distance > dist) reach = o->k_distance;
        reach_sum = fixed_add(reach_sum, reach);
    }

    if (reach_sum > 0)
        target->lrd_value = fixed_div(uint_to_fixed(KNN), reach_sum);
    else
        target->lrd_value = uint_to_fixed(0);
}

/* ================= LOF ================= */
static __always_inline void compute_lof_for_target(data_point *target,
                                                   fixed *knn_dist,
                                                   struct flow_key *knn_keys)
{
    if (!target) return;

    int neighbor_count = 0;
    fixed sum_ratio = uint_to_fixed(0);

    for (int i = 0; i < KNN; i++) {
        if (knn_dist[i] == (fixed)~(fixed)0ULL || knn_keys[i].src_ip == 0) continue;
        data_point *nbr = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!nbr) continue;
        if (nbr->lrd_value > 0 && target->lrd_value > 0) {
            fixed ratio = fixed_div(nbr->lrd_value, target->lrd_value);
            sum_ratio = fixed_add(sum_ratio, ratio);
            neighbor_count++;
        }
    }

    if (neighbor_count > 0 && sum_ratio > 0)
        target->lof_value = fixed_div(sum_ratio, uint_to_fixed(neighbor_count));
    else
        target->lof_value = uint_to_fixed(0);
}

/* ================= ANOMALY ================= */
static __always_inline void compute_anomaly_for_target(const struct flow_key *key,
                                                       data_point *target)
{
    if (!target) return;

    fixed knn_dist[KNN];
    struct flow_key knn_keys[KNN];

    compute_k_distance_and_lrd(key, target, knn_dist, knn_keys);
    compute_lof_for_target(target, knn_dist, knn_keys);

    if (target->lof_value > uint_to_fixed(LOF_THRESHOLD)) {
        target->is_normal = 0;
        bpf_map_update_elem(&flow_dropped, key, target, BPF_ANY);
    } else {
        target->is_normal = 1;
    }

    bpf_map_update_elem(&xdp_flow_tracking, key, target, BPF_ANY);
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

    __u32 idx = 0;
    __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
    if (cnt) {
        if (*cnt > DATA_CAL_LOF) {
            compute_anomaly_for_target(&key, target);
        } else {
            target->is_normal = 1;
            bpf_map_update_elem(&xdp_flow_tracking, &key, target, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
