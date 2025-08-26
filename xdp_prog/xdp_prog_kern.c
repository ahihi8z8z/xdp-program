#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC     1000000000ULL
#define MAX_FLOW_SAVED      100

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* LRU map: tracking flow -> feature/statistics */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

/* Hash map: target flow -> danh sách k-RNN của target */
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct krnn_entries);   /* <-- value là mảng e[UPDATE_MAX] */
    __uint(max_entries, MAX_FLOW_SAVED);  /* <-- không phải UPDATE_MAX */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_update SEC(".maps");

/* Map debug để dump kết quả KNN[0] */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct knn_entry);
} debug_knn SEC(".maps");

/* BPF Array map chứa update_set */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UPDATE_MAX);
    __type(key, __u32);
    __type(value, struct update_lrd_entry);
} update_set_map SEC(".maps");

/* ========================== PARSING ========================== */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                struct flow_key *key,
                                                __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    __u16 src_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        src_port = tcph->source;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        src_port = udph->source;
    }

    key->src_port = bpf_ntohs(src_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);

    bpf_printk("parse_packet_get_data(): src_ip=%u src_port=%u pkt_len=%llu\n",
               key->src_ip, key->src_port, *pkt_len);

    return 0;
}

/* ========================== CALCULATE LOG2(x) ========================== */
// static __always_inline __u8 ilog2_u64(__u64 x)
// {
//     static const __u8 tbl[16] = {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};
//     __u8 r = 0;

//     if (x >> 32) {
//         __u32 hi = x >> 32;
//         if (hi >= (1<<16)) { hi >>= 16; r += 16; }
//         if (hi >= (1<<8))  { hi >>= 8;  r += 8; }
//         if (hi >= (1<<4))  { hi >>= 4;  r += 4; }
//         return r + tbl[hi & 0xF];
//     } else {
//         __u32 lo = x & 0xFFFFFFFF;
//         if (lo >= (1<<16)) { lo >>= 16; r += 16; }
//         if (lo >= (1<<8))  { lo >>= 8;  r += 8; }
//         if (lo >= (1<<4))  { lo >>= 4;  r += 4; }
//         return r + tbl[lo & 0xF];
//     }
// }
/* ========================== CALCULATE SQRT(x) ========================== */
// static __always_inline __u16 bpf_sqrt(__u32 x)
// {
//     if (x == 0)
//         return 0;

//     __u32 res = x;
//     __u32 prev = 0;
//     for (int i = 0; i < 4; i++) {
//         prev = res;
//         res = (res + x / res) >> 1;
//         if (res == prev)
//             break;
//     }
//     return res;
// }
/* ========================== STATS ========================== */
static __always_inline int update_stats(struct flow_key *key, struct xdp_md *ctx)
{
    __u64 ts = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts;
        zero.last_seen = ts;
        zero.total_pkts = 1;
        zero.total_bytes = pkt_len;
        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return -1;
        bpf_printk("update_stats(): new flow %u:%u -> pkts=1 bytes=%llu\n",
                   key->src_ip, key->src_port, pkt_len);
        return 1;
    }

    __u64 iat_ns = (ts >= dp->last_seen) ? ts - dp->last_seen : 0;
    lock_xadd(&dp->total_pkts, 1);
    lock_xadd(&dp->total_bytes, pkt_len);
    if (iat_ns > 0) dp->sum_IAT += iat_ns;
    dp->last_seen = ts;
    dp->flow_IAT_mean = (dp->total_pkts > 1) ? dp->sum_IAT / (dp->total_pkts - 1) : 0;

    bpf_printk("update_stats(): flow %u:%u pkts=%llu bytes=%llu meanIAT=%llu\n",
               key->src_ip, key->src_port,
               dp->total_pkts, dp->total_bytes, dp->flow_IAT_mean);
    return 0;
}

/* ========================== DISTANCE ========================== */
static __always_inline __u32 euclidean_distance(const data_point *a, const data_point *b)
{
    __u64 fx = (a->total_bytes > b->total_bytes) ? a->total_bytes - b->total_bytes : b->total_bytes - a->total_bytes;
    __u64 fy = (a->total_pkts > b->total_pkts) ? a->total_pkts - b->total_pkts : b->total_pkts - a->total_pkts;
    __u64 fz = (a->flow_IAT_mean > b->flow_IAT_mean) ? a->flow_IAT_mean - b->flow_IAT_mean : b->flow_IAT_mean - a->flow_IAT_mean;
    __u64 flow_dur_a = a->last_seen - a->start_ts;
    __u64 flow_dur_b = b->last_seen - b->start_ts;
    __u64 fw = (flow_dur_a > flow_dur_b) ? flow_dur_a - flow_dur_b : flow_dur_b - flow_dur_a;

    // __u8 dx = ilog2_u64(fx);
    // __u8 dy = ilog2_u64(fy);
    // __u8 dz = ilog2_u64(fz);
    // __u8 dw = ilog2_u64(fw);
    __u8 dx = fx;
    __u8 dy = fy;
    __u8 dz = fz;
    __u8 dw = fw;

    __u32 sum = dx*dx + dy*dy + dz*dz + dw*dw;
    return sum;
    // __u16 root = bpf_sqrt(sum);

    // bpf_printk("euclidean_distance(): sum=%u root=%u\n", sum, root);
    // return (root > UINT16_MAX) ? UINT16_MAX : root;
}


/* ========================== CALL BACK FOR KNN ========================== */
static __always_inline int callback_knn(void *map, const void *key, void *value, void *ctx)
{
    struct knn_context *c = ctx;
    const data_point *neighbor = value;

    /* stop if null or over limit */
    if (!neighbor)
        return 0;
    if (c->processed++ >= c->limit)
        return 1;

    /* skip chính target */
    if (__builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0)
        return 0;

    __u16 dist = euclidean_distance(c->target_dp, neighbor);

    /* tìm index có distance lớn nhất trong KNN hiện tại */
    int idx_max = 0;
    __u16 dmax  = c->results[0].distance;
#pragma unroll
    for (int i = 1; i < KNN; i++) {
        if (c->results[i].distance > dmax) {
            dmax = c->results[i].distance;
            idx_max = i;
        }
    }

    if (dist < dmax) {
        c->results[idx_max].distance = dist;
        __builtin_memcpy(&c->results[idx_max].key, key, sizeof(struct flow_key));
    }
    return 0;
}

/* ========================== COMPUTE RECAH DIST ========================== */
static __always_inline void compute_reach_dist(data_point *target_dp, struct knn_entry *results)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (results[i].distance == 0xffff)
            break;

        data_point *nbr = bpf_map_lookup_elem(&xdp_flow_tracking, &results[i].key);
        if (!nbr)
            continue;

        __u16 dist = euclidean_distance(target_dp, nbr);
        __u16 rd   = (dist > nbr->k_distance) ? dist : nbr->k_distance;
        target_dp->reach_dist[i] = rd;
    }
}

/* ========================== FIND KNN ========================== */
static __always_inline int find_knn(const struct flow_key *target_key,
                                    data_point *target,
                                    struct knn_entry *results)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        __builtin_memset(&results[i].key, 0, sizeof(struct flow_key));
        results[i].distance = 0xffff;
    }

    struct knn_context c = {
        .target_key = target_key,
        .target_dp  = target,
        .results    = results,
        .processed  = 0,
        .limit      = MAX_FLOW_SAVED /* hoặc clamp nhỏ hơn nếu muốn */
    };

    /* Duyệt tất cả entry nhưng dừng khi c.processed >= limit */
    bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn, &c, 0);

    /* Tính reach_dist cho target theo KNN tìm được */
    compute_reach_dist(target, results);
    return 0;
}

/* ========================== CALLBACK FOR KRNN ========================== */
static int callback_krnn(void *map, const void *key, void *value, void *ctx)
{
    struct krnn_callback_ctx *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || __builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0)
        return 0;

    struct knn_entry knn_results[KNN];
    find_knn((const struct flow_key *)key, neighbor, knn_results);

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_results[i].distance == 0xffff)
            break;

        if (__builtin_memcmp(&knn_results[i].key, c->target_key, sizeof(struct flow_key)) == 0) {
            /* Update k-distance cho neighbor */
            neighbor->k_distance = knn_results[KNN - 1].distance;

            /* Ghi vào map kết quả RNN */
            struct krnn_entry *stored = bpf_map_lookup_elem(&xdp_update, c->target_key);
            if (!stored)
                return 0;

#pragma unroll
            for (int j = 0; j < UPDATE_MAX; j++) {
                if (stored[j].distance == 0xffff) {
                    stored[j].distance = knn_results[i].distance;
                    __builtin_memcpy(&stored[j].key, key, sizeof(struct flow_key));
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

/* ========================== FIND KRNN ========================== */
static __always_inline int find_krnn(const struct flow_key *target_key,
                                    const data_point *target)
{
    /* Khởi tạo mảng rỗng trong map */
    struct krnn_entry empty[UPDATE_MAX];
#pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        __builtin_memset(&empty[i].key, 0, sizeof(struct flow_key));
        empty[i].distance = 0xffff;
    }
    int ret = bpf_map_update_elem(&xdp_update, target_key, empty, BPF_ANY);
    bpf_printk("find_krnn(): init update set for %u:%u ret=%d\n",
               target_key->src_ip, target_key->src_port, ret);

    /* Truyền target_key xuống callback */
    struct krnn_callback_ctx {
        const struct flow_key *target_key;
        const data_point *target;
    } ctx = {
        .target_key = target_key,
        .target = target,
    };
    bpf_printk("find_krnn(): start for %u:%u\n",
               target_key->src_ip, target_key->src_port);

    bpf_for_each_map_elem(&xdp_flow_tracking, callback_krnn, &ctx, 0);
      /* Đếm số neighbor thực sự đã insert */
    int count = 0;
    struct krnn_entry *kr = bpf_map_lookup_elem(&xdp_update, target_key);
    if (kr) {
#pragma unroll
        for (int i = 0; i < UPDATE_MAX; i++) {
            if (kr[i].distance != 0xffff) {
                count++;
                bpf_printk("find_krnn(): neighbor[%d]=%u:%u dist=%u\n",
                           i, kr[i].key.src_ip, kr[i].key.src_port, kr[i].distance);
            }
        }
    } else {
        bpf_printk("find_krnn(): lookup update set failed for %u:%u\n",
                   target_key->src_ip, target_key->src_port);
    }

    bpf_printk("find_krnn(): found %d neighbors for %u:%u\n",
               count, target_key->src_ip, target_key->src_port);

    return count;
}

/* ========================== UPDATE-SET HELPERS (MAP) ========================== */
static __always_inline void clear_update_slot(__u32 count)
{
#pragma unroll
    for (__u32 i = 0; i < count; i++) {
        if (i >= count) break;

        __u32 key = i;
        struct update_lrd_entry *slot = bpf_map_lookup_elem(&update_set_map, &key);
        if (slot && slot->is_valid) {
            slot->is_valid = false;
            __builtin_memset(&slot->key, 0, sizeof(struct flow_key));
        }
    }
    bpf_printk("clear_update_set(): reset %u entries\n", count);
}

/* ========================== IS KEY IN UPDATE SET ========================== */
// static __always_inline bool is_key_in_update_set_map(const struct flow_key *key, int count)
// {
// #pragma unroll
//     for (int i = 0; i < UPDATE_MAX; i++) {
//         if (i >= count)
//             break;
//         __u32 idx = i;
//         struct update_lrd_entry *slot = bpf_map_lookup_elem(&update_set_map, &idx);
//         if (!slot)
//             continue;
//         if (slot->is_valid &&
//             __builtin_memcmp(&slot->key, key, sizeof(struct flow_key)) == 0) {
//             bpf_printk("is_key_in_update_set(): key %u:%u exists at %d\n",
//                        key->src_ip, key->src_port, i);
//             return true;
//         }
//     }
//     return false;
// }

/* ========================== ADD TO UPDATE SET ========================== */
// static __always_inline int add_to_update_set_map(const struct flow_key *key,
//                                                  int *count,
//                                                  int max_size)
// {
//     if (*count >= max_size) {
//         bpf_printk("add_to_update_set(): set full, cannot add key %u:%u\n",
//                    key->src_ip, key->src_port);
//         return -1;
//     }

//     if (is_key_in_update_set_map(key, *count)) {
//         bpf_printk("add_to_update_set(): key %u:%u already in set\n",
//                    key->src_ip, key->src_port);
//         return 0;
//     }

//     __u32 idx = *count;
//     struct update_lrd_entry *slot = bpf_map_lookup_elem(&update_set_map, &idx);
//     if (!slot) {
//         return -1;
//     }
//     __builtin_memcpy(&slot->key, key, sizeof(struct flow_key));
//     slot->is_valid = true;

//     bpf_printk("add_to_update_set(): added key %u:%u at index %u\n",
//                key->src_ip, key->src_port, idx);

//     (*count)++;
//     return 1;
// }
static __always_inline int add_to_update_set_map(const struct flow_key *key,
                                                 int *count,
                                                 int max_size)
{
    if (*count >= max_size)
        return -1;

    __u32 idx = *count;
    struct update_lrd_entry *slot = bpf_map_lookup_elem(&update_set_map, &idx);

    if (slot && slot->is_valid) {
        if (__builtin_memcmp(&slot->key, key, sizeof(*key)) == 0) {
            return 0; 
        }

        clear_update_slot(idx);
    }

    struct update_lrd_entry new_entry = {
        .key = *key,
        .is_valid = true,
    };
    bpf_map_update_elem(&update_set_map, &idx, &new_entry, BPF_ANY);

    (*count)++;
    return 1;
}

/* ========================== CALL KNN FOR UPDATE ========================== */
static int callback_knn_for_update(void *map, const void *key, void *value, void *ctx)
{
    struct knn_for_update_context *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || __builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0)
        return 0;

    __u16 dist = euclidean_distance(c->target_dp, neighbor);
    if (dist <= c->target_dp->k_distance) {
        bpf_printk("callback_knn_for_update(): neighbor %u:%u within k-distance=%u (dist=%u)\n",
                   ((struct flow_key *)key)->src_ip,
                   ((struct flow_key *)key)->src_port,
                   c->target_dp->k_distance,
                   dist);
        add_to_update_set_map((const struct flow_key *)key, c->update_count, c->max_size);
    }
    else{
        bpf_printk("callback_knn_for_update(): neighbor %u:%u too far (dist=%u > k-dist=%u)\n",
                   ((struct flow_key *)key)->src_ip,
                   ((struct flow_key *)key)->src_port,
                   dist, c->target_dp->k_distance);
    }
    return 0;
}

/* ========================== DETERMINE UPDATE LRD SET (dùng map) ========================== */
static __always_inline int determine_update_lrd_set_map(const struct flow_key *target_key,
                                                        const data_point *target_dp)
{
    int update_count = 0;
    bpf_printk("determine_update_lrd_set(): start for target %u:%u\n",
               target_key->src_ip, target_key->src_port);

    // clear_update_set_partial();
    add_to_update_set_map(target_key, &update_count, UPDATE_MAX);

    /* lấy danh sách KRNN của target */
    struct krnn_entry *kr = bpf_map_lookup_elem(&xdp_update, (void *)target_key);
    if (!kr) {
        bpf_printk("determine_update_lrd_set(): no krnn_entry found for target\n");
        return update_count;
    }

#pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (kr[i].distance == 0xffff)
            break;

        bpf_printk("determine_update_lrd_set(): krnn flow %u:%u dist=%u\n",
                   kr[i].key.src_ip, kr[i].key.src_port, kr[i].distance);

        add_to_update_set_map(&kr[i].key, &update_count, UPDATE_MAX);

        /* mở rộng thêm hàng xóm của krnn */
        data_point *krnn_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &kr[i].key);
        if (!krnn_dp) {
            bpf_printk("determine_update_lrd_set(): no datapoint for krnn %u:%u\n",
                       kr[i].key.src_ip, kr[i].key.src_port);
            continue;
        }

        struct knn_for_update_context ctx = {
            .target_key = &kr[i].key,
            .target_dp = krnn_dp,
            .update_count = &update_count,
            .max_size = UPDATE_MAX,
            .limit = KNN
        };
        bpf_printk("determine_update_lrd_set(): expanding neighbors for krnn %u:%u\n",
                   kr[i].key.src_ip, kr[i].key.src_port);

        bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn_for_update, &ctx, 0);
    }

    bpf_printk("determine_update_lrd_set(): finished, update_count=%d\n", update_count);
    return update_count;
}


/* ========================== LRD ========================== */
static __always_inline void compute_lrd(data_point *dp, const struct flow_key *key)
{
    __u64 sum_reach_dist = 0;
    int valid_neighbors = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (dp->reach_dist[i] > 0) {
            sum_reach_dist += dp->reach_dist[i];
            valid_neighbors++;
        }
    }
    dp->lrd_value = (valid_neighbors > 0 && sum_reach_dist > 0) ?
                    (__u16)(((__u64)valid_neighbors * SCALEEEEEE) / sum_reach_dist) : 0;
    bpf_printk("compute_lrd(): key %u:%u -> valid=%d sum=%llu lrd=%u\n",
               key->src_ip, key->src_port,
               valid_neighbors, sum_reach_dist, dp->lrd_value);
}

/* ========================== UPDATE LRD FOR SET (map) ========================== */
static __always_inline void update_lrd_for_set_map(int update_count)
{
#pragma clang loop unroll(disable)
    for (int i = 0; i < update_count; i++) {
        if (i >= update_count)
            break;

        __u32 idx = i;
        struct update_lrd_entry *slot = bpf_map_lookup_elem(&update_set_map, &idx);
        if (!slot || !slot->is_valid)
            continue;

        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &slot->key);
        if (!dp)
            continue;

        struct knn_entry knn_results[KNN];
        find_knn(&slot->key, dp, knn_results);

        bpf_printk("update_lrd_for_set(): recomputing LRD for key=%u:%u\n",
                   slot->key.src_ip, slot->key.src_port);

        compute_lrd(dp, &slot->key);
        bpf_printk(" -> new LRD=%u\n", dp->lrd_value);
    }
}

/* ========================== COMPUTE LOF ========================== */
static __always_inline void compute_lof(data_point *dp, 
                                       const struct flow_key *key,
                                       struct knn_entry *knn_results)
{
    __u64 sum_lrd_ratio = 0;
    int valid_neighbors = 0;

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_results[i].distance == 0xffff)
            break;

        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_results[i].key);
        if (!neighbor_dp)
            continue;

        if (dp->lrd_value > 0 && neighbor_dp->lrd_value > 0) {
            __u64 ratio = ((__u64)neighbor_dp->lrd_value * SCALEEEEEE) / dp->lrd_value;
            sum_lrd_ratio += ratio;
            valid_neighbors++;
            bpf_printk("compute_lof(): neighbor[%d] %u:%u lrd=%u ratio=%llu\n",
                       i, knn_results[i].key.src_ip, knn_results[i].key.src_port,
                       neighbor_dp->lrd_value, ratio);
        }
    }

    dp->lof_value = (valid_neighbors > 0) ? (__u16)(sum_lrd_ratio / valid_neighbors) : 1000;
    bpf_printk("compute_lof(): flow %u:%u -> LOF=%u\n",
               key->src_ip, key->src_port, dp->lof_value);
}

/* ========================== UPDATE LOF FOR SET (map) ========================== */
static __always_inline void update_lof_for_set_map(int update_count)
{
#pragma clang loop unroll(disable)
    for (int i = 0; i < update_count; i++) {
        if (i >= update_count)
            break;

        __u32 idx = i;
        struct update_lrd_entry *slot = bpf_map_lookup_elem(&update_set_map, &idx);
        if (!slot || !slot->is_valid)
            continue;

        bpf_printk("update_lof_for_set(): processing flow %u:%u\n",
                   slot->key.src_ip, slot->key.src_port);

        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &slot->key);
        if (!dp){
            bpf_printk(" -> data_point not found for LOF update\n");
            continue;
        }
        struct knn_entry knn_results[KNN];
        find_knn(&slot->key, dp, knn_results);
        compute_lof(dp, &slot->key, knn_results);
    }
}

/* ========================== UPDATE LRD STEP ========================== */
static __always_inline int lof_update_lrd_step(const struct flow_key *target_key,
                                              const data_point *target_dp)
{
    int update_count = determine_update_lrd_set_map(target_key, target_dp);
    bpf_printk("lof_update_lrd_step(): target=%u:%u update_count=%d\n",
               target_key->src_ip, target_key->src_port, update_count);

    if (update_count <= 0)
        return -1;

    update_lrd_for_set_map(update_count);
    return update_count;
}

/* ========================== FINAL LOF STEP ========================== */
static __always_inline int lof_final_step(const struct flow_key *target_key,
                                         data_point *target_dp)
{
    int update_lof_count = determine_update_lrd_set_map(target_key, target_dp);
    bpf_printk("lof_final_step(): target=%u:%u lof_update_count=%d\n",
               target_key->src_ip, target_key->src_port, update_lof_count);

    update_lof_for_set_map(update_lof_count);

    struct knn_entry target_knn[KNN];
    find_knn(target_key, target_dp, target_knn);
    compute_lof(target_dp, target_key, target_knn);

    return 0;
}

/* ========================== INCREMENTAL LOF ========================== */
static __always_inline int incremental_lof_insertion(const struct flow_key *target_key,
                                                    data_point *target_dp)
{
    int krnn_count = find_krnn(target_key, target_dp);
    bpf_printk("incremental_lof_insertion(): target=%u:%u krnn_count=%d\n",
               target_key->src_ip, target_key->src_port, krnn_count);

    if (krnn_count <= 0) {
        bpf_printk("incremental_lof_insertion(): skip, krnn_count <= 0 for flow %u:%u\n",
                   target_key->src_ip, target_key->src_port);
        return -1;
    }

    int lrd_updated = lof_update_lrd_step(target_key, target_dp);
    bpf_printk("incremental_lof_insertion(): lof_update_lrd_step() returned %d for flow %u:%u\n",
               lrd_updated, target_key->src_ip, target_key->src_port);

    if (lrd_updated < 0) {
        bpf_printk("incremental_lof_insertion(): error updating LRD for flow %u:%u\n",
                   target_key->src_ip, target_key->src_port);
        return -1;
    }

    int lof_result = lof_final_step(target_key, target_dp);
    bpf_printk("incremental_lof_insertion(): lof_final_step() returned %d for flow %u:%u\n",
               lof_result, target_key->src_ip, target_key->src_port);

    return lof_result;
}

/* ========================== CHECK IS ANOMALY ========================== */
static __always_inline bool is_anomaly(const data_point *dp, __u16 threshold)
{
    return dp->lof_value > threshold;
}

/* ========================== DETECT ========================== */
static __always_inline int detect_anomaly_lof(struct flow_key *key,
                                             struct xdp_md *ctx,
                                             __u16 anomaly_threshold)
{
    bpf_printk("detect_anomaly_lof(): CALLED for flow %u:%u\n",
               key->src_ip, key->src_port);

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        bpf_printk("detect_anomaly_lof(): dp NULL for flow %u:%u\n",
                   key->src_ip, key->src_port);
        return 0;
    }

    if (dp->total_pkts < 3) {
        bpf_printk("detect_anomaly_lof(): pkts=%llu < 3, skip flow %u:%u\n",
                   dp->total_pkts, key->src_ip, key->src_port);
        return 0;
    }

    int result = incremental_lof_insertion(key, dp);
    if (result < 0)
        return 0;

    return is_anomaly(dp, anomaly_threshold) ? 1 : 0;
}
/* ========================== MAIN ========================== */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    if (update_stats(&key, ctx) < 0)
        return XDP_PASS;

    int anomaly_detected = detect_anomaly_lof(&key, ctx, 1500);
    if (anomaly_detected) {
        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &key);
        if (dp) {
            bpf_printk("Anomaly detected: src_ip=%u, src_port=%u, LOF=%u\n",
                       key.src_ip, key.src_port, (unsigned int)dp->lof_value);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";