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
#define WINDOW_TIME_US      10000000ULL  // 10 seconds window
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================= MAPS ================= */
/* flow tracking hash map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_tracking SEC(".maps");

/* circular datapoints buffer (index -> datapoint) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FLOW_SAVED);
    __type(key, __u32);
    __type(value, data_point);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} datapoints SEC(".maps");

/* per-point MCO state (index -> MCO) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FLOW_SAVED);
    __type(key, __u32);
    __type(value, MCO);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mco_states SEC(".maps");

/* micro-clusters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MC);
    __type(key, __u32);
    __type(value, MicroCluster);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} micro_clusters SEC(".maps");

/* PD set: array of slots holding point_idx (0 = free) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PD);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} PD_set SEC(".maps");

/* Event queue: array of EVENT_CAPACITY slots */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, EVENT_CAPACITY);
    __type(key, __u32);         // id of event - timestamp 
    __type(value, Event);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} event_queue SEC(".maps");

/* flow counter (for allocate_datapoint_slot) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");

/* control map to store last maintenance timestamp (ns) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} control SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} heap_size SEC(".maps");


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
    dp->features[0] = dp->flow_duration;
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
    __u64 ts_us  = ts_ns / 1000ULL;  // convert ns -> µs
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&flow_tracking, key);
    if (!dp) {
        /* create new */
        data_point zero = {};
        zero.start_time  = ( __u32 )(ts_us & 0xFFFFFFFFULL);
        zero.last_seen   = ( __u32 )(ts_us & 0xFFFFFFFFULL);
        zero.total_pkts  = 1;
        zero.total_bytes = (__u32)pkt_len;
        zero.sum_IAT     = 0;
        zero.sum_pkt_len = (__u32)pkt_len;
        zero.label = -1;
        if (bpf_map_update_elem(&flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        __u32 idx0 = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx0);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return bpf_map_lookup_elem(&flow_tracking, key);
    }

    /* update existing dp - be careful with types in header (32-bit timestamps) */
    __u64 current_us = ts_us;
    __u64 last_seen_us = ( __u64 ) dp->last_seen;
    __u64 iat_us = (last_seen_us > 0 && current_us >= last_seen_us) ? (current_us - last_seen_us) : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, (__u32)pkt_len);
    __sync_fetch_and_add(&dp->sum_pkt_len, (__u32)pkt_len);

    if (iat_us > 0) {
        /* sum_IAT is 64-bit in header */
        dp->sum_IAT += iat_us;
    }

    dp->last_seen = ( __u32 )(current_us & 0xFFFFFFFFULL);

    if (dp->total_pkts > 1){
        dp->flow_IAT_mean = ( __u32 )(dp->sum_IAT / (dp->total_pkts - 1));
        dp->pkt_len_mean   = dp->sum_pkt_len / dp->total_pkts;
    }

    dp->flow_duration = dp->last_seen - dp->start_time;
    if (dp->flow_duration > 0) {
        dp->flow_bytes_per_s = (dp->total_bytes * 1000000ULL) / dp->flow_duration;
        dp->flow_pkts_per_s  = (dp->total_pkts  * 1000000ULL) / dp->flow_duration;
    }
    update_feature_in_datapoint(dp);
    return dp;
}

/* ================= EVENT QUEUE FUNCTION ================= */
static __always_inline int event_insert(__u32 point_id, __u32 expire_time)
{
    Event ev = {
        .mco_id = (int)point_id,
        .time   = expire_time,
    };

    __u32 key0 = 0;
    __u32 *size = bpf_map_lookup_elem(&heap_size, &key0);
    if (!size)
        return FAIL;

    if (*size >= EVENT_CAPACITY)
        return FAIL;  // heap đầy

    __u32 idx = *size;  // thêm vào cuối
    bpf_map_update_elem(&event_queue, &idx, &ev, BPF_ANY);

    // bubble up với vòng for giới hạn
    // #pragma clang loop unroll(disable)
    for (int iter = 0; iter < 32; iter++) {
        if (idx == 0)
            break;

        __u32 parent = (idx - 1) / 2;

        Event *cur = bpf_map_lookup_elem(&event_queue, &idx);
        Event *par = bpf_map_lookup_elem(&event_queue, &parent);
        if (!cur || !par)
            break;

        if (cur->time < par->time) {
            // swap
            Event tmp = *cur;
            bpf_map_update_elem(&event_queue, &idx, par, BPF_ANY);
            bpf_map_update_elem(&event_queue, &parent, &tmp, BPF_ANY);

            idx = parent;
        } else {
            break;
        }
    }

    (*size)++;
    bpf_map_update_elem(&heap_size, &key0, size, BPF_ANY);

    return SUCCESS;
}

// static __always_inline int event_find_min(Event *out_event, __u32 *out_slot)
// {
//     __u32 key0 = 0;
//     __u32 *size = bpf_map_lookup_elem(&heap_size, &key0);
//     if (!size || *size == 0)
//         return FAIL;

//     __u32 root = 0;
//     Event *ev = bpf_map_lookup_elem(&event_queue, &root);
//     if (!ev)
//         return FAIL;

//     *out_event = *ev;
//     if (out_slot)
//         *out_slot = root;

//     return SUCCESS;
// }

/* extract_min: O(log n) bằng bubble-down */
static __always_inline int event_extract_min(Event *out_event, __u32 *out_slot)
{
    __u32 key0 = 0;
    __u32 *size = bpf_map_lookup_elem(&heap_size, &key0);
    if (!size || *size == 0)
        return FAIL;

    __u32 n = *size;
    __u32 root = 0;
    __u32 last = n - 1;

    Event *min_ev = bpf_map_lookup_elem(&event_queue, &root);
    Event *last_ev = bpf_map_lookup_elem(&event_queue, &last);
    if (!min_ev || !last_ev)
        return FAIL;

    /* trả về event nhỏ nhất */
    *out_event = *min_ev;
    if (out_slot)
        *out_slot = root;

    /* đưa phần tử cuối lên root */
    if (last > 0)
        bpf_map_update_elem(&event_queue, &root, last_ev, BPF_ANY);

    /* clear slot cuối */
    Event empty = {};
    bpf_map_update_elem(&event_queue, &last, &empty, BPF_ANY);
    n--;
    *size = n;
    bpf_map_update_elem(&heap_size, &key0, size, BPF_ANY);
    __u32 idx = root;

    #pragma unroll
    for (int depth = 0; depth < 16; depth++) {  // giả sử heap không quá 2^16 phần tử
        __u32 left  = 2 * idx + 1;
        __u32 right = 2 * idx + 2;
        if (left >= n)
            break;

        __u32 smallest = idx;

        Event *cur = bpf_map_lookup_elem(&event_queue, &idx);
        Event *lch = bpf_map_lookup_elem(&event_queue, &left);
        Event *rch = (right < n) ? bpf_map_lookup_elem(&event_queue, &right) : NULL;

        if (cur && lch && lch->time < cur->time)
            smallest = left;
        if (rch) {
            Event *sm_ev = bpf_map_lookup_elem(&event_queue, &smallest);
            if (sm_ev && rch->time < sm_ev->time)
                smallest = right;
        }

        if (smallest != idx) {
            Event *sm_ev = bpf_map_lookup_elem(&event_queue, &smallest);
            Event *cur_ev = bpf_map_lookup_elem(&event_queue, &idx);
            if (sm_ev && cur_ev) {
                Event tmp = *cur_ev;
                bpf_map_update_elem(&event_queue, &idx, sm_ev, BPF_ANY);
                bpf_map_update_elem(&event_queue, &smallest, &tmp, BPF_ANY);
            }
            idx = smallest;
        } else {
            break;
        }
    }

    return SUCCESS;
}

/* ==================== CALCULATE LOG2(x) ==================== */
static __always_inline __u8 ilog2_u64(__u64 x)
{
    static const __u8 tbl[16] = {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};
    __u8 r = 0;

    if (x >> 32) {
        __u32 hi = ( __u32 )(x >> 32);
        if (hi >= (1<<16)) { hi >>= 16; r += 16; }
        if (hi >= (1<<8))  { hi >>= 8;  r += 8; }
        if (hi >= (1<<4))  { hi >>= 4;  r += 4; }
        return r + tbl[hi & 0xF];
    } else {
        __u32 lo = ( __u32 )(x & 0xFFFFFFFFULL);
        if (lo >= (1<<16)) { lo >>= 16; r += 16; }
        if (lo >= (1<<8))  { lo >>= 8;  r += 8; }
        if (lo >= (1<<4))  { lo >>= 4;  r += 4; }
        return r + tbl[lo & 0xF];
    }
}

/* ==================== CALCULATE SQRT(x) ==================== */
static __always_inline __u16 bpf_sqrt(__u32 x)
{
    if (x == 0)
        return 0;

    __u32 res = x;
    __u32 prev = 0;
    for (int i = 0; i < 6; i++) {
        prev = res;
        res = (res + x / res) >> 1;
        if (res == prev)
            break;
    }
    return ( __u16 ) res;
}

/* safe absolute difference for features (avoid unsigned underflow) */
static __always_inline __u64 abs_diff_u64(__u64 a, __u64 b)
{
    if (a >= b) return a - b;
    return b - a;
}

static __always_inline __u16 distance_data_vs_data(const data_point *a, const data_point *b)
{
    __u64 sum = 0;
    for (int i = 0; i < MAX_FEATURES; i++) {
        __u64 da = ( __u64 ) a->features[i];
        __u64 db = ( __u64 ) b->features[i];
        __u64 diff = abs_diff_u64(da, db);
        __u64 v = ilog2_u64(diff + 1);
        sum += v * v;
    }
    return bpf_sqrt((__u32)sum);
}

static __always_inline __u16 distance_data_vs_center(const data_point *a, MicroCluster *mc)
{
    if (!mc) return UINT16_MAX;
    /* center_idx is index of MCO (point slot) */
    MCO *center_mco = bpf_map_lookup_elem(&mco_states, &mc->center_idx);
    if (!center_mco) return UINT16_MAX;
    const data_point *c = &center_mco->d;
    return distance_data_vs_data(a, c);
}

static __always_inline __u32 count_pd_neighbors_in_R(const data_point *p, __u32 radius)
{
    __u32 count = 0;
    for (int i = 0; i < MAX_PD; i++) {
        __u32 idx = ( __u32 ) i;
        __u32 *slot = bpf_map_lookup_elem(&PD_set, &idx);
        if (!slot) continue;
        __u32 pid = *slot;
        if (pid == 0) continue;
        MCO *mco = bpf_map_lookup_elem(&mco_states, &pid);
        if (!mco) continue;
        __u32 dist = distance_data_vs_data(p, &mco->d);
        if (dist <= radius) count++;
    }
    return count;
}

static __always_inline __u32 count_mc_contribution(const data_point *p, __u32 radius)
{
    __u32 count = 0;
    for (int i = 0; i < MAX_MC; i++) {
        __u32 idx = ( __u32 ) i;
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &idx);
        if (!mc) continue;
        if (mc->size == 0) continue;
        __u32 dist = distance_data_vs_center(p, mc);
        if (dist <= radius) count += mc->size;
    }
    return count;
}

static __always_inline int is_core_point(const data_point *p, __u32 k)
{
    __u32 neighbor_count = 0;
    neighbor_count += count_pd_neighbors_in_R(p, R);
    neighbor_count += count_mc_contribution(p, R);
    return (neighbor_count >= k) ? SUCCESS : FAIL;
}

static __always_inline int is_new_mc_candidate(const data_point *p, __u32 k)
{
    __u32 neighbor_count = 0;
    neighbor_count += count_pd_neighbors_in_R(p, R/2);
    neighbor_count += count_mc_contribution(p, R/2);
    return (neighbor_count >= k) ? SUCCESS : FAIL;
}

static __always_inline int create_microcluster(__u32 point_idx)
{
    for (int i = 0; i < MAX_MC; i++) {
        __u32 idx = ( __u32 ) i;
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &idx);
        if (!mc) continue;
        if (mc->size > 0) continue;
        MicroCluster new_mc = {};
        new_mc.id = idx;
        new_mc.center_idx = point_idx;
        new_mc.size = 1;
        new_mc.member_idx[0] = point_idx;
        return bpf_map_update_elem(&micro_clusters, &idx, &new_mc, BPF_ANY);
    }
    return FAIL;
}

static __always_inline void recompute_mc_center(MicroCluster *mc)
{
    if (!mc)
        return;
    if (mc->size == 0)
        return;

    __u32 sz = mc->size;
    if (sz > MAX_POINTS_PER_MC)
        sz = MAX_POINTS_PER_MC;

    __u64 sum[MAX_FEATURES];
    #pragma unroll
    for (int f = 0; f < MAX_FEATURES; f++)
        sum[f] = 0;
    for (int i = 0; i < (int)sz; i++) {
        if (i >= MAX_POINTS_PER_MC)
            break;

        __u32 pid = mc->member_idx[i];
        MCO *mco = bpf_map_lookup_elem(&mco_states, &pid);
        if (!mco)
            continue;

        #pragma unroll
        for (int f = 0; f < MAX_FEATURES; f++) {
            sum[f] += (__u64)mco->d.features[f];
        }
    }
    __u32 best_idx = mc->member_idx[0];
    __u64 best_dist = ~0ULL;

    /* --- Tìm member gần mean nhất --- */
    for (int i = 0; i < (int)sz; i++) {
        if (i >= MAX_POINTS_PER_MC)
            break;

        __u32 pid = mc->member_idx[i];
        MCO *mco = bpf_map_lookup_elem(&mco_states, &pid);
        if (!mco)
            continue;

        __u64 diff = 0;

        #pragma unroll
        for (int f = 0; f < MAX_FEATURES; f++) {
            __s64 mean_f = (__s64)(sum[f] / sz);
            __s64 d = (__s64)mco->d.features[f] - mean_f;
            if (d < 0)
                d = -d;
            diff += (__u64)(d * d);
        }

        if (diff < best_dist) {
            best_dist = diff;
            best_idx = pid;
        }
    }

    mc->center_idx = best_idx;
}

static __always_inline int add_point_to_mc(MicroCluster *mc, __u32 point_idx)
{
    if (!mc) return FAIL;
    if (mc->size >= MAX_POINTS_PER_MC) return FAIL;
    mc->member_idx[mc->size] = point_idx;
    mc->size++;
    recompute_mc_center(mc);
    bpf_map_update_elem(&micro_clusters, &mc->id, mc, BPF_ANY);
    return SUCCESS;
}

static __always_inline void remove_mc(__u32 mcid)
{
    MicroCluster empty = {};
    bpf_map_update_elem(&micro_clusters, &mcid, &empty, BPF_ANY);
}

static __always_inline int init_mco(__u32 point_idx, data_point *p)
{
    MCO m = {};
    m.d = *p;
    m.mc_id = MC_NONE;
    m.is_center = 0;
    m.is_in_cluster = 0;
    m.exps_size = 0;
    m.Rmc_size = 0;
    m.ev = 0;
    m.numberOfSucceeding = 0;
    for (int i = 0; i < MAX_K; i++) m.exps[i] = 0;
    for (int i = 0; i < MAX_RMC; i++) m.Rmc[i] = MC_NONE;
    return bpf_map_update_elem(&mco_states, &point_idx, &m, BPF_ANY);
}

static __always_inline void trim_expirations(MCO *m, __u64 now_us)
{
    if (!m) return;
    if (m->exps_size == 0) return;

    __u32 new_start = 0;
    for (int i = 0; i < MAX_K; i++) {
        if (( __u32 ) i >= m->exps_size) break;
        /* exps[] stored as 32-bit time values (µs truncated) */
        __u64 evt = ( __u64 ) m->exps[i];
        if (evt > now_us) break;
        new_start++;
    }
    if (new_start == 0) return;

    __u32 remain = m->exps_size - new_start;
    for (int j = 0; j < MAX_K; j++) {
        if (( __u32 ) j < remain)
            m->exps[j] = m->exps[j + new_start];
        else
            m->exps[j] = 0;
    }
    m->exps_size = remain;
    m->ev = (m->exps_size > 0) ? m->exps[0] : 0;
}

static __always_inline int remove_point_from_mc(__u32 mc_id, __u32 point_idx)
{
    if (mc_id >= MAX_MC) return FAIL;
    MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &mc_id);
    if (!mc) return FAIL;
    if (mc->size == 0) return FAIL;

    int found = 0;
    for (int i = 0; i < (int)mc->size; i++) {
        if (mc->member_idx[i] == point_idx) {
            found = 1;
        }
        if (found && (i + 1) < (int)mc->size) {
            mc->member_idx[i] = mc->member_idx[i + 1];
        }
    }
    if (!found) return FAIL;
    mc->size--;
    if (mc->size == 0) {
        MicroCluster empty = {};
        bpf_map_update_elem(&micro_clusters, &mc_id, &empty, BPF_ANY);
    } else {
        bpf_map_update_elem(&micro_clusters, &mc_id, mc, BPF_ANY);
    }
    return SUCCESS;
}

static __always_inline void remove_mco_with_m(MCO *m, __u32 point_idx)
{
    if (!m) return;
    /* clear PD_set entries that point to this point_idx */
    for (int i = 0; i < MAX_PD; i++) {
        __u32 idx = ( __u32 ) i;
        __u32 *val = bpf_map_lookup_elem(&PD_set, &idx);
        if (!val) continue;
        if (*val == point_idx) {
            __u32 zero = 0;
            bpf_map_update_elem(&PD_set, &idx, &zero, BPF_ANY);
        }
    }
    if (m->mc_id != MC_NONE && m->mc_id < MAX_MC) {
        remove_point_from_mc(m->mc_id, point_idx);
    }
    /* remove any event entries referring to this point */
    /* we search event_queue and clear matching mco_id entries */
    #pragma unroll
    for (int i = 0; i < EVENT_CAPACITY; i++) {
        __u32 idx = ( __u32 ) i;
        Event *ev = bpf_map_lookup_elem(&event_queue, &idx);
        if (!ev) continue;
        if (ev->mco_id == (int)point_idx) {
            Event empty = {};
            bpf_map_update_elem(&event_queue, &idx, &empty, BPF_ANY);
        }
    }
    /* delete mco state */
    {
        MCO empty = {};
        bpf_map_update_elem(&mco_states, &point_idx, &empty, BPF_ANY);
    }
}

/* process expired events up to EVENT_CAPACITY times */
static __always_inline void process_expired_events(void)
{
    /* use truncated 32-bit µs timestamps stored in Event.time */
    __u64 now_us_full = bpf_ktime_get_ns() / 1000ULL;
    __u32 now_us = ( __u32 )(now_us_full & 0xFFFFFFFFULL);

    Event ev;
    __u32 slot;
    // #pragma clang loop unroll(disable)
    for (int i = 0; i < EVENT_CAPACITY; i++) {
        if (event_extract_min(&ev, &slot) != SUCCESS)
            break;
        /* if event not yet expired -> reinsert and stop */
        /* both ev.time and now_us are 32-bit; unsigned comparison handles wrap */
        if (( __u32 ) ev.time > now_us) {
            /* reinsert */
            event_insert((__u32)ev.mco_id, ev.time);
            break;
        }
        __u32 mco_idx = ( __u32 ) ev.mco_id;
        MCO *m = bpf_map_lookup_elem(&mco_states, &mco_idx);
        if (!m) continue;
        trim_expirations(m, now_us_full);
        remove_mco_with_m(m, mco_idx);
    }
}

/* find nearest micro-cluster id, returns MC_NONE if none */
static __always_inline __u32 find_nearest_mc_id(const data_point *p, __u16 *out_dist)
{
    __u16 best = UINT16_MAX;
    __u32 best_id = MC_NONE;
    for (int i = 0; i < MAX_MC; i++) {
        __u32 idx = ( __u32 ) i;
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &idx);
        if (!mc) continue;
        if (mc->size == 0) continue;
        __u16 d = distance_data_vs_center(p, mc);
        if (d < best) {
            best = d;
            best_id = idx;
        }
    }
    if (out_dist) *out_dist = best;
    return best_id;
}

static __always_inline int find_free_pd_slot(void)
{
    for (int i = 0; i < MAX_PD; i++) {
        __u32 idx = ( __u32 ) i;
        __u32 *val = bpf_map_lookup_elem(&PD_set, &idx);
        if (!val) continue;
        if (*val == 0) {
            __u32 zero = 0;
            bpf_map_update_elem(&PD_set, &idx, &zero, BPF_ANY);
            return idx;
        }
    }
    return FAIL;
}

/* ================= STEP 2, 3, 4: PROCESS CORE POINT ================= */
static __always_inline void step234_process_point(__u32 point_idx, MCO *mco)
{
    if (!mco) return;
    data_point *p = &mco->d;
    if (!p) return;

    __u16 nearest_d = UINT16_MAX;
    __u32 nearest_mc = find_nearest_mc_id(p, &nearest_d);

    if (nearest_mc != MC_NONE && nearest_d <= (R/2)) {
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &nearest_mc);
        if (mc) {
            add_point_to_mc(mc, point_idx);
            mco->mc_id = nearest_mc;
            mco->is_in_cluster = 1;
            mco->is_center = 0;
            /* remove possible PD entry and event */
            /* remove PD_set occurrences */
            for (int i = 0; i < MAX_PD; i++) {
                __u32 idx = ( __u32 ) i;
                __u32 *val = bpf_map_lookup_elem(&PD_set, &idx);
                if (!val) continue;
                if (*val == point_idx) {
                    __u32 zero = 0;
                    bpf_map_update_elem(&PD_set, &idx, &zero, BPF_ANY);
                }
            }
            /* clear event entries for this point */
            // #pragma clang loop unroll(disable)
            for (int i = 0; i < EVENT_CAPACITY; i++) {
                __u32 idx = ( __u32 ) i;
                Event *ev = bpf_map_lookup_elem(&event_queue, &idx);
                if (!ev) continue;
                if (ev->mco_id == (int)point_idx) {
                    Event empty = {};
                    bpf_map_update_elem(&event_queue, &idx, &empty, BPF_ANY);
                }
            }
            bpf_map_update_elem(&mco_states, &point_idx, mco, BPF_ANY);

            /* update PD neighbors: increment succeeding neighbors if distance <= R */
            for (int i = 0; i < MAX_PD; i++) {
                __u32 idx = ( __u32 ) i;
                __u32 *pd_idx_ptr = bpf_map_lookup_elem(&PD_set, &idx);
                if (!pd_idx_ptr || *pd_idx_ptr == 0) continue;
                MCO *neighbor = bpf_map_lookup_elem(&mco_states, pd_idx_ptr);
                if (!neighbor) continue;
                __u16 dist = distance_data_vs_data(p, &neighbor->d);
                if (dist <= R) {
                    lock_xadd(&neighbor->numberOfSucceeding, 1);
                    bpf_map_update_elem(&mco_states, pd_idx_ptr, neighbor, BPF_ANY);
                }
            }
            return;
        }
    }

    /* 3b: core point candidate logic */
    if (is_core_point(p, MAX_K)) {
        if (is_new_mc_candidate(p, MAX_K)) {
            if (create_microcluster(point_idx) == SUCCESS) {
                mco->is_center = 1;
                mco->is_in_cluster = 1;
                mco->mc_id = point_idx;
                bpf_map_update_elem(&mco_states, &point_idx, mco, BPF_ANY);

                /* update Rmc lists of PD points within 3/2*R */
                for (int i = 0; i < MAX_PD; i++) {
                    __u32 idx = ( __u32 ) i;
                    __u32 *pd_idx_ptr = bpf_map_lookup_elem(&PD_set, &idx);
                    if (!pd_idx_ptr || *pd_idx_ptr == 0) continue;
                    MCO *neighbor = bpf_map_lookup_elem(&mco_states, pd_idx_ptr);
                    if (!neighbor) continue;
                    __u16 dist = distance_data_vs_data(p, &neighbor->d);
                    if (dist <= (R * 3 / 2)) {
                        for (int j = 0; j < MAX_RMC; j++) {
                            if (neighbor->Rmc[j] == MC_NONE) {
                                neighbor->Rmc[j] = point_idx;
                                neighbor->Rmc_size++;
                                bpf_map_update_elem(&mco_states, pd_idx_ptr, neighbor, BPF_ANY);
                                break;
                            }
                        }
                    }
                }
                return;
            }
        }
    }
    int slot = find_free_pd_slot();
    if (slot != FAIL) {
        __u32 point = point_idx;
        bpf_map_update_elem(&PD_set, ( __u32 * ) &slot, &point, BPF_ANY); 
        __u32 key = ( __u32 ) slot;
        bpf_map_update_elem(&PD_set, &key, &point, BPF_ANY);
    }

    __u64 expire_time_full = ( (__u64) p->last_seen ) + WINDOW_TIME_US;
    __u32 expire_time32 = ( __u32 )(expire_time_full & 0xFFFFFFFFULL);
    event_insert(point_idx, expire_time32);
}

/* ================= PROCESS NEW POINT ================= */
static __always_inline void process_new_point(__u32 point_idx)
{
    __u32 key = point_idx;
    data_point *p = bpf_map_lookup_elem(&datapoints, &key);
    if (!p) return;

    MCO *mco = bpf_map_lookup_elem(&mco_states, &key);
    if (!mco) {
        if (init_mco(point_idx, p) != 0) return;
        mco = bpf_map_lookup_elem(&mco_states, &key);
        if (!mco) return;
    }
    process_expired_events();
    step234_process_point(point_idx, mco);
}

/* detect anomaly for MCO at slot */
static __always_inline int is_anomaly_mco(__u32 point_idx)
{
    __u32 key = point_idx;
    MCO *m = bpf_map_lookup_elem(&mco_states, &key);
    if (!m) return 0;
    if (m->mc_id != MC_NONE) return 0;
    if (!m->is_in_cluster) {
        __u64 now_us_full = bpf_ktime_get_ns() / 1000ULL;
        __u32 now_us = ( __u32 )(now_us_full & 0xFFFFFFFFULL);
        __u32 valid_neighbors = m->numberOfSucceeding;
        for (int i = 0; i < MAX_K; i++) {
            __u32 evt = m->exps[i];
            if (evt == 0) continue;
            if (evt > now_us) valid_neighbors++;
        }
        for (int i = 0; i < MAX_RMC; i++) {
            __u32 mcid = m->Rmc[i];
            if (mcid == MC_NONE) continue;
            if (mcid >= MAX_MC) continue;
            MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &mcid);
            if (!mc) continue;
            if (mc->size > 0) valid_neighbors += mc->size;
        }
        if (valid_neighbors < MAX_K) return 1;
    }
    return 0;
}

static __always_inline void check_dissolving_mcs(void)
{
    for (int i = 0; i < MAX_MC; i++) {
        __u32 idx = ( __u32 ) i;
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &idx);
        if (!mc) continue;
        if (mc->size > 0 && mc->size < (MAX_K + 1)) {
            for (int j = 0; j < (int)mc->size; j++) {
                __u32 pid = mc->member_idx[j];
                MCO *m = bpf_map_lookup_elem(&mco_states, &pid);
                if (!m) continue;
                m->mc_id = MC_NONE;
                m->is_in_cluster = 0;
                m->is_center = 0;
                bpf_map_update_elem(&mco_states, &pid, m, BPF_ANY);
                /* push back to PD set if slot exists */
                int slot = find_free_pd_slot();
                if (slot != FAIL) {
                    __u32 s = ( __u32 ) slot;
                    bpf_map_update_elem(&PD_set, &s, &pid, BPF_ANY);
                }
                __u64 expire_time_full = ( (__u64) m->d.last_seen ) + WINDOW_TIME_US;
                __u32 expire_time32 = ( __u32 )(expire_time_full & 0xFFFFFFFFULL);
                event_insert(pid, expire_time32);
            }
            remove_mc(idx);
        }
    }
}

static __always_inline void periodic_maintenance(void)
{
    process_expired_events();
    check_dissolving_mcs();
}

/* allocate datapoint slot using flow_counter map */
static __always_inline __u32 allocate_datapoint_slot(void)
{
    __u32 idx0 = 0;
    __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx0);
    if (!cnt) return 0;
    __u32 old = *cnt;          // lấy giá trị hiện tại
    __sync_fetch_and_add(cnt, 1);  // tăng atomic
    __u32 slot = old % MAX_FLOW_SAVED;
    return slot;
}

/* ENTRY */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;
    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2) return XDP_DROP; /* LLDP */
    if (ret < 0) return XDP_PASS;   /* non-IP */

    data_point *flow_dp = update_stats(&key, ctx, 1);
    if (!flow_dp) return XDP_PASS;
    if (flow_dp->total_pkts < 5) return XDP_PASS;

    /* last maintenance stamp via control map (avoid static writable) */
    __u32 cidx = 0;
    __u64 *last_ns = bpf_map_lookup_elem(&control, &cidx);
    if (!last_ns) {
        __u64 zero = 0;
        bpf_map_update_elem(&control, &cidx, &zero, BPF_ANY);
        last_ns = bpf_map_lookup_elem(&control, &cidx);
        if (!last_ns) return XDP_PASS;
    }
    __u64 now_ns = bpf_ktime_get_ns();
    if (now_ns - *last_ns > NANOSEC_PER_SEC) {
        periodic_maintenance();
        /* update last_ns */
        __sync_fetch_and_add(last_ns, now_ns - *last_ns);
    }

    __u32 slot = allocate_datapoint_slot();
    __u32 key_slot = slot;
    /* store datapoint snapshot */
    bpf_map_update_elem(&datapoints, &key_slot, flow_dp, BPF_ANY);
    process_new_point(slot);

    int anomaly = is_anomaly_mco(slot);
    if (anomaly) {
        MCO *m = bpf_map_lookup_elem(&mco_states, &key_slot);
        if (m) {
            m->d.label = 1;
            bpf_map_update_elem(&mco_states, &key_slot, m, BPF_ANY);
        }
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";