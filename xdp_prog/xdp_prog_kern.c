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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries, MAX_FLOW_SAVED);
    __type(key, __u32);    
    __type(value, data_point);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} datapoints SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FLOW_SAVED);
    __type(key, __u32);
    __type(value, MCO);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mco_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MC);
    __type(key, __u32);
    __type(value, MicroCluster);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} micro_clusters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PD);
    __type(key, __u32);   // slot id
    __type(value, __u32); // datapoint index
} PD_set SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FLOW_SAVED);
    __type(key, __u32);
    __type(value, Event);
} event_queue SEC(".maps");

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
    __u64 ts_us  = ts_ns / 1000;  // convert ns -> µs
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_time  = ts_us;
        zero.last_seen   = ts_us;
        zero.total_pkts  = 1;
        zero.total_bytes = pkt_len;
        zero.sum_IAT     = 0;
        zero.sum_pkt_len = pkt_len;
        zero.label = -1;     

        #pragma unroll
        for (int i = 0; i < MAX_FEATURES; i++) {
            zero.features[i] = 0;
        }
        if (bpf_map_update_elem(&flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        /* tăng counter flow */
        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return bpf_map_lookup_elem(&flow_tracking, key);
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

    dp->flow_duration = dp->last_seen - dp->start_time;  // µs
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
        .mco_id    = point_id,
        .time = expire_time,
    };
    return bpf_map_update_elem(&event_queue, &point_id, &ev, BPF_ANY);
}

static __always_inline int event_find_min(Event *out_event)
{
    __u64 min_time = UINT64_MAX;
    int found = 0;

    for (__u32 i = 0; i < EVENT_CAPACITY; i++) {
        Event *ev = bpf_map_lookup_elem(&event_queue, &i);
        if (!ev) continue;

        if (ev->time < min_time) {
            min_time = ev->time;
            *out_event = *ev;
            found = 1;
        }
    }

    return found ? SUCCESS : FAIL;
}

static __always_inline int event_extract_min(Event *out_event)
{
    if (event_find_min(out_event) == FAIL)
        return FAIL;

    // Xoá theo point_id (unique key)
    bpf_map_delete_elem(&event_queue, &out_event->mco_id);
    return SUCCESS;
}

// static __always_inline int event_increase_time(__u32 point_id, __u32 delta)
// {
//     Event *ev = bpf_map_lookup_elem(&event_queue, &point_id);
//     if (!ev) return FAIL;

//     ev->time += delta;
//     return SUCCESS;
// }

// static __always_inline int event_remove(__u32 point_id)
// {
//     return bpf_map_delete_elem(&event_queue, &point_id);
// }
/* ==================== CALCULATE LOG2(x) ==================== */
static __always_inline __u8 ilog2_u64(__u64 x)
{
    static const __u8 tbl[16] = {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};
    __u8 r = 0;

    if (x >> 32) {
        __u32 hi = x >> 32;
        if (hi >= (1<<16)) { hi >>= 16; r += 16; }
        if (hi >= (1<<8))  { hi >>= 8;  r += 8; }
        if (hi >= (1<<4))  { hi >>= 4;  r += 4; }
        return r + tbl[hi & 0xF];
    } else {
        __u32 lo = x & 0xFFFFFFFF;
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
#pragma unroll
    for (int i = 0; i < 6; i++) {
        prev = res;
        res = (res + x / res) >> 1;
        if (res == prev)
            break;
    }
    return res;
}

static __always_inline __u16 distance_data_vs_data(const data_point *a, const data_point *b)
{
    __u64 sum = 0;
    #pragma unroll
    for(int i = 0; i < MAX_FEATURES; i++){
        __u64 diff = ((__s64)a->features[i] - (__s64)b->features[i] > 0) ?
                      (a->features[i] - b->features[i]) :
                      (b->features[i] - a->features[i]);
        
        sum += ilog2_u64(diff + 1) * ilog2_u64(diff + 1);
    }
    return bpf_sqrt(sum);
}

static __always_inline __u16 distance_data_vs_center(const data_point *a, MicroCluster *mc)
{
    MCO *center_mco = bpf_map_lookup_elem(&mco_states, &mc->center_idx);
    if (!center_mco)
        return UINT16_MAX; /* không có center hợp lệ */

    const data_point *c = &center_mco->d;
    return distance_data_vs_data(a, c);
}

static __always_inline __u32 count_pd_neighbors_in_R(const data_point *p, __u32 radius)
{
    __u32 count = 0;
    #pragma unroll MAX_PD
    for (__u32 i = 0; i < MAX_PD; i++) {
        MCO *mco = bpf_map_lookup_elem(&mco_states, &i);
        if (!mco) continue;

        __u32 dist = distance_data_vs_data(p, &mco->d);
        if (dist <= radius) {
            count++;
        }
    }
    return count;
}

static __always_inline __u32 count_mc_contribution(const data_point *p, __u32 radius)
{
    __u32 count = 0;

    for (__u32 i = 0; i < MAX_MC; i++) {
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &i);
        if (!mc || mc->size == 0) continue;

        __u32 dist = distance_data_vs_center(p, mc);
        if (dist <= radius) {
            count += mc->size; 
        }
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
    #pragma unroll MAX_MC
    for (__u32 i = 0; i < MAX_MC; i++) {
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &i);
        if (!mc || mc->size > 0) continue;

        MicroCluster new_mc = {};
        new_mc.id = i;
        new_mc.center_idx = point_idx;
        new_mc.size = 1;
        new_mc.member_idx[0] = point_idx;

        return bpf_map_update_elem(&micro_clusters, &i, &new_mc, BPF_ANY);
    }
    return FAIL;
}

static __always_inline void recompute_mc_center(MicroCluster *mc)
{
    if (mc->size == 0) return;

    __u64 sum[MAX_FEATURES] = {0};

    for (__u32 i = 0; i < mc->size; i++) {
        __u32 pid = mc->member_idx[i];
        MCO *mco = bpf_map_lookup_elem(&mco_states, &pid);
        if (!mco) continue;

        #pragma unroll
        for (int f = 0; f < MAX_FEATURES; f++) {
            sum[f] += mco->d.features[f];
        }
    }

    /* tìm point gần vector trung bình nhất làm center_idx */
    __u32 best_idx = mc->member_idx[0];
    __u64 best_dist = ~0ULL;

    for (__u32 i = 0; i < mc->size; i++) {
        __u32 pid = mc->member_idx[i];
        MCO *mco = bpf_map_lookup_elem(&mco_states, &pid);
        if (!mco) continue;

        __u64 diff = 0;
        #pragma unroll
        for (int f = 0; f < MAX_FEATURES; f++) {
            __s64 d = (__s64)mco->d.features[f] - (sum[f] / mc->size);
            diff += d * d;
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
    if (mc->size >= MAX_POINTS_PER_MC) {
        return FAIL;
    }
    mc->member_idx[mc->size] = point_idx;
    mc->size++;
    // mc->last_updated = bpf_ktime_get_ns();
    recompute_mc_center(mc);
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

    /* init arrays */
    #pragma unroll
    for (int i = 0; i < MAX_K; i++) m.exps[i] = 0;
    #pragma unroll
    for (int i = 0; i < MAX_RMC; i++) m.Rmc[i] = MC_NONE;

    return bpf_map_update_elem(&mco_states, &point_idx, &m, BPF_ANY);
}

// static __always_inline void add_expiration_to_mco(__u32 mco_idx, __u64 expire_time)
// {
//     MCO *m = bpf_map_lookup_elem(&mco_states, &mco_idx);
//     if (!m) return;

//     /* if already full and new expire_time is >= last, skip */
//     if (m->exps_size > 0 && m->exps_size >= MAX_K) {
//         /* find largest existing */
//         __u32 max_idx = m->exps_size - 1;
//         if ((__u64)m->exps[max_idx] <= expire_time) {
//             return;
//         }
//     }

//     /* insert sorted */
//     __u32 insert_pos = m->exps_size;
//     if (insert_pos >= MAX_K) insert_pos = MAX_K - 1;

//     /* shift right to make room */
//     for (int i = (int)insert_pos - 1; i >= 0; i--) {
//         if (m->exps[i] > expire_time) {
//             /* move one step */
//             if (i + 1 < MAX_K)
//                 m->exps[i + 1] = m->exps[i];
//             if (i == 0) {
//                 m->exps[0] = (__u32)expire_time;
//             }
//         } else {
//             if (i + 1 < MAX_K)
//                 m->exps[i + 1] = (__u32)expire_time;
//             goto upd_size;
//         }
//     }
//     if (insert_pos == 0) {
//         m->exps[0] = (__u32)expire_time;
//     }
// upd_size:
//     if (m->exps_size < MAX_K) m->exps_size++;

//     /* keep only up to MAX_K smallest exps: if more (shouldn't), truncate */
//     if (m->exps_size > MAX_K) m->exps_size = MAX_K;

//     /* update ev */
//     if (m->exps_size > 0) m->ev = m->exps[0];
//     else m->ev = 0;

//     bpf_map_update_elem(&mco_states, &mco_idx, m, BPF_ANY);
// }

static __always_inline void trim_expirations(__u32 mco_idx, __u64 now_us)
{
    MCO *m = bpf_map_lookup_elem(&mco_states, &mco_idx);
    if (!m) return;

    if (m->exps_size == 0) return;

    __u32 new_start = 0;

    /* check tất cả exps */
    #pragma unroll
    for (__u32 i = 0; i < MAX_K; i++) {
        if (i >= m->exps_size) break;
        if ((__u64)m->exps[i] > now_us) {
            break;
        }
        new_start++;
    }

    if (new_start == 0) return; /* không có gì hết hạn */

    __u32 remain = m->exps_size - new_start;

    /* dịch phần còn lại về đầu */
    #pragma unroll
    for (__u32 j = 0; j < MAX_K; j++) {
        if (j < remain)
            m->exps[j] = m->exps[j + new_start];
        else
            m->exps[j] = 0;   /* clear tail */
    }

    m->exps_size = remain;
    m->ev = (m->exps_size > 0) ? m->exps[0] : 0;
}

// static __always_inline void update_rmc(__u32 mco_idx, __u32 mc_id)
// {
//     if (mc_id >= MAX_MC) return;
//     MCO *m = bpf_map_lookup_elem(&mco_states, &mco_idx);
//     if (!m) return;

//     /* check exists */
//     #pragma unroll
//     for (int i = 0; i < MAX_RMC; i++) {
//         if (m->Rmc[i] == mc_id) return;
//     }
//     /* find free slot (use MC_NONE sentinel) */
//     #pragma unroll
//     for (int i = 0; i < MAX_RMC; i++) {
//         if (m->Rmc[i] == MC_NONE) {
//             m->Rmc[i] = mc_id;
//             m->Rmc_size++;
//             bpf_map_update_elem(&mco_states, &mco_idx, m, BPF_ANY);
//             return;
//         }
//     }
//     /* no slot -> ignore (bounded memory) */
// }

static __always_inline int remove_point_from_mc(__u32 mc_id, __u32 point_idx)
{
    if (mc_id >= MAX_MC) return FAIL;
    MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &mc_id);
    if (!mc) return FAIL;
    if (mc->size == 0) return FAIL;

    int found = 0;
    for (__u32 i = 0; i < mc->size; i++) {
        if (mc->member_idx[i] == point_idx) {
            found = 1;
        }
        if (found && i + 1 < mc->size) {
            mc->member_idx[i] = mc->member_idx[i + 1];
        }
    }
    if (!found) return FAIL;

    mc->size--;
    /* if cluster now empty -> remove cluster */
    if (mc->size == 0) {
        MicroCluster empty = {};
        bpf_map_update_elem(&micro_clusters, &mc_id, &empty, BPF_ANY);
    } else {
        bpf_map_update_elem(&micro_clusters, &mc_id, mc, BPF_ANY);
    }
    return SUCCESS;
}

static __always_inline void remove_mco(__u32 point_idx)
{
    __u32 zero = 0;

    // Duyệt PD_set và xóa tất cả entry bằng point_idx
    #pragma unroll MAX_PD
    for (__u32 i = 0; i < MAX_PD; i++) {
        __u32 *val = bpf_map_lookup_elem(&PD_set, &i);
        if (!val)
            continue;
        if (*val == point_idx) {
            bpf_map_update_elem(&PD_set, &i, &zero, BPF_ANY);
        }
    }

    // Lấy MCO tương ứng và xóa khỏi micro-cluster nếu cần
    MCO *m = bpf_map_lookup_elem(&mco_states, &point_idx);
    if (m && m->mc_id != MC_NONE && m->mc_id < MAX_MC) {
        remove_point_from_mc(m->mc_id, point_idx);
    }

    // Xóa khỏi event queue và MCO map
    bpf_map_delete_elem(&event_queue, &point_idx);
    bpf_map_delete_elem(&mco_states, &point_idx);
}

static __always_inline void process_expired_events(void)
{
    __u32 now_us = bpf_ktime_get_ns() / 1000ULL;
    Event ev = {};
    #pragma unroll EVENT_CAPACITY
    for (int i = 0; i < EVENT_CAPACITY; i++) {
        if (event_extract_min(&ev) != SUCCESS)
            break;

        if (ev.time > now_us) {
            event_insert(ev.mco_id, ev.time);
            break;
        }

        __u32 mco_idx = ev.mco_id;
        trim_expirations(mco_idx, now_us);
        remove_mco(mco_idx);
    }
}

static __always_inline __u32 find_nearest_mc_id(const data_point *p, __u16 *out_dist)
{
    __u16 best = UINT16_MAX;
    __u32 best_id = MC_NONE;

    for (__u32 i = 0; i < MAX_MC; i++) {
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &i);
        if (!mc || mc->size == 0) continue;

        __u16 d = distance_data_vs_center((data_point *)p, mc);
        if (d < best) {
            best = d;
            best_id = i;
        }
    }
    if (out_dist) *out_dist = best;
    return best_id;
}

static __always_inline int find_free_pd_slot(void)
{
    __u32 val = 0;   
    #pragma unroll MAX_PD
    for (__u32 i = 0; i < MAX_PD; i++) {
        if (bpf_map_lookup_elem(&PD_set, &i) == NULL) {
            val = 0;
            bpf_map_update_elem(&PD_set, &i, &val, BPF_ANY);
            return i;
        }
    }
    return FAIL;
}

/* ================= PROCESS NEW POINT ================= */
static __always_inline void process_new_point(__u32 point_idx)
{
    data_point *p = bpf_map_lookup_elem(&datapoints, &point_idx);
    if (!p) return;

    MCO *mco = bpf_map_lookup_elem(&mco_states, &point_idx);
    if (!mco) {
        if (init_mco(point_idx, p) != 0) return;
        mco = bpf_map_lookup_elem(&mco_states, &point_idx);
        if (!mco) return;
    }
    process_expired_events();
    /* Step 2: join nearest MC if close enough */
    __u16 nearest_d = UINT16_MAX;
    __u32 nearest_mc = find_nearest_mc_id(p, &nearest_d);
    if (nearest_mc != MC_NONE && nearest_d <= ((__u16)(R/2))) {
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &nearest_mc);
        if (mc) {
            add_point_to_mc(mc, point_idx);
            mco->mc_id = nearest_mc;
            mco->is_in_cluster = 1;
            mco->is_center = 0;
            bpf_map_delete_elem(&event_queue, &point_idx);
            bpf_map_update_elem(&mco_states, &point_idx, mco, BPF_ANY);
            return;
        }
    }
    /* Step 3: core point logic */
    if (is_core_point(p, MAX_K)) {
        if (is_new_mc_candidate(p, MAX_K)) {
            if (create_microcluster(point_idx) == SUCCESS) {
                mco->is_center = 1;
                mco->is_in_cluster = 1;
                mco->mc_id = point_idx;
                bpf_map_update_elem(&mco_states, &point_idx, mco, BPF_ANY);
                return;
            }
        }
    }
    /* Step 4: treat as PD (Potential Outlier) */
    int slot = find_free_pd_slot();
    if (slot != FAIL) {
        bpf_map_update_elem(&PD_set, &slot, &point_idx, BPF_ANY);
    }
    __u64 expire_time = (__u64)p->last_seen + WINDOW_TIME_US;
    event_insert(point_idx, (__u32)(expire_time & 0xFFFFFFFFULL));
}

static __always_inline int is_anomaly_mco(__u32 point_idx)
{
    MCO *m = bpf_map_lookup_elem(&mco_states, &point_idx);
    if (!m) return 0; 
    if (m->mc_id != MC_NONE) return 0;
    if (!m->is_in_cluster) {
        __u64 now_us = bpf_ktime_get_ns() / 1000ULL;
        __u32 valid_neighbors = m->numberOfSucceeding;
        for (int i = 0; i < MAX_K; i++) {
            __u32 evt = m->exps[i];
            if (evt == 0) continue;
            if (( __u64)evt > now_us) valid_neighbors++;
        }

        for (int i = 0; i < MAX_RMC; i++) {
            __u32 mcid = m->Rmc[i];
            if (mcid == MC_NONE) continue;
            if (mcid >= MAX_MC) continue;
            MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &mcid);
            if (!mc) continue;
            if (mc->size > 0) valid_neighbors += mc->size;
        }

        if (valid_neighbors < MAX_K) return 1; /* anomaly */
    }
    return 0;
}

static __always_inline void check_dissolving_mcs(void)
{
    for (__u32 i = 0; i < MAX_MC; i++) {
        MicroCluster *mc = bpf_map_lookup_elem(&micro_clusters, &i);
        if (!mc) continue;
        if (mc->size > 0 && mc->size < (MAX_K + 1)) {
            for (__u32 j = 0; j < mc->size; j++) {
                __u32 pid = mc->member_idx[j];
                MCO *m = bpf_map_lookup_elem(&mco_states, &pid);
                if (!m) continue;
                m->mc_id = MC_NONE;
                m->is_in_cluster = 0;
                m->is_center = 0;
                __u64 expire_time = (__u64)m->d.last_seen + WINDOW_TIME_US;
                event_insert(pid, (__u32)(expire_time & 0xFFFFFFFFULL));
                bpf_map_update_elem(&mco_states, &pid, m, BPF_ANY);
            }
            remove_mc(i);
        }
    }
}

static __always_inline void periodic_maintenance(void){
    process_expired_events();
    check_dissolving_mcs();
}

static __always_inline __u32 allocate_datapoint_slot(void)
{
    __u32 idx = 0;
    __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
    if (!cnt) return 0;

    __u32 old = *cnt;
    lock_xadd(cnt, 1);   // atomic ++cnt

    __u32 slot = old % MAX_FLOW_SAVED;
    return slot;
}

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
    static __u64 last_maintenance_ns = 0;
    __u64 now_ns = bpf_ktime_get_ns();
    if (now_ns - last_maintenance_ns > NANOSEC_PER_SEC) {
        periodic_maintenance();
        last_maintenance_ns = now_ns;
    }
    __u32 slot = allocate_datapoint_slot();
    bpf_map_update_elem(&datapoints, &slot, flow_dp, BPF_ANY);
    process_new_point(slot);
    int anomaly = is_anomaly_mco(slot);
    if (anomaly) {
        MCO *m = bpf_map_lookup_elem(&mco_states, &slot);
        if (m) {
            m->d.label = 1; /* label=1 -> anomaly marker (user-defined)*/
            bpf_map_update_elem(&mco_states, &slot, m, BPF_ANY);
        }
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";