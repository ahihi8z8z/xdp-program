/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
#define KNN                 2
#define SCALEEEEEE          1000
#define DATA_CAL_LOF        100
#define MAX_FLOW_SAVED      200
#define LOF_THRESHOLD       1 // Threshold accuracy cao nhất

#define FIXED_SHIFT         32
#define FIXED_SCALE         (1ULL << FIXED_SHIFT)

/*The high 32 bits store integer part*/
/*The low 32 bits store the fractional part*/
typedef __u64 fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
} __attribute__((packed));

struct knn_entry {
    struct flow_key key;   /* flow láng giềng */
    fixed distance;        /* khoảng cách tới neighbor */
};

/*I think we only use fixed point for flow_duration, flow_pkts_per_s, flow_bytes_per_s
pkts_len_mean, flow_IAT_mean, k_distance, reach_dist, lrd value, lof value.    
*/

/* Flow statistics and anomaly detection data */
typedef struct {
    /* Timing information */
    __u64 start_ts;             /* Timestamp of first packet */
    __u64 last_seen;            /* Timestamp of last packet */
    
    __u32 total_pkts;           /* Total packet count (Paccket/s)*/
    __u32 total_bytes;          /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    fixed flow_IAT_mean;        /* Mean Inter-Arrival Time */
    __u64 flow_duration;
    fixed flow_pkts_per_s;
    fixed flow_bytes_per_s;
    fixed pkts_len_mean;
    __u8  is_normal;           /*Value of is_normal is only 0 or 1*/

    fixed k_distance;            /* k-distance value */
    fixed reach_dist[KNN];       /* Reachability distances to k neighbors */
    fixed lrd_value;             /* Local Reachability Density */
    fixed lof_value;             /* Local Outlier Factor score */

    struct knn_entry knn[KNN];
} data_point;

static inline fixed uint_to_fixed(__u64 x){
    return (fixed)(x << FIXED_SHIFT);
}

// static inline

static inline __u64 fixed_to_uint(fixed x){
    return x >> FIXED_SHIFT;
}

static inline fixed fixed_add(fixed a, fixed b)
{
    __u64 r = a + b;
    if (r < a)
        return (fixed)~(fixed)0ULL; 
    return (fixed)r;
}

/*a > b*/
static inline fixed fixed_sub(fixed a, fixed b)
{
    return (a >= b) ? (a - b) : 0;
}

static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    /* Q32.32 * Q32.32 = Q64.64, cần chia lại cho 2^32 */
    __u64 a_hi = a >> 32;
    __u64 a_lo = a & 0xFFFFFFFF;
    __u64 b_hi = b >> 32;
    __u64 b_lo = b & 0xFFFFFFFF;

    /* Nhân chéo (giới hạn trong 64-bit, tránh tràn) */
    __u64 hi = a_hi * b_hi;
    __u64 mid1 = a_hi * b_lo;
    __u64 mid2 = a_lo * b_hi;
    __u64 lo = (a_lo * b_lo) >> 32;

    /* Tổng hợp lại — hiệu chỉnh theo FIXED_SHIFT */
    __u64 result = (hi << 32) + mid1 + mid2 + lo;

    return result;
}

static inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return (fixed)~(fixed)0ULL;

    /* scale numerator before division */
    return (a / b) << FIXED_SHIFT ;
}

// static __always_inline fixed fixed_log2(fixed x)
// {
//     if (x == 0) return 0;

//     // count leading zeros (BPF helper understood by verifier)
//     __u64 leading = (__u64)__builtin_clzll(x);
//     int exp = 63 - leading - FIXED_SHIFT;
//     if (exp < 0) exp = 0;

//     // Only return integer log part scaled
//     return (fixed)(((__u64)exp) << FIXED_SHIFT);
// }

static __always_inline fixed fixed_sqrt(fixed x)
{
    if (x == 0) return 0;

    __u64 n = x;
    __u64 res = 0;
    __u64 bit = 1ULL << 62; // highest power of four <= 2^64

// #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (bit > n)
            bit >>= 2;
        else
            break;
    }

// #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (n >= res + bit) {
            n -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }

    return (fixed)res;
}
/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */