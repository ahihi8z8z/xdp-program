/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
/*Config numbers of total data_points to training*/
#define TRAINING_SET         3200
/*Config numbers of flow to save to map xdp_flow_tracking or flow_dropped*/
#define MAX_FLOW_SAVED       300
/*Don't configure here*/
#define NULL_IDX             -1
#define MAX_FEATURES         5
#define SCALE                1000
#define MAP_SIZE             (2*MAX_FEATURES + 2)
/*Define for fixed point*/
#define FIXED_SHIFT          24
#define FIXED_SCALE          (1 << FIXED_SHIFT)
typedef __u32                fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;
} __attribute__((packed));

typedef struct {
    __u32   start_ts;             /* Timestamp of first packet */
    __u32   last_seen;            /* Timestamp of last packet */
    __u32   total_pkts;           /* Total packet count (Paccket/s)*/
    __u32   total_bytes;          /* Total byte count (Bytes/s)*/
    __u64   sum_IAT;              /* Sum of Inter-Arrival Times */
    /* Feature use for algorithm */
    __u32   flow_duration;        /* Duration of a flow */
    __u32   pkt_len_mean;
    /*
        features[0]: flow_duration      (Log2) 
        features[1]: flow_pkts_per_s    (Log2)
        features[2]: flow_bytes_per_s   (Log2)
        features[3]: flow_IAT_mean      (Log2)
        features[4]: pkts_len_mean      (Log2)
    */
    fixed features[MAX_FEATURES];
    int   label;
} data_point;

typedef struct mlp_params{
    fixed min_vals[MAX_FEATURES];
    fixed max_vals[MAX_FEATURES];
} mlp_params;

/* Convert float (as double in user space) to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{
    return (__u32)(value * (double)FIXED_SCALE);
}

/* Convert fixed-point to float */
static __always_inline float fixed_to_float(fixed value)
{
    return (float)value / (float)FIXED_SCALE;
}

/* Convert unsigned integer to fixed-point */
static __always_inline fixed fixed_from_uint(__u32 value)
{
    return value << FIXED_SHIFT;
}

/* Convert fixed-point to integer (truncate fractional) */
static __always_inline __u32 fixed_to_uint(fixed value)
{
    return value >> FIXED_SHIFT;
}

/* Add (safe for unsigned overflow wraparound) */
static __always_inline fixed fixed_add(fixed a, fixed b)
{
    return a + b;
}

/* Subtract (saturating underflow protection) */
static __always_inline fixed fixed_sub(fixed a, fixed b)
{
    return (a > b) ? (a - b) : 0;
}

/* Multiply (with scale correction) */
static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    /* Cast to 64-bit temporarily to avoid overflow before shift */
    unsigned long long temp = (unsigned long long)a * (unsigned long long)b;
    return (fixed)(temp >> FIXED_SHIFT);
}

/* Fixed-point division */
static __always_inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return 0;
    unsigned long long temp = ((unsigned long long)a << FIXED_SHIFT);
    return (fixed)(temp / b);
}

/* Square root using integer Newton's method */
static __always_inline fixed fixed_sqrt(fixed value)
{
    if (value == 0)
        return 0;

    fixed x = value;
    for (int i = 0; i < 8; i++) {
        x = fixed_div(fixed_add(x, fixed_div(value, x)), fixed_from_uint(2));
    }
    return x;
}
/* Fixed-point absolute value */
static inline fixed fixed_abs(fixed value)
{
    return (value < 0) ? -value : value;
}

/* Compare two fixed-point values */
static inline int fixed_compare(fixed a, fixed b)
{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

/* Fixed-point minimum */
static inline fixed fixed_min(fixed a, fixed b)
{
    return (a < b) ? a : b;
}

/* Fixed-point maximum */
static inline fixed fixed_max(fixed a, fixed b)
{
    return (a > b) ? a : b;
}

static __always_inline fixed fixed_log2(__u32 x)
{
    if (x == 0)
        return 0;

    __u32 int_part = 0;
    __u32 tmp = x;
    while (tmp >>= 1)
        int_part++;

    __u32 base = 1 << int_part;
    __u32 remainder = x - base;

    __u32 frac = (remainder << FIXED_SHIFT) / base;
    return (int_part << FIXED_SHIFT) | frac;
}

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */