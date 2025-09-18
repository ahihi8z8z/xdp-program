/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
#define SCALE               1000
#define MAX_FLOW_SAVED      100
#define MAX_FEATURES        5
#define MAX_POINTS_PER_MC   8
#define MAX_MC              8
#define MAX_PD              8
#define MAX_RMC             8
#define MAX_K               4
#define SUCCESS             1
#define FAIL                0
#define R                   1000
#define R2_HALF_SQ          (R/2)
#define R3_2_SQ             3*R/2
#define EVENT_CAPACITY      (MAX_FLOW_SAVED * MAX_K)
#define MC_NONE             UINT32_MAX
#define MC_MEMBER_IDX_OFFSET 12
#define MEMBER_SIZE_BYTES 4
/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;
} __attribute__((packed));

typedef struct {
    /* METRIC TO COMPUTE FEATURES */
    __u32   start_time;           /* Timestamp of first packet        */
    __u32   last_seen;            /* Timestamp of last packet         */
    __u32   total_pkts;           /* Total packet count (Paccket/s)   */
    __u32   total_bytes;          /* Total byte count (Bytes/s)       */
    __u64   sum_IAT;              /* Sum of Inter-Arrival Times       */
    __u32   sum_pkt_len;
    __u32   flow_duration;        /* Duration of a flow       */
    __u32   flow_IAT_mean;        /* Mean Inter-Arrival Time  */
    __u32   flow_bytes_per_s;     /* Bytes/s                  */
    __u32   flow_pkts_per_s;      /* Packets/s                */
    __u32   pkt_len_mean;         /* Mean of Packet Length    */
    
    __u32   features[MAX_FEATURES];
    int     label;
} data_point;
 
typedef struct {
    data_point d;
    __u32      mc_id;
    __u32      is_center;
    __u32      is_in_cluster;
    __u32      exps[MAX_K]; 
    __u32      exps_size;
    __u32      Rmc[MAX_RMC];
    __u32      Rmc_size;
    __u32      ev;
    __u32      numberOfSucceeding;
} MCO;

typedef struct {
    __u32   id;
    __u32   center_idx;
    __u32   size;
    __u32   member_idx[MAX_POINTS_PER_MC];
} MicroCluster;

typedef struct{
    __u32   time;
    int     mco_id;
} Event;

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */