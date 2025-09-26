/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
#define SCALE               1000
#define TRAINING_SET        3200
#define MAX_FLOW_SAVED      5000
#define MAX_FEATURES        5
#define MAX_TREES           100
#define MAX_NODE_PER_TREE   128
#define MAX_SAMPLE_PER_NODE 256
#define NULL_IDX            -1
#define MAX_TEST            300
#define MAX_DEPTH           8
#define CONTAMINATION       10

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;
} __attribute__((packed));

typedef struct {
    __u64 start_ts;             /* Timestamp of first packet        */
    __u64 last_seen;            /* Timestamp of last packet         */
    __u32 total_pkts;           /* Total packet count (Paccket/s)   */
    __u32 total_bytes;          /* Total byte count (Bytes/s)       */
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times       */
    __u32 sum_pkt_len;

    __u64 flow_duration;        /* Duration of a flow       */
    __u32 flow_IAT_mean;        /* Mean Inter-Arrival Time  */
    __u32 flow_bytes_per_s;     /* Bytes/s                  */
    __u32 flow_pkts_per_s;      /* Packets/s                */
    __u32 pkt_len_mean;         /* Mean of Packet Length    */
    __u32 features[MAX_FEATURES];
    int   label;
} data_point;

typedef struct iTreeNode{
    int left_idx;
    int right_idx;
    int feature_idx;
    int split_value;             /* Have to SCALE */
    int num_points;
    int is_leaf;
} iTreeNode;

typedef struct iTree{
    iTreeNode nodes[MAX_NODE_PER_TREE];
    __u32     num_nodes;
    __u32     max_depth;
}iTree;

typedef struct{
    iTree trees[MAX_TREES];
    __u32 n_trees;
    __u32 max_depth;
    __u32 sample_size;
}IsolationForest;

struct forest_params {
    __u32 n_trees;
    __u32 sample_size;
    __u32 threshold; /* integer threshold on avg path length */
    __u32 max_depth;
    __u32 contamination;
};

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */