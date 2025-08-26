#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <stdbool.h>

#define KNN                 3
#define UPDATE_MAX          5
#define SCALEEEEEE          100

/* ==== Flow key ==== */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding; /* giữ 8-byte alignment */
} __attribute__((packed));

/* ==== Per-flow stats + LOF fields ==== */
typedef struct {
    __u64 start_ts;
    __u64 last_seen;

    __u32 total_pkts;
    __u32 total_bytes;
    __u64 sum_IAT;
    __u32 flow_IAT_mean;

    __u16 k_distance;
    __u16 reach_dist[KNN];
    __u16 lrd_value;
    __u16 lof_value;
} data_point;

/* KNN result item */
struct knn_entry {
    struct flow_key key;
    __u16 distance; /* 0xffff = empty */
};

struct knn_context {
    const struct flow_key *target_key; /* pointer (verifier-friendly) */
    const data_point      *target_dp;  /* pointer (verifier-friendly) */
    struct knn_entry      *results;    /* array trên stack */
    int                    processed;  /* đếm phần tử đã duyệt */
    int                    limit;      /* giới hạn duyệt */
};

/* kRNN list (giá trị của map xdp_update) */
struct krnn_entry {
    struct flow_key key;
    __u16 distance;
};

struct krnn_entries {
    struct krnn_entry e[UPDATE_MAX];
};

struct krnn_callback_ctx {
    const struct flow_key *target_key;
    int                    processed;
    int                    limit;
};

/* Update-set item */
struct update_lrd_entry {
    struct flow_key key;
    bool is_valid;
};

struct knn_for_update_context {
    const struct flow_key     *target_key;
    const data_point          *target_dp;
    struct update_lrd_entry   *update_set;
    int                       *update_count;
    int                        max_size;
    int                        processed;
    int                        limit;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
