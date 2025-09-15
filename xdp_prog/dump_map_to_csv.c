// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <unistd.h>
#include <limits.h>
#include <bpf/libbpf.h>

#include "common_kern_user.h" 

/* chỉ khai báo prototype cần dùng */
int open_bpf_map_file(const char *pin_dir,
                      const char *mapname,
                      struct bpf_map_info *info);

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* In ra node dưới dạng CSV */
static void print_node_csv(FILE *f, __u32 key, iTreeNode *node) {
    fprintf(f, "%u,%d,%d,%u,%d,%u\n",
            key,
            node->left_idx,
            node->right_idx,
            node->feature_idx,
            node->split_value,
            node->is_leaf);
}

static void print_flow_csv(FILE *f, struct flow_key *key, data_point *dp) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = key->src_ip; // network order
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    fprintf(f, "%s,%u,%u,%u,%u,%u,%u,%d\n",
        ip_str,
        ntohs(key->src_port),
        dp->features[0],
        dp->features[1],
        dp->features[2],
        dp->features[3],
        dp->features[4],
        dp->label
    );
}

/* Dump toàn bộ map -> file CSV */
static void dump_nodes_to_csv(int map_fd, FILE *f) {
    __u32 key = 0, next_key;
    iTreeNode value;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            print_node_csv(f, next_key, &value);
        }
        key = next_key;
    }
    fflush(f);
}

static void dump_flow_map_to_csv(int map_fd, FILE *f) {
    struct flow_key key, next_key;
    data_point dp;

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &dp) == 0) {
            print_flow_csv(f, &next_key, &dp);
        }
        key = next_key;
    }
    fflush(f);
}

int main(int argc, char **argv)
{
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd, map_fd1;
    int len;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return EXIT_FAILURE;
    }

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, argv[1]);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAILURE;
    }

    map_fd = open_bpf_map_file(pin_dir, "xdp_isoforest_nodes", &info);
    if (map_fd < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_isoforest_nodes\n");
        return EXIT_FAILURE;
    }

    map_fd1 = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd1 < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_flow_tracking\n");
        return EXIT_FAILURE;
    }

    FILE *f1 = fopen("isoforest_nodes.csv", "w");
    FILE *f2 = fopen("xdp_flow_tracking.csv", "w");
    if (!f1 || !f2) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(f1, "Key,LeftIdx,RightIdx,Feature,SplitValue,Size,IsLeaf\n");
    fprintf(f2, "SrcIP,SrcPort,feature1,feature2,feature3,feature4,Label\n");
    dump_nodes_to_csv(map_fd, f1);
    dump_flow_map_to_csv(map_fd1, f2);
    fclose(f1);
    fclose(f2);
    printf("Dumped isoforest nodes to isoforest_nodes.csv\n");
    printf("Dumped flow_tracking map to flow_dropped.csv\n");
    return EXIT_SUCCESS;
}
