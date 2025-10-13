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

#include "common_kern_user.h"   // để có struct flow_key, data_point

/* chỉ khai báo prototype cần dùng */
int open_bpf_map_file(const char *pin_dir,
                      const char *mapname,
                      struct bpf_map_info *info);

const char *pin_basedir = "/sys/fs/bpf";

/* In ra flow key dưới dạng IP:Port */
static void print_flow_key_csv(FILE *f, struct flow_key *key) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->dst_ip, dst_ip, sizeof(dst_ip));
    fprintf(f, "%s,%u,%s,%u,%d", src_ip, key->src_port, dst_ip, key->dst_port, key->proto);
}

/* In ra data_point dưới dạng CSV */
static void print_data_point_csv(FILE *f, data_point *dp) {
    fprintf(f, ",%llu,%u,%u",
           dp->flow_duration,
           dp->pkts_len_mean,
           dp->is_normal);
}

/* Dump toàn bộ map -> file CSV */
static void dump_map_to_csv(int map_fd, FILE *f) {
    struct flow_key key, next_key;
    data_point value;
    int stt = 1;

    memset(&key, 0, sizeof(key));

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            fprintf(f, "%d,", stt++);
            print_flow_key_csv(f, &next_key);
            print_data_point_csv(f, &value);
            fprintf(f, "\n");
        }
        key = next_key;
    }
    fflush(f);
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd;
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

    map_fd = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd < 0) {
        fprintf(stderr, "ERR: cannot open map\n");
        return EXIT_FAILURE;
    }

    // FILE *f = fopen("/home/dongtv/dtuan/data_pcap/lof_results/lof_2_13.csv", "w");
    FILE *f = fopen("test.csv", "w");
    if (!f) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(f, "STT,SrcIP,SrcPort,DstIP,DstPort,Proto,FlowDuration,FlowPktsPerSec,FlowBytesPerSec,FlowIATMean,PktLenMean,Label\n");

    dump_map_to_csv(map_fd, f);

    fclose(f);
    printf("Dumped flow stats to flow_stats.csv\n");
    return EXIT_SUCCESS;
}