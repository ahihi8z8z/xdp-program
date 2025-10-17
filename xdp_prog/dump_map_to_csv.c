// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "common_kern_user.h"
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

const char *pin_basedir = "/sys/fs/bpf";
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// In một flow ra CSV
static void print_flow_csv(FILE *f, const struct flow_key *key, const data_point *dp) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = key->src_ip; // network order
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    char ip_dest[INET_ADDRSTRLEN];
    struct in_addr addr1;
    addr1.s_addr = key->dst_ip; // network order
    inet_ntop(AF_INET, &addr1, ip_dest, sizeof(ip_dest));

    fprintf(f, "%s,%u,%s,%u,%u,%f,%f,%f,%f,%f,%d\n",
        ip_str,
        key->src_port,
        ip_dest,
        key->dst_port,
        key->proto,
        fixed_to_float(dp->features[0]),
        fixed_to_float(dp->features[1]),
        fixed_to_float(dp->features[2]),
        fixed_to_float(dp->features[3]),
        fixed_to_float(dp->features[4]),
        dp->label
    );
}
// Dump toàn bộ flow map ra CSV
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
// int open_bpf_map_file(const char *subdir, const char *mapname, struct bpf_map_info *info)
// {
//     char filename[PATH_MAX];
//     int err, len, map_fd;
//     __u32 info_len = sizeof(*info);

//     len = snprintf(filename, PATH_MAX, "%s/%s", subdir, mapname);
//     if (len < 0) {
//         fprintf(stderr, "ERR: building map filename\n");
//         return -1;
//     }

//     map_fd = bpf_obj_get(filename);
//     if (map_fd < 0) {
//         fprintf(stderr, "ERR: cannot open map file '%s': %s\n",
//                 filename, strerror(errno));
//         return -1;
//     }

//     err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
//     if (err) {
//         fprintf(stderr, "ERR: bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
//         close(map_fd);
//         return -1;
//     }

//     return map_fd;
// }
/* ================= MAIN ================= */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <flows_out.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *flows_filename = argv[2];

    char pin_dir[PATH_MAX];
    snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);

    struct bpf_map_info info = {0};
    int map_fd_flows = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd_flows < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_flow_tracking\n");
        return EXIT_FAILURE;
    }

    FILE *f_flows = fopen(flows_filename, "w");
    if (!f_flows) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    // Header CSV
    fprintf(f_flows, "SrcIP,SrcPort,DstIP,DstPort,Proto,Feature0,Feature1,Feature2,Feature3,Feature4,Label\n");

    // Dump map
    dump_flow_map_to_csv(map_fd_flows, f_flows);

    fclose(f_flows);
    close(map_fd_flows);

    printf("Dumped xdp_flow_tracking -> %s\n", flows_filename);
    return EXIT_SUCCESS;
}
