// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common_kern_user.h"

const char *pin_basedir = "/sys/fs/bpf";
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// In một flow ra CSV
static void print_flow_csv(FILE *f, const struct flow_key *key, const data_point *dp) {
    struct in_addr ip_addr;
    ip_addr.s_addr = key->src_ip;
    fprintf(f, "%s,%u,%u,%u,%u,%u,%u,%u\n",
            inet_ntoa(ip_addr),
            key->src_port,
            dp->features[0],
            dp->features[1],
            dp->features[2],
            dp->features[3],
            dp->features[4],
            dp->label);
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
    fprintf(f_flows, "SrcIP,SrcPort,Feature0,Feature1,Feature2,Feature3,Feature4,Label\n");

    // Dump map
    dump_flow_map_to_csv(map_fd_flows, f_flows);

    fclose(f_flows);
    close(map_fd_flows);

    printf("Dumped xdp_flow_tracking -> %s\n", flows_filename);
    return EXIT_SUCCESS;
}
