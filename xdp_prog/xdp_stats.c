/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <math.h>

#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

/*==================== Command line options ====================*/
static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'},
     "Show help", false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>", "<ifname>", true},

    {{"contamination", required_argument, NULL, 'c'},
     "Contamination (fraction of anomalies to set threshold)", "<float>", false},

    {{"quiet", no_argument, NULL, 'q'},
     "Quiet mode (no output)"},

    {{0, 0, NULL, 0}}
};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

/*==================== CSV Reading ====================*/
int read_csv_dataset(const char *filename, data_point *dataset, int max_rows) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "[ERROR] Cannot open file: %s\n", filename);
        return -1;
    }

    char line[1024];
    int count = 0;

    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }

    while (fgets(line, sizeof(line), f) && count < max_rows) {
        data_point dp = {0};
        int index, src_port;
        char src_ip[64];
        double flow_duration, flow_bytes_per_s, flow_pkts_per_s, len_fwd_pkts;
        double len_bwd_pkts, flow_IAT_mean;
        int label;
        
        int n = sscanf(line,
                       "%d,%63[^,],%d,%lf,%lf,%lf,%lf,%lf,%lf,%d",
                       &index, src_ip, &src_port,
                       &flow_duration, &flow_bytes_per_s, &flow_pkts_per_s,
                       &len_fwd_pkts, &len_bwd_pkts, &flow_IAT_mean,
                       &label);

        if (n != 10) continue;

        // Calculate features correctly
        double total_length = len_fwd_pkts + len_bwd_pkts;
        
        dp.flow_duration    = (__u64)(flow_duration); // Convert to microseconds
        dp.total_bytes      = (__u64)total_length;
        dp.flow_IAT_mean    = (__u32)(flow_IAT_mean); // Convert to microseconds
        dp.pkt_len_mean     = len_bwd_pkts + len_fwd_pkts;
        
        // Calculate per-second rates
        dp.flow_pkts_per_s  = flow_pkts_per_s;
        dp.flow_bytes_per_s = flow_bytes_per_s;

        /* Copy to dp.features[] - order must match kernel */
        dp.features[0] = (__u32)dp.flow_duration;
        dp.features[1] = dp.flow_pkts_per_s;
        dp.features[2] = dp.pkt_len_mean;
        dp.features[3] = dp.flow_IAT_mean;
        dp.features[4] = dp.flow_bytes_per_s;
        
        dp.label = label;
        dataset[count++] = dp;

        if (count <= 5) { // Print first few for debugging
            printf("Sample %d: duration=%u, pkts/s=%u, mean_len=%u, IAT=%u, bytes/s=%u, label=%d\n",
                   count, dp.features[0], dp.features[1], dp.features[2], 
                   dp.features[3], dp.features[4], dp.label);
        }
    }
    fclose(f);
    return count;
}

int read_csv_dataset1(const char *filename, data_point *dataset, int max_rows) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "[ERROR] Cannot open file: %s\n", filename);
        return -1;
    }

    char line[1024];
    int count = 0;

    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }

    while (fgets(line, sizeof(line), f) && count < max_rows) {
        data_point dp = {0};
        int src_port;
        char src_ip[64];
        double feature0, feature1, feature2, feature3, feature4;
        int label;
        
        int n = sscanf(line,
                       "%63[^,],%d,%lf,%lf,%lf,%lf,%lf,%d",
                        src_ip, &src_port,
                       &feature0, &feature1, &feature2,
                       &feature3, &feature4, &label);

        if (n != 8) continue;
        /* Copy to dp.features[] - order must match kernel */
        dp.features[0] = feature0;
        dp.features[1] = feature1;
        dp.features[2] = feature2;
        dp.features[3] = feature3;
        dp.features[4] = feature4;
        
        dp.label = label;
        dataset[count++] = dp;

        if (count <= 5) { // Print first few for debugging
            printf("Sample %d: duration=%u, pkts/s=%u, mean_len=%u, IAT=%u, bytes/s=%u, label=%d\n",
                   count, dp.features[0], dp.features[1], dp.features[2], 
                   dp.features[3], dp.features[4], dp.label);
        }
    }
    fclose(f);
    return count;
}

/*==================== MAIN ====================*/
int main(int argc, char **argv) {
    srand(time(NULL));
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd_nodes = -1, map_fd_params = -1, map_fd_c = -1;
    int len;

    struct config cfg = {.ifindex = -1, .do_unload = false};
    const char *__doc__ = "Train IsolationForest and load into XDP BPF maps\n";
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERR: required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    /* Open pinned maps */
    map_fd_nodes = open_bpf_map_file(pin_dir, "xdp_isoforest_nodes", &info);
    if (map_fd_nodes < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_nodes'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    map_fd_c = open_bpf_map_file(pin_dir, "xdp_isoforest_c", &info);
    if (map_fd_c < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_c'\n", pin_dir);
        close(map_fd_nodes);
        return EXIT_FAIL_BPF;
    }

    map_fd_params = open_bpf_map_file(pin_dir, "xdp_isoforest_params", &info);
    if (map_fd_params < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_params'\n", pin_dir);
        close(map_fd_nodes);
        close(map_fd_c);
        return EXIT_FAIL_BPF;
    }

    return EXIT_SUCCESS;
}