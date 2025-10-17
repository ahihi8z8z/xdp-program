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

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'}, "Show help", false},
    {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},
    {{0, 0, NULL, 0}}
};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

void min_max_scale_fixed(data_point *dataset, int n_samples, int n_feature, mlp_params *params){
    fixed min_vals[n_feature];
    fixed max_vals[n_feature];

    for(int j = 0; j < n_feature; j++){
        min_vals[j] = UINT32_MAX;
        max_vals[j] = 0;
    }

    for (int i = 0; i < n_samples; i++) {
        for (int j = 0; j < n_feature; j++) {
            fixed val = dataset[i].features[j];
            if (val < min_vals[j]) min_vals[j] = val;
            if (val > max_vals[j]) max_vals[j] = val;
        }
    }

    for(int i = 0; i < n_feature; i++){
        params->min_vals[i] = min_vals[i];
        params->max_vals[i] = max_vals[i];
    }

    for (int i = 0; i < n_samples; i++) {
        for (int j = 0; j < n_feature; j++) {
            __u32 val = dataset[i].features[j];
            __u32 range = max_vals[j] - min_vals[j];
            if (range > 0) {
                // scaled = (val - min) / range
                // => fixed = ((val - min) << 24) / range
                fixed scaled = fixed_div(fixed_sub(val, min_vals[j]), range);
                // fixed scaled = ((__s64)(val - min_vals[j]) << 24) / range;
                dataset[i].features[j] = scaled;
            } else {
                dataset[i].features[j] = 0;
            }
        }
    }
}

/*==================== CSV Reading ====================*/
int read_csv_dataset1(const char *filename, data_point *dataset, int max_rows, mlp_params *params) {
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
        int idx;
        int src_port, dst_port;
        char src_ip[64];
        char dst_ip[64];
        double feature0, feature1, feature2, feature3, feature4;
        int un_label, proto;
        char label_str[32];  // label as string
        
        int n = sscanf(line,
                       "%d,%63[^,],%d,%63[^,],%d,%d,%lf,%lf,%lf,%lf,%lf,%d,%31s",
                       &idx, src_ip, &src_port, dst_ip, &dst_port, &proto,
                       &feature0, &feature1, &feature2,
                       &feature3, &feature4, &un_label, label_str);

        if (n != 13) continue;

        /* Copy features */
        dp.features[0] = fixed_from_float(log2(feature0 + 1.0));
        dp.features[1] = fixed_from_float(log2(feature1 + 1.0));
        dp.features[2] = fixed_from_float(log2(feature2 + 1.0));
        dp.features[3] = fixed_from_float(log2(feature3 + 1.0));
        dp.features[4] = fixed_from_float(log2(feature4 + 1.0));
        
        /* Convert label string to int: BENIGN=1, else=0 */
        if (strcmp(label_str, "BENIGN") == 0)
            dp.label = 1;
        else
            dp.label = 0;

        dataset[count++] = dp;
    }
    fclose(f);
    min_max_scale_fixed(dataset, count, MAX_FEATURES, params);
    return count;
}

int read_neural_to_map(const char *filename){
    FILE *fp = fopen(filename, "r");
    if(!fp){
        perror("fopen");
        return EXIT_FAILURE;
    }

    char line[256];
    int header = 1;
    fixed map[2*MAX_FEATURES + 2];
    memset(map, 0, sizeof(map));
    while (fgets(line, sizeof(line), fp)){
        if(header) {header = 0; continue;}
        int out_idx, in_idx;
        double weight;
        if(sscanf(line, "%d,%d,%lf", &out_idx, &in_idx, &weight) != 3){
            fprintf(stderr, "Invalid line: %s\n", line);
            continue;
        }
        fixed fw = fixed_from_float(weight);

        if(in_idx > 0){
            map[out_idx * MAX_FEATURES + in_idx] = fw;
        }
        else if (in_idx == -1){
            map[MAX_FEATURES * 2 + out_idx] = fw;
        }
    }
    fclose(fp);

    int map_fd = bpf_obj_get("/sys/fs/bpf/eno3/mlp_maps");
    if(map_fd < 0){
        perror("bpf_obj_get");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < MAP_SIZE; i++) {
        __u32 key = i;
        if (bpf_map_update_elem(map_fd, &key, &map[i], BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update key %u: %s\n", key, strerror(errno));
        }
    }

    printf("[INFO] Loaded MLP weights to map successfully.\n");
    return 0;
}

/*==================== MAIN ====================*/
int main(int argc, char **argv) {
    srand(time(NULL));
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd, map_fd_params, map_weight;
    int len;

    struct config cfg = {.ifindex = -1, .do_unload = false};
    const char *__doc__ = "Train RandomForest and load into XDP BPF maps\n";
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

    // Open BPF maps
    map_fd = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd < 0) return EXIT_FAIL_BPF;

    map_weight = open_bpf_map_file(pin_dir, "mlp_maps", &info);
    if (map_weight < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/mlp_maps'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    map_fd_params = open_bpf_map_file(pin_dir, "xdp_mlp_params", &info);
    if (map_weight < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_mlp_params'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    mlp_params params = {0};

    // Load dataset
    data_point dataset[TRAINING_SET];
    int data_count = read_csv_dataset1("/home/dongtv/dtuan/training_isolation/data.csv",
                                       dataset, TRAINING_SET, &params);

    for(int i = 0; i < MAX_FEATURES; i++){
        printf("MIN VALUES: %u\n", params.min_vals[i]);
        printf("MAX VALUES: %u\n", params.max_vals[i]);
    }
    if (data_count < 1) {
        fprintf(stderr, "[ERROR] Training dataset empty or invalid\n");
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d training samples\n", data_count);

    const char *weight_path = "/home/dongtv/userspace_test/model/mlp_weights.csv";
    int ret = read_neural_to_map(weight_path);
    if(ret == 0){
        printf("[INFO] Loaded neural_to_map successfully!");
    }
    __u32 key = 0;
    if (bpf_map_update_elem(map_fd_params, &key, &params, BPF_ANY) != 0) {
        fprintf(stderr, "[ERROR] Failed to update xdp_randforest_params: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Close map file descriptors
    close(map_fd);
    close(map_weight);
    close(map_fd_params);

    return EXIT_SUCCESS;
}
