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

double c_factor(int n) {
    if (n <= 1) return 0.0;
    return 2.0 * (log((double)n - 1.0) + 0.5772156649) - 2.0*(n-1.0)/n;
}

void init_forest(IsolationForest *forest, __u32 n_trees, __u32 max_depth){
    if (!forest) return;
    forest->n_trees = n_trees;
    forest->max_depth = max_depth;
    forest->sample_size = 0;
    for(__u32 t = 0; t < n_trees && t < MAX_TREES; t++){
        forest->trees[t].num_nodes = 0;
        for(__u32 n = 0; n < MAX_NODE_PER_TREE; n++){
            iTreeNode *node = &forest->trees[t].nodes[n];
            node->is_leaf       = 1;
            node->left_idx      = NULL_IDX;
            node->right_idx     = NULL_IDX;
            node->feature_idx   = -1;
            node->split_value   = 0;
            node->num_points    = 0;
        }
    }
}

int build_tree(iTree *tree, data_point *points, __u32 num_points, int depth, int node_idx) {
    if (!tree || !points) return -1;
    if (node_idx < 0 || node_idx >= MAX_NODE_PER_TREE) return -1;

    iTreeNode *node = &tree->nodes[node_idx];
    /* initialize node */
    node->left_idx      = NULL_IDX;
    node->right_idx     = NULL_IDX;
    node->feature_idx   = -1;
    node->split_value   = 0;
    node->is_leaf       = 1;
    node->num_points    = (int)num_points;
    tree->num_nodes     = (tree->num_nodes > (unsigned)(node_idx+1)) ? tree->num_nodes : (node_idx+1);

    /* stop conditions */
    if (num_points <= 1 || depth >= (int)tree->max_depth) {
        node->is_leaf = 1;
        node->num_points = num_points;
        return node_idx;
    }

    /* choose random feature */
    int feat = rand() % MAX_FEATURES;
    __u32 minv = points[0].features[feat];
    __u32 maxv = minv;
    for (__u32 i = 1; i < num_points; i++) {
        if (points[i].features[feat] < minv) minv = points[i].features[feat];
        if (points[i].features[feat] > maxv) maxv = points[i].features[feat];
    }

    if (minv == maxv) {
        node->is_leaf = 1;
        node->num_points = num_points;
        return node_idx;
    }

    __u32 split = minv + (rand() % (maxv - minv + 1));
    node->is_leaf = 0;
    node->feature_idx = feat;
    node->split_value = split;

    /* partition points */
    /* Use dynamic arrays on stack sized by sample (safe because sample_size <= MAX_FLOW_SAVED) */
    data_point left[MAX_FLOW_SAVED];
    data_point right[MAX_FLOW_SAVED];
    __u32 li = 0, ri = 0;
    for (__u32 i = 0; i < num_points; i++) {
        if (points[i].features[feat] <= split) {
            if (li < MAX_FLOW_SAVED) left[li++] = points[i];
        } else {
            if (ri < MAX_FLOW_SAVED) right[ri++] = points[i];
        }
    }

    /* left subtree at node_idx + 1 */
    int left_idx = node_idx + 1;
    if (left_idx >= MAX_NODE_PER_TREE) {
        /* cannot allocate subtree -> make leaf */
        node->is_leaf = 1;
        node->num_points = num_points;
        node->left_idx = NULL_IDX;
        node->right_idx = NULL_IDX;
        return node_idx;
    }

    int last_left = build_tree(tree, left, li, depth + 1, left_idx);
    if (last_left < 0) {
        /* failed to build left -> make leaf */
        node->is_leaf = 1;
        node->num_points = num_points;
        node->left_idx = NULL_IDX;
        node->right_idx = NULL_IDX;
        return node_idx;
    }
    node->left_idx = left_idx;

    /* right subtree starts after last_left */
    int right_start = last_left + 1;
    if (right_start >= MAX_NODE_PER_TREE) {
        /* cannot allocate right -> set right NULL */
        node->right_idx = NULL_IDX;
        tree->num_nodes = (tree->num_nodes > (unsigned)(last_left+1)) ? tree->num_nodes : (last_left+1);
        return last_left; /* last used index is last_left */
    }

    int last_right = build_tree(tree, right, ri, depth + 1, right_start);
    if (last_right < 0) {
        /* no right subtree */
        node->right_idx = NULL_IDX;
        return last_left;
    }
    node->right_idx = right_start;

    /* update tree->num_nodes */
    tree->num_nodes = (tree->num_nodes > (unsigned)(last_right+1)) ? tree->num_nodes : (last_right+1);
    node->num_points = num_points;

    return last_right;
}

void train_isolation_tree(iTree *tree, data_point *dataset, __u32 num_points, __u32 max_depth) {
    if (!tree) return;
    tree->num_nodes = 0;
    tree->max_depth = max_depth;
    for (int i = 0; i < MAX_NODE_PER_TREE; i++) {
        tree->nodes[i].is_leaf = 1;
        tree->nodes[i].left_idx = NULL_IDX;
        tree->nodes[i].right_idx = NULL_IDX;
        tree->nodes[i].feature_idx = -1;
        tree->nodes[i].split_value = 0;
        tree->nodes[i].num_points = 0;
    }

    /* build tree at index 0 */
    int last = build_tree(tree, dataset, num_points, 0, 0);
    if (last < 0) {
        fprintf(stderr, "[WARN] build_tree returned error\n");
        tree->num_nodes = 0;
    }
}

void bootstrap_sample(data_point *dataset, __u32 num_points, __u32 sample_size, data_point *sample) {
    if (!dataset || !sample || num_points == 0) return;
    if (sample_size > MAX_FLOW_SAVED) sample_size = MAX_FLOW_SAVED; /* safety */
    for (__u32 i = 0; i < sample_size; i++) {
        __u32 idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
}

void train_isolation_forest(IsolationForest *forest, data_point *dataset, int num_points, struct forest_params *params) {
    if (!forest || !dataset || !params) return;

    forest->n_trees = params->n_trees;
    forest->max_depth = params->max_depth;
    forest->sample_size = params->sample_size;
    printf("[INFO] Training %u trees with max_depth=%u, sample_size=%u\n",
           params->n_trees, params->max_depth, params->sample_size);

    __u32 sample_size = params->sample_size;
    if (sample_size > MAX_FLOW_SAVED) sample_size = MAX_FLOW_SAVED;
    if (sample_size == 0) sample_size = (num_points > 0) ? ( (__u32) num_points ) : 1;
    if (sample_size > (unsigned)num_points) sample_size = (unsigned)num_points;

    for (__u32 t = 0; t < params->n_trees && t < MAX_TREES; t++) {
        printf("Training tree %u/%u...\n", t + 1, params->n_trees);
        data_point sample[MAX_FLOW_SAVED];
        memset(sample, 0, sizeof(sample));
        bootstrap_sample(dataset, (unsigned)num_points, sample_size, sample);
        train_isolation_tree(&forest->trees[t], sample, sample_size, params->max_depth);
        printf("Tree %u: %u nodes\n", t, forest->trees[t].num_nodes);
    }
}

int save_forest_to_map(int map_fd_nodes, int map_fd_c, int map_fd_params, IsolationForest *forest, struct forest_params *params) {
    if (!forest || map_fd_nodes < 0) return -1;

    int total_nodes = 0;
    for (__u32 t = 0; t < forest->n_trees && t < MAX_TREES; t++) {
        iTree *tree = &forest->trees[t];
        for (int n = 0; n < (int)tree->num_nodes && n < MAX_NODE_PER_TREE; n++) {
            __u32 key = t * MAX_NODE_PER_TREE + (unsigned)n;
            iTreeNode node = tree->nodes[n]; /* copy */
            if (bpf_map_update_elem(map_fd_nodes, &key, &node, BPF_ANY) != 0) {
                fprintf(stderr, "[ERROR] Failed to update node %u: %s\n", key, strerror(errno));
                return -1;
            }
            total_nodes++;
        }
    }
    printf("[INFO] Saved %d nodes to map\n", total_nodes);

    /* populate c(n) map if provided */
    if (map_fd_c >= 0) {
        for (__u32 n = 0; n <= (unsigned)TRAINING_SET; n++) {
            double c = c_factor((int)n);
            __u32 scaled = (__u32)(c * SCALE);
            if (bpf_map_update_elem(map_fd_c, &n, &scaled, BPF_ANY) != 0) {
                fprintf(stderr, "[WARN] Failed to update c(%u): %s\n", n, strerror(errno));
                /* continue attempting others */
            }
        }
        printf("[INFO] Populated xdp_isoforest_c map (0..%d)\n", TRAINING_SET);
    }

    /* save params map if provided */
    if (map_fd_params >= 0 && params) {
        __u32 k0 = 0;
        if (bpf_map_update_elem(map_fd_params, &k0, params, BPF_ANY) != 0) {
            fprintf(stderr, "[ERROR] Failed to update params map: %s\n", strerror(errno));
            return -1;
        }
        printf("[INFO] Saved forest params to map\n");
    }

    return 0;
}

/*==================== Path length & Anomaly ====================*/
int path_length_point(iTreeNode *nodes, int node_idx, data_point *dp) {
    int length = 0;
    if (!nodes || node_idx < 0) return 0;
    while (node_idx != NULL_IDX && node_idx < MAX_NODE_PER_TREE) {
        iTreeNode *node = &nodes[node_idx];
        if (node->is_leaf) return length + (int)round(c_factor(node->num_points));
        __u32 feat = (node->feature_idx >= 0 && node->feature_idx < MAX_FEATURES) ? node->feature_idx : 0;
        __u32 f_val = dp->features[feat];
        if (f_val <= node->split_value) node_idx = node->left_idx;
        else node_idx = node->right_idx;
        length++;
        if (length > MAX_NODE_PER_TREE) break;
    }
    return length;
}

static inline int is_anomaly_by_depth(IsolationForest *forest, data_point *dp, struct forest_params *params)
{
    if (!forest || !dp || !params) return 0;

    double sum_path = 0.0;
    for (__u32 t = 0; t < forest->n_trees; t++) {
        sum_path += (double)path_length_point(forest->trees[t].nodes, 0, dp);
    }

    double avg_path = sum_path / (double)forest->n_trees;
    double c_n = c_factor((int)params->sample_size);
    return (avg_path * c_n >= (double)params->threshold / SCALE) ? 1 : 0;
}

double anomaly_score_point(IsolationForest *forest, data_point *dp, __u32 sample_size) {
    if (!forest || forest->n_trees == 0) return 0.0;
    double sum_path = 0.0;
    for (__u32 t = 0; t < forest->n_trees; t++) {
        sum_path += (double)path_length_point(forest->trees[t].nodes, 0, dp);
    }
    double avg_path = sum_path / (double)forest->n_trees;
    double c_n = c_factor((int)sample_size);
    if (c_n <= 0.0) return 0.0;
    return pow(2.0, -avg_path / c_n);
}

// int is_anomaly(double score, struct forest_params *params) {
//     int path_len = path_length_point(...);
//         return (path_len >= params->threshold); // threshold là depth   
// }

/*==================== Testing helper ====================*/
void test_forest_accuracy(IsolationForest *forest, data_point *test_data, int test_count, struct forest_params *params) {
    if (!forest || !test_data || test_count <= 0 || !params) return;

    int correct = 0;
    for (int i = 0; i < test_count; i++) {
        int pred = is_anomaly_by_depth(forest, &test_data[i], params);
        int actual = (test_data[i].label != 0) ? 1 : 0;
        if (pred == actual) correct++;

        if (i < 10) {
            double avg_path = 0.0;
            for (__u32 t = 0; t < forest->n_trees; t++) {
                avg_path += (double)path_length_point(forest->trees[t].nodes, 0, &test_data[i]);
            }
            avg_path /= forest->n_trees;
            printf("Test %d: avg_path=%.2f pred=%d actual=%d\n", i, avg_path, pred, actual);
        }
    }

    printf("[INFO] Accuracy: %d/%d = %.2f%%\n", correct, test_count, (double)correct / test_count * 100.0);
}



int cmp_double_desc(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return 1;
    else if (da > db) return -1;
    else return 0;
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

    /* Load dataset */
    data_point train_dataset[TRAINING_SET];
    int train_count = read_csv_dataset("/home/dongtv/dtuan/training_isolation/processed/train_portmap_data.csv",
                                       train_dataset, TRAINING_SET);
    if (train_count < 1) {
        fprintf(stderr, "[ERROR] Training dataset empty or invalid\n");
        close(map_fd_nodes);
        close(map_fd_params);
        close(map_fd_c);
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d training samples\n", train_count);

    /* Load test data */
    data_point test_dataset[MAX_TEST];
    int test_count = read_csv_dataset("/home/dongtv/dtuan/training_isolation/processed/test_portmap_data.csv",
                                       test_dataset, MAX_TEST);
    if (test_count < 1) {
        fprintf(stderr, "[ERROR] Testing dataset empty or invalid\n");
        close(map_fd_nodes);
        close(map_fd_params);
        close(map_fd_c);
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d testing samples\n", test_count);

    /* Initialize forest */
    IsolationForest forest;
    init_forest(&forest, MAX_TREES, MAX_DEPTH);

    struct forest_params params;
    memset(&params, 0, sizeof(params));
    params.n_trees = MAX_TREES;
    params.sample_size = MAX_SAMPLE_PER_NODE;
    params.max_depth = MAX_DEPTH;
    params.contamination = CONTAMINATION;

    /* Train */
    printf("[INFO] Starting Isolation Forest training...\n");
    train_isolation_forest(&forest, train_dataset, train_count, &params);
    printf("[INFO] Isolation Forest trained with %u trees\n", forest.n_trees);
    /* Compute anomaly scores for training set */
    double *scores = malloc(train_count * sizeof(double));
    for (int i = 0; i < train_count; i++) {
        scores[i] = anomaly_score_point(&forest, &train_dataset[i], params.sample_size);
    }

    double max_score = 0.0;
    for (int i = 0; i < train_count; i++) {
        double score = anomaly_score_point(&forest, &train_dataset[i], params.sample_size);
        if (score > max_score) max_score = score;
    }
    /* Sort scores */
    qsort(scores, train_count, sizeof(double), cmp_double_desc);

    /* Select threshold based on contamination */
    int threshold_index = (int)((1.0 - (double)params.contamination/SCALE) * train_count);
    if (threshold_index >= train_count) threshold_index = train_count - 1;
    if (threshold_index < 0) threshold_index = 0;

    double threshold_score = scores[threshold_index];

    /* Convert score threshold -> depth threshold */
    double c_n = c_factor(params.sample_size);
    double depth_threshold = -log2(threshold_score) * c_n;

    params.threshold = (__u32)(depth_threshold * SCALE);
    /* Save to maps (nodes + c(n) + params) */
    if (save_forest_to_map(map_fd_nodes, map_fd_c, map_fd_params, &forest, &params) != 0) {
        fprintf(stderr, "[ERROR] Failed to save forest to maps\n");
        close(map_fd_nodes);
        close(map_fd_c);
        close(map_fd_params);
        return EXIT_FAILURE;
    }
    test_forest_accuracy(&forest, test_dataset, test_count, &params);

    printf("[INFO] Successfully updated BPF maps\n");
    printf("[INFO] Forest params: n_trees=%u, max_depth=%u, sample_size=%u, threshold=%u\n",
           params.n_trees, params.max_depth, params.sample_size, params.threshold);

    close(map_fd_nodes);
    close(map_fd_c);
    close(map_fd_params);
    return EXIT_SUCCESS;
}