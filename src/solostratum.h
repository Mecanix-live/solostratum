/*
 * solostratum.h
 *
 *  Created on: Feb 14, 2026
 *      Author: mecanix
 *      Email: mecanix@blockaxe.io
 * 		Support: https://discord.gg/QpQBCRvdcZ
 */

#ifndef SOLOSTRATUM_H_
#define SOLOSTRATUM_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <openssl/ssl.h>
#include <jansson.h>

#define LOG_INFO	0
#define LOG_WARN	1
#define LOG_ERROR	2
#define LOG_HTTP	3
#define MAX_LOG_PATH 512
#define MAX_MERKLE_BRANCHES 16

typedef struct {
    char pooltag[10];
    char poolsig[18];
    char rpc_server[256];
    char rpc_user[128];
    char rpc_pass[128];
    int job_update_interval;
    double difficulty;
    char zmq_hashblock_address[128];
    bool zmq_enabled;
    bool zmq_newhash;
    bool plaintext_enabled;
    int plaintext_port;
    bool tls_enabled;
    int tls_port;
    char tls_cert_file[256];
    char tls_key_file[256];
    char tls_ca_file[256];
    int httpd_port;

    char donation_address[128];
	double donation_percent;

} ServerConfig;

typedef struct {
    char *txid;
    char *data;
    size_t data_len;
    uint64_t fee;
    int sigops;
    int weight;
} transaction_t;

typedef struct {
    char job_id[64];
    char prev_hash[65];
    char coinb1[512];
    char coinb2[512];
    unsigned char raw_coinb1[256];
    size_t coinb1_len;
    unsigned char raw_coinb2[512];
    size_t coinb2_len;
    char merkle_root[65];
    char merkle_branch[MAX_MERKLE_BRANCHES][65];
    uint8_t merkle_count;
    uint32_t version;
    char version_str[9];
    uint32_t nbits;
    char nbits_str[9];
    uint32_t ntime;
    char ntime_str[9];
    int extranonce2_size;
    char witness_commitment[77];
} MiningJob;

typedef struct {
    char prev_hash[65];
    char prev_hash_original[65];
    uint64_t coinbase_value;
    uint32_t version;
    char version_str[9];
    uint32_t nbits;
    char nbits_str[9];
    uint32_t ntime;
    char ntime_str[9];
    uint32_t height;
    char witness_commitment[77];
    int extranonce2_size;
    time_t timestamp;
    uint32_t last_network_difficulty;
    double network_difficulty;
    size_t tx_count;
    transaction_t *transactions;
    uint8_t **tx_hashes_reversed;
} MiningJobTemplate;

typedef struct Client {
    SSL *ssl;
    bool is_tls;
    bool handshake_done;
    bool disconnect_pending;
    int socket;
    char ip[INET_ADDRSTRLEN];
    char worker_name[64];
    char address[128];
    uint8_t address_type;
    uint8_t address_hash[32];
    uint8_t address_hash_len;
    uint32_t extranonce1;
    MiningJob *job;
    bool authorized;
    double difficulty;
    bool auto_adjust_difficulty;
    time_t last_share_time;
    int share_count;
    double hashrate_history[60];
    int hashrate_index;
    struct Client *next;
} Client;

typedef struct ExtranonceEntry {
    uint32_t extranonce1;
    char address[128];
    struct ExtranonceEntry *next;
} ExtranonceEntry;

struct memory {
    char *data;
    size_t size;
};

extern MiningJobTemplate job_template;

void add_client(Client *client);
void remove_client(int sock);
Client* find_client_by_socket(int sock);
void send_response(Client *client, const char *response);
void send_job_to_client(Client *client, bool force_clean);
void* handle_client(void *arg);
void* job_update_thread(void *arg);
void* difficulty_adjustment_thread(void *arg);
void* zmq_listener_thread(void *arg);
void* http_stats_server(void *arg);
bool validate_and_decode_address(Client *client);
int compute_coinbase(MiningJob *job,
                     uint64_t coinbase_value,
                     uint32_t height,
                     const char *miner_address_hex,
                     const char *donation_address_hex,
                     float donation_percent,
                     const char *pool_tag,
                     const char *pool_sig,
                     char *coinbase_hash_le_out);
void compute_merkle_branches(json_t *transactions,
                            const char *coinbase_hash_le,
                            MiningJob *job);
bool is_blockchain_synced(void);
void fetch_block_template(void);
MiningJob* create_client_job(Client *client);
bool load_config_from_file(const char *filename);
SSL_CTX* create_stratum_ssl_context(ServerConfig *cfg);
void daemonize(const char *instance_name);
json_t* rpc_request(const char *method, json_t *params);
void log_msg(int level, const char *format, ...);
double get_hourly_average_hashrate(Client *client);

#endif /* SOLOSTRATUM_H_ */
