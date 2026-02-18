/*
 * solostratum.c
 *
 *  Created on: Feb 14, 2026
 *      Author: mecanix
 *      Email: mecanix@blockaxe.io
 * 		Support: https://discord.gg/QpQBCRvdcZ
 */

#include "solostratum.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <sys/epoll.h>
#include <signal.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <pthread.h>
#include <zmq.h>
#include "stats.h"

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

int g_daemon_mode = 0;
FILE *log_file = NULL;
char log_path[MAX_LOG_PATH] = {0};

#define RX_BUFFER_SIZE 8192
ServerConfig servercfg;
Client *connected_clients = NULL;
MiningJobTemplate job_template;
pthread_mutex_t template_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t extranonce_mutex = PTHREAD_MUTEX_INITIALIZER;
ExtranonceEntry *used_extranonces = NULL;
SSL_CTX *global_ssl_ctx = NULL;

const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
const double pow2_192 = 6277101735386680763835789423207666416102355444464034512896.0;
const double pow2_128 = 340282366920938463463374607431768211456.0;
const double pow2_64  = 18446744073709551616.0;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
static void hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
static void bin2hex(const unsigned char *bin, size_t len, char *out);
static double le256todouble(const void *restrict target);
static void hex_8byte_chunk_reverse(const char *input, char *output);
static void double_sha256(const uint8_t *data, size_t len, uint8_t *hash);
static SSL* create_client_ssl(int fd);
static int tls_handshake(SSL *ssl);
static void record_extranonce_usage(uint32_t extranonce1, const char *address);
static uint32_t generate_unique_extranonce1(void);
static void handle_configure(Client *client, json_t *request);
static void handle_subscribe(Client *client, json_t *request);
static void handle_authorize(Client *client, json_t *request);
static void handle_suggest_difficulty(Client *client, json_t *request);
static void handle_extranonce_subscribe(Client *client, json_t *request);
static void handle_submit(Client *client, json_t *request);
static void calculate_and_log_hashrate(Client *client);
static void adjust_client_difficulty(Client *client);

static EVP_MD_CTX *g_sha256_ctx = NULL;
static pthread_mutex_t sha256_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        log_msg(LOG_ERROR, "realloc failed for %zu bytes!", mem->size + realsize + 1);
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';
    return realsize;
}

static const uint8_t HEX_TO_NIBBLE[256] = {
    ['0']=0, ['1']=1, ['2']=2, ['3']=3, ['4']=4, ['5']=5, ['6']=6, ['7']=7,
    ['8']=8, ['9']=9, ['a']=10, ['b']=11, ['c']=12, ['d']=13, ['e']=14, ['f']=15,
    ['A']=10, ['B']=11, ['C']=12, ['D']=13, ['E']=14, ['F']=15
};

static const char NIBBLE_TO_HEX[16] = {
    '0','1','2','3','4','5','6','7',
    '8','9','a','b','c','d','e','f'
};

static void hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++) {
        uint8_t high = HEX_TO_NIBBLE[(uint8_t)hex[i * 2]];
        uint8_t low = HEX_TO_NIBBLE[(uint8_t)hex[i * 2 + 1]];
        bin[i] = (uint8_t)((high << 4) | low);
    }
}

static void bin2hex(const unsigned char *bin, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = NIBBLE_TO_HEX[bin[i] >> 4];
        out[i * 2 + 1] = NIBBLE_TO_HEX[bin[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static double le256todouble(const void *restrict target) {

	const uint8_t *t = target;
	uint64_t chunk;

	memcpy(&chunk, t + 24, 8);
	double result = (double)chunk * pow2_192;
	memcpy(&chunk, t + 16, 8);
	result += (double)chunk * pow2_128;
	memcpy(&chunk, t + 8, 8);
	result += (double)chunk * pow2_64;
	memcpy(&chunk, t, 8);
	result += (double)chunk;

	return result;
}

static void hex_8byte_chunk_reverse(const char *input, char *output) {
    if (strlen(input) != 64) return;

    for (int chunk = 0; chunk < 8; chunk++) {
        int chunk_start = chunk * 8;

        for (int byte = 0; byte < 4; byte++) {
            int src_pos = chunk_start + (3 - byte) * 2;
            int dst_pos = chunk_start + byte * 2;

            output[dst_pos] = input[src_pos];
            output[dst_pos + 1] = input[src_pos + 1];
        }
    }
    output[64] = '\0';
}

static void double_sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    pthread_mutex_lock(&sha256_mutex);

    if (unlikely(!g_sha256_ctx)) {
        g_sha256_ctx = EVP_MD_CTX_new();
    }

    if (likely(g_sha256_ctx)) {
        unsigned int tmp_len;
        uint8_t tmp[EVP_MAX_MD_SIZE];

        EVP_DigestInit_ex(g_sha256_ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(g_sha256_ctx, data, len);
        EVP_DigestFinal_ex(g_sha256_ctx, tmp, &tmp_len);

        EVP_DigestInit_ex(g_sha256_ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(g_sha256_ctx, tmp, tmp_len);
        EVP_DigestFinal_ex(g_sha256_ctx, hash, &tmp_len);
    }

    pthread_mutex_unlock(&sha256_mutex);
}

json_t* rpc_request(const char *method, json_t *params) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        log_msg(LOG_ERROR, "Failed to initialize CURL");
        return NULL;
    }

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("stratum"));
    json_object_set_new(request, "method", json_string(method));
    json_object_set_new(request, "params", params);

    char *request_json = json_dumps(request, JSON_COMPACT);
    json_decref(request);

    if (!request_json) {
        log_msg(LOG_ERROR, "Failed to serialize JSON request");
        curl_easy_cleanup(curl);
        return NULL;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char credentials[256];
    snprintf(credentials, sizeof(credentials), "%s:%s",
             servercfg.rpc_user, servercfg.rpc_pass);

    struct memory chunk = {NULL, 0};

    curl_easy_setopt(curl, CURLOPT_URL, servercfg.rpc_server);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json);
    curl_easy_setopt(curl, CURLOPT_USERPWD, credentials);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    free(request_json);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        log_msg(LOG_ERROR, "RPC failed (%s): %s", method, curl_easy_strerror(res));
        if (chunk.data) free(chunk.data);
        curl_easy_cleanup(curl);
        return NULL;
    }

    json_error_t error;
    json_t *result = json_loads(chunk.data, 0, &error);
    if (!result) {
        log_msg(LOG_ERROR, "JSON parse error for %s: %s", method, error.text);
        log_msg(LOG_ERROR, "Raw response: %s", chunk.data);
    }

    //printf("RPC response for %s: %s (%zu bytes)\n", method, chunk.data, chunk.size);

    free(chunk.data);
    curl_easy_cleanup(curl);
    return result;
}

Client* find_client_by_socket(int sock) {
    pthread_mutex_lock(&clients_mutex);
    Client *client = connected_clients;
    while (client) {
        if (client->socket == sock) {
            pthread_mutex_unlock(&clients_mutex);
            return client;
        }
        client = client->next;
    }
    pthread_mutex_unlock(&clients_mutex);
    return NULL;
}

void add_client(Client *client) {
    pthread_mutex_lock(&clients_mutex);
    client->next = connected_clients;
    connected_clients = client;
    pthread_mutex_unlock(&clients_mutex);
}

void remove_client(int sock) {
    pthread_mutex_lock(&clients_mutex);
    Client **ptr = &connected_clients;

    while (*ptr) {
        if ((*ptr)->socket == sock) {
            Client *to_remove = *ptr;
            *ptr = to_remove->next;

            if (to_remove && to_remove->authorized) {
                to_remove->disconnect_pending = true;

                // Update Stats
                stats_worker_disconnect(to_remove);
            }

            // Remove from extranonce tracking
            pthread_mutex_lock(&extranonce_mutex);
            ExtranonceEntry **eptr = &used_extranonces;
            while (*eptr) {
                if ((*eptr)->extranonce1 == to_remove->extranonce1) {
                    ExtranonceEntry *to_free = *eptr;
                    *eptr = to_free->next;
                    free(to_free);
                    break;
                }
                eptr = &(*eptr)->next;
            }
            pthread_mutex_unlock(&extranonce_mutex);

            // Clean TLS
            if (servercfg.tls_enabled && to_remove->ssl) {
                SSL_shutdown(to_remove->ssl);
                SSL_free(to_remove->ssl);
            }

            if (to_remove->job) {
                free(to_remove->job);
            }

            close(to_remove->socket);
            free(to_remove);
            break;
        }
        ptr = &(*ptr)->next;
    }

    pthread_mutex_unlock(&clients_mutex);
}

bool validate_and_decode_address(Client *client) {
    const char *address = client->address;

    json_t *params = json_array();
    json_array_append_new(params, json_string(address));

    json_t *result = rpc_request("validateaddress", params);

    if (!result) {
        log_msg(LOG_ERROR, "RPC call failed for address validation: %s", address);
        return false;
    }

    json_t *error = json_object_get(result, "error");
    if (error && !json_is_null(error)) {
        const char *error_msg = json_string_value(json_object_get(error, "message"));
        log_msg(LOG_ERROR, "Address validation RPC error: %s", error_msg ? error_msg : "Unknown error");
        json_decref(result);
        return false;
    }

    json_t *validation_result = json_object_get(result, "result");
    if (!validation_result) {
        log_msg(LOG_ERROR, "No result in validateaddress response");
        json_decref(result);
        return false;
    }

    json_t *isvalid = json_object_get(validation_result, "isvalid");
    if (!isvalid || !json_is_true(isvalid)) {
        log_msg(LOG_ERROR, "Invalid wallet address: %s", address);
        json_decref(result);
        return false;
    }

    // Get scriptPubKey (hash in hex)
    json_t *scriptPubKey = json_object_get(validation_result, "scriptPubKey");
    if (!scriptPubKey || !json_is_string(scriptPubKey)) {
        log_msg(LOG_ERROR, "No scriptPubKey in validation result for address: %s", address);
        json_decref(result);
        return false;
    }

    const char *scriptPubKey_hex = json_string_value(scriptPubKey);
    size_t script_len = strlen(scriptPubKey_hex);
    //printf("scriptPubKey for %s: %s (len: %zu)\n", address, scriptPubKey_hex, script_len);

    // Determine address type and extract hash
    json_t *iswitness = json_object_get(validation_result, "iswitness");

    if (iswitness && json_is_true(iswitness)) {
        // SegWit address (P2WPKH or P2WSH)
        json_t *witness_program = json_object_get(validation_result, "witness_program");

        if (!witness_program || !json_is_string(witness_program)) {
            log_msg(LOG_ERROR, "No witness_program for SegWit address: %s", address);
            json_decref(result);
            return false;
        }

        const char *witness_program_hex = json_string_value(witness_program);
        size_t program_len = strlen(witness_program_hex) / 2;

        if (program_len != 20 && program_len != 32) {
            log_msg(LOG_ERROR, "Invalid witness program length %zu for address: %s", program_len, address);
            json_decref(result);
            return false;
        }

        // Store the witness program hash (20 bytes for P2WPKH, 32 bytes for P2WSH)
        hex2bin(witness_program_hex, client->address_hash, program_len);
        client->address_hash_len = (uint8_t)program_len;
        client->address_type = 2;  // SegWit

        //printf("Validated SegWit address %s -> witness_version: %lld, program: %s (%zu bytes)\n",
        //       address,
        //       witness_version ? json_integer_value(witness_version) : 0,
        //       witness_program_hex,
        //       program_len);

    } else {
        // Legacy P2PKH address
        if (script_len == 50 && strncmp(scriptPubKey_hex, "76a914", 6) == 0) {
            // Extract the 20-byte hash160 (40 hex chars) from middle
            const char *hash160_hex = scriptPubKey_hex + 6;  // Skip "76a914"

            hex2bin(hash160_hex, client->address_hash, 20);
            client->address_hash_len = 20;
            client->address_type = 1;  // P2PKH
            //printf("Validated P2PKH address %s -> hash160: %s\n", address, hash160_hex);

        } else {
            // Check for P2SH (not typically used for mining, but handle it)
            if (script_len == 46 && strncmp(scriptPubKey_hex, "a914", 4) == 0) {
                log_msg(LOG_WARN, "P2SH address %s detected (not typically used for mining)", address);
                // Extract the 20-byte hash160
                const char *hash160_hex = scriptPubKey_hex + 4;
                hex2bin(hash160_hex, client->address_hash, 20);
                client->address_hash_len = 20;
                client->address_type = 3;  // P2SH
            } else {
                log_msg(LOG_ERROR, "Unsupported address type for %s (scriptPubKey: %s)", address, scriptPubKey_hex);
                json_decref(result);
                return false;
            }
        }
    }

    json_decref(result);
    return true;
}

int compute_coinbase(MiningJob *job,
                     uint64_t coinbase_value,
                     uint32_t height,
                     const char *miner_address_hex,
                     const char *donation_address_hex,
                     float donation_percent,
                     const char *pool_tag,
                     const char *pool_sig,
                     char *coinbase_hash_le_out) {

    // Convert miner address
    uint8_t miner_addr[20];
    hex2bin(miner_address_hex, miner_addr, 20);

    // Convert donation address
    uint8_t donation_addr[20];
    int has_donation = (donation_address_hex != NULL && donation_percent > 0);
    if (has_donation) {
        hex2bin(donation_address_hex, donation_addr, 20);
    }

    // Calculate donation amounts
    uint64_t donation_amount = 0;
    uint64_t miner_amount = coinbase_value;
    if (has_donation) {
        donation_amount = (uint64_t)((double)coinbase_value * (double)donation_percent / 100.0);
        miner_amount = coinbase_value - donation_amount;
    }

    // Get pool tag and signature lengths
    size_t pool_tag_len = (pool_tag != NULL) ? strlen(pool_tag) : 0;
    size_t pool_sig_len = (pool_sig != NULL) ? strlen(pool_sig) : 0;

    // Check if pool_sig already has slashes
    int add_slashes_to_sig = 0;
    if (pool_sig_len > 0) {
        if (pool_sig[0] != '/' || pool_sig[pool_sig_len-1] != '/') {
            add_slashes_to_sig = 1;
        }
    }

    // Build the transaction byte by byte
    uint8_t buffer[1024];
    size_t offset = 0;

    // Transaction header
    buffer[offset++] = 0x02;  // Version
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;

    buffer[offset++] = 0x01;  // Input count

    // Previous hash (32 zeros for coinbase)
    memset(buffer + offset, 0, 32);
    offset += 32;

    // Previous index
    buffer[offset++] = 0xFF;
    buffer[offset++] = 0xFF;
    buffer[offset++] = 0xFF;
    buffer[offset++] = 0xFF;

    // ScriptSig length - placeholder
    size_t scriptsig_len_pos = offset;
    buffer[offset++] = 0x00; // Will update later

    // ScriptSig content

    // Height encoding - Bitcoin's CScriptNum serialization (little-endian)
    if (height <= 0x7F) {
        buffer[offset++] = 0x01;
        buffer[offset++] = height & 0xFF;
    }
    else if (height <= 0x7FFF) {
        buffer[offset++] = 0x02;
        buffer[offset++] = height & 0xFF;
        buffer[offset++] = (height >> 8) & 0xFF;
    }
    else if (height <= 0x7FFFFF) {
        buffer[offset++] = 0x03;
        buffer[offset++] = height & 0xFF;
        buffer[offset++] = (height >> 8) & 0xFF;
        buffer[offset++] = (height >> 16) & 0xFF;
    }
    else {
        buffer[offset++] = 0x04;
        buffer[offset++] = (uint8_t)(height & 0xFF);
        buffer[offset++] = (uint8_t)((height >> 8) & 0xFF);
        buffer[offset++] = (uint8_t)((height >> 16) & 0xFF);
        buffer[offset++] = (uint8_t)((height >> 24) & 0xFF);
    }

    // Extranonce1 marker
    buffer[offset++] = 0x04;

    // Save position where coinb1 ends (BEFORE actual extranonce1 value)
    size_t coinb1_end = offset;

    // Continue ScriptSig after coinb1 split point;

    // Pool tag (if any)
    if (pool_tag_len > 0) {
        // Simple push if <= 75 bytes
        if (pool_tag_len <= 75) {
            buffer[offset++] = (uint8_t)pool_tag_len;
        } else if (pool_tag_len <= 255) {
            buffer[offset++] = 0x4c;  // OP_PUSHDATA1
            buffer[offset++] = (uint8_t)pool_tag_len;
        }

        memcpy(buffer + offset, pool_tag, pool_tag_len);
        offset += pool_tag_len;
    }

    // Pool signature (if any)
    if (pool_sig_len > 0) {
        size_t total_sig_len = pool_sig_len;
        if (add_slashes_to_sig) {
            total_sig_len += 2; // Add 2 for slashes
        }

        // Simple push if <= 75 bytes
        if (total_sig_len <= 75) {
            buffer[offset++] = (uint8_t)total_sig_len;
        } else if (total_sig_len <= 255) {
            buffer[offset++] = 0x4c;  // OP_PUSHDATA1
            buffer[offset++] = (uint8_t)total_sig_len;
        }

        // Add slashes if needed
        if (add_slashes_to_sig) {
            buffer[offset++] = '/';
            memcpy(buffer + offset, pool_sig, pool_sig_len);
            offset += pool_sig_len;
            buffer[offset++] = '/';
        } else {
            memcpy(buffer + offset, pool_sig, pool_sig_len);
            offset += pool_sig_len;
        }
    }

    // Sequence
    buffer[offset++] = 0xFF;
    buffer[offset++] = 0xFF;
    buffer[offset++] = 0xFF;
    buffer[offset++] = 0xFF;

    // Outputs;

    // Output count
    if (has_donation) {
        buffer[offset++] = 0x03;  // miner + donation + witness commitment
    } else {
        buffer[offset++] = 0x02;  // miner + witness commitment
    }

    // Output 1: Miner reward
    for (int i = 0; i < 8; i++) {
        buffer[offset++] = (miner_amount >> (i * 8)) & 0xFF;
    }

    buffer[offset++] = 0x16;  // Script length (22 bytes)
    buffer[offset++] = 0x00;  // OP_0
    buffer[offset++] = 0x14;  // OP_PUSH20

    memcpy(buffer + offset, miner_addr, 20);
    offset += 20;

    // Output 2: Donation (if any)
    if (has_donation) {
        for (int i = 0; i < 8; i++) {
            buffer[offset++] = (donation_amount >> (i * 8)) & 0xFF;
        }

        buffer[offset++] = 0x16;  // Script length (22 bytes)
        buffer[offset++] = 0x00;  // OP_0
        buffer[offset++] = 0x14;  // OP_PUSH20

        memcpy(buffer + offset, donation_addr, 20);
        offset += 20;
    }

    // Output 3: Witness Commitment
    memset(buffer + offset, 0, 8);
    offset += 8;

    uint8_t witness_commitment_bin[38];
    hex2bin(job->witness_commitment, witness_commitment_bin, 38);
    buffer[offset++] = 38;  // Length

    memcpy(buffer + offset, witness_commitment_bin, 38);
    offset += 38;

    // Locktime
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;

    // Calculate ScriptSig length;

    // Start counting from height bytes (excluding the ScriptSig length byte itself)
    size_t actual_scriptsig_len = 0;

    // Height encoding bytes (including the length byte)
    if (height <= 0x7F) {
        actual_scriptsig_len += 2; // 0x01 + 1 byte height
    } else if (height <= 0x7FFF) {
        actual_scriptsig_len += 3; // 0x02 + 2 bytes height
    } else if (height <= 0x7FFFFF) {
        actual_scriptsig_len += 4; // 0x03 + 3 bytes height
    } else {
        actual_scriptsig_len += 5; // 0x04 + 4 bytes height
    }

    // Extranonce1 marker: 1 byte (0x04)
    actual_scriptsig_len += 1;

    // Extranonce1: 4 bytes (from job)
    actual_scriptsig_len += 4;

    // Extranonce2: job->extranonce2_size bytes
    actual_scriptsig_len += (size_t)job->extranonce2_size;

    // Pool tag
    if (pool_tag_len > 0) {
        if (pool_tag_len <= 75) {
            actual_scriptsig_len += 1 + pool_tag_len;
        } else if (pool_tag_len <= 255) {
            actual_scriptsig_len += 2 + pool_tag_len;
        }
    }

    // Pool signature
    if (pool_sig_len > 0) {
        size_t total_sig_len = pool_sig_len;
        if (add_slashes_to_sig) {
            total_sig_len += 2;
        }

        if (total_sig_len <= 75) {
            actual_scriptsig_len += 1 + total_sig_len;
        } else if (total_sig_len <= 255) {
            actual_scriptsig_len += 2 + total_sig_len;
        }
    }

    // For stratum protocol, we use the actual length (≤ 255 for single byte)
    if (actual_scriptsig_len > 255) {
        // might need to cap it
        buffer[scriptsig_len_pos] = 255;
    } else {
        buffer[scriptsig_len_pos] = (uint8_t)actual_scriptsig_len;
    }

    // Split into coinb1 and coinb2 for stratum
    job->coinb1_len = coinb1_end;
    memcpy(job->raw_coinb1, buffer, coinb1_end);
    bin2hex(job->raw_coinb1, job->coinb1_len, job->coinb1);

    job->coinb2_len = offset - coinb1_end;
    memcpy(job->raw_coinb2, buffer + coinb1_end, job->coinb2_len);
    bin2hex(job->raw_coinb2, job->coinb2_len, job->coinb2);

    // Build full coinbase for merkle calculation
    uint8_t full_coinbase[1024];
    size_t full_offset = 0;

    // Copy everything up to ScriptSig length
    memcpy(full_coinbase, buffer, scriptsig_len_pos);
    full_offset = scriptsig_len_pos;

    // Write actual ScriptSig length (for hash calculation)
    if (actual_scriptsig_len <= 252) {
        full_coinbase[full_offset++] = (uint8_t)actual_scriptsig_len;
    } else if (actual_scriptsig_len <= 0xFFFF) {
        full_coinbase[full_offset++] = 0xFD;
        full_coinbase[full_offset++] = actual_scriptsig_len & 0xFF;
        full_coinbase[full_offset++] = (actual_scriptsig_len >> 8) & 0xFF;
    } else {
        full_coinbase[full_offset++] = 0xFE;
        for (int i = 0; i < 4; i++) {
            full_coinbase[full_offset++] = (actual_scriptsig_len >> (i * 8)) & 0xFF;
        }
    }

    // Copy height bytes
    size_t height_bytes_start = scriptsig_len_pos + 1;
    size_t height_bytes_len = 0;
    if (height <= 0x7F) {
        height_bytes_len = 2;  // 0x01 + 1 byte
    } else if (height <= 0x7FFF) {
        height_bytes_len = 3;  // 0x02 + 2 bytes
    } else if (height <= 0x7FFFFF) {
        height_bytes_len = 4;  // 0x03 + 3 bytes
    } else {
        height_bytes_len = 5;  // 0x04 + 4 bytes
    }

    memcpy(full_coinbase + full_offset, buffer + height_bytes_start, height_bytes_len);
    full_offset += height_bytes_len;

    // Extranonce1 marker
    full_coinbase[full_offset++] = 0x04;

    // Extranonce1 placeholder (from job or zeros)
    memset(full_coinbase + full_offset, 0, 4);
    full_offset += 4;

    // Extranonce2 placeholder
    memset(full_coinbase + full_offset, 0, (size_t)job->extranonce2_size);
    full_offset += (size_t)job->extranonce2_size;

    // Copy the rest (pool data, outputs, etc.)
    memcpy(full_coinbase + full_offset, buffer + coinb1_end, job->coinb2_len);
    full_offset += job->coinb2_len;

    // Hash calculation
    uint8_t coinbase_hash[SHA256_DIGEST_LENGTH];
    double_sha256(full_coinbase, full_offset, coinbase_hash);

    uint8_t coinbase_hash_le[SHA256_DIGEST_LENGTH];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        coinbase_hash_le[i] = coinbase_hash[SHA256_DIGEST_LENGTH - 1 - i];
    }

    bin2hex(coinbase_hash_le, SHA256_DIGEST_LENGTH, coinbase_hash_le_out);

    return 0;
}

void compute_merkle_branches(json_t *transactions,
                            const char *coinbase_hash_le,
                            MiningJob *job) {

    size_t tx_count = json_array_size(transactions);

    if (tx_count == 0) {
        job->merkle_count = 0;
        memset(job->merkle_root, 0, sizeof(job->merkle_root));
        return;
    }

    // Dynamic allocation based on actual tx count + coinbase
    size_t max_hashes = tx_count + 1;
    unsigned char (*hashes)[32] = malloc(max_hashes * sizeof(*hashes));
    if (!hashes) {
        job->merkle_count = 0;
        return;
    }

    int hash_count = 0;

    // Add coinbase hash (already little-endian)
    hex2bin(coinbase_hash_le, hashes[hash_count], 32);
    hash_count++;

    // Add transaction hashes REVERSED
    for (size_t i = 0; i < tx_count; i++) {
        json_t *tx = json_array_get(transactions, i);
        const char *txid = json_string_value(json_object_get(tx, "txid"));

        if (!txid || strlen(txid) != 64) continue;

        // Reverse bytes directly into hash array
        hex2bin(txid, hashes[hash_count], 32);

        // Reverse in place
        for (int j = 0; j < 16; j++) {
            uint8_t temp = hashes[hash_count][j];
            hashes[hash_count][j] = hashes[hash_count][31 - j];
            hashes[hash_count][31 - j] = temp;
        }
        hash_count++;
    }

    job->merkle_count = 0;
    int index = 0; // Coinbase position

    unsigned char (*current)[32] = hashes;
    int current_count = hash_count;
    unsigned char (*next)[32] = NULL;

    // Flag to track if we need to free current at the end
    int current_is_allocated = 0;  // 0 = points to hashes, 1 = allocated separately

    while (current_count > 1 && job->merkle_count < MAX_MERKLE_BRANCHES) {
        // Duplicate last if odd
        if (current_count % 2 == 1) {
            // Create new array with +1 size
            unsigned char (*new_current)[32] = malloc((size_t)(current_count + 1) * sizeof(*new_current));
            if (!new_current) {
                if (next) free(next);
                if (current_is_allocated) free(current);
                free(hashes);
                job->merkle_count = 0;
                return;
            }

            // Copy existing data
            memcpy(new_current, current, (size_t)current_count * sizeof(*new_current));

            // Duplicate last
            memcpy(new_current[current_count], current[current_count - 1], 32);

            // Free old if it was allocated
            if (current_is_allocated) {
                free(current);
            }

            current = new_current;
            current_is_allocated = 1;
            current_count++;
        }

        // Find partner for coinbase and store branch
        int partner_index;
        if (index % 2 == 0) {
            partner_index = index + 1;
        } else {
            partner_index = index - 1;
        }

        if (partner_index < current_count) {
            bin2hex(current[partner_index], 32,
                    job->merkle_branch[job->merkle_count]);
            job->merkle_count++;
        }

        // Prepare next level
        int next_count = current_count / 2;
        next = malloc((size_t)next_count * sizeof(*next));
        if (!next) {
            if (current_is_allocated) free(current);
            free(hashes);
            job->merkle_count = 0;
            return;
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            free(next);
            if (current_is_allocated) free(current);
            free(hashes);
            job->merkle_count = 0;
            return;
        }

        // Process all pairs
        for (int i = 0; i < next_count; i++) {
            // Concatenate left and right
            unsigned char combined[64];
            memcpy(combined, current[i * 2], 32);
            memcpy(combined + 32, current[i * 2 + 1], 32);

            // Double SHA256 in one go with EVP
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, combined, 64);

            unsigned char tmp[32];
            unsigned int tmp_len;
            EVP_DigestFinal_ex(ctx, tmp, &tmp_len);

            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, tmp, tmp_len);
            EVP_DigestFinal_ex(ctx, next[i], &tmp_len);
        }

        EVP_MD_CTX_free(ctx);

        // Free current level (if it was allocated)
        if (current_is_allocated) {
            free(current);
        }

        current = next;
        current_is_allocated = 1;  // Next is always allocated
        current_count = next_count;
        next = NULL;  // Prevent double-free
        index = index / 2;
    }

    // Store merkle root
    if (current_count == 1) {
        bin2hex(current[0], 32, job->merkle_root);
    }

    // Cleanup
    if (current_is_allocated) {
        free(current);
    }
    free(hashes);

    if (job->merkle_count > MAX_MERKLE_BRANCHES) {
        job->merkle_count = MAX_MERKLE_BRANCHES;
    }
}

bool is_blockchain_synced(void) {
    json_t *params = json_array();
    json_t *result = rpc_request("getblockchaininfo", params);

    if (!result) {
        log_msg(LOG_ERROR, "Failed to get blockchain info");
        return false;
    }

    json_t *error = json_object_get(result, "error");
    if (error && !json_is_null(error)) {
        log_msg(LOG_ERROR, "getblockchaininfo error: %s",
                json_string_value(json_object_get(error, "message")));
        json_decref(result);
        return false;
    }

    json_t *result_data = json_object_get(result, "result");
    if (!result_data) {
        log_msg(LOG_ERROR, "No result field in response");
        json_decref(result);
        return false;
    }

    // Check verification progress - handle both real AND integer types
    json_t *progress = json_object_get(result_data, "verificationprogress");
    double verification_progress = 0.0;

    if (json_is_real(progress)) {
        verification_progress = json_real_value(progress);
    } else if (json_is_integer(progress)) {
        // Convert integer to double
        verification_progress = (double)json_integer_value(progress);
    } else {
        int json_type = -1;
        if (progress) {
            json_type = (int)json_typeof(progress);  // Cast to int
        }
        log_msg(LOG_ERROR, "verificationprogress is neither real nor integer (type: %d)",
                json_type);
        json_decref(result);
        return false;
    }

    // Check headers and blocks
    json_t *headers = json_object_get(result_data, "headers");
    json_t *blocks = json_object_get(result_data, "blocks");

    int headers_val = headers ? (int)json_integer_value(headers) : 0;
    int blocks_val = blocks ? (int)json_integer_value(blocks) : 0;
    bool headers_match = (headers_val == blocks_val);

    // Check IBD status
    json_t *ibd = json_object_get(result_data, "initialblockdownload");
    bool ibd_false = ibd ? !json_is_true(ibd) : true;

//	log_msg(LOG_INFO, "sync status: progress=%.10f, headers=%d, blocks=%d, headers_match=%s, IBD=%s",
//			verification_progress,
//			headers_val,
//			blocks_val,
//			headers_match ? "yes" : "no",
//			ibd_false ? "false" : "true");

    json_decref(result);

    // Consider synced when verification progress is extremely close to 1.0
    bool synced = (verification_progress >= 0.999999) && headers_match && ibd_false;

    if (!synced) {
        log_msg(LOG_WARN, "Node not fully synced yet (progress=%.10f)", verification_progress);
    }

    return synced;
}

void fetch_block_template(void) {

    json_t *params = json_array();
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_t *gbt_request = json_object();
    json_object_set_new(gbt_request, "rules", rules);
    json_array_append_new(params, gbt_request);

    json_t *result = rpc_request("getblocktemplate", params);
    if (!result) {
        log_msg(LOG_ERROR, "RPC request failed");
        return;
    }

    json_t *error = json_object_get(result, "error");
    if (error && !json_is_null(error)) {
        log_msg(LOG_ERROR, "GBT error: %s", json_string_value(json_object_get(error, "message")));
        json_decref(result);
        return;
    }

    json_t *gbt_data = json_object_get(result, "result");
    if (!gbt_data) {
        log_msg(LOG_ERROR, "No result in RPC response");
        json_decref(result);
        return;
    }

    // Extract basic data
    const char *prev_hash = json_string_value(json_object_get(gbt_data, "previousblockhash"));
    const char *witness_commitment = json_string_value(json_object_get(gbt_data, "default_witness_commitment"));
    json_t *coinbase_value = json_object_get(gbt_data, "coinbasevalue");
    json_t *transactions = json_object_get(gbt_data, "transactions");
    json_t *height_json = json_object_get(gbt_data, "height");
    json_t *version_json = json_object_get(gbt_data, "version");
    const char *bits_str = json_string_value(json_object_get(gbt_data, "bits"));
    json_t *curtime_json = json_object_get(gbt_data, "curtime");

    if (!prev_hash || !coinbase_value || !transactions || !height_json ||
        !version_json || !bits_str || !curtime_json) {
        log_msg(LOG_ERROR, "Missing required fields in GBT");
        json_decref(result);
        return;
    }

    // Convert prevhash to mining format (reverse byte order)
    char prev_hash_mining[65] = {0};
    if (strlen(prev_hash) == 64) {
        for (int i = 0; i < 8; i++) {
            int src_pos = (7 - i) * 8;
            int dst_pos = i * 8;
            memcpy(prev_hash_mining + dst_pos, prev_hash + src_pos, 8);
        }
        prev_hash_mining[64] = '\0';
    }

	// Update network difficulty if changed
	uint32_t newnbits = (uint32_t)strtoul(bits_str, NULL, 16);

	if (newnbits != job_template.last_network_difficulty) {
		job_template.last_network_difficulty = newnbits;
		uint32_t exponent = newnbits >> 24UL;
		uint32_t coefficient = newnbits & 0x007FFFFF;
		double expanded_nbits = (exponent <= 3) ?
			(coefficient >> (8 * (3 - exponent))) :
			(coefficient * pow(256.0, exponent - 3));
		job_template.network_difficulty = (0xFFFFULL * pow(2.0, 208)) / expanded_nbits;
		//printf("[%s] Network difficulty change: %.2f\n", __func__, job_template.network_difficulty);
	}

    pthread_mutex_lock(&template_mutex);

    snprintf(job_template.prev_hash, sizeof(job_template.prev_hash), "%s", prev_hash_mining);
    snprintf(job_template.prev_hash_original, sizeof(job_template.prev_hash_original), "%s", prev_hash);
    job_template.coinbase_value = (uint64_t)json_integer_value(coinbase_value);
    job_template.height = (uint32_t)json_integer_value(height_json);
    job_template.version = (uint32_t)json_integer_value(version_json);
    snprintf(job_template.version_str, sizeof(job_template.version_str), "%08x", job_template.version);

    snprintf(job_template.nbits_str, sizeof(job_template.nbits_str), "%s", bits_str);
    job_template.nbits = (uint32_t)strtoul(bits_str, NULL, 16);
    job_template.ntime = (uint32_t)json_integer_value(curtime_json);
    snprintf(job_template.ntime_str, sizeof(job_template.ntime_str), "%08x", job_template.ntime);

    job_template.extranonce2_size = 8;
    job_template.timestamp = time(NULL);

    // Store witness commitment
    if (witness_commitment && strlen(witness_commitment) == 76) {
    	snprintf(job_template.witness_commitment, sizeof(job_template.witness_commitment), "%s", witness_commitment);
        job_template.witness_commitment[76] = '\0';
    } else {
    	job_template.witness_commitment[0] = '\0';  // Empty if invalid or not segwit
    }

    // Free old transactions if any
    if (job_template.transactions) {
        for (size_t i = 0; i < job_template.tx_count; i++) {
            free(job_template.transactions[i].txid);
            free(job_template.transactions[i].data);
        }
        free(job_template.transactions);
        job_template.transactions = NULL;
    }

    if (job_template.tx_hashes_reversed) {
        for (size_t i = 0; i < job_template.tx_count; i++) {
            free(job_template.tx_hashes_reversed[i]);
        }
        free(job_template.tx_hashes_reversed);
        job_template.tx_hashes_reversed = NULL;
    }

    job_template.tx_count = 0;

    // Store full transaction data
    size_t tx_count = json_array_size(transactions);
    job_template.tx_count = tx_count;
    job_template.transactions = malloc(tx_count * sizeof(transaction_t));
    job_template.tx_hashes_reversed = malloc(tx_count * sizeof(uint8_t*));

    for (size_t i = 0; i < tx_count; i++) {
        json_t *tx = json_array_get(transactions, i);

        // Get transaction data
        const char *txid = json_string_value(json_object_get(tx, "txid"));
        const char *data = json_string_value(json_object_get(tx, "data"));
        json_t *fee_json = json_object_get(tx, "fee");
        json_t *sigops_json = json_object_get(tx, "sigops");
        json_t *weight_json = json_object_get(tx, "weight");

        // Store transaction
        job_template.transactions[i].txid = strdup(txid ? txid : "");
        job_template.transactions[i].data = strdup(data ? data : "");
        job_template.transactions[i].data_len = data ? strlen(data) / 2 : 0;
        job_template.transactions[i].fee = fee_json ? (uint64_t)json_integer_value(fee_json) : 0;
        job_template.transactions[i].sigops = sigops_json ? (int)json_integer_value(sigops_json) : 0;
        job_template.transactions[i].weight = weight_json ? (int)json_integer_value(weight_json) : 0;

        // Allocate space for reversed hash (for merkle)
        job_template.tx_hashes_reversed[i] = malloc(32);

        // Pre-calculate reversed hash for this transaction
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (data) {
            uint8_t tx_bytes[job_template.transactions[i].data_len];
            hex2bin(data, tx_bytes, job_template.transactions[i].data_len);

            uint8_t tx_hash[32];
            unsigned int tmp_len;
            uint8_t tmp[EVP_MAX_MD_SIZE];

            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, tx_bytes, job_template.transactions[i].data_len);
            EVP_DigestFinal_ex(ctx, tmp, &tmp_len);

            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, tmp, tmp_len);
            EVP_DigestFinal_ex(ctx, tx_hash, &tmp_len);

            // Reverse for merkle tree
            for (int j = 0; j < 32; j++) {
                job_template.tx_hashes_reversed[i][j] = tx_hash[31 - j];
            }
            EVP_MD_CTX_free(ctx);
        }
    }

    pthread_mutex_unlock(&template_mutex);

    printf("[GBT] Height=%u, txs=%zu, coinbase=%lusats, difficulty:%.2f\n",
           job_template.height, tx_count, job_template.coinbase_value, job_template.network_difficulty);

    json_decref(result);
}

MiningJob* create_client_job(Client *client) {

    if (!client || !client->authorized) return NULL;

    MiningJob *job = malloc(sizeof(MiningJob));
    if (!job) return NULL;

    // Initialize job
    memset(job, 0, sizeof(MiningJob));

    pthread_mutex_lock(&template_mutex);

    // Copy ONLY the fields needed for mining.notify
    snprintf(job->prev_hash, sizeof(job->prev_hash), "%s", job_template.prev_hash);
    job->version = job_template.version;
    snprintf(job->version_str, sizeof(job->version_str), "%s", job_template.version_str);
    job->nbits = job_template.nbits;
    snprintf(job->nbits_str, sizeof(job->nbits_str), "%s", job_template.nbits_str);
    job->ntime = job_template.ntime;
    snprintf(job->ntime_str, sizeof(job->ntime_str), "%s", job_template.ntime_str);
    job->extranonce2_size = job_template.extranonce2_size;
    snprintf(job->witness_commitment, sizeof(job->witness_commitment), "%s", job_template.witness_commitment);

    // Store template values for coinbase construction
    uint64_t coinbase_value = job_template.coinbase_value;
    uint32_t height = job_template.height;

    pthread_mutex_unlock(&template_mutex);

    // Generate unique job ID
    snprintf(job->job_id, sizeof(job->job_id), "%08lx%04x", time(NULL), client->extranonce1);

    // Build client-specific coinbase
    char extranonce1_hex[9];
    snprintf(extranonce1_hex, sizeof(extranonce1_hex), "%04x", client->extranonce1);

    char miner_address_hex[41];
    bin2hex(client->address_hash, client->address_hash_len, miner_address_hex);

    // Gen donation address hash (if set in .conf)
    char donation_address_hex[41] = {0};
    if (servercfg.donation_address[0] != '\0' && servercfg.donation_percent > 0) {
        Client donation_client;
        memset(&donation_client, 0, sizeof(Client));
        strcpy(donation_client.address, servercfg.donation_address);
        if (validate_and_decode_address(&donation_client)) {
            bin2hex(donation_client.address_hash, donation_client.address_hash_len, donation_address_hex);
        } else {
            log_msg(LOG_ERROR, "Invalid donation address: %s", servercfg.donation_address);
            servercfg.donation_percent = 0; // disable donation for this job
        }
    }

    // Compute coinbase
    char coinbase_hash_le[65];
    int result = compute_coinbase(job,
								   coinbase_value,
								   height,
								   miner_address_hex,
								   donation_address_hex,
								   (float)servercfg.donation_percent,
								   servercfg.pooltag,
								   servercfg.poolsig,
								   coinbase_hash_le);

    if (result != 0) {
        log_msg(LOG_ERROR, "Failed to build coinbase for client %s\n", client->ip);
        free(job);
        return NULL;
    }

    // Create JSON array of transactions for merkle computation
    json_t *tx_array = json_array();
    pthread_mutex_lock(&template_mutex);
    for (size_t i = 0; i < job_template.tx_count; i++) {
        json_t *tx_obj = json_object();
        json_object_set_new(tx_obj, "txid", json_string(job_template.transactions[i].txid));
        json_array_append_new(tx_array, tx_obj);
    }
    pthread_mutex_unlock(&template_mutex);

    // Compute merkle root and branches for this client
    compute_merkle_branches(tx_array, coinbase_hash_le, job);
    json_decref(tx_array);

//	printf("=== JOB DEBUG ===\n");
//	printf("Job id: %s\n", job->job_id);
//	printf("For client: %s (worker: %s)\n", client->ip, client->worker_name);
//	printf("Extranonce1: %s\n", extranonce1_hex);
//	printf("Miner address hash: %s\n", miner_address_hex);
//	printf("Stratum donation address hash: %s\n", donation_address_hex);
//	printf("Stratum donation percentage: %.2f\n", servercfg.donation_percent);
//	printf("Coinbase value: %lu sat\n", coinbase_value);
//	printf("Height: %u\n", height);
//	printf("=======================\n");
//	printf("Coinbase parts:\n");
//	printf("Coinb1 (hex): %s (length: %zu)\n", job->coinb1, job->coinb1_len);
//	printf("Coinb2 (hex): %s (length: %zu)\n", job->coinb2, job->coinb2_len);
//	printf("Coinbase hash (LE): %s\n", coinbase_hash_le);
//	printf("=======================\n");
//	printf("bitcoin-cli decoderawtransaction %s111111112222222222222222%s \n", job->coinb1, job->coinb2);
//	printf("=======================\n");
//	printf("=======================\n");
//	printf("Merkle root: %s\n", job->merkle_root);
//	printf("Merkle branches: %d\n", job->merkle_count);
//	for (int i = 0; i < job->merkle_count; i++) {
//		printf("  Branch[%d]: %s\n", i, job->merkle_branch[i]);
//	}
//	printf("\n");
//	printf("=======================\n");

    return job;
}

void send_response(Client *client, const char *response) {
    if (!client) return;

    int len = (int)strlen(response);

    if (client->is_tls && client->ssl) {
        int ret = SSL_write(client->ssl, response, len);
        if (ret <= 0) {
            int err = SSL_get_error(client->ssl, ret);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                // Fatal error - mark client for removal
                client->disconnect_pending = true;
                log_msg(LOG_ERROR, "[%s] SSL_write error for %s, will disconnect", __func__, client->ip);
            }
        }
    } else {
        ssize_t ret = write(client->socket, response, (size_t)len);
        if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            log_msg(LOG_ERROR, "[%s] Write error for %s", __func__, client->ip);
        }
    }
}

void send_job_to_client(Client *client, bool force_clean) {
    if (!client || !client->job) return;

    char merkle_branches[4096] = "[";
    for (int i = 0; i < client->job->merkle_count; i++) {
        if (i > 0) strcat(merkle_branches, ",");
        strcat(merkle_branches, "\"");
        strcat(merkle_branches, client->job->merkle_branch[i]);
        strcat(merkle_branches, "\"");
    }
    strcat(merkle_branches, "]");

    char *job_id = client->job->job_id;
	char notify[8192];
	snprintf(notify, sizeof(notify),
			"{\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",%s,\"%s\",\"%s\",\"%s\",%s],\"id\":null,\"method\":\"mining.notify\"}\n",
			job_id, client->job->prev_hash, client->job->coinb1, client->job->coinb2,
			merkle_branches, client->job->version_str, client->job->nbits_str, client->job->ntime_str,
			force_clean ? "true" : "false");
	send_response(client, notify);

	//printf("Sent job %s to %s (worker: %s)\n", job_id, client->ip, client->worker_name);
}

static void record_extranonce_usage(uint32_t extranonce1, const char *address) {
    pthread_mutex_lock(&extranonce_mutex);

    // Check if already exists
    ExtranonceEntry *entry = used_extranonces;
    while (entry) {
        if (entry->extranonce1 == extranonce1) {
            // Update address if different
            if (strcmp(entry->address, address) != 0) {
            	snprintf(entry->address, sizeof(entry->address), "%s", address);
            }
            pthread_mutex_unlock(&extranonce_mutex);
            return;
        }
        entry = entry->next;
    }

    // Create new entry
    entry = malloc(sizeof(ExtranonceEntry));
    if (entry) {
        entry->extranonce1 = extranonce1;
        snprintf(entry->address, sizeof(entry->address), "%s", address);
        entry->next = used_extranonces;
        used_extranonces = entry;
    }

    pthread_mutex_unlock(&extranonce_mutex);
}

static void handle_configure(Client *client, json_t *request) {

    json_t *id = json_object_get(request, "id");
    json_t *params = json_object_get(request, "params");

    if (!id || !params || !json_is_array(params) || json_array_size(params) < 2) {
        send_response(client, "{\"id\":1,\"error\":\"Invalid parameters\",\"result\":null}\n");
        return;
    }

    json_t *mask_obj = json_array_get(params, 1);
    if (!mask_obj || !json_is_object(mask_obj)) {
        send_response(client, "{\"id\":1,\"error\":\"Invalid mask object\",\"result\":null}\n");
        return;
    }

    json_t *mask = json_object_get(mask_obj, "version-rolling.mask");
    if (!mask || !json_is_string(mask)) {
        send_response(client, "{\"id\":1,\"error\":\"Invalid version mask\",\"result\":null}\n");
        return;
    }

    int id_value = json_is_number(id) ? (int)json_integer_value(id) : 1;

    char response[256];
    snprintf(response, sizeof(response),
        "{\"id\":%d,\"result\":{\"version-rolling\":true,\"version-rolling.mask\":\"1fffe000\"},\"error\":null}\n",
        id_value);
    send_response(client, response);

    //printf("Sent version rolling configuration to client (id=%d)\n", id_value);
}

static void handle_subscribe(Client *client, json_t *request) {

    json_t *id = json_object_get(request, "id");
    int id_value = json_is_number(id) ? (int)json_integer_value(id) : 2;

    char response[256];

    snprintf(response, sizeof(response),
        "{\"id\":%d,\"result\":[[[\"mining.notify\",\"%04x\"]],\"%08x\",%d],\"error\":null}\n",
        id_value, client->extranonce1, client->extranonce1, 8);

    send_response(client, response);

   //printf("Sent subscription to %s (extranonce: %04x, id=%d)\n",
   //        client->ip, client->extranonce1, id_value);
}

static void handle_authorize(Client *client, json_t *request) {
    json_t *id = json_object_get(request, "id");
    int id_value = json_is_number(id) ? (int)json_integer_value(id) : 3;

    json_t *params = json_object_get(request, "params");
    if (!params || json_array_size(params) < 2) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"error\":\"Invalid parameters\",\"result\":null}\n",
                id_value);
        send_response(client, error);
        return;
    }

    const char *username = json_string_value(json_array_get(params, 0));
    const char *password = json_string_value(json_array_get(params, 1));

    if (!username || !password) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"error\":\"Missing parameters\",\"result\":null}\n",
                id_value);
        send_response(client, error);
        return;
    }

    char address[128] = {0};
    char worker_name[64] = {0};

    const char *dot = strchr(username, '.');
    if (dot) {
        size_t addr_len = (size_t)(dot - username);
        if (addr_len >= sizeof(address)) {
            char error[256];
            snprintf(error, sizeof(error),
                    "{\"id\":%d,\"error\":\"Address too long\",\"result\":null}\n",
                    id_value);
            send_response(client, error);
            return;
        }

        snprintf(address, addr_len + 1, "%s", username);
        address[addr_len] = '\0';
        snprintf(worker_name, sizeof(worker_name), "%s", dot + 1);
    } else {
        snprintf(address, sizeof(address), "%s", username);
        snprintf(worker_name, sizeof(worker_name), "default");
    }

    snprintf(client->worker_name, sizeof(client->worker_name), "%s", worker_name);
    snprintf(client->address, sizeof(client->address), "%s", address);

    //printf("Parsed username '%s' -> address: '%s', worker: '%s'\n",
    //       username, address, worker_name);

    if (!validate_and_decode_address(client)) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"error\":\"Invalid Bitcoin address\",\"result\":null}\n",
                id_value);
        send_response(client, error);
        return;
    }

    client->authorized = true;

    // Record the extranonce usage with this address
    record_extranonce_usage(client->extranonce1, client->address);

    log_msg(LOG_INFO, "Client %s authorized with address '%s' (worker:%s)",
            client->ip, address, worker_name);

    char success[256];
    snprintf(success, sizeof(success),
            "{\"id\":%d,\"result\":true,\"error\":null}\n",
            id_value);
    send_response(client, success);

    // Send client-specific difficulty
    char response[256];
    snprintf(response, sizeof(response),
             "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[%.2f]}\n",
             client->difficulty);
    send_response(client, response);

    if (client->job) free(client->job);
    client->job = create_client_job(client);
    if (client->job) {
        send_job_to_client(client, true);
    }
}

static void handle_suggest_difficulty(Client *client, json_t *request) {

    json_t *id = json_object_get(request, "id");
    int id_value = json_is_number(id) ? (int)json_integer_value(id) : 5;

    json_t *params = json_object_get(request, "params");
    if (!params || json_array_size(params) < 1) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"error\":\"Invalid parameters\",\"result\":null}\n",
                id_value);
        send_response(client, error);
        return;
    }

    json_t *difficulty_json = json_array_get(params, 0);
    double suggested_difficulty = 0.0;

    // Handle both integer and real JSON types
    if (json_is_integer(difficulty_json)) {
        suggested_difficulty = (double)json_integer_value(difficulty_json);
    } else if (json_is_real(difficulty_json)) {
        suggested_difficulty = json_real_value(difficulty_json);
    } else {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"error\":\"Difficulty must be a number\",\"result\":null}\n",
                id_value);
        send_response(client, error);
        return;
    }

    // Special case: difficulty = 0 means enable auto-adjustment
    if (fabs(suggested_difficulty) < 1e-10) {
        client->auto_adjust_difficulty = true;
        printf("Client %s enabled auto-difficulty adjustment\n", client->ip);

        char response[256];
        snprintf(response, sizeof(response),
                "{\"id\":%d,\"result\":true,\"error\":null}\n",
                id_value);
        send_response(client, response);
        return;
    }

    // Validate difficulty for non-zero values
    if (suggested_difficulty < 1.0 || suggested_difficulty > 65535.0) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"error\":\"Difficulty out of range (<1.0 - >65535.0)\",\"result\":null}\n",
                id_value);
        send_response(client, error);
        return;
    }

    // Update client difficulty and disable auto-adjustment
    client->difficulty = suggested_difficulty;
    client->auto_adjust_difficulty = false;  // User explicitly set difficulty

    // Send confirmation
    char response[256];
    snprintf(response, sizeof(response),
            "{\"id\":%d,\"result\":true,\"error\":null}\n",
            id_value);
    send_response(client, response);

    printf("Client %s set difficulty to %.2f (auto-adjust: %s)\n",
           client->ip, client->difficulty,
           client->auto_adjust_difficulty ? "enabled" : "disabled");

    // Send new difficulty notification
    char notify[256];
    snprintf(notify, sizeof(notify),
            "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[%.2f]}\n",
            client->difficulty);
    send_response(client, notify);
}

static void handle_extranonce_subscribe(Client *client, json_t *request) {
    json_t *id = json_object_get(request, "id");
    int id_value = json_is_number(id) ? (int)json_integer_value(id) : 0;

    char response[256];
    snprintf(response, sizeof(response),
            "{\"id\":%d,\"result\":true,\"error\":null}\n",
            id_value);
			//"{\"id\":%d,\"result\":false,\"error\":[20,\"Not supported.\",null]}\n",
			//id_value);
    send_response(client, response);
}

double get_hourly_average_hashrate(Client *client) {
    double sum = 0.0;
    int count = 0;
    for (int i = 0; i < 60; i++) {
        if (client->hashrate_history[i] > 0) {
            sum += client->hashrate_history[i];
            count++;
        }
    }
    return count > 0 ? sum / count : 0.0;
}

static void calculate_and_log_hashrate(Client *client) {
    time_t now = time(NULL);

    // Need at least some shares to estimate hashrate
    if (client->share_count < 2 || client->last_share_time == 0) {
        return;
    }

    double time_elapsed = difftime(now, client->last_share_time);

    // Need sufficient data (at least 60 seconds for meaningful estimate)
    if (time_elapsed < 60.0) {
        return;
    }

    // Calculate shares per minute
    double shares_per_minute = (double)client->share_count * 60.0 / time_elapsed;

    // Calculate estimated hashrate
    double hashes_per_share = client->difficulty * 4294967296.0;  // D × 2^32
    double hashrate_hps = shares_per_minute * hashes_per_share / 60.0;  // hashes per second
    double hashrate_ths = hashrate_hps / 1000000000000.0; // TH/s

    // In log_all_clients_hashrate():
    client->hashrate_history[client->hashrate_index] = hashrate_ths;
    client->hashrate_index = (client->hashrate_index + 1) % 60;

    //double hrs_avg = get_hourly_average_hashrate(client);
    //printf("HASHRATE: Client %s (worker: %s) - Difficulty: %.2f, Shares/min: %.2f, Est. Hashrate: %.3f TH/s, Auto-adjust: %s, 1hr Avg: %.3f TH/s\n",
    //       client->ip, client->worker_name, client->difficulty, shares_per_minute,
    //       hashrate_ths, client->auto_adjust_difficulty ? "yes" : "no", hrs_avg);
}

static void adjust_client_difficulty(Client *client) {

    calculate_and_log_hashrate(client);

    // Only adjust difficulty if auto-adjustment is enabled
    if (!client->auto_adjust_difficulty) {
        // Still reset counters periodically for hashrate logging
        time_t now = time(NULL);
        double time_elapsed = difftime(now, client->last_share_time);
        if (time_elapsed >= 60.0 && client->share_count > 0) {
            client->share_count = 0;
            client->last_share_time = now;
        }
        return;
    }

    time_t now = time(NULL);

    // Need at least 10 shares for estimation
    if (client->share_count < 10 || client->last_share_time == 0) {
        return;
    }

    double time_elapsed = difftime(now, client->last_share_time);

    // 120 seconds (2 minutes) window
    if (time_elapsed < 120.0) {
        return;
    }

    // Calculate shares per minute
    double shares_per_minute = (double)client->share_count * 60.0 / time_elapsed;

    // Simple difficulty adjustment algorithm
    double target_shares_per_minute = 20.0;

    if (shares_per_minute > 0) {
        double ratio = shares_per_minute / target_shares_per_minute;

        // Adjust difficulty if ratio is outside reasonable bounds
        if (ratio > 1.5 || ratio < 0.67) {
            double new_difficulty = client->difficulty * ratio;

            // Clamp difficulty to reasonable bounds
            if (new_difficulty < 1.0) new_difficulty = 1.0;
            if (new_difficulty > 65535.0) new_difficulty = 65535.0;

            // Don't adjust if change is too small (< 15%)
            double change_ratio = new_difficulty / client->difficulty;
            if (change_ratio < 0.85 || change_ratio > 1.15) {
                // Update client difficulty
                client->difficulty = new_difficulty;

                // Reset share tracking for next adjustment period
                client->share_count = 0;
                client->last_share_time = now;

                // Notify client of new difficulty
                char notify[256];
                snprintf(notify, sizeof(notify),
                        "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[%.2f]}\n",
                        client->difficulty);
                send_response(client, notify);

                if (client->job) free(client->job);
                client->job = create_client_job(client);
                if (client->job) {
                    send_job_to_client(client, true);
                }

                //printf("Auto-adjusted difficulty for client %s to %.2f (shares/min: %.2f)\n",
                //       client->ip, client->difficulty, shares_per_minute);

            } else {
                // Reset counters even if no adjustment (for next cycle)
                client->share_count = 0;
                client->last_share_time = now;
            }
        } else {
            // Within target range, reset counters for next cycle
            client->share_count = 0;
            client->last_share_time = now;
        }
    }
}

static void handle_submit(Client *client, json_t *request) {

    double job_difficulty = 0;
    time_t now = time(NULL);
    client->share_count++;
    if (client->last_share_time == 0) {
        client->last_share_time = now;
    }

    json_t *id = json_object_get(request, "id");
    int id_value = json_is_number(id) ? (int)json_integer_value(id) : 4;

    json_t *params = json_object_get(request, "params");
    size_t param_count = json_array_size(params);

    if (!params || json_array_size(params) < 5) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"result\":false,\"error\":[\"Invalid parameters\"],\"reject-reason\":\"Invalid parameters\"}\n",
                id_value);
        send_response(client, error);
        stats_share_rejected(client, job_difficulty);
        return;
    }

    //const char *worker_name = json_string_value(json_array_get(params, 0));
    const char *job_id = json_string_value(json_array_get(params, 1));
    const char *extranonce2_hex = json_string_value(json_array_get(params, 2));
    const char *ntime_hex = json_string_value(json_array_get(params, 3));
    const char *nonce_hex = json_string_value(json_array_get(params, 4));
    const char *version_hex = "00000000";  // Default to legacy non version rolling
    if (param_count >= 6) {
        const char *rolled_version = json_string_value(json_array_get(params, 5));
        if (rolled_version) {
            version_hex = rolled_version;
        }
    }

    // Stale job
    if (!client->job || strcmp(client->job->job_id, job_id) != 0) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"result\":false,\"error\":[\"Stale job\"],\"reject-reason\":\"Stale job\"}\n",
                id_value);
        send_response(client, error);
        stats_share_rejected(client, job_difficulty);
        return;
    }

    // Parse miner values
    uint32_t submitted_version = (uint32_t)strtoul(version_hex, NULL, 16);
    uint32_t submitted_nonce = (uint32_t)strtoul(nonce_hex, NULL, 16);
    uint32_t submitted_ntime = (uint32_t)strtoul(ntime_hex, NULL, 16);
    uint32_t rolled_version_new = submitted_version ^ client->job->version;

    // Build Coinbase
    uint8_t full_cb[1024];
    size_t cb_len = 0;

    // Coin1
    memcpy(full_cb + cb_len, client->job->raw_coinb1, client->job->coinb1_len);
    cb_len += client->job->coinb1_len;

    // Extranonce1
    uint8_t extranonce1_bin[4];
    extranonce1_bin[0] = (uint8_t)(client->extranonce1 >> 24) & 0xFF;
    extranonce1_bin[1] = (client->extranonce1 >> 16) & 0xFF;
    extranonce1_bin[2] = (client->extranonce1 >> 8) & 0xFF;
    extranonce1_bin[3] = (client->extranonce1 >> 0) & 0xFF;
    memcpy(full_cb + cb_len, extranonce1_bin, 4);
    cb_len += 4;

    // Extranonce2
    uint8_t extranonce2_bin[8];
    size_t extranonce2_bytes = strlen(extranonce2_hex) / 2;
    hex2bin(extranonce2_hex, extranonce2_bin, extranonce2_bytes);
    memcpy(full_cb + cb_len, extranonce2_bin, extranonce2_bytes);
    cb_len += extranonce2_bytes;

    // Coin2
    memcpy(full_cb + cb_len, client->job->raw_coinb2, client->job->coinb2_len);
    cb_len += client->job->coinb2_len;

    // Calculate merkle root
    uint8_t coinbase_hash[32];
    double_sha256(full_cb, cb_len, coinbase_hash);

    uint8_t merkle_root[32];
    memcpy(merkle_root, coinbase_hash, 32);

    if (client->job->merkle_count > 0) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        for (int i = 0; i < client->job->merkle_count; i++) {
            uint8_t branch[32];
            hex2bin(client->job->merkle_branch[i], branch, 32);

            uint8_t combined[64];
            memcpy(combined, merkle_root, 32);
            memcpy(combined + 32, branch, 32);

            unsigned char tmp[32];
            unsigned int tmp_len;

            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, combined, 64);
            EVP_DigestFinal_ex(ctx, tmp, &tmp_len);

            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, tmp, tmp_len);
            EVP_DigestFinal_ex(ctx, merkle_root, &tmp_len);
        }

        EVP_MD_CTX_free(ctx);
    }

    // Build header
    uint8_t header[80];
    memset(header, 0, sizeof(header));

    // Version
    uint32_t version_le = htole32(rolled_version_new);
    memcpy(header, &version_le, 4);

    // Prevhash
    char prev_hash[65];
    hex_8byte_chunk_reverse(client->job->prev_hash, prev_hash);
    uint8_t binary_prev_hash[32];
    hex2bin(prev_hash, binary_prev_hash, 32);
    memcpy(header + 4, binary_prev_hash, 32);

    // Merkle root
    memcpy(header + 36, merkle_root, 32);

    // Time
    uint32_t ntime_le = htole32(submitted_ntime);
    memcpy(header + 68, &ntime_le, 4);

    // Bits
    uint32_t nbits = client->job->nbits;
    uint32_t nbits_le = htole32(nbits);
    memcpy(header + 72, &nbits_le, 4);

    // Nonce
    uint32_t nonce_le = htole32(submitted_nonce);
    memcpy(header + 76, &nonce_le, 4);

    // VALIDATE
    uint8_t hash_result[32];
    double_sha256(header, 80, hash_result);

    double hash_value = le256todouble(hash_result);
    double diff = truediffone / hash_value;
    job_difficulty = (diff > 0.0001) ? diff : 0.0;

    // LOW DIFF
    if (job_difficulty < client->difficulty) {
        char error[256];
        snprintf(error, sizeof(error),
                "{\"id\":%d,\"result\":false,\"error\":[\"Low difficulty\"],\"reject-reason\":\"Stale job\"}\n",
                id_value);
        send_response(client, error);
        //printf("Share REJECTED from %s (low difficulty)\n", client->ip);
        stats_share_rejected(client, job_difficulty);
        return;
    }

    // Found block
    if (job_difficulty >= job_template.network_difficulty) {

    	pthread_mutex_lock(&template_mutex);

        // Calculate block size
        size_t estimated_size = 80;  // header

        // Add coinbase transaction size
        estimated_size += cb_len;  // coinbase raw data

        // Add varint for transaction count
        size_t total_txs = job_template.tx_count + 1;  // +1 for coinbase
        if (total_txs < 0xFD) {
            estimated_size += 1;
        } else if (total_txs <= 0xFFFF) {
            estimated_size += 3;  // 0xFD + 2 bytes
        } else if (total_txs <= 0xFFFFFFFF) {
            estimated_size += 5;  // 0xFE + 4 bytes
        } else {
            estimated_size += 9;  // 0xFF + 8 bytes
        }

        // Add all other transactions
        for (size_t i = 0; i < job_template.tx_count; i++) {
            estimated_size += job_template.transactions[i].data_len;
        }

        // Add safety margin (witness data, etc.)
        estimated_size += 1000;  // Your existing buffer
        uint8_t *full_block = malloc(estimated_size);
        size_t block_len = 0;

        // Header
        memcpy(full_block, header, 80);
        block_len = 80;

        // Transactions. Bitcoin varint encoding, serialize.h (see WriteCompactSize())
        if (total_txs < 0xFD) {
            full_block[block_len++] = (uint8_t)total_txs;
        }
        else if (total_txs <= 0xFFFF) {
            full_block[block_len++] = 0xFD;
            full_block[block_len++] = (total_txs >> 0) & 0xFF;
            full_block[block_len++] = (total_txs >> 8) & 0xFF;
        }
        else if (total_txs <= 0xFFFFFFFF) {
            full_block[block_len++] = 0xFE;
            full_block[block_len++] = (total_txs >> 0) & 0xFF;
            full_block[block_len++] = (total_txs >> 8) & 0xFF;
            full_block[block_len++] = (total_txs >> 16) & 0xFF;
            full_block[block_len++] = (total_txs >> 24) & 0xFF;
        }
        else {
            full_block[block_len++] = 0xFF;
            // 8 bytes, unlikely but handles it anyway
            for (int i = 0; i < 8; i++) {
                full_block[block_len++] = (total_txs >> (i * 8)) & 0xFF;
            }
        }

        // Coinbase
        memcpy(full_block + block_len, full_cb, cb_len);
        block_len += cb_len;

        // Other transactions
        for (size_t i = 0; i < job_template.tx_count; i++) {
            uint8_t *tx_data = malloc(job_template.transactions[i].data_len);
            hex2bin(job_template.transactions[i].data, tx_data, job_template.transactions[i].data_len);
            memcpy(full_block + block_len, tx_data, job_template.transactions[i].data_len);
            block_len += job_template.transactions[i].data_len;
            free(tx_data);
        }

        pthread_mutex_unlock(&template_mutex);

        // ========== SUBMIT BLOCK ==========

        char hex_block[block_len * 2 + 1]; // Stack allocated
        for (size_t i = 0; i < block_len; i++) sprintf(hex_block + i*2, "%02x", full_block[i]);

        json_t *submit_params = json_array();
        json_array_append_new(submit_params, json_string(hex_block));
        json_t *submit_result = rpc_request("submitblock", submit_params);

        if (submit_result) {

        	//printf("Block Submitted Result: %s\n", json_dumps(submit_result, JSON_COMPACT));

            // Check if block was accepted
            json_t *error = json_object_get(submit_result, "error");
            if (!error || json_is_null(error)) {

                // Create finder info string
                char finder_info[256];
                snprintf(finder_info, sizeof(finder_info), "%s/%s",
                         client->ip, client->worker_name);

                // Get block hash from header
                uint8_t block_hash[32];
                double_sha256(header, 80, block_hash);

                char block_hash_hex[65];
                for (int i = 0; i < 32; i++) {
                    sprintf(block_hash_hex + (i * 2), "%02x", block_hash[31 - i]);
                }
                block_hash_hex[64] = '\0';

                // Update stats
                if (submit_result && (!error || json_is_null(error))) {
                    snprintf(finder_info, sizeof(finder_info), "%s/%s",
                    		//client->ip,
							client->address,
							client->worker_name);

                    stats_block_found(job_template.height, block_hash_hex, finder_info);
                }
            }
            json_decref(submit_result);
        }
        free(full_block);
    }

    if (job_difficulty >= client->difficulty){
        // ACCEPT SHARE
        char response[256];
        snprintf(response, sizeof(response),
                "{\"id\":%d,\"result\":true,\"error\":null}\n",
                id_value);
        send_response(client, response);
        stats_share_accepted(client, job_difficulty);
    }

    //printf("Share accepted from %s (ip:%s): job=%s, difficulty: %.2f of %.2f\n",
   	//	worker_name, client->ip, job_id, job_difficulty, client->difficulty);
}

static uint32_t generate_unique_extranonce1(void) {
    uint32_t extranonce;

    pthread_mutex_lock(&extranonce_mutex);

    // Generate until we find a unique one
    int attempts = 0;
    do {
    	extranonce = (uint32_t)rand() & 0xFFFFFFFF;
        ExtranonceEntry *entry = used_extranonces;
        int found = 0;

        while (entry) {
            if (entry->extranonce1 == extranonce) {
                found = 1;
                break;
            }
            entry = entry->next;
        }

        if (!found) break;

        attempts++;
        if (attempts > 1000) {
        	extranonce = ((uint32_t)rand() & 0xFFFFF) | 0x100000;
            break;
        }
    } while (1);

    pthread_mutex_unlock(&extranonce_mutex);

    return extranonce;
}

static SSL* create_client_ssl(int fd) {
    if (!global_ssl_ctx) return NULL;

    SSL *ssl = SSL_new(global_ssl_ctx);
    if (!ssl) return NULL;

    if (!SSL_set_fd(ssl, fd)) {
        SSL_free(ssl);
        return NULL;
    }

    SSL_set_accept_state(ssl);
    return ssl;
}

static int tls_handshake(SSL *ssl) {
    int ret = SSL_accept(ssl);
    if (ret == 1) return 1;  // Handshake complete

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0;  // Need more I/O
    }
    return -1;  // Handshake failed
}

void* handle_client(void *arg) {
    int *conn_info = (int*)arg;
    int sock = conn_info[0];
    int is_tls = conn_info[1];
    free(arg);

    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getpeername(sock, (struct sockaddr*)&addr, &len);
    strcpy(ip, inet_ntoa(addr.sin_addr));

    Client *client = malloc(sizeof(Client));
    memset(client, 0, sizeof(Client));
    client->socket = sock;
    strcpy(client->ip, ip);
    client->extranonce1 = generate_unique_extranonce1();
    client->authorized = false;
    client->job = NULL;
    client->address_type = 0;
    client->difficulty = servercfg.difficulty;
    client->auto_adjust_difficulty = true;
    client->last_share_time = 0;
    client->share_count = 0;
    client->is_tls = is_tls;
    client->ssl = NULL;
    client->handshake_done = false;

    if (is_tls) {
        client->ssl = create_client_ssl(sock);
        if (!client->ssl) {
            log_msg(LOG_ERROR, "Failed to create SSL for client %s", ip);
            close(sock);
            free(client);
            return NULL;
        }
        //printf("TLS Handshake started for %s\n", ip);
    }

    add_client(client);

    log_msg(LOG_INFO, "Client connected: %s (socket:%d, %s, extranonce1:%04x)",
            ip, sock, is_tls ? "TLS" : "plaintext", client->extranonce1);

    char buffer[RX_BUFFER_SIZE];
    ssize_t bytes;

    while (1) {

        if (client->is_tls && !client->handshake_done) {
            int hs_ret = tls_handshake(client->ssl);

            if (hs_ret == 0) {
                // Handshake still in progress - wait a bit and retry
                usleep(10000);  // 10ms
                if (!client->ssl || client->handshake_done) {
                    break; // Connection died during sleep
                }
                continue;
            }

            if (hs_ret == -1) {
                log_msg(LOG_ERROR, "TLS handshake failed for %s", ip);
                if (client->ssl) {
                    SSL_free(client->ssl);
                    client->ssl = NULL;
                }
                break;
            }

            client->handshake_done = true;
            //printf("TLS handshake completed for %s\n", ip);
            continue; // Proceed to read stratum datas
        }

        if (client->is_tls) {

            // SSL object gone, disconnect || Check for pending disconnect BEFORE reading
            if (!client->ssl || client->disconnect_pending) {
                break;
            }

            bytes = SSL_read(client->ssl, buffer, sizeof(buffer)-1);
            if (bytes <= 0) {
                int err = SSL_get_error(client->ssl, (int)bytes);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    usleep(10000);
                    continue;
                }
                break; // Connection closed or error
            }
        } else {

            if (client->disconnect_pending) {
                break;
            }

        	bytes = read(sock, buffer, sizeof(buffer)-1);
            if (bytes <= 0) break;
        }

        buffer[bytes] = 0;

        char *line = strtok(buffer, "\n");
        while (line) {

            //printf("Client sent: %s\n", line);

            json_error_t error;
            json_t *request = json_loads(line, 0, &error);

            if (request) {
                const char *method = json_string_value(json_object_get(request, "method"));

                if (method) {
                    if (strcmp(method, "mining.configure") == 0) {
                        handle_configure(client, request);
                    }
                    else if (strcmp(method, "mining.subscribe") == 0) {
                        handle_subscribe(client, request);
                    }
                    else if (strcmp(method, "mining.authorize") == 0) {
                        handle_authorize(client, request);
                    }
                    else if (strcmp(method, "mining.submit") == 0) {
                        handle_submit(client, request);
                    }
                    else if (strcmp(method, "mining.suggest_difficulty") == 0) {
                        handle_suggest_difficulty(client, request);
                    }
                    else if (strcmp(method, "mining.extranonce.subscribe") == 0) {
                        handle_extranonce_subscribe(client, request);
                    }
                    else {
                        printf("Unknown method: %s\n", method);
                    }
                }
                json_decref(request);
            } else {
                printf("Failed to parse JSON: %s (line: %d, col: %d)\n",
                       error.text, error.line, error.column);
                printf("Raw problematic line: %s\n", line);
            }
            line = strtok(NULL, "\n");
        }
    }

    remove_client(sock);
    log_msg(LOG_INFO, "Client disconnected: %s", ip);

    return NULL;
}

void* job_update_thread(void *arg) {
	(void)arg;

    time_t last_sync_check = 0;
    bool node_synced = true;  // Assume synced initially

    fetch_block_template();

    while (1) {
        // Wait up to N seconds, but wake immediately on ZMQ if enabled
        int waited = 0;
        int interval = servercfg.job_update_interval;

        while (waited < interval) {
            if (servercfg.zmq_enabled && servercfg.zmq_newhash) {
                break;  // ZMQ wakeup!
            }
            sleep(1);
            waited++;
        }

        // Check sync status only every 5 minutes (300 seconds)
        time_t now = time(NULL);
        if (now - last_sync_check > 300) {
            last_sync_check = now;
            node_synced = is_blockchain_synced();
        }

        // Only fetch template if node is synced
        if (node_synced) {
            fetch_block_template();

            // Send jobs to ALL clients
            pthread_mutex_lock(&clients_mutex);
            Client *client = connected_clients;
            while (client) {
                if (client->authorized) {
                    if (client->job) free(client->job);
                    client->job = create_client_job(client);
                    if (client->job) {
                        bool force_clean = (servercfg.zmq_enabled && servercfg.zmq_newhash);
                        send_job_to_client(client, force_clean);
                    }
                }
                client = client->next;
            }
            pthread_mutex_unlock(&clients_mutex);
        } else {
            static time_t last_log = 0;
            if (now - last_log > 300) {  // Log every 5 minutes if unsynced
                last_log = now;
                log_msg(LOG_WARN, "Node not synced, skipping template fetch");
            }
        }
        if (servercfg.zmq_enabled && servercfg.zmq_newhash) {
            servercfg.zmq_newhash = false;
        }
    }
    return NULL;
}

void* difficulty_adjustment_thread(void *arg) {
	(void)arg;

    while (1) {

        sleep(60);  // Check every minute

        pthread_mutex_lock(&clients_mutex);
        Client *client = connected_clients;
        while (client) {
            if (client->authorized) {
                adjust_client_difficulty(client);
            }
            client = client->next;
        }
        pthread_mutex_unlock(&clients_mutex);

        // Update stats
        stats_worker_heartbeat(client);
    }
    return NULL;
}

void* zmq_listener_thread(void *arg) {
	(void)arg;

    if (!servercfg.zmq_enabled) {
        return NULL;
    }

    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);

    if (zmq_connect(subscriber, servercfg.zmq_hashblock_address) != 0) {
        log_msg(LOG_ERROR, "ZMQ failed to connect to %s", servercfg.zmq_hashblock_address);
        return NULL;
    }

    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "hashblock", 9);
    //printf("ZMQ listening on %s\n", servercfg.zmq_hashblock_address);

    while (1) {
        zmq_msg_t msg;

        zmq_msg_init(&msg);
        if (zmq_msg_recv(&msg, subscriber, 0) == -1) break;

        char *topic = (char*)zmq_msg_data(&msg);
        if (strncmp(topic, "hashblock", 9) != 0) {
            zmq_msg_close(&msg);
            continue;
        }
        zmq_msg_close(&msg);

        unsigned char hash[32];
        int hash_len = 0;
        int more = 0;
        size_t more_size = sizeof(more);

        do {
            zmq_msg_init(&msg);
            if (zmq_msg_recv(&msg, subscriber, 0) == -1) break;

            unsigned char *data = (unsigned char*)zmq_msg_data(&msg);
            size_t size = zmq_msg_size(&msg);

            if (((size_t)hash_len + size) <= 32) {
                memcpy(hash + hash_len, data, size);
                hash_len += (int)size;
            }

            zmq_msg_close(&msg);
            zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);

        } while (more);

        if (hash_len == 32) {
            char hash_hex[65];
            for (int i = 0; i < 32; i++) {
                sprintf(hash_hex + (i * 2), "%02x", hash[i]);
            }
            hash_hex[64] = '\0';
            printf("[ZMQ] New block Hash: %s\n", hash_hex);
            servercfg.zmq_newhash = true;
        }
    }

    zmq_close(subscriber);
    return NULL;
}

bool load_config_from_file(const char *filename) {

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_msg(LOG_WARN, "Config file %s not found, using defaults", filename);
        return false;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {

        line[strcspn(line, "\n")] = 0;
        char key[128], value[384];

        if (sscanf(line, "%127[^=]=%383[^\n]", key, value) == 2) {

            char *start = value;
            char *end = value + strlen(value) - 1;
            if (*start == '"' && *end == '"') {
                value[strlen(value)-1] = 0;
                memmove(value, value+1, strlen(value));
            }

            if (strcmp(key, "rpc_server") == 0) {
            	snprintf(servercfg.rpc_server, sizeof(servercfg.rpc_server), "%s", value);
            } else if (strcmp(key, "rpc_user") == 0) {
            	snprintf(servercfg.rpc_user, sizeof(servercfg.rpc_user), "%s", value);
            } else if (strcmp(key, "rpc_pass") == 0) {
            	snprintf(servercfg.rpc_pass, sizeof(servercfg.rpc_pass), "%s", value);
            } else if (strcmp(key, "job_update_interval") == 0) {
                servercfg.job_update_interval = atoi(value);
            } else if (strcmp(key, "difficulty") == 0) {
                servercfg.difficulty = atof(value);
            } else if (strcmp(key, "pooltag") == 0) {
            	snprintf(servercfg.pooltag, sizeof(servercfg.pooltag), "%s", value);
            } else if (strcmp(key, "poolsig") == 0) {
            	snprintf(servercfg.poolsig, sizeof(servercfg.poolsig), "%s", value);
            } else if (strcmp(key, "donation_address") == 0) {
                snprintf(servercfg.donation_address, sizeof(servercfg.donation_address), "%s", value);
            } else if (strcmp(key, "donation_percent") == 0) {
                servercfg.donation_percent = atof(value);
            } else if (strcmp(key, "zmq_enabled") == 0) {
                servercfg.zmq_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(key, "zmq_hashblock_address") == 0) {
            	snprintf(servercfg.zmq_hashblock_address, sizeof(servercfg.zmq_hashblock_address), "%s", value);
            } else if (strcmp(key, "plaintext_enabled") == 0) {
                servercfg.plaintext_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(key, "plaintext_port") == 0) {
                servercfg.plaintext_port = atoi(value);
            } else if (strcmp(key, "tls_enabled") == 0) {
                servercfg.tls_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(key, "tls_port") == 0) {
                servercfg.tls_port = atoi(value);
            } else if (strcmp(key, "tls_cert_file") == 0) {
            	snprintf(servercfg.tls_cert_file, sizeof(servercfg.tls_cert_file), "%s", value);
            } else if (strcmp(key, "tls_key_file") == 0) {
            	snprintf(servercfg.tls_key_file, sizeof(servercfg.tls_key_file), "%s", value);
			} else if (strcmp(key, "httpd_port") == 0) {
				servercfg.httpd_port = atoi(value);
            }
        }
    }
    fclose(f);
    log_msg(LOG_INFO, "Loaded configuration from %s", filename);
    return true;
}

SSL_CTX* create_stratum_ssl_context(ServerConfig *cfg) {

    SSL_CTX *ctx = NULL;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_msg(LOG_ERROR, "Failed to create SSL context");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, cfg->tls_cert_file, SSL_FILETYPE_PEM) <= 0) {
        log_msg(LOG_ERROR, "Failed to load certificate: %s", cfg->tls_cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->tls_key_file, SSL_FILETYPE_PEM) <= 0) {
        log_msg(LOG_ERROR, "Failed to load private key: %s", cfg->tls_key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify key matches cert
    if (!SSL_CTX_check_private_key(ctx)) {
        log_msg(LOG_ERROR, "Private key does not match certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA");
    SSL_CTX_set_dh_auto(ctx, 1);

    //printf("TLS context created successfully\n");
    //printf("Certificate: %s\n", cfg->tls_cert_file);
    //printf("Key file: %s\n", cfg->tls_key_file);

    return ctx;
}

void* http_stats_server(void *arg) {
    (void)arg;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)servercfg.httpd_port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return NULL;
    }

    if (listen(server_fd, 5) < 0) {
        close(server_fd);
        return NULL;
    }

    // Get local IP address
    char local_ip[64] = "127.0.0.1"; //default
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                // Skip loopback
                struct sockaddr_in *s4 = (struct sockaddr_in *)ifa->ifa_addr;
                if (strcmp(ifa->ifa_name, "lo") != 0) {
                    inet_ntop(AF_INET, &s4->sin_addr, local_ip, sizeof(local_ip));
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    }

    log_msg(LOG_HTTP, "HTTP server listening on port %d", servercfg.httpd_port);
    log_msg(LOG_HTTP, "Server stats: http://%s:%d/stats/server", local_ip, servercfg.httpd_port);
    log_msg(LOG_HTTP, "Wallet stats: http://%s:%d/stats/wallet/{address}", local_ip, servercfg.httpd_port);
    log_msg(LOG_HTTP, "Recent blocks: http://%s:%d/stats/blocks", local_ip, servercfg.httpd_port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_sock >= 0) {
            char buffer[4096] = {0};
            ssize_t bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);

            if (bytes_read <= 0) {
                close(client_sock);
                continue;
            }

            char response[16384] = {0};
            const char *content_type = "application/json";
            char *content = NULL;

            if (strstr(buffer, "GET /stats/server ")) {
                content = stats_get_server_json();
                content_type = "application/json";
            }
            else if (strstr(buffer, "GET /stats/wallet/")) {
                char *start = strstr(buffer, "/stats/wallet/") + 14;
                char *end = strstr(start, " ");
                if (end && start) {
                    int len = (int)(end - start);
                    if (len > 0 && len < 256) {
                        char wallet[256];
                        snprintf(wallet, sizeof(wallet), "%.*s", len, start);
                        content = stats_get_wallet_json(wallet);
                    }
                }
            }
            else if (strstr(buffer, "GET /stats/blocks ")) {
                content = stats_get_blocks_json();
            }

            if (!content) {
                content = strdup("{\"error\": \"Not found\"}");
            }

            if (content) {
                snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: %s\r\n"
                    "Content-Length: %zu\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "%s",
                    content_type, strlen(content), content);

                ssize_t bytes_written = write(client_sock, response, strlen(response));

                if (bytes_written < 0) {
                    log_msg(LOG_HTTP, "Warning: Failed to write response to client");
                }
                free(content);
            }
            close(client_sock);
        }
    }
    close(server_fd);
    return NULL;
}

void log_msg(int level, const char *format, ...) {
    va_list args;
    va_start(args, format);

    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", tm_info);

    const char *level_str = "INFO";
    if (level == LOG_WARN) level_str = "WARN";
    if (level == LOG_ERROR) level_str = "ERROR";
    if (level == LOG_HTTP) level_str = "HTTP";

    if (g_daemon_mode && log_file) {
        fprintf(log_file, "[%s] [%s] ", timestamp, level_str);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fflush(log_file);
    } else if (!g_daemon_mode) {
        printf("[%s] [%s] ", timestamp, level_str);
        vprintf(format, args);
        printf("\n");
    }

    va_end(args);
}

void daemonize(const char *instance_name) {
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        perror("First fork failed");
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }

    if (setsid() < 0) {
        perror("setsid failed");
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    open("/dev/null", O_RDWR);  // fd 0
    if (dup(0) < 0) {  // fd 1
        exit(1);
    }
    if (dup(0) < 0) {  // fd 2
        exit(1);
    }

    // Create logs directory in current working directory
    char log_dir[MAX_LOG_PATH];
    snprintf(log_dir, sizeof(log_dir), "logs");
    if (mkdir(log_dir, 0755) != 0 && errno != EEXIST) {
        // Log error but continue
        fprintf(stderr, "Warning: Could not create logs directory\n");
    }

    // Build log path
    if (strcmp(instance_name, "default") == 0) {
        snprintf(log_path, sizeof(log_path), "logs/solostratum.log");
    } else {
        snprintf(log_path, sizeof(log_path), "logs/%s.log", instance_name);
    }

    // Open log file
    log_file = fopen(log_path, "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", log_path);
        exit(1);
    }
    setlinebuf(log_file);

    // Write PID file to current directory
    char pid_path[MAX_LOG_PATH];
    if (strcmp(instance_name, "default") == 0) {
        snprintf(pid_path, sizeof(pid_path), "solostratum.pid");
    } else {
        snprintf(pid_path, sizeof(pid_path), "%s.pid", instance_name);
    }

    FILE *pidfile = fopen(pid_path, "w");
    if (pidfile) {
        fprintf(pidfile, "%d\n", getpid());
        fclose(pidfile);
    } else {
        log_msg(LOG_ERROR, "Failed to create PID file %s: %s",
                pid_path, strerror(errno));
    }

    log_msg(LOG_INFO, "SoloStratum daemon started (PID: %d)", getpid());
    log_msg(LOG_INFO, "Instance: %s", instance_name);
    log_msg(LOG_INFO, "Log file: %s", log_path);
}

int main(int argc, char *argv[]) {

    const char *config_file = "solostratum.conf";
    char instance_name[128] = "default";
    int daemon_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                config_file = argv[++i];
            }
        }
        else if (argv[i][0] != '-') {
            config_file = argv[i];
        }
    }

    const char *base = strrchr(config_file, '/');
    base = base ? base + 1 : config_file;

    strncpy(instance_name, base, sizeof(instance_name) - 1);
    instance_name[sizeof(instance_name) - 1] = '\0';

    char *dot = strrchr(instance_name, '.');
    if (dot && strcmp(dot, ".conf") == 0) {
        *dot = '\0';
    }

    if (daemon_mode) {
        g_daemon_mode = 1;
        daemonize(instance_name);
    }

    // defaults
    memset(&servercfg, 0, sizeof(servercfg));
    snprintf(servercfg.pooltag, sizeof(servercfg.pooltag), "%s", "pooltag");
    snprintf(servercfg.poolsig, sizeof(servercfg.poolsig), "%s", "poolsig");
    snprintf(servercfg.donation_address, sizeof(servercfg.donation_address), "%s", "donation_address");
    servercfg.donation_percent = 0.00;
    snprintf(servercfg.rpc_server, sizeof(servercfg.rpc_server), "%s", "127.0.0.1:8332");
    snprintf(servercfg.rpc_user, sizeof(servercfg.rpc_user), "%s", "username");
    snprintf(servercfg.rpc_pass, sizeof(servercfg.rpc_pass), "%s", "password");
    servercfg.plaintext_enabled = true;
    servercfg.plaintext_port = 3333;
    servercfg.tls_enabled = true;
    servercfg.tls_port = 3443;
    servercfg.tls_cert_file[0] = '\0';
    servercfg.tls_key_file[0] = '\0';
    servercfg.job_update_interval = 30;
    servercfg.difficulty = 512.00;
    servercfg.httpd_port = 8080;

    // Override with config file
    if (!load_config_from_file(config_file)) {
        if (g_daemon_mode) {
            log_msg(LOG_WARN, "Failed to open config file for instance '%s'", instance_name);
        } else {
            fprintf(stderr, "WARNING: Failed to open config file for instance '%s'\n", instance_name);
        }
    }

    // Wait for blockchain to sync
    log_msg(LOG_INFO, "Checking blockchain synchronization status...");

    int sync_checks = 0;
    while (sync_checks < 300) { // Check for up to 5 minutes
        if (is_blockchain_synced()) {
            log_msg(LOG_INFO, "Blockchain is fully synced, starting stratum server");
            break;
        }

        if (sync_checks % 12 == 0) {
            log_msg(LOG_INFO, "Waiting for the blockchain to sync...");
        }

        sleep(1);
        sync_checks++;
    }

    if (sync_checks >= 300) {
        log_msg(LOG_WARN, "Blockchain sync timeout, starting anyway");
    }

    // Initialize stats
    if (!stats_init(instance_name)) {
        if (g_daemon_mode) {
            log_msg(LOG_WARN, "Failed to initialize stats system for instance '%s'", instance_name);
        } else {
            fprintf(stderr, "WARNING: Failed to initialize stats system for instance '%s'\n", instance_name);
        }
    }

    // Ignore SIGPIPE, let write/SSL_write return -1
//    signal(SIGPIPE, SIG_IGN);

    // Initialize SSL context if TLS is enabled
    if (servercfg.tls_enabled) {
        if (servercfg.tls_cert_file[0] == '\0' || servercfg.tls_key_file[0] == '\0') {
            fprintf(stderr, "ERROR: TLS enabled but certificate or key file not specified\n");
            return 1;
        }
        global_ssl_ctx = create_stratum_ssl_context(&servercfg);
        if (!global_ssl_ctx) {
            fprintf(stderr, "ERROR: Failed to create SSL context\n");
            return 1;
        }
    }

    srand((unsigned int)time(NULL));
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create plaintxt socket
    int plain_sock = -1;
    if (servercfg.plaintext_enabled && servercfg.plaintext_port > 0) {
        plain_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (plain_sock < 0) {
            perror("plain socket() failed");
            return 1;
        }

        int opt = 1;
        setsockopt(plain_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((uint16_t)servercfg.plaintext_port);

        if (bind(plain_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("plain bind() failed");
            log_msg(LOG_ERROR, "plain bind() failed");
            return 1;
        }

        if (listen(plain_sock, 128) < 0) {
            perror("plain listen() failed");
            log_msg(LOG_ERROR, "plain listen() failed");
            return 1;
        }
        log_msg(LOG_INFO, "Plaintext listener ready on port %d", servercfg.plaintext_port);
    }

    // Create TLS socket
    int tls_sock = -1;
    if (servercfg.tls_enabled) {
        tls_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (tls_sock < 0) {
            perror("TLS socket() failed");
            return 1;
        }

        int opt = 1;
        setsockopt(tls_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((uint16_t)servercfg.tls_port);

        if (bind(tls_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("TLS bind() failed");
            log_msg(LOG_ERROR, "TLS bind() failed");
            return 1;
        }

        if (listen(tls_sock, 128) < 0) {
            perror("TLS Listen() failed");
            log_msg(LOG_ERROR, "TLS Listen() failed");
            return 1;
        }
        log_msg(LOG_INFO, "TLS listener ready on port %d", servercfg.tls_port);
    }

    if (plain_sock < 0 && tls_sock < 0) {
        fprintf(stderr, "No listeners configured!\n");
        return 1;
    }

    pthread_t http_stats_thread;
    if (pthread_create(&http_stats_thread, NULL, http_stats_server, NULL) != 0) {
        perror("pthread_create() failed for HTTP stats server");
        log_msg(LOG_ERROR, "pthread_create() failed for HTTP stats server");
    } else {
        pthread_detach(http_stats_thread);
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1() failed");
        log_msg(LOG_ERROR, "epoll_create1() failed");
        return 1;
    }

    struct epoll_event ev, events[2];
    ev.events = EPOLLIN;

    // Add plain socket
    if (plain_sock >= 0) {
        ev.data.fd = plain_sock;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, plain_sock, &ev) < 0) {
            perror("epoll_ctl() failed for plain socket");
            log_msg(LOG_ERROR, "epoll_ctl() failed for plain socket");
            return 1;
        }
    }

    // Add TLS socket
    if (tls_sock >= 0) {
        ev.data.fd = tls_sock;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tls_sock, &ev) < 0) {
            perror("epoll_ctl() failed for TLS socket");
            log_msg(LOG_ERROR, "epoll_ctl() failed for TLS socket");
            return 1;
        }
    }

    // Create ZMQ listener thread
    servercfg.zmq_newhash = false;
    if (servercfg.zmq_enabled) {
        pthread_t zmq_thread;
        if (pthread_create(&zmq_thread, NULL, zmq_listener_thread, NULL) != 0) {
            perror("pthread_create() failed for ZMQ thread");
            log_msg(LOG_ERROR, "pthread_create() failed for ZMQ thread");
            log_msg(LOG_WARN, "Failed to start ZMQ listener, continuing without it");
        } else {
            pthread_detach(zmq_thread);
            log_msg(LOG_INFO, "ZMQ monitoring started");
        }
    }

    // Create job update thread
    pthread_t job_thread;
    if (pthread_create(&job_thread, NULL, job_update_thread, NULL) != 0) {
        perror("pthread_create() failed for job thread");
        log_msg(LOG_ERROR, "pthread_create() failed for job thread");
        return 1;
    }

    // Create difficulty adjustment thread
    pthread_t diff_thread;
    if (pthread_create(&diff_thread, NULL, difficulty_adjustment_thread, NULL) != 0) {
        perror("pthread_create() failed for difficulty thread");
        log_msg(LOG_ERROR, "pthread_create() failed for difficulty thread");
        return 1;
    }

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, 2, 100); // 100ms timeout

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            // Accept from plain socket
            if (fd == plain_sock) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(plain_sock, (struct sockaddr*)&client_addr, &client_len);

                if (client_sock >= 0) {

                    //log_msg(LOG_INFO, "Plaintext connection from %s:%d",
                    //        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

                    int *conn_info = malloc(sizeof(int) * 2);
                    conn_info[0] = client_sock;
                    conn_info[1] = 0;

                    pthread_t client_thread;
                    if (pthread_create(&client_thread, NULL, handle_client, conn_info) == 0) {
                        pthread_detach(client_thread);
                    } else {
                        free(conn_info);
                        close(client_sock);
                    }
                }
            }

            // Accept from TLS socket
            if (tls_sock >= 0 && fd == tls_sock) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(tls_sock, (struct sockaddr*)&client_addr, &client_len);

                if (client_sock >= 0) {

                	//log_msg(LOG_INFO, "TLS connection from %s:%d",
                    //        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

                    int *conn_info = malloc(sizeof(int) * 2);
                    conn_info[0] = client_sock;
                    conn_info[1] = 1;

                    pthread_t client_thread;
                    if (pthread_create(&client_thread, NULL, handle_client, conn_info) == 0) {
                        pthread_detach(client_thread);
                    } else {
                        free(conn_info);
                        close(client_sock);
                    }
                }
            }
        }
    }

    close(epoll_fd);
    if (plain_sock >= 0) close(plain_sock);
    if (tls_sock >= 0) close(tls_sock);
    if (global_ssl_ctx) SSL_CTX_free(global_ssl_ctx);
    curl_global_cleanup();

    return 0;
}
