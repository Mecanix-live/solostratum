/*
 * stats.h
 *
 *  Created on: Feb 14, 2026
 *      Author: mecanix
 *      Email: mecanix@blockaxe.io
 * 		Support: https://discord.gg/QpQBCRvdcZ
 */

#ifndef STATS_H_
#define STATS_H_

#include "solostratum.h"
#include <sqlite3.h>


#define STATS_FLUSH_INTERVAL 5	// Flush every 5 seconds
#define MAX_PENDING 5000		// Ring buffer size

typedef struct {
    time_t timestamp;
    char wallet[128];
    char worker[64];
    double difficulty;
    bool accepted;
    double hashrate;
    bool is_disconnect;
} PendingUpdate;

typedef struct {
    sqlite3 *db;
    pthread_mutex_t db_mutex;
    pthread_mutex_t pending_mutex;

    char instance[128];
    char db_path[256];

    PendingUpdate pending[MAX_PENDING];
    int head;
    int count;

    pthread_t flush_thread;
    bool running;
} StatsContext;

extern StatsContext g_stats;

bool stats_init(const char *instance);
void stats_shutdown(void);
void stats_share_accepted(Client *client, double difficulty);
void stats_share_rejected(Client *client, double difficulty);
void stats_worker_heartbeat(Client *client);
void stats_worker_disconnect(Client *client);

// HTTP API
char* stats_get_server_json(void);
char* stats_get_wallet_json(const char *address);
char* stats_get_blocks_json(void);
void stats_block_found(uint32_t height, const char *hash, const char *finder);

#endif /* STATS_H_ */
