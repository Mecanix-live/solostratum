/*
 * stats.c
 *
 *  Created on: Feb 14, 2026
 *      Author: mecanix
 *      Email: mecanix@blockaxe.io
 * 		Support: https://discord.gg/QpQBCRvdcZ
 */

#include "stats.h"
#include <sys/stat.h>

StatsContext g_stats = {0};

static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;"

    "CREATE TABLE IF NOT EXISTS wallets ("
    "    address TEXT PRIMARY KEY,"
    "    total_shares INTEGER DEFAULT 0,"
    "    accepted_shares INTEGER DEFAULT 0,"
    "    rejected_shares INTEGER DEFAULT 0,"
    "    highest_difficulty REAL DEFAULT 0,"
    "    first_seen INTEGER NOT NULL,"
    "    last_seen INTEGER NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS workers ("
    "    wallet_address TEXT NOT NULL,"
    "    worker_name TEXT NOT NULL,"
    "    total_shares INTEGER DEFAULT 0,"
    "    accepted_shares INTEGER DEFAULT 0,"
    "    rejected_shares INTEGER DEFAULT 0,"
    "    highest_difficulty REAL DEFAULT 0,"
    "    current_hashrate REAL DEFAULT 0,"
    "    first_seen INTEGER NOT NULL,"
    "    last_seen INTEGER NOT NULL,"
    "    PRIMARY KEY(wallet_address, worker_name)"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_workers_wallet ON workers(wallet_address);"

    "CREATE TABLE IF NOT EXISTS blocks ("
    "    height INTEGER PRIMARY KEY,"
    "    hash TEXT NOT NULL,"
    "    finder TEXT NOT NULL,"
    "    timestamp INTEGER NOT NULL"
    ");";

static void process_pending(void);
static void* flush_thread(void *arg);

static bool ensure_directories(const char *instance) {
    struct stat st = {0};

    if (stat("stats", &st) == -1 && mkdir("stats", 0755) == -1) {
        log_msg(LOG_ERROR, "Cannot create stats directory");
        return false;
    }

    char path[256];
    snprintf(path, sizeof(path), "stats/%s", instance);
    if (stat(path, &st) == -1 && mkdir(path, 0755) == -1) {
        log_msg(LOG_ERROR, "Cannot create instance directory %s", path);
        return false;
    }

    return true;
}

bool stats_init(const char *instance) {

    strncpy(g_stats.instance, instance, sizeof(g_stats.instance)-1);

    if (!ensure_directories(instance)) {
        return false;
    }

    snprintf(g_stats.db_path, sizeof(g_stats.db_path),
             "stats/%s/stats.db", instance);

    pthread_mutex_init(&g_stats.db_mutex, NULL);
    pthread_mutex_init(&g_stats.pending_mutex, NULL);

    int rc = sqlite3_open(g_stats.db_path, &g_stats.db);
    if (rc != SQLITE_OK) {
        log_msg(LOG_ERROR, "Cannot open database: %s", sqlite3_errmsg(g_stats.db));
        return false;
    }

    char *err = NULL;
    rc = sqlite3_exec(g_stats.db, SCHEMA, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        log_msg(LOG_ERROR, "Cannot create schema: %s", err);
        sqlite3_free(err);
        return false;
    }

    // Use RAM for batch queueing and temporary storage
    sqlite3_exec(g_stats.db, "PRAGMA temp_store = MEMORY;", NULL, NULL, NULL);

    g_stats.running = true;
    pthread_create(&g_stats.flush_thread, NULL, flush_thread, NULL);

    log_msg(LOG_INFO, "Stats initialized: %s", g_stats.db_path);
    return true;
}

void stats_shutdown(void) {
    g_stats.running = false;
    pthread_join(g_stats.flush_thread, NULL);
    process_pending();  // Final flush
    sqlite3_close(g_stats.db);
    pthread_mutex_destroy(&g_stats.db_mutex);
    pthread_mutex_destroy(&g_stats.pending_mutex);
}

static void queue_update(const char *wallet, const char *worker,
                         double difficulty, bool accepted,
                         double hashrate, bool disconnect) {
    pthread_mutex_lock(&g_stats.pending_mutex);

    if (g_stats.count < MAX_PENDING) {
        PendingUpdate *p = &g_stats.pending[g_stats.head];
        p->timestamp = time(NULL);
        snprintf(p->wallet, sizeof(p->wallet), "%s", wallet);
        snprintf(p->worker, sizeof(p->worker), "%s", worker);
        p->difficulty = difficulty;
        p->accepted = accepted;
        p->hashrate = hashrate;
        p->is_disconnect = disconnect;
        g_stats.head = (g_stats.head + 1) % MAX_PENDING;
        g_stats.count++;
    } else {
        log_msg(LOG_WARN, "Stats queue full, dropping update");
    }

    pthread_mutex_unlock(&g_stats.pending_mutex);
}

void stats_share_accepted(Client *client, double difficulty) {
    if (!client || !client->authorized) return;
    queue_update(client->address, client->worker_name,
                 difficulty, true,
                 get_hourly_average_hashrate(client), false);
}

void stats_share_rejected(Client *client, double difficulty) {
    if (!client || !client->authorized) return;
    queue_update(client->address, client->worker_name,
                 difficulty, false,
                 get_hourly_average_hashrate(client), false);
}

void stats_worker_heartbeat(Client *client) {
    if (!client || !client->authorized) return;
    queue_update(client->address, client->worker_name,
                 0.0, false,
                 get_hourly_average_hashrate(client), false);
}

void stats_worker_disconnect(Client *client) {
    if (!client || !client->authorized) return;
    queue_update(client->address, client->worker_name,
                 0.0, false, 0.0, true);
}

static void process_pending(void) {
    pthread_mutex_lock(&g_stats.pending_mutex);

    if (g_stats.count == 0) {
        pthread_mutex_unlock(&g_stats.pending_mutex);
        return;
    }

    pthread_mutex_lock(&g_stats.db_mutex);
    sqlite3_exec(g_stats.db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    sqlite3_stmt *wallet_stmt = NULL;
    sqlite3_stmt *worker_stmt = NULL;
    sqlite3_stmt *delete_stmt = NULL;

    // Prepare statements
    const char *wallet_sql =
        "INSERT INTO wallets (address, total_shares, accepted_shares, rejected_shares, "
        "highest_difficulty, first_seen, last_seen) "
        "VALUES (?, 1, ?, ?, ?, ?, ?) "
        "ON CONFLICT(address) DO UPDATE SET "
        "total_shares = total_shares + 1, "
        "accepted_shares = accepted_shares + ?, "
        "rejected_shares = rejected_shares + ?, "
        "highest_difficulty = MAX(highest_difficulty, ?), "
        "last_seen = ?;";

    const char *worker_sql =
        "INSERT INTO workers (wallet_address, worker_name, total_shares, "
        "accepted_shares, rejected_shares, highest_difficulty, "
        "current_hashrate, first_seen, last_seen) "
        "VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(wallet_address, worker_name) DO UPDATE SET "
        "total_shares = total_shares + 1, "
        "accepted_shares = accepted_shares + ?, "
        "rejected_shares = rejected_shares + ?, "
        "highest_difficulty = MAX(highest_difficulty, ?), "
        "current_hashrate = ?, "
        "last_seen = ?;";

    const char *delete_sql =
        "DELETE FROM workers WHERE wallet_address = ? AND worker_name = ?;";

    sqlite3_prepare_v2(g_stats.db, wallet_sql, -1, &wallet_stmt, NULL);
    sqlite3_prepare_v2(g_stats.db, worker_sql, -1, &worker_stmt, NULL);
    sqlite3_prepare_v2(g_stats.db, delete_sql, -1, &delete_stmt, NULL);

    // Process queue
    time_t now = time(NULL);
    int processed = 0;
    int idx = (g_stats.head - g_stats.count + MAX_PENDING) % MAX_PENDING;

    while (processed < g_stats.count) {
        PendingUpdate *p = &g_stats.pending[idx];

        if (p->is_disconnect) {
            // DISCONNECT: Delete the worker
            sqlite3_bind_text(delete_stmt, 1, p->wallet, -1, SQLITE_STATIC);
            sqlite3_bind_text(delete_stmt, 2, p->worker, -1, SQLITE_STATIC);
            sqlite3_step(delete_stmt);
            sqlite3_reset(delete_stmt);

        } else if (p->difficulty > 0 || (fabs(p->difficulty) < 1e-10 && !p->accepted)) {
            // SHARE: Update wallet and worker
            int accepted = p->accepted ? 1 : 0;
            int rejected = p->accepted ? 0 : 1;

            // Update wallet
            sqlite3_bind_text(wallet_stmt, 1, p->wallet, -1, SQLITE_STATIC);
            sqlite3_bind_int(wallet_stmt, 2, accepted);
            sqlite3_bind_int(wallet_stmt, 3, rejected);
            sqlite3_bind_double(wallet_stmt, 4, p->difficulty);
            sqlite3_bind_int64(wallet_stmt, 5, now);  // first_seen if new
            sqlite3_bind_int64(wallet_stmt, 6, now);  // last_seen
            sqlite3_bind_int(wallet_stmt, 7, accepted);
            sqlite3_bind_int(wallet_stmt, 8, rejected);
            sqlite3_bind_double(wallet_stmt, 9, p->difficulty);
            sqlite3_bind_int64(wallet_stmt, 10, now);
            sqlite3_step(wallet_stmt);
            sqlite3_reset(wallet_stmt);

            // Update worker
            sqlite3_bind_text(worker_stmt, 1, p->wallet, -1, SQLITE_STATIC);
            sqlite3_bind_text(worker_stmt, 2, p->worker, -1, SQLITE_STATIC);
            sqlite3_bind_int(worker_stmt, 3, accepted);
            sqlite3_bind_int(worker_stmt, 4, rejected);
            sqlite3_bind_double(worker_stmt, 5, p->difficulty);
            sqlite3_bind_double(worker_stmt, 6, p->hashrate);
            sqlite3_bind_int64(worker_stmt, 7, now);  // first_seen
            sqlite3_bind_int64(worker_stmt, 8, now);  // last_seen
            sqlite3_bind_int(worker_stmt, 9, accepted);
            sqlite3_bind_int(worker_stmt, 10, rejected);
            sqlite3_bind_double(worker_stmt, 11, p->difficulty);
            sqlite3_bind_double(worker_stmt, 12, p->hashrate);
            sqlite3_bind_int64(worker_stmt, 13, now);
            sqlite3_step(worker_stmt);
            sqlite3_reset(worker_stmt);

        } else {
            // HEARTBEAT: Just update hashrate and last_seen
            const char *heartbeat_sql =
                "UPDATE workers SET current_hashrate = ?, last_seen = ? "
                "WHERE wallet_address = ? AND worker_name = ?;";

            sqlite3_stmt *hb_stmt;
            sqlite3_prepare_v2(g_stats.db, heartbeat_sql, -1, &hb_stmt, NULL);
            sqlite3_bind_double(hb_stmt, 1, p->hashrate);
            sqlite3_bind_int64(hb_stmt, 2, now);
            sqlite3_bind_text(hb_stmt, 3, p->wallet, -1, SQLITE_STATIC);
            sqlite3_bind_text(hb_stmt, 4, p->worker, -1, SQLITE_STATIC);
            sqlite3_step(hb_stmt);
            sqlite3_finalize(hb_stmt);
        }

        idx = (idx + 1) % MAX_PENDING;
        processed++;
    }

    sqlite3_finalize(wallet_stmt);
    sqlite3_finalize(worker_stmt);
    sqlite3_finalize(delete_stmt);

    // Delete empty wallets
    const char *cleanup_sql =
        "DELETE FROM wallets WHERE address NOT IN "
        "(SELECT DISTINCT wallet_address FROM workers);";
    sqlite3_exec(g_stats.db, cleanup_sql, NULL, NULL, NULL);

    sqlite3_exec(g_stats.db, "COMMIT", NULL, NULL, NULL);

    // Reset queue
    g_stats.count = 0;
    g_stats.head = 0;

    pthread_mutex_unlock(&g_stats.db_mutex);
    pthread_mutex_unlock(&g_stats.pending_mutex);
}

static void* flush_thread(void *arg) {
    (void)arg;  // Mark as unused

    while (g_stats.running) {
        sleep(STATS_FLUSH_INTERVAL);
        process_pending();
    }

    return NULL;
}

// HTTP API: Server stats
char* stats_get_server_json(void) {
    pthread_mutex_lock(&g_stats.db_mutex);

    json_t *root = json_object();
    sqlite3_stmt *stmt;

    // Blocks found
    sqlite3_prepare_v2(g_stats.db, "SELECT COUNT(*) FROM blocks", -1, &stmt, NULL);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        json_object_set_new(root, "blocks_found", json_integer(sqlite3_column_int64(stmt, 0)));
    }
    sqlite3_finalize(stmt);

    // Active workers (workers that have submitted in last 60 seconds)
    time_t cutoff = time(NULL) - 60;
    sqlite3_prepare_v2(g_stats.db,
        "SELECT COUNT(*) FROM workers WHERE last_seen > ?",
        -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, cutoff);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        json_object_set_new(root, "active_workers", json_integer(sqlite3_column_int64(stmt, 0)));
    }
    sqlite3_finalize(stmt);

    // Active workers list
    sqlite3_prepare_v2(g_stats.db,
        "SELECT wallet_address, worker_name, current_hashrate FROM workers WHERE last_seen > ?",
        -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, cutoff);

    json_t *workers = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_t *w = json_object();
        json_object_set_new(w, "wallet", json_string((const char*)sqlite3_column_text(stmt, 0)));
        json_object_set_new(w, "worker", json_string((const char*)sqlite3_column_text(stmt, 1)));
        json_object_set_new(w, "hashrate", json_real(sqlite3_column_double(stmt, 2)));
        json_array_append_new(workers, w);
    }
    json_object_set_new(root, "workers", workers);
    sqlite3_finalize(stmt);

    // Recent blocks
    sqlite3_prepare_v2(g_stats.db,
        "SELECT height, hash, finder, timestamp FROM blocks ORDER BY timestamp DESC LIMIT 10",
        -1, &stmt, NULL);

    json_t *blocks = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_t *b = json_object();
        json_object_set_new(b, "height", json_integer(sqlite3_column_int64(stmt, 0)));
        json_object_set_new(b, "hash", json_string((const char*)sqlite3_column_text(stmt, 1)));
        json_object_set_new(b, "finder", json_string((const char*)sqlite3_column_text(stmt, 2)));
        json_object_set_new(b, "time", json_integer(sqlite3_column_int64(stmt, 3)));
        json_array_append_new(blocks, b);
    }
    json_object_set_new(root, "recent_blocks", blocks);
    sqlite3_finalize(stmt);

    // Add current block info
    json_object_set_new(root, "current_height", json_integer(job_template.height));
    json_object_set_new(root, "current_hash", json_string(job_template.prev_hash_original));
    json_object_set_new(root, "network_difficulty", json_real(job_template.network_difficulty));

    pthread_mutex_unlock(&g_stats.db_mutex);

    char *json = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    return json;
}

char* stats_get_wallet_json(const char *address) {
    pthread_mutex_lock(&g_stats.db_mutex);

    json_t *root = json_object();
    sqlite3_stmt *stmt;

    // Get wallet info
    sqlite3_prepare_v2(g_stats.db,
        "SELECT total_shares, accepted_shares, rejected_shares, "
        "highest_difficulty, first_seen, last_seen FROM wallets WHERE address = ?",
        -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        json_object_set_new(root, "address", json_string(address));
        json_object_set_new(root, "total_shares", json_integer(sqlite3_column_int64(stmt, 0)));
        json_object_set_new(root, "accepted", json_integer(sqlite3_column_int64(stmt, 1)));
        json_object_set_new(root, "rejected", json_integer(sqlite3_column_int64(stmt, 2)));
        json_object_set_new(root, "highest_diff", json_real(sqlite3_column_double(stmt, 3)));
        json_object_set_new(root, "first_seen", json_integer(sqlite3_column_int64(stmt, 4)));
        json_object_set_new(root, "last_seen", json_integer(sqlite3_column_int64(stmt, 5)));
    }
    sqlite3_finalize(stmt);

    // Get workers for this wallet
    sqlite3_prepare_v2(g_stats.db,
        "SELECT worker_name, total_shares, accepted_shares, rejected_shares, "
        "highest_difficulty, current_hashrate, first_seen, last_seen "
        "FROM workers WHERE wallet_address = ? ORDER BY last_seen DESC",
        -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_STATIC);

    json_t *workers = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_t *w = json_object();
        json_object_set_new(w, "name", json_string((const char*)sqlite3_column_text(stmt, 0)));
        json_object_set_new(w, "shares", json_integer(sqlite3_column_int64(stmt, 1)));
        json_object_set_new(w, "accepted", json_integer(sqlite3_column_int64(stmt, 2)));
        json_object_set_new(w, "rejected", json_integer(sqlite3_column_int64(stmt, 3)));
        json_object_set_new(w, "highest_diff", json_real(sqlite3_column_double(stmt, 4)));
        json_object_set_new(w, "hashrate", json_real(sqlite3_column_double(stmt, 5)));
        json_object_set_new(w, "first_seen", json_integer(sqlite3_column_int64(stmt, 6)));
        json_object_set_new(w, "last_seen", json_integer(sqlite3_column_int64(stmt, 7)));

        // Check if worker is active (last_seen within 60 seconds)
        time_t last = sqlite3_column_int64(stmt, 7);
        json_object_set_new(w, "active", json_boolean(time(NULL) - last < 60));

        json_array_append_new(workers, w);
    }
    json_object_set_new(root, "workers", workers);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_stats.db_mutex);

    char *json = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    return json;
}

char* stats_get_blocks_json(void) {
    pthread_mutex_lock(&g_stats.db_mutex);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_stats.db,
        "SELECT height, hash, finder, timestamp FROM blocks ORDER BY timestamp DESC",
        -1, &stmt, NULL);

    json_t *blocks = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_t *b = json_object();
        json_object_set_new(b, "height", json_integer(sqlite3_column_int64(stmt, 0)));
        json_object_set_new(b, "hash", json_string((const char*)sqlite3_column_text(stmt, 1)));
        json_object_set_new(b, "finder", json_string((const char*)sqlite3_column_text(stmt, 2)));
        json_object_set_new(b, "time", json_integer(sqlite3_column_int64(stmt, 3)));
        json_array_append_new(blocks, b);
    }
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_stats.db_mutex);

    char *json = json_dumps(blocks, JSON_INDENT(2));
    json_decref(blocks);
    return json;
}

void stats_block_found(uint32_t height, const char *hash, const char *finder) {
    pthread_mutex_lock(&g_stats.db_mutex);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_stats.db,
        "INSERT INTO blocks (height, hash, finder, timestamp) VALUES (?, ?, ?, ?)",
        -1, &stmt, NULL);

    sqlite3_bind_int(stmt, 1, (int)height);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, finder, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, time(NULL));

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_stats.db_mutex);

    log_msg(LOG_INFO, "");
    log_msg(LOG_INFO, "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★");
    log_msg(LOG_INFO, "★ BLOCK FOUND! Height: %d - by: %s", height, finder);
    log_msg(LOG_INFO, "★ Hash: %s", hash);
    log_msg(LOG_INFO, "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★");
    log_msg(LOG_INFO, "");
}
