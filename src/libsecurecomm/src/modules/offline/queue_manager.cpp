#include "queue_manager.hpp"
#include <sqlite3.h>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace securecomm {

struct OfflineQueue::Impl {
    sqlite3* db = nullptr;
    
    ~Impl() {
        if (db) sqlite3_close(db);
    }
    
    bool exec(const std::string& sql) {
        char* err = nullptr;
        if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
            std::cerr << "[OfflineQueue] SQLite error: " << err << std::endl;
            sqlite3_free(err);
            return false;
        }
        return true;
    }
};

OfflineQueue::OfflineQueue() : impl_(std::make_unique<Impl>()) {}

OfflineQueue::~OfflineQueue() = default;

bool OfflineQueue::initialize(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &impl_->db) != SQLITE_OK) {
        std::cerr << "[OfflineQueue] Cannot open database: " 
                  << sqlite3_errmsg(impl_->db) << std::endl;
        return false;
    }
    
    std::cout << "[OfflineQueue] Opened database at: " << db_path << std::endl;
    
    // Enable WAL mode for better concurrency
    impl_->exec("PRAGMA journal_mode=WAL");
    
    // Create messages table
    const char* create_table_sql = R"(
        CREATE TABLE IF NOT EXISTS queued_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE NOT NULL,
            recipient_id TEXT NOT NULL,
            envelope BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            last_attempt INTEGER NOT NULL,
            retry_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            
            UNIQUE(message_id)
        );
        
        CREATE INDEX IF NOT EXISTS idx_status ON queued_messages(status);
        CREATE INDEX IF NOT EXISTS idx_recipient ON queued_messages(recipient_id);
        CREATE INDEX IF NOT EXISTS idx_created ON queued_messages(created_at);
    )";
    
    if (!impl_->exec(create_table_sql)) {
        return false;
    }
    
    std::cout << "[OfflineQueue] Database initialized successfully" << std::endl;
    return true;
}

bool OfflineQueue::queue_message(const std::string& message_id,
                                 const std::string& recipient_id,
                                 const std::vector<uint8_t>& envelope) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        INSERT OR REPLACE INTO queued_messages 
        (message_id, recipient_id, envelope, created_at, last_attempt, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
    )";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[OfflineQueue] Failed to prepare statement: " 
                  << sqlite3_errmsg(impl_->db) << std::endl;
        return false;
    }
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    sqlite3_bind_text(stmt, 1, message_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, recipient_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, envelope.data(), envelope.size(), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, now);
    sqlite3_bind_int64(stmt, 5, now);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    if (!success) {
        std::cerr << "[OfflineQueue] Failed to insert message: " 
                  << sqlite3_errmsg(impl_->db) << std::endl;
    } else {
        std::cout << "[OfflineQueue] Queued message: " << message_id 
                  << " for recipient: " << recipient_id << std::endl;
    }
    sqlite3_finalize(stmt);
    
    return success;
}

std::vector<OfflineQueue::QueuedMessage> OfflineQueue::get_pending_messages() {
    std::vector<QueuedMessage> messages;
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT id, message_id, recipient_id, envelope, 
               created_at, last_attempt, retry_count, status
        FROM queued_messages 
        WHERE status = 'pending' 
        ORDER BY created_at ASC
        LIMIT 100
    )";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[OfflineQueue] Failed to prepare query: " 
                  << sqlite3_errmsg(impl_->db) << std::endl;
        return messages;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QueuedMessage msg;
        msg.id = sqlite3_column_int64(stmt, 0);
        msg.message_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        msg.recipient_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        
        // Get envelope blob
        const void* blob = sqlite3_column_blob(stmt, 3);
        int blob_size = sqlite3_column_bytes(stmt, 3);
        msg.envelope.assign(static_cast<const uint8_t*>(blob), 
                           static_cast<const uint8_t*>(blob) + blob_size);
        
        msg.created_at = std::chrono::system_clock::time_point(
            std::chrono::seconds(sqlite3_column_int64(stmt, 4)));
        msg.last_attempt = std::chrono::system_clock::time_point(
            std::chrono::seconds(sqlite3_column_int64(stmt, 5)));
        msg.retry_count = sqlite3_column_int(stmt, 6);
        msg.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        
        messages.push_back(msg);
    }
    
    sqlite3_finalize(stmt);
    return messages;
}

bool OfflineQueue::mark_delivered(const std::string& message_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE queued_messages SET status = 'delivered' WHERE message_id = ?";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, message_id.c_str(), -1, SQLITE_STATIC);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    if (success) {
        std::cout << "[OfflineQueue] Marked as delivered: " << message_id << std::endl;
    }
    sqlite3_finalize(stmt);
    
    return success;
}

bool OfflineQueue::mark_failed(const std::string& message_id) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        UPDATE queued_messages 
        SET status = 'failed', 
            last_attempt = ?,
            retry_count = retry_count + 1
        WHERE message_id = ?
    )";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_text(stmt, 2, message_id.c_str(), -1, SQLITE_STATIC);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return success;
}

void OfflineQueue::cleanup_old_messages(int days_to_keep) {
    auto cutoff = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() - (days_to_keep * 86400);
    
    std::ostringstream sql;
    sql << "DELETE FROM queued_messages WHERE created_at < " << cutoff 
        << " AND status IN ('delivered', 'failed')";
    
    if (impl_->exec(sql.str())) {
        std::cout << "[OfflineQueue] Cleaned up old messages" << std::endl;
    }
}

OfflineQueue::Stats OfflineQueue::get_stats() const {
    Stats stats = {0, 0, 0, 0};
    
    const char* sql = R"(
        SELECT 
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
            COUNT(CASE WHEN status = 'delivered' THEN 1 END) as delivered,
            COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
            COALESCE(SUM(retry_count), 0) as total_retries
        FROM queued_messages
    )";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.pending_count = sqlite3_column_int(stmt, 0);
            stats.delivered_count = sqlite3_column_int(stmt, 1);
            stats.failed_count = sqlite3_column_int(stmt, 2);
            stats.total_retries = sqlite3_column_int(stmt, 3);
        }
        sqlite3_finalize(stmt);
    }
    
    return stats;
}

} // namespace securecomm
