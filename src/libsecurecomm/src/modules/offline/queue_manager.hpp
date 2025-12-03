#pragma once

#include <vector>
#include <string>
#include <optional>
#include <functional>
#include <memory>
#include <chrono>

namespace securecomm {

class OfflineQueue {
public:
    struct QueuedMessage {
        int64_t id;
        std::string message_id;
        std::string recipient_id;
        std::vector<uint8_t> envelope;
        std::chrono::system_clock::time_point created_at;
        int retry_count;
        std::chrono::system_clock::time_point last_attempt;
        std::string status; // "pending", "delivered", "failed"
    };
    
    OfflineQueue();
    ~OfflineQueue();
    
    // Initialize with database path
    bool initialize(const std::string& db_path);
    
    // Queue a message for delivery
    bool queue_message(const std::string& message_id,
                      const std::string& recipient_id,
                      const std::vector<uint8_t>& envelope);
    
    // Get all pending messages
    std::vector<QueuedMessage> get_pending_messages();
    
    // Mark message as delivered
    bool mark_delivered(const std::string& message_id);
    
    // Mark message as failed (increment retry count)
    bool mark_failed(const std::string& message_id);
    
    // Clean up old delivered/failed messages
    void cleanup_old_messages(int days_to_keep = 30);
    
    // Get statistics
    struct Stats {
        int pending_count;
        int delivered_count;
        int failed_count;
        int total_retries;
    };
    
    Stats get_stats() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecomm
