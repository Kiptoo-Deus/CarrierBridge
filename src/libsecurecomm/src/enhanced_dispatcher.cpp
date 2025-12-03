#include "securecomm/enhanced_dispatcher.hpp"
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace securecomm {

EnhancedDispatcher::EnhancedDispatcher(TransportPtr transport, 
                                     const std::string& data_dir)
    : data_dir_(data_dir)
    , connection_state_(STATE_OFFLINE)
    , mesh_enabled_(true)
    , offline_mode_(false) {
    
    // Create dispatcher
    dispatcher_ = std::make_shared<Dispatcher>(transport);
    
    // Initialize offline queue
    offline_queue_ = std::make_unique<OfflineQueue>();
    std::string db_path = data_dir_ + "/carrierbridge_queue.db";
    offline_queue_->initialize(db_path);
    
    // Initialize mesh network
    mesh_network_ = std::make_unique<MeshNetwork>();
    
    // Set mesh network callbacks
    mesh_network_->set_on_packet_received([this](const MeshNetwork::MeshPacket& packet) {
        process_mesh_packet(packet);
    });
    
    std::cout << "[EnhancedDispatcher] Initialized with data_dir: " << data_dir_ << std::endl;
}

EnhancedDispatcher::~EnhancedDispatcher() {
    stop();
}

void EnhancedDispatcher::start() {
    dispatcher_->start();
    
    running_ = true;
    
    // Start mesh networking
    if (mesh_enabled_) {
        mesh_network_->initialize(device_id_);
        mesh_network_->start();
    }
    
    // Start connectivity monitoring thread
    connectivity_thread_ = std::thread([this]() {
        while (running_) {
            check_connectivity();
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    });
    
    // Start retry thread for queued messages
    retry_thread_ = std::thread([this]() {
        while (running_) {
            retry_queued_messages();
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    });
    
    std::cout << "[EnhancedDispatcher] Started" << std::endl;
}

void EnhancedDispatcher::stop() {
    running_ = false;
    
    if (connectivity_thread_.joinable()) {
        connectivity_thread_.join();
    }
    if (retry_thread_.joinable()) {
        retry_thread_.join();
    }
    
    mesh_network_->stop();
    dispatcher_->stop();
    
    std::cout << "[EnhancedDispatcher] Stopped" << std::endl;
}

void EnhancedDispatcher::register_device(const std::string& device_id) {
    device_id_ = device_id;
    dispatcher_->register_device(device_id);
}

void EnhancedDispatcher::create_session_with(const std::string& remote_device_id, 
                                            const std::vector<uint8_t>& root_key) {
    dispatcher_->create_session_with(remote_device_id, root_key);
}

void EnhancedDispatcher::send_message_to_device(const std::string& remote_device_id, 
                                               const std::vector<uint8_t>& plaintext) {
    messages_sent_++;
    
    // Generate unique message ID
    std::ostringstream msg_id;
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    msg_id << device_id_ << "-" << remote_device_id << "-" << timestamp;
    
    try {
        // Send via dispatcher
        dispatcher_->send_message_to_device(remote_device_id, plaintext);
        std::cout << "[EnhancedDispatcher] Message sent via dispatcher" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[EnhancedDispatcher] Failed to send via dispatcher: " 
                  << e.what() << std::endl;
        
        // Queue for later delivery
        offline_queue_->queue_message(msg_id.str(), remote_device_id, plaintext);
        messages_queued_++;
        std::cout << "[EnhancedDispatcher] Message queued for offline delivery" << std::endl;
    }
}

void EnhancedDispatcher::set_on_inbound(Dispatcher::OnInboundMessage cb) {
    dispatcher_->set_on_inbound(cb);
}

void EnhancedDispatcher::check_connectivity() {
    // Check if transport is connected (simplified)
    bool transport_connected = true; // In real implementation, check transport state
    
    ConnectionState new_state;
    if (transport_connected && !offline_mode_) {
        new_state = STATE_ONLINE;
    } else if (mesh_network_->has_internet_connection()) {
        new_state = STATE_MESH_ONLY;
    } else {
        new_state = STATE_OFFLINE;
    }
    
    ConnectionState old_state = connection_state_;
    connection_state_ = new_state;
    
    if (old_state != new_state) {
        std::string state_str;
        switch (new_state) {
            case STATE_ONLINE: state_str = "ONLINE"; break;
            case STATE_MESH_ONLY: state_str = "MESH_ONLY"; break;
            case STATE_CONNECTING: state_str = "CONNECTING"; break;
            case STATE_OFFLINE: state_str = "OFFLINE"; break;
        }
        std::cout << "[EnhancedDispatcher] Connection state changed to: " << state_str << std::endl;
    }
}

void EnhancedDispatcher::retry_queued_messages() {
    if (connection_state_ == STATE_OFFLINE) {
        return;
    }
    
    auto pending = offline_queue_->get_pending_messages();
    
    std::cout << "[EnhancedDispatcher] Checking " << pending.size() 
              << " pending messages for retry" << std::endl;
    
    for (const auto& msg : pending) {
        if (msg.retry_count > 10) { // Max retries
            offline_queue_->mark_failed(msg.message_id);
            std::cout << "[EnhancedDispatcher] Message exceeded max retries: " 
                      << msg.message_id << std::endl;
            continue;
        }
        
        try {
            // Try to send via dispatcher
            dispatcher_->send_message_to_device(msg.recipient_id, msg.envelope);
            offline_queue_->mark_delivered(msg.message_id);
            std::cout << "[EnhancedDispatcher] Retry successful for message: " 
                      << msg.message_id << std::endl;
        } catch (const std::exception& e) {
            offline_queue_->mark_failed(msg.message_id);
            std::cerr << "[EnhancedDispatcher] Retry failed for message: " 
                      << msg.message_id << ", error: " << e.what() << std::endl;
        }
        
        // Small delay between retries
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void EnhancedDispatcher::process_mesh_packet(const MeshNetwork::MeshPacket& packet) {
    if (packet.recipient_device_id == device_id_ || 
        packet.recipient_device_id == "broadcast") {
        
        // This is for us
        try {
            messages_received_++;
            
            // Send ACK if needed
            if (packet.recipient_device_id != "broadcast") {
                // Send ACK back through mesh
                std::vector<uint8_t> ack = {'A','C','K'};
                mesh_network_->send_packet(packet.sender_mesh_id, ack);
            }
        } catch (const std::exception& e) {
            std::cerr << "[EnhancedDispatcher] Failed to process mesh packet: " 
                      << e.what() << std::endl;
        }
    }
}

EnhancedDispatcher::ConnectionState EnhancedDispatcher::get_connection_state() const {
    return connection_state_;
}

void EnhancedDispatcher::enable_mesh_networking(bool enable) {
    mesh_enabled_ = enable;
    if (enable && running_) {
        mesh_network_->start();
        std::cout << "[EnhancedDispatcher] Mesh networking enabled" << std::endl;
    } else if (!enable) {
        mesh_network_->stop();
        std::cout << "[EnhancedDispatcher] Mesh networking disabled" << std::endl;
    }
}

void EnhancedDispatcher::set_offline_mode(bool offline) {
    offline_mode_ = offline;
    std::cout << "[EnhancedDispatcher] Offline mode: " << (offline ? "ON" : "OFF") << std::endl;
}

EnhancedDispatcher::EnhancedStats EnhancedDispatcher::get_stats() const {
    EnhancedStats stats;
    stats.messages_sent = messages_sent_;
    stats.messages_received = messages_received_;
    stats.messages_queued = messages_queued_;
    stats.messages_delivered_via_mesh = messages_delivered_via_mesh_;
    stats.queue_stats = offline_queue_->get_stats();
    return stats;
}

} // namespace securecomm

