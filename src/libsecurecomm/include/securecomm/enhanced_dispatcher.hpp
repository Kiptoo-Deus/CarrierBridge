#pragma once

#include "securecomm/dispatcher.hpp"
#include "securecomm/transport.hpp"
#include "../src/modules/offline/queue_manager.hpp"
#include "../src/modules/mesh/mesh_network.hpp"
#include <string>
#include <memory>
#include <map>
#include <atomic>

namespace securecomm {

class EnhancedDispatcher {
public:
    enum ConnectionState {
        STATE_OFFLINE,
        STATE_MESH_ONLY,
        STATE_CONNECTING,
        STATE_ONLINE
    };
    
    EnhancedDispatcher(TransportPtr transport, 
                      const std::string& data_dir = ".");
    ~EnhancedDispatcher();
    
    // Wrapper methods for dispatcher
    void start();
    void stop();
    void register_device(const std::string& device_id);
    void create_session_with(const std::string& remote_device_id, const std::vector<uint8_t>& root_key);
    void send_message_to_device(const std::string& remote_device_id, 
                               const std::vector<uint8_t>& plaintext);
    void set_on_inbound(Dispatcher::OnInboundMessage cb);
    
    // New methods
    ConnectionState get_connection_state() const;
    void enable_mesh_networking(bool enable);
    void set_offline_mode(bool offline);
    
    // Stats
    struct EnhancedStats {
        int messages_sent;
        int messages_received;
        int messages_queued;
        int messages_delivered_via_mesh;
        OfflineQueue::Stats queue_stats;
    };
    
    EnhancedStats get_stats() const;
    
    // Access to underlying dispatcher
    DispatcherPtr get_dispatcher() { return dispatcher_; }
    
private:
    void check_connectivity();
    void retry_queued_messages();
    void process_mesh_packet(const MeshNetwork::MeshPacket& packet);
    
    DispatcherPtr dispatcher_;
    std::unique_ptr<OfflineQueue> offline_queue_;
    std::unique_ptr<MeshNetwork> mesh_network_;
    std::string data_dir_;
    std::string device_id_;
    std::atomic<ConnectionState> connection_state_;
    std::atomic<bool> mesh_enabled_;
    std::atomic<bool> offline_mode_;
    
    // Stats
    std::atomic<int> messages_sent_{0};
    std::atomic<int> messages_received_{0};
    std::atomic<int> messages_queued_{0};
    std::atomic<int> messages_delivered_via_mesh_{0};
    
    std::thread connectivity_thread_;
    std::thread retry_thread_;
    std::atomic<bool> running_{false};
};

} // namespace securecomm

