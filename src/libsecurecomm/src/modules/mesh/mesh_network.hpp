#pragma once

#include <vector>
#include <string>
#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <chrono>

namespace securecomm {

class MeshNetwork {
public:
    struct MeshPacket {
        std::vector<uint8_t> packet_id;
        std::string sender_mesh_id;
        std::string recipient_device_id;
        std::vector<uint8_t> payload;
        uint8_t ttl;
        uint8_t hops;
        uint64_t timestamp;
    };
    
    struct MeshPeer {
        std::string mesh_id;
        std::string device_id;
        std::string address; // Bluetooth MAC, IP, etc.
        bool has_internet;
        int signal_strength;
        uint64_t last_seen;
    };
    
    using OnPacketReceived = std::function<void(const MeshPacket&)>;
    using OnPeerDiscovered = std::function<void(const MeshPeer&)>;
    
    MeshNetwork();
    ~MeshNetwork();
    
    // Initialize mesh with device ID
    void initialize(const std::string& device_id);
    
    // Start mesh discovery and routing
    void start();
    
    // Stop mesh networking
    void stop();
    
    // Send packet through mesh
    void send_packet(const std::string& recipient_device_id, 
                    const std::vector<uint8_t>& payload);
    
    // Broadcast to all mesh peers
    void broadcast(const std::vector<uint8_t>& payload);
    
    // Check if any peer has internet connectivity
    bool has_internet_connection() const;
    
    // Get all discovered peers
    std::vector<MeshPeer> get_peers() const;
    
    // Callbacks
    void set_on_packet_received(OnPacketReceived cb);
    void set_on_peer_discovered(OnPeerDiscovered cb);
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecomm
