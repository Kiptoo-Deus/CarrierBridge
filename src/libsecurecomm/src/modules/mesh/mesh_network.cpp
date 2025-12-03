#include "mesh_network.hpp"
#include <sodium.h>
#include <chrono>
#include <algorithm>
#include <iostream>
#include <cstdio>

namespace securecomm {

struct MeshNetwork::Impl {
    std::string device_id;
    std::string mesh_id;
    std::atomic<bool> running{false};
    
    // Mesh state
    mutable std::mutex state_mutex;
    std::map<std::string, MeshPeer> peers;
    std::set<std::vector<uint8_t>> seen_packets;
    std::queue<MeshPacket> send_queue;
    
    // Callbacks
    OnPacketReceived on_packet_received;
    OnPeerDiscovered on_peer_discovered;
    
    // Threads
    std::thread discovery_thread;
    std::thread routing_thread;
    
    Impl() {
        // Generate unique mesh ID
        unsigned char mesh_id_bytes[8];
        randombytes_buf(mesh_id_bytes, sizeof(mesh_id_bytes));
        char hex[17] = {0};
        for (int i = 0; i < 8; i++) {
            snprintf(hex + i*2, 3, "%02x", mesh_id_bytes[i]);
        }
        mesh_id = std::string(hex, 16);
        std::cout << "[Mesh] Generated mesh ID: " << mesh_id << std::endl;
    }
    
    void start_discovery() {
        int discovery_counter = 0;
        while (running) {
            // Simulate discovering peers (in real implementation, use Bluetooth/WiFi Direct)
            {
                std::lock_guard<std::mutex> lock(state_mutex);
                
                // Check if we should simulate new peer discovery
                if (discovery_counter++ % 10 == 0) {
                    MeshPeer new_peer;
                    new_peer.mesh_id = "simulated-peer-" + std::to_string(discovery_counter);
                    new_peer.device_id = "device-" + std::to_string(discovery_counter);
                    new_peer.address = "00:11:22:33:44:55";
                    new_peer.has_internet = (discovery_counter % 3 == 0); // 1/3 have internet
                    new_peer.signal_strength = 75;
                    new_peer.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    
                    if (peers.find(new_peer.mesh_id) == peers.end()) {
                        peers[new_peer.mesh_id] = new_peer;
                        
                        if (on_peer_discovered) {
                            std::cout << "[Mesh] Discovered new peer: " << new_peer.device_id << std::endl;
                            on_peer_discovered(new_peer);
                        }
                    }
                }
                
                // Remove old peers (timeout after 5 minutes)
                auto now = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                
                for (auto it = peers.begin(); it != peers.end(); ) {
                    if (now - it->second.last_seen > 300) { // 5 minutes
                        std::cout << "[Mesh] Peer timeout: " << it->second.device_id << std::endl;
                        it = peers.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    void start_routing() {
        while (running) {
            // Process send queue
            MeshPacket packet;
            bool has_packet = false;
            
            {
                std::lock_guard<std::mutex> lock(state_mutex);
                if (!send_queue.empty()) {
                    packet = send_queue.front();
                    send_queue.pop();
                    has_packet = true;
                }
            }
            
            if (has_packet) {
                // Flood packet to all peers
                std::lock_guard<std::mutex> lock(state_mutex);
                
                // Check if we've seen this packet before
                if (seen_packets.find(packet.packet_id) != seen_packets.end()) {
                    continue; // Already processed
                }
                
                seen_packets.insert(packet.packet_id);
                
                // Decrement TTL and increment hops
                if (packet.ttl > 0) {
                    packet.ttl--;
                    packet.hops++;
                    
                    // Check if we're the recipient
                    if (packet.recipient_device_id == device_id) {
                        if (on_packet_received) {
                            std::cout << "[Mesh] Packet received for us from: " 
                                      << packet.sender_mesh_id << std::endl;
                            on_packet_received(packet);
                        }
                    } else {
                        // Forward to all peers
                        int internet_peers = 0;
                        for (const auto& peer_pair : peers) {
                            if (peer_pair.second.has_internet) {
                                internet_peers++;
                                // In real implementation, send via Bluetooth/WiFi Direct
                                std::cout << "[Mesh] Peer " << peer_pair.second.device_id 
                                          << " has internet, could relay packet" << std::endl;
                            }
                        }
                        if (internet_peers > 0) {
                            std::cout << "[Mesh] Found " << internet_peers 
                                      << " peer(s) with internet for relay" << std::endl;
                        }
                    }
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    std::vector<uint8_t> generate_packet_id() {
        std::vector<uint8_t> id(16);
        randombytes_buf(id.data(), id.size());
        return id;
    }
};

MeshNetwork::MeshNetwork() : impl_(std::make_unique<Impl>()) {}

MeshNetwork::~MeshNetwork() {
    stop();
}

void MeshNetwork::initialize(const std::string& device_id) {
    impl_->device_id = device_id;
    std::cout << "[Mesh] Initialized with device ID: " << device_id << std::endl;
}

void MeshNetwork::start() {
    if (impl_->running) return;
    
    impl_->running = true;
    impl_->discovery_thread = std::thread([this]() { impl_->start_discovery(); });
    impl_->routing_thread = std::thread([this]() { impl_->start_routing(); });
    
    std::cout << "[Mesh] Network started" << std::endl;
}

void MeshNetwork::stop() {
    impl_->running = false;
    
    if (impl_->discovery_thread.joinable()) {
        impl_->discovery_thread.join();
    }
    if (impl_->routing_thread.joinable()) {
        impl_->routing_thread.join();
    }
    
    std::cout << "[Mesh] Network stopped" << std::endl;
}

void MeshNetwork::send_packet(const std::string& recipient_device_id, 
                             const std::vector<uint8_t>& payload) {
    MeshPacket packet;
    packet.packet_id = impl_->generate_packet_id();
    packet.sender_mesh_id = impl_->mesh_id;
    packet.recipient_device_id = recipient_device_id;
    packet.payload = payload;
    packet.ttl = 10; // Max hops
    packet.hops = 0;
    packet.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::lock_guard<std::mutex> lock(impl_->state_mutex);
    impl_->send_queue.push(packet);
    std::cout << "[Mesh] Packet queued for delivery to: " << recipient_device_id << std::endl;
}

void MeshNetwork::broadcast(const std::vector<uint8_t>& payload) {
    // Broadcast to special "all" recipient
    send_packet("broadcast", payload);
}

bool MeshNetwork::has_internet_connection() const {
    std::lock_guard<std::mutex> lock(impl_->state_mutex);
    for (const auto& peer_pair : impl_->peers) {
        if (peer_pair.second.has_internet) {
            return true;
        }
    }
    return false;
}

std::vector<MeshNetwork::MeshPeer> MeshNetwork::get_peers() const {
    std::lock_guard<std::mutex> lock(impl_->state_mutex);
    std::vector<MeshPeer> result;
    for (const auto& peer_pair : impl_->peers) {
        result.push_back(peer_pair.second);
    }
    return result;
}

void MeshNetwork::set_on_packet_received(OnPacketReceived cb) {
    impl_->on_packet_received = cb;
}

void MeshNetwork::set_on_peer_discovered(OnPeerDiscovered cb) {
    impl_->on_peer_discovered = cb;
}

} // namespace securecomm
