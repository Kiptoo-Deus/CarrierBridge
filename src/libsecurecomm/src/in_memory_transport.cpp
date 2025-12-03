#include "securecomm/transport.hpp"
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <map>

namespace securecomm {

class InMemoryTransport;

// Global bridge to connect transports with proper ownership
class TransportBridge {
private:
    struct Connection {
        std::weak_ptr<InMemoryTransport> peer;
    };
    
    static std::map<InMemoryTransport*, Connection> connections;
    static std::mutex bridge_mutex;
    
public:
    static void connect(InMemoryTransport* a, std::shared_ptr<InMemoryTransport> b) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        connections[a].peer = b;
        std::cout << "TransportBridge: Connected " << a << " -> " << b.get() << std::endl;
    }
    
    static void disconnect(InMemoryTransport* a) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        connections.erase(a);
    }
    
    static std::shared_ptr<InMemoryTransport> get_peer(InMemoryTransport* a) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        auto it = connections.find(a);
        if (it != connections.end()) {
            return it->second.peer.lock();
        }
        return nullptr;
    }
};

// Initialize static members
std::map<InMemoryTransport*, TransportBridge::Connection> TransportBridge::connections;
std::mutex TransportBridge::bridge_mutex;

class InMemoryTransport : public Transport {
public:
    InMemoryTransport() : running_(false) {
        std::cout << "InMemoryTransport constructor: " << this << std::endl;
    }
    
    ~InMemoryTransport() override { 
        std::cout << "InMemoryTransport destructor: " << this << std::endl;
        stop();
        TransportBridge::disconnect(this);
    }

    void start() override {
        std::cout << "InMemoryTransport::start() called for " << this << std::endl;
        
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) {
            std::cout << "Transport " << this << " already started, skipping" << std::endl;
            return;
        }
        
        worker_ = std::thread([this] {
            std::cout << "Transport worker thread started for " << this << std::endl;
            std::unique_lock<std::mutex> lk(mutex_);
            while (running_) {
                cond_.wait(lk, [this]{ return !queue_.empty() || !running_; });
                std::cout << "Transport " << this << " worker woke up, queue size: " << queue_.size() << std::endl;
                while (!queue_.empty()) {
                    auto msg = queue_.front(); queue_.pop();
                    lk.unlock();
                    if (on_message_) {
                        std::cout << "Transport " << this << " calling on_message callback" << std::endl;
                        on_message_(msg);
                    } else {
                        std::cout << "Transport " << this << " ERROR: on_message_ callback is null!" << std::endl;
                    }
                    lk.lock();
                }
            }
            std::cout << "Transport worker thread exiting for " << this << std::endl;
        });
        std::cout << "InMemoryTransport::start() completed for " << this << std::endl;
    }

    void stop() override {
        std::cout << "InMemoryTransport::stop() for " << this << std::endl;
        running_ = false;
        cond_.notify_all();
        if (worker_.joinable()) {
            worker_.join();
            std::cout << "Transport worker joined for " << this << std::endl;
        }
    }

    void send(const std::vector<uint8_t>& bytes) override {
        std::cout << "Transport " << this << " sending " << bytes.size() << " bytes" << std::endl;
        
        auto peer = TransportBridge::get_peer(this);
        if (peer) {
            std::cout << "Transport " << this << " delivering to peer " << peer.get() << std::endl;
            peer->deliver(bytes);
        } else {
            std::cout << "Transport " << this << " has NO peer! Delivering to self." << std::endl;
            deliver(bytes);  // Fallback: deliver to self
        }
    }
    
    void deliver(const std::vector<uint8_t>& bytes) {
        std::cout << "Transport " << this << " delivering " << bytes.size() << " bytes to own queue" << std::endl;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            queue_.push(bytes);
        }
        cond_.notify_one();
    }

    void set_on_message(OnMessageCb cb) override { 
        std::cout << "Transport " << this << " setting on_message callback" << std::endl;
        on_message_ = cb; 
    }

private:
    std::mutex mutex_;
    std::condition_variable cond_;
    std::queue<std::vector<uint8_t>> queue_;
    OnMessageCb on_message_;
    std::thread worker_;
    std::atomic<bool> running_;
};

} // namespace securecomm

// Global static pair shared by both factory functions
namespace {
    static std::pair<
        std::shared_ptr<securecomm::InMemoryTransport>,
        std::shared_ptr<securecomm::InMemoryTransport>
    > global_transport_pair;
    static std::once_flag global_pair_flag;
    
    void initialize_global_pair() {
        auto transportA = std::make_shared<securecomm::InMemoryTransport>();
        auto transportB = std::make_shared<securecomm::InMemoryTransport>();
        
        // Connect them bidirectionally
        securecomm::TransportBridge::connect(transportA.get(), transportB);
        securecomm::TransportBridge::connect(transportB.get(), transportA);
        
        std::cout << "Created connected transport pair: A=" << transportA.get() 
                  << " <-> B=" << transportB.get() << std::endl;
        
        global_transport_pair = {transportA, transportB};
    }
}

// Factory function for transport A
extern "C" securecomm::Transport* create_inmemory_transport_a() {
    std::call_once(global_pair_flag, initialize_global_pair);
    return global_transport_pair.first.get();
}

// Factory function for transport B
extern "C" securecomm::Transport* create_inmemory_transport_b() {
    std::call_once(global_pair_flag, initialize_global_pair);
    return global_transport_pair.second.get();
}

// For backward compatibility
extern "C" securecomm::Transport* create_inmemory_transport() {
    return create_inmemory_transport_a();
}