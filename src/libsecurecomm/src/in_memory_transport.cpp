#include "securecomm/transport.hpp"
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace securecomm {

class InMemoryTransport : public Transport {
public:
    InMemoryTransport() : running_(false) {}
    ~InMemoryTransport() override { stop(); }

    void start() override {
        std::cout << "InMemoryTransport::start() called" << std::endl;
        
        // Check if already running - make idempotent
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) {
            std::cout << "Transport already started, skipping" << std::endl;
            return;
        }
        
        running_ = true;
        worker_ = std::thread([this] {
            std::cout << "Transport worker thread started" << std::endl;
            std::unique_lock<std::mutex> lk(mutex_);
            while (running_) {
                cond_.wait(lk, [this]{ return !queue_.empty() || !running_; });
                std::cout << "Transport worker woke up, queue size: " << queue_.size() << std::endl;
                while (!queue_.empty()) {
                    auto msg = queue_.front(); queue_.pop();
                    lk.unlock();
                    if (on_message_) {
                        std::cout << "Transport calling on_message callback" << std::endl;
                        on_message_(msg);
                    } else {
                        std::cout << "Transport ERROR: on_message_ callback is null!" << std::endl;
                    }
                    lk.lock();
                }
            }
            std::cout << "Transport worker thread exiting" << std::endl;
        });
        std::cout << "InMemoryTransport::start() completed" << std::endl;
    }

    void stop() override {
        running_ = false;
        cond_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    void send(const std::vector<uint8_t>& bytes) override {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            queue_.push(bytes);
        }
        cond_.notify_one();
    }

    void set_on_message(OnMessageCb cb) override { on_message_ = cb; }

private:
    std::mutex mutex_;
    std::condition_variable cond_;
    std::queue<std::vector<uint8_t>> queue_;
    OnMessageCb on_message_;
    std::thread worker_;
    std::atomic<bool> running_;
};

} // namespace securecomm

// Factory for test/demo usage
extern "C" securecomm::Transport* create_inmemory_transport() {
    return new securecomm::InMemoryTransport();
}