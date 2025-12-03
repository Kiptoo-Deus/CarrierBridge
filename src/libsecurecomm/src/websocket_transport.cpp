#include "securecomm/transport.hpp"
#include <curl/curl.h>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <iostream>
#include <vector>
#include <string>
#include <memory>

namespace securecomm {

// Callback for libcurl to write response data
static size_t curl_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    auto* buffer = static_cast<std::vector<uint8_t>*>(userp);
    
    auto* ptr = static_cast<uint8_t*>(contents);
    buffer->insert(buffer->end(), ptr, ptr + realsize);
    
    return realsize;
}

// Callback for libcurl to read request data
static size_t curl_read_callback(void* ptr, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    auto* buffer = static_cast<std::vector<uint8_t>*>(userp);
    
    if (buffer->empty()) {
        return 0;
    }
    
    size_t to_copy = std::min(realsize, buffer->size());
    std::memcpy(ptr, buffer->data(), to_copy);
    buffer->erase(buffer->begin(), buffer->begin() + to_copy);
    
    return to_copy;
}

class WebSocketClientTransport : public Transport {
public:
    WebSocketClientTransport(const std::string& uri) 
        : uri_(uri), connected_(false), running_(false) {
        
        // Convert ws:// to http:// and wss:// to https://
        std::string http_uri = uri;
        if (http_uri.find("ws://") == 0) {
            http_uri.replace(0, 5, "http://");
        } else if (http_uri.find("wss://") == 0) {
            http_uri.replace(0, 6, "https://");
        }
        
        uri_ = http_uri;
        
        // Initialize curl
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_handle_ = curl_easy_init();
        
        if (!curl_handle_) {
            std::cerr << "[WebSocket] Failed to initialize curl handle" << std::endl;
            throw std::runtime_error("Failed to initialize curl");
        }
        
        std::cout << "[WebSocket] Initialized with URI: " << uri_ << std::endl;
    }
    
    ~WebSocketClientTransport() {
        stop();
        
        if (curl_handle_) {
            curl_easy_cleanup(curl_handle_);
            curl_global_cleanup();
        }
    }
    
    void start() override {
        running_ = true;
        
        // Start worker thread for sending
        send_thread_ = std::thread([this]() {
            while (running_) {
                std::vector<uint8_t> data;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    cond_.wait(lock, [this]() { 
                        return !send_queue_.empty() || !running_; 
                    });
                    
                    if (!running_) break;
                    
                    if (!send_queue_.empty()) {
                        data = send_queue_.front();
                        send_queue_.pop();
                    }
                }
                
                if (!data.empty()) {
                    send_impl(data);
                }
            }
        });
        
        // Start worker thread for receiving
        receive_thread_ = std::thread([this]() {
            while (running_) {
                std::vector<uint8_t> data;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    cond_.wait(lock, [this]() { 
                        return !receive_queue_.empty() || !running_; 
                    });
                    
                    if (!running_) break;
                    
                    if (!receive_queue_.empty()) {
                        data = receive_queue_.front();
                        receive_queue_.pop();
                    }
                }
                
                if (!data.empty() && on_message_) {
                    on_message_(data);
                }
            }
        });
        
        // Start polling thread
        poll_thread_ = std::thread([this]() {
            poll_server();
        });
        
        std::cout << "[WebSocket] Transport started, polling: " << uri_ << std::endl;
    }
    
    void stop() override {
        running_ = false;
        connected_ = false;
        cond_.notify_all();
        
        if (send_thread_.joinable()) {
            send_thread_.join();
        }
        if (receive_thread_.joinable()) {
            receive_thread_.join();
        }
        if (poll_thread_.joinable()) {
            poll_thread_.join();
        }
        
        std::cout << "[WebSocket] Transport stopped" << std::endl;
    }
    
    void send(const std::vector<uint8_t>& bytes) override {
        std::lock_guard<std::mutex> lock(mutex_);
        send_queue_.push(bytes);
        cond_.notify_one();
    }
    
    void set_on_message(OnMessageCb cb) override {
        std::lock_guard<std::mutex> lock(mutex_);
        on_message_ = cb;
    }
    
    bool is_connected() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return connected_;
    }
    
private:
    void poll_server() {
        int poll_interval = 1000; // Start at 1 second
        int max_poll_interval = 30000; // Max 30 seconds
        
        while (running_) {
            // Try to connect and check server status
            try {
                std::vector<uint8_t> response;
                
                if (perform_http_request("GET", uri_ + "/health", 
                                        std::vector<uint8_t>(), response)) {
                    connected_ = true;
                    poll_interval = 1000; // Reset to 1 second on success
                    std::cout << "[WebSocket] Connected to server" << std::endl;
                } else {
                    if (connected_) {
                        std::cout << "[WebSocket] Lost connection to server" << std::endl;
                    }
                    connected_ = false;
                    // Exponential backoff
                    poll_interval = std::min(poll_interval * 2, max_poll_interval);
                }
            } catch (const std::exception& e) {
                std::cerr << "[WebSocket] Poll error: " << e.what() << std::endl;
                connected_ = false;
                poll_interval = std::min(poll_interval * 2, max_poll_interval);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval));
        }
    }
    
    void send_impl(const std::vector<uint8_t>& data) {
        if (!connected_) {
            std::cout << "[WebSocket] Cannot send: not connected" << std::endl;
            return;
        }
        
        try {
            std::vector<uint8_t> response;
            std::string endpoint = uri_ + "/message";
            
            if (perform_http_request("POST", endpoint, data, response)) {
                std::cout << "[WebSocket] Sent " << data.size() << " bytes" << std::endl;
            } else {
                std::cerr << "[WebSocket] Send failed" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[WebSocket] Send error: " << e.what() << std::endl;
            std::lock_guard<std::mutex> lock(mutex_);
            connected_ = false;
        }
    }
    
    bool perform_http_request(const std::string& method, const std::string& url,
                             const std::vector<uint8_t>& request_data,
                             std::vector<uint8_t>& response_data) {
        if (!curl_handle_) {
            return false;
        }
        
        // Set URL
        curl_easy_setopt(curl_handle_, CURLOPT_URL, url.c_str());
        
        // Set timeout
        curl_easy_setopt(curl_handle_, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl_handle_, CURLOPT_CONNECTTIMEOUT, 5L);
        
        // Set method
        if (method == "POST") {
            curl_easy_setopt(curl_handle_, CURLOPT_POST, 1L);
            
            if (!request_data.empty()) {
                curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDS, request_data.data());
                curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDSIZE, request_data.size());
            }
        } else if (method == "GET") {
            curl_easy_setopt(curl_handle_, CURLOPT_HTTPGET, 1L);
        }
        
        // Set SSL options for HTTPS
        curl_easy_setopt(curl_handle_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle_, CURLOPT_SSL_VERIFYHOST, 0L);
        
        // Set write callback for response
        curl_easy_setopt(curl_handle_, CURLOPT_WRITEFUNCTION, curl_write_callback);
        curl_easy_setopt(curl_handle_, CURLOPT_WRITEDATA, &response_data);
        
        // Perform request
        CURLcode res = curl_easy_perform(curl_handle_);
        
        if (res != CURLE_OK) {
            std::cerr << "[WebSocket] curl_easy_perform() failed: " 
                      << curl_easy_strerror(res) << std::endl;
            return false;
        }
        
        // Check HTTP response code
        long http_code = 0;
        curl_easy_getinfo(curl_handle_, CURLINFO_RESPONSE_CODE, &http_code);
        
        if (http_code != 200) {
            std::cerr << "[WebSocket] HTTP error code: " << http_code << std::endl;
            return false;
        }
        
        return true;
    }
    
    std::string uri_;
    CURL* curl_handle_;
    std::atomic<bool> connected_;
    std::atomic<bool> running_;
    
    mutable std::mutex mutex_;
    std::condition_variable cond_;
    std::queue<std::vector<uint8_t>> send_queue_;
    std::queue<std::vector<uint8_t>> receive_queue_;
    OnMessageCb on_message_;
    
    std::thread send_thread_;
    std::thread receive_thread_;
    std::thread poll_thread_;
};

} // namespace securecomm

extern "C" securecomm::Transport* create_websocket_transport(const char* uri) {
    return new securecomm::WebSocketClientTransport(uri);
}
