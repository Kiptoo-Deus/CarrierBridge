#pragma once
#include <string>
#include <functional>

class CBServer {
public:
    using MessageCallback = std::function<void(const std::string& from, const std::string& message)>;

    explicit CBServer(unsigned short port = 9000);
    ~CBServer();

    // start / stop
    void init();
    void shutdown();

    // client operations (client-side helpers that send to the broker)
    void register_user(const std::string& username);
    void send_message(const std::string& to, const std::string& message);

    // broker-side callback when a message is routed to local process
    void set_message_callback(MessageCallback cb);

private:
    struct Impl;
    Impl* pImpl;
};
