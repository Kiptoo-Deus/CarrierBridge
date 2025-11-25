#include <asio.hpp>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <mutex>
#include "include/carrierbridge.h"

struct CBServer::Impl {
    asio::io_context io;
    asio::ip::udp::socket socket;
    asio::ip::udp::endpoint remote_endpoint;
    std::thread io_thread;
    std::unordered_map<std::string, asio::ip::udp::endpoint> registry;
    CBServer::MessageCallback msg_cb;
    std::mutex mtx;

    Impl(unsigned short port)
        : socket(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)) {}
};

CBServer::CBServer(unsigned short port) : pImpl(new Impl(port)) {}
CBServer::~CBServer() { delete pImpl; }

void CBServer::init() {
    std::cout << "[CarrierBridge] UDP server init\n";

    // start async receive
    auto buffer = std::make_shared<std::array<char, 1024>>();
    auto endpoint = std::make_shared<asio::ip::udp::endpoint>();

    std::function<void()> do_receive = [this, buffer, endpoint, &do_receive]() {
        pImpl->socket.async_receive_from(
            asio::buffer(*buffer), *endpoint,
            [this, buffer, endpoint, &do_receive](std::error_code ec, std::size_t bytes_recvd) {
                if (!ec && bytes_recvd > 0) {
                    std::string msg(buffer->data(), bytes_recvd);
                    // very simple: "REGISTER Joel" or "MESSAGE Kiptoo Hello"
                    if (msg.rfind("REGISTER ", 0) == 0) {
                        std::string user = msg.substr(9);
                        {
                            std::lock_guard<std::mutex> lock(pImpl->mtx);
                            pImpl->registry[user] = *endpoint;
                        }
                        std::cout << "[CarrierBridge] Registered user via UDP: " << user << "\n";
                    }
                    else if (msg.rfind("MESSAGE ", 0) == 0) {
                        auto space = msg.find(' ', 8);
                        if (space != std::string::npos) {
                            std::string to = msg.substr(8, space - 8);
                            std::string text = msg.substr(space + 1);
                            if (pImpl->msg_cb)
                                pImpl->msg_cb(to, text);
                        }
                    }
                }
        do_receive(); // loop
            }
        );
    };
    do_receive();

    pImpl->io_thread = std::thread([this]() { pImpl->io.run(); });
}

void CBServer::shutdown() {
    pImpl->io.stop();
    if (pImpl->io_thread.joinable())
        pImpl->io_thread.join();
    std::cout << "[CarrierBridge] UDP server shutdown\n";
}

void CBServer::register_user(const std::string& username) {
    asio::ip::udp::endpoint ep(asio::ip::make_address("127.0.0.1"), 9001);

    std::string msg = "REGISTER " + username;
    pImpl->socket.send_to(asio::buffer(msg), ep);
}

void CBServer::send_message(const std::string& to, const std::string& message) {
    asio::ip::udp::endpoint ep;
    {
        std::lock_guard<std::mutex> lock(pImpl->mtx);
        auto it = pImpl->registry.find(to);
        if (it != pImpl->registry.end())
            ep = it->second;
        else {
            std::cerr << "[CarrierBridge] User not found: " << to << "\n";
            return;
        }
    }
    std::string msg = "MESSAGE " + to + " " + message;
    pImpl->socket.send_to(asio::buffer(msg), ep);
}

void CBServer::set_message_callback(MessageCallback cb) {
    pImpl->msg_cb = cb;
}

// C API wrappers
static CBServer* g_srv = nullptr;

void cb_init() { if (!g_srv) g_srv = new CBServer(9000); g_srv->init(); }
void cb_shutdown() { if (g_srv) { g_srv->shutdown(); delete g_srv; g_srv = nullptr; } }
void cb_register(const char* username) { if (g_srv) g_srv->register_user(username); }
void cb_send_message(const char* to, const char* message) { if (g_srv) g_srv->send_message(to, message); }
