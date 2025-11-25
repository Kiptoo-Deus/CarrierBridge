#include "include/carrierbridge.h"
#include <asio.hpp>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <memory>


struct CBServer::Impl {
    asio::io_context io;
    asio::ip::udp::socket socket;
    asio::ip::udp::endpoint remote_endpoint;
    std::thread io_thread;
    std::unordered_map<std::string, asio::ip::udp::endpoint> registry;
    CBServer::MessageCallback msg_cb;
    std::mutex mtx;
    unsigned short port;

    Impl(unsigned short requested_port)
        : socket(io), port(requested_port)
    {
        socket.open(asio::ip::udp::v4());
        socket.set_option(asio::socket_base::reuse_address(true));
        socket.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), requested_port));
        port = socket.local_endpoint().port();
        std::cout << "[CarrierBridge] UDP server running on port " << port << "\n";
    }
};

CBServer::CBServer(unsigned short port) : pImpl(new Impl(port)) {}
CBServer::~CBServer() { delete pImpl; }

void CBServer::init() {
    std::cout << "[CarrierBridge] UDP server async loop starting\n";

    auto buffer = std::make_shared<std::array<char, 1024>>();
    auto endpoint = std::make_shared<asio::ip::udp::endpoint>();
    auto do_receive = std::make_shared<std::function<void()>>(); // <--- shared_ptr

    *do_receive = [this, buffer, endpoint, do_receive]() {
        pImpl->socket.async_receive_from(
            asio::buffer(*buffer), *endpoint,
            [this, buffer, endpoint, do_receive](std::error_code ec, std::size_t bytes_recvd) {
                if (!ec && bytes_recvd > 0) {
                    std::string msg(buffer->data(), bytes_recvd);

                    if (msg.rfind("REGISTER ", 0) == 0) {
                        std::string user = msg.substr(9);
                        {
                            std::lock_guard<std::mutex> lock(pImpl->mtx);
                            pImpl->registry[user] = *endpoint;
                        }
                        std::cout << "[CarrierBridge] Registered user: " << user << "\n";
                    }
                    else if (msg.rfind("MESSAGE ", 0) == 0) {
                        auto space = msg.find(' ', 8);
                        if (space != std::string::npos) {
                            std::string to = msg.substr(8, space - 8);
                            std::string text = msg.substr(space + 1);
                            if (pImpl->msg_cb) pImpl->msg_cb(to, text);
                        }
                    }
                }

                (*do_receive)(); // recursive call safely via shared_ptr
            }
        );
    };

    (*do_receive)();
    pImpl->io_thread = std::thread([this]() { pImpl->io.run(); });
}


void CBServer::shutdown() {
    pImpl->io.stop();
    if (pImpl->io_thread.joinable()) pImpl->io_thread.join();
    std::cout << "[CarrierBridge] UDP server shutdown\n";
}

void CBServer::register_user(const std::string& username) {
    asio::ip::udp::endpoint ep(asio::ip::make_address("127.0.0.1"), pImpl->port);
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
