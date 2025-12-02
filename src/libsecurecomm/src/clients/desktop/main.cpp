#include "securecomm/dispatcher.hpp"
#include <memory>
#include <thread>
#include <iostream>
#include <chrono>
#include <exception>

extern "C" securecomm::Transport* create_inmemory_transport();

int main() {
    try {
        std::cout << "Starting SecureComm demo..." << std::endl;
        
        auto transport = std::shared_ptr<securecomm::Transport>(create_inmemory_transport());
        std::cout << "Transport created" << std::endl;

        auto dispatcherA = std::make_shared<securecomm::Dispatcher>(transport);
        auto dispatcherB = std::make_shared<securecomm::Dispatcher>(transport);
        std::cout << "Dispatchers created" << std::endl;

        dispatcherA->register_device("alice");
        dispatcherB->register_device("bob");
        std::cout << "Devices registered" << std::endl;

        dispatcherA->start();
        dispatcherB->start();
        std::cout << "Dispatchers started" << std::endl;

        std::vector<uint8_t> root(32, 5);
        dispatcherA->create_session_with("bob", root);
        dispatcherB->create_session_with("alice", root);
        std::cout << "Sessions created" << std::endl;

        dispatcherA->set_on_inbound([](const securecomm::Envelope& env){
            auto pt = env.ciphertext;
            std::string s(pt.begin(), pt.end());
            std::cout << "Alice inbound: " << s << "\n";
        });

        dispatcherB->set_on_inbound([](const securecomm::Envelope& env){
            auto pt = env.ciphertext;
            std::string s(pt.begin(), pt.end());
            std::cout << "Bob inbound: " << s << "\n";
        });

        std::cout << "Sending messages..." << std::endl;
        dispatcherA->send_message_to_device("bob", std::vector<uint8_t>({'H','i',' ','B','o','b'}));
        dispatcherB->send_message_to_device("alice", std::vector<uint8_t>({'H','i',' ','A','l','i','c','e'}));

        std::cout << "Waiting for messages..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::cout << "Stopping..." << std::endl;
        dispatcherA->stop();
        dispatcherB->stop();
        
        std::cout << "Demo complete!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        return 1;
    }
}