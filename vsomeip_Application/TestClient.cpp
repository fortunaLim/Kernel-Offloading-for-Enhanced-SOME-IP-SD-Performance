#include <iomanip>
#include <iostream>
#include <vsomeip/vsomeip.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>

class Subscriber {
private:
    std::shared_ptr<vsomeip::application> app_;
    bool running_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool is_registered_;

public:
    Subscriber() : 
        app_(vsomeip::runtime::get()->create_application("client-sample")),
        running_(true),
        is_registered_(false) {
    }

    bool init() {
        std::cout << "Initializing subscriber..." << std::endl;

        if (!app_->init()) {
            std::cerr << "Failed to initialize application" << std::endl;
            return false;
        }

        app_->register_availability_handler(0x1234, 0x5678,
            std::bind(&Subscriber::on_availability, this,
                     std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

        app_->register_state_handler(
            std::bind(&Subscriber::on_state_change, this, std::placeholders::_1));

        // 이벤트 그룹 설정
        std::set<vsomeip::eventgroup_t> groups;
        groups.insert(0x4465);

        // 이벤트 요청
        for (auto event_id : {0x0778, 0x0779}) {  // eventgroup 0x4465에 속한 이벤트들
            app_->request_event(
                0x1234, 0x5678, event_id,
                groups,
                vsomeip::event_type_e::ET_FIELD);

            app_->register_message_handler(
                0x1234, 0x5678, event_id,
                std::bind(&Subscriber::on_message, this, std::placeholders::_1));
        }

        app_->request_service(0x1234, 0x5678);

        return true;
    }

    void start() {
        std::cout << "Starting subscriber..." << std::endl;
        app_->start();
    }

    void stop() {
        std::cout << "Stopping subscriber..." << std::endl;
        running_ = false;
        app_->stop();
    }

    void on_state_change(vsomeip::state_type_e _state) {
        std::cout << "State changed to: " << std::hex << static_cast<int>(_state) << std::endl;
        
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            if (!is_registered_) {
                is_registered_ = true;
                std::cout << "Registering Subscription" << std::endl;
            }
        } else {
            is_registered_ = false;
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _available) {
        std::cout << "Service ["
                  << std::hex << _service << "." << _instance
                  << "] is " << (_available ? "available." : "NOT available.")
                  << std::endl;
        
        if (_available && is_registered_) {
            std::cout << "Subscribing to eventgroup 0x4465" << std::endl;
            app_->subscribe(0x1234, 0x5678, 0x4465);
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        std::shared_ptr<vsomeip::payload> payload = _message->get_payload();
        const vsomeip::byte_t* data = payload->get_data();
        vsomeip::length_t length = payload->get_length();
        
        std::cout << "Received message with event ID: 0x" << std::hex << _message->get_method() 
                  << " Length: " << std::dec << length << std::endl;
        
        if (length >= 4) {
            uint32_t count = (data[3] << 24) | (data[2] << 16) | (data[1] << 8) | data[0];
            std::cout << "Data: " << std::dec << count << std::endl;
        }
    }

    void run() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
};

int main() {
    Subscriber subscriber;
    
    if (subscriber.init()) {
        std::thread subscriber_thread([&subscriber]() { subscriber.run(); });
        subscriber.start();
        
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();
        
        subscriber.stop();
        subscriber_thread.join();
    } else {
        std::cerr << "Failed to initialize subscriber" << std::endl;
        return 1;
    }
    
    return 0;
}