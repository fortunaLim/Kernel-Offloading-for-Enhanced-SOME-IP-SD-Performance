#include <iomanip>
#include <iostream>
#include <vsomeip/vsomeip.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <signal.h>

class Publisher {
private:
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::payload> payload_;
    bool running_;
    uint32_t count_;

public:
    Publisher() : 
        app_(vsomeip::runtime::get()->create_application("service-sample")),
        running_(true),
        count_(0) {
    }

    bool init() {
        std::cout << "Initializing publisher..." << std::endl;

        if (!app_->init()) {
            std::cerr << "Failed to initialize application" << std::endl;
            return false;
        }

        std::cout << "Publisher settings:" << std::endl;
        std::cout << "Service ID: 0x1234, Instance ID: 0x5678" << std::endl;
        std::cout << "Event ID: 0x0778, Eventgroup ID: 0x4465" << std::endl;

        app_->register_state_handler(
            std::bind(&Publisher::on_state_change, this, std::placeholders::_1));

        // 이벤트 제공 설정
        std::set<vsomeip::eventgroup_t> groups;
        groups.insert(0x4465);
        
        // 이벤트 오퍼링
        app_->offer_event(
            0x1234,  // service
            0x5678,  // instance
            0x0778,  // event
            groups,
            vsomeip::event_type_e::ET_FIELD,
            std::chrono::milliseconds::zero(),
            false,
            true,
            nullptr,
            vsomeip::reliability_type_e::RT_UNRELIABLE
        );

        payload_ = vsomeip::runtime::get()->create_payload();
        return true;
    }

    void start() {
        std::cout << "Starting publisher..." << std::endl;
        app_->start();
    }

    void stop() {
        std::cout << "Stopping publisher..." << std::endl;
        running_ = false;
        app_->stop();
    }

    void on_state_change(vsomeip::state_type_e _state) {
        std::cout << "State changed to: " << std::hex << static_cast<int>(_state) << std::endl;
        
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::cout << "Offering service 0x1234.0x5678" << std::endl;
            app_->offer_service(0x1234, 0x5678);
        }
    }

    void run() {
        std::cout << "Publisher running. Press Ctrl+C to exit." << std::endl;

        while (running_) {
            std::vector<vsomeip::byte_t> data;
            data.push_back(count_ & 0xFF);
            data.push_back((count_ >> 8) & 0xFF);
            data.push_back((count_ >> 16) & 0xFF);
            data.push_back((count_ >> 24) & 0xFF);
            
            payload_->set_data(data);
            
            app_->notify(0x1234, 0x5678, 0x0778, payload_);
            
            std::cout << "Published count: " << std::dec << count_ << std::endl;
            count_++;
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
};

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
Publisher *its_sample_ptr(nullptr);
void handle_signal(int _signal) {
    if (its_sample_ptr != nullptr && (_signal == SIGINT || _signal == SIGTERM))
        its_sample_ptr->stop();
}
#endif

int main() {
    Publisher publisher;

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    its_sample_ptr = &publisher;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#endif

    if (publisher.init()) {
        std::thread runner([&publisher]() { publisher.run(); });
        publisher.start();
        
        runner.join();
        return 0;
    } else {
        return 1;
    }
}
