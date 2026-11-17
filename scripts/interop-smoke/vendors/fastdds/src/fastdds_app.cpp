// fastdds_app.cpp
//
// HDDS interop-smoke CLI app for the eProsima Fast DDS peer. Implements the
// pub/sub contract described in scripts/interop-smoke/CONTRACT.md against the
// InteropPing type (idl/InteropPing.idl). This is a standalone smoke-test
// client built on top of upstream Fast DDS; it does not modify or wrap any
// Fast DDS source.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/rtps/attributes/BuiltinTransports.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/qos/DataWriterQos.hpp>
#include <fastdds/dds/publisher/qos/PublisherQos.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/qos/DataReaderQos.hpp>
#include <fastdds/dds/subscriber/qos/SubscriberQos.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/topic/qos/TopicQos.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "InteropPingPubSubTypes.hpp"

using eprosima::fastdds::dds::DataReader;
using eprosima::fastdds::dds::DataReaderListener;
using eprosima::fastdds::dds::DataReaderQos;
using eprosima::fastdds::dds::DataWriter;
using eprosima::fastdds::dds::DataWriterListener;
using eprosima::fastdds::dds::DataWriterQos;
using eprosima::fastdds::dds::DomainParticipant;
using eprosima::fastdds::dds::DomainParticipantFactory;
using eprosima::fastdds::dds::DomainParticipantQos;
using eprosima::fastdds::dds::HistoryQosPolicyKind;
using eprosima::fastdds::dds::PublicationMatchedStatus;
using eprosima::fastdds::dds::Publisher;
using eprosima::fastdds::dds::PublisherQos;
using eprosima::fastdds::dds::ReliabilityQosPolicyKind;
using eprosima::fastdds::dds::RETCODE_OK;
using eprosima::fastdds::dds::SampleInfo;
using eprosima::fastdds::dds::StatusMask;
using eprosima::fastdds::dds::Subscriber;
using eprosima::fastdds::dds::SubscriberQos;
using eprosima::fastdds::dds::SubscriptionMatchedStatus;
using eprosima::fastdds::dds::Topic;
using eprosima::fastdds::dds::TopicQos;
using eprosima::fastdds::dds::TypeSupport;

namespace
{

// --- CLI options, defaults per CONTRACT.md -------------------------------

struct Options
{
    std::string mode;              // "pub" or "sub"
    int domain = 200;
    std::string topic = "InteropSmoke";
    std::string reliability = "best_effort";
    unsigned int count = 100;
    int key = 42;
    unsigned int timeout_s = 30;
    unsigned int challenge = 0;    // 0-255; only affects the publisher's payload
};

void print_usage()
{
    std::cerr <<
        "usage: fastdds_app --mode pub|sub [--domain N] [--topic NAME]\n"
        "       [--reliability reliable|best_effort] [--count N]\n"
        "       [--key N] [--timeout SECONDS] [--challenge N]\n";
}

// Settle time between EVENT matched and the first write, in milliseconds.
// Overridable via INTEROP_SMOKE_SETTLE_MS so the orchestrator can run a
// no-settle investigation against an already-built image without a rebuild.
// Falls back to the 500 ms default if the env var is unset or not a valid
// non-negative integer.
unsigned long settle_ms_from_env()
{
    const char* raw = std::getenv("INTEROP_SMOKE_SETTLE_MS");
    if (raw == nullptr || raw[0] == '\0')
    {
        return 500;
    }
    char* end = nullptr;
    long value = std::strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || value < 0)
    {
        return 500;
    }
    return static_cast<unsigned long>(value);
}

bool parse_args(
        int argc,
        char** argv,
        Options& opt)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        auto next_value = [&](const char* name) -> std::string
                {
                    if (i + 1 >= argc)
                    {
                        std::cerr << "missing value for " << name << std::endl;
                        std::exit(2);
                    }
                    return argv[++i];
                };

        if (arg == "--mode")
        {
            opt.mode = next_value("--mode");
        }
        else if (arg == "--domain")
        {
            opt.domain = std::atoi(next_value("--domain").c_str());
        }
        else if (arg == "--topic")
        {
            opt.topic = next_value("--topic");
        }
        else if (arg == "--reliability")
        {
            opt.reliability = next_value("--reliability");
        }
        else if (arg == "--count")
        {
            opt.count = static_cast<unsigned int>(std::atoi(next_value("--count").c_str()));
        }
        else if (arg == "--key")
        {
            opt.key = std::atoi(next_value("--key").c_str());
        }
        else if (arg == "--timeout")
        {
            opt.timeout_s = static_cast<unsigned int>(std::atoi(next_value("--timeout").c_str()));
        }
        else if (arg == "--challenge")
        {
            opt.challenge = static_cast<unsigned int>(std::atoi(next_value("--challenge").c_str())) % 256;
        }
        else if (arg == "--help" || arg == "-h")
        {
            print_usage();
            std::exit(0);
        }
        else
        {
            std::cerr << "unknown argument: " << arg << std::endl;
            print_usage();
            std::exit(2);
        }
    }

    if (opt.mode != "pub" && opt.mode != "sub")
    {
        std::cerr << "--mode must be pub or sub" << std::endl;
        return false;
    }
    if (opt.reliability != "reliable" && opt.reliability != "best_effort")
    {
        std::cerr << "--reliability must be reliable or best_effort" << std::endl;
        return false;
    }
    return true;
}

ReliabilityQosPolicyKind reliability_kind(
        const Options& opt)
{
    return (opt.reliability == "reliable")
           ? ReliabilityQosPolicyKind::RELIABLE_RELIABILITY_QOS
           : ReliabilityQosPolicyKind::BEST_EFFORT_RELIABILITY_QOS;
}

// Force plain UDPv4 for the RTPS path. Fast DDS's default transport set
// (BuiltinTransports::DEFAULT) also instantiates a shared-memory transport
// that it prefers for same-host peers; that fast path depends on peers
// sharing one /dev/shm, which does not hold across container boundaries or
// against a natively-run peer process. This is a cross-vendor wire-level
// smoke test, so it always goes over UDPv4 regardless of host placement.
void force_udp_only(
        DomainParticipantQos& pqos)
{
    pqos.setup_transports(eprosima::fastdds::rtps::BuiltinTransports::UDPv4);
}

void hex_dump(
        const std::array<uint8_t, 32>& payload,
        char* out_65_bytes)
{
    static const char* digits = "0123456789abcdef";
    for (size_t i = 0; i < payload.size(); ++i)
    {
        out_65_bytes[i * 2] = digits[(payload[i] >> 4) & 0x0F];
        out_65_bytes[i * 2 + 1] = digits[payload[i] & 0x0F];
    }
    out_65_bytes[64] = '\0';
}

// Hard watchdog: no matter what the rest of the program is doing, force an
// exit after the given deadline so the orchestrator never hangs waiting on
// this process.
void arm_watchdog(
        unsigned int budget_s,
        std::atomic<bool>& finished)
{
    std::thread([budget_s, &finished]()
            {
                // Match-wait and receive/send phases are each budgeted
                // --timeout seconds; the hard stop covers both plus margin.
                std::this_thread::sleep_for(std::chrono::seconds(2ULL * budget_s + 10));
                if (!finished.load())
                {
                    std::cout << "DONE timeout_forced" << std::endl;
                    std::cout.flush();
                    std::fflush(stdout);
                    std::_Exit(0);
                }
            }).detach();
}

// --- Publisher side --------------------------------------------------------

class PubListener : public DataWriterListener
{
public:

    void on_publication_matched(
            DataWriter*,
            const PublicationMatchedStatus& info) override
    {
        if (info.current_count_change == 1)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            matched_ = true;
            cv_.notify_all();
        }
    }

    bool wait_matched(
            unsigned int timeout_s)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(timeout_s), [this]()
                {
                    return matched_;
                });
    }

private:

    std::mutex mutex_;
    std::condition_variable cv_;
    bool matched_ = false;
};

int run_pub(
        const Options& opt,
        std::atomic<bool>& finished)
{
    std::shared_ptr<DomainParticipantFactory> factory = DomainParticipantFactory::get_shared_instance();

    DomainParticipantQos pqos = eprosima::fastdds::dds::PARTICIPANT_QOS_DEFAULT;
    force_udp_only(pqos);
    DomainParticipant* participant = factory->create_participant(opt.domain, pqos, nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        return 2;
    }

    TypeSupport type(new InteropPingPubSubType());
    type.register_type(participant);

    PublisherQos pub_qos = eprosima::fastdds::dds::PUBLISHER_QOS_DEFAULT;
    participant->get_default_publisher_qos(pub_qos);
    Publisher* publisher = participant->create_publisher(pub_qos, nullptr, StatusMask::none());
    if (publisher == nullptr)
    {
        return 2;
    }

    TopicQos topic_qos = eprosima::fastdds::dds::TOPIC_QOS_DEFAULT;
    participant->get_default_topic_qos(topic_qos);
    Topic* topic = participant->create_topic(opt.topic, type.get_type_name(), topic_qos);
    if (topic == nullptr)
    {
        return 2;
    }

    unsigned int depth = std::max<unsigned int>(opt.count, 1);

    DataWriterQos writer_qos = eprosima::fastdds::dds::DATAWRITER_QOS_DEFAULT;
    publisher->get_default_datawriter_qos(writer_qos);
    writer_qos.reliability().kind = reliability_kind(opt);
    writer_qos.history().kind = HistoryQosPolicyKind::KEEP_LAST_HISTORY_QOS;
    writer_qos.history().depth = static_cast<int32_t>(depth);
    writer_qos.resource_limits().max_samples_per_instance = static_cast<int32_t>(depth);
    writer_qos.resource_limits().allocated_samples = static_cast<int32_t>(depth);

    PubListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, writer_qos, &listener, StatusMask::all());
    if (writer == nullptr)
    {
        return 2;
    }

    if (!listener.wait_matched(opt.timeout_s))
    {
        std::cout << "EVENT no_match" << std::endl;
        std::cout.flush();
        finished.store(true);
        return 3;
    }
    std::cout << "EVENT matched" << std::endl;
    std::cout.flush();

    // A reader that has just matched is not always ready to receive on the
    // first datagram yet (socket/buffer setup on the remote side can lag
    // the match notification by a few hundred ms); on BEST_EFFORT that gap
    // loses the earliest samples outright, with nothing to retransmit them.
    // A short settle before the first write avoids that warm-up race.
    std::this_thread::sleep_for(std::chrono::milliseconds(settle_ms_from_env()));

    unsigned int sent_count = 0;
    for (unsigned int seq = 0; seq < opt.count; ++seq)
    {
        InteropPing sample;
        sample.key(opt.key);
        sample.seq(seq);
        std::array<uint8_t, 32> payload{};
        for (size_t i = 0; i < payload.size(); ++i)
        {
            payload[i] = static_cast<uint8_t>((seq + i + opt.challenge) % 256);
        }
        sample.payload(payload);

        if (RETCODE_OK == writer->write(&sample))
        {
            ++sent_count;
            std::cout << "SENT seq=" << seq << std::endl;
            std::cout.flush();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }

    // Let RELIABLE retransmits flush before tearing down.
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << "DONE sent=" << sent_count << std::endl;
    std::cout.flush();
    finished.store(true);

    participant->delete_contained_entities();
    factory->delete_participant(participant);
    return 0;
}

// --- Subscriber side --------------------------------------------------------

class SubListener : public DataReaderListener
{
public:

    explicit SubListener(
            unsigned int target_distinct)
        : target_distinct_(target_distinct)
    {
    }

    void on_subscription_matched(
            DataReader*,
            const SubscriptionMatchedStatus& info) override
    {
        if (info.current_count_change == 1)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            matched_ = true;
            cv_.notify_all();
        }
    }

    void on_data_available(
            DataReader* reader) override
    {
        InteropPing sample;
        SampleInfo info;
        while (eprosima::fastdds::dds::RETCODE_OK == reader->take_next_sample(&sample, &info))
        {
            if (!info.valid_data)
            {
                continue;
            }

            char hex[65];
            hex_dump(sample.payload(), hex);

            {
                std::lock_guard<std::mutex> lock(mutex_);
                ++total_received_;
                distinct_.insert(sample.seq());
            }

            std::cout << "SAMPLE seq=" << sample.seq()
                       << " key=" << sample.key()
                       << " payload=" << hex << std::endl;
            std::cout.flush();

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (distinct_.size() >= target_distinct_)
                {
                    cv_.notify_all();
                }
            }
        }
    }

    bool wait_matched(
            unsigned int timeout_s)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(timeout_s), [this]()
                {
                    return matched_;
                });
    }

    // Returns true if distinct target reached before the deadline.
    bool wait_done(
            unsigned int timeout_s)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(timeout_s), [this]()
                {
                    return distinct_.size() >= target_distinct_;
                });
    }

    unsigned int total_received() const
    {
        return total_received_;
    }

    size_t distinct_count() const
    {
        return distinct_.size();
    }

private:

    unsigned int target_distinct_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool matched_ = false;
    unsigned int total_received_ = 0;
    std::set<uint32_t> distinct_;
};

int run_sub(
        const Options& opt,
        std::atomic<bool>& finished)
{
    std::shared_ptr<DomainParticipantFactory> factory = DomainParticipantFactory::get_shared_instance();

    DomainParticipantQos pqos = eprosima::fastdds::dds::PARTICIPANT_QOS_DEFAULT;
    force_udp_only(pqos);
    DomainParticipant* participant = factory->create_participant(opt.domain, pqos, nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        return 2;
    }

    TypeSupport type(new InteropPingPubSubType());
    type.register_type(participant);

    SubscriberQos sub_qos = eprosima::fastdds::dds::SUBSCRIBER_QOS_DEFAULT;
    participant->get_default_subscriber_qos(sub_qos);
    Subscriber* subscriber = participant->create_subscriber(sub_qos, nullptr, StatusMask::none());
    if (subscriber == nullptr)
    {
        return 2;
    }

    TopicQos topic_qos = eprosima::fastdds::dds::TOPIC_QOS_DEFAULT;
    participant->get_default_topic_qos(topic_qos);
    Topic* topic = participant->create_topic(opt.topic, type.get_type_name(), topic_qos);
    if (topic == nullptr)
    {
        return 2;
    }

    unsigned int depth = std::max<unsigned int>(opt.count, 1);

    DataReaderQos reader_qos = eprosima::fastdds::dds::DATAREADER_QOS_DEFAULT;
    subscriber->get_default_datareader_qos(reader_qos);
    reader_qos.reliability().kind = reliability_kind(opt);
    reader_qos.history().kind = HistoryQosPolicyKind::KEEP_LAST_HISTORY_QOS;
    reader_qos.history().depth = static_cast<int32_t>(depth);
    reader_qos.resource_limits().max_samples_per_instance = static_cast<int32_t>(depth);
    reader_qos.resource_limits().allocated_samples = static_cast<int32_t>(depth);

    SubListener listener(opt.count);
    DataReader* reader = subscriber->create_datareader(topic, reader_qos, &listener, StatusMask::all());
    if (reader == nullptr)
    {
        return 2;
    }

    if (!listener.wait_matched(opt.timeout_s))
    {
        std::cout << "EVENT no_match" << std::endl;
        std::cout.flush();
        finished.store(true);
        return 3;
    }
    std::cout << "EVENT matched" << std::endl;
    std::cout.flush();

    // Wait until distinct target reached, or --timeout seconds since match.
    listener.wait_done(opt.timeout_s);

    std::cout << "DONE received=" << listener.total_received()
               << " distinct=" << listener.distinct_count() << std::endl;
    std::cout.flush();
    finished.store(true);

    participant->delete_contained_entities();
    factory->delete_participant(participant);
    return 0;
}

} // namespace

int main(
        int argc,
        char** argv)
{
    Options opt;
    if (!parse_args(argc, argv, opt))
    {
        print_usage();
        return 2;
    }

    std::atomic<bool> finished(false);
    arm_watchdog(opt.timeout_s, finished);

    int rc = (opt.mode == "pub") ? run_pub(opt, finished) : run_sub(opt, finished);

    finished.store(true);
    return rc;
}
