/*
 * opendds_app.cpp
 *
 * Single pub/sub binary for the HDDS cross-vendor interop smoke test,
 * built against OpenDDS. Implements the CLI contract described in
 * scripts/interop-smoke/CONTRACT.md: one process, --mode pub or --mode
 * sub picks the role, everything else (domain, topic, reliability,
 * count, key, timeout, challenge) is a flag.
 *
 * Contract lines (EVENT/SENT/SAMPLE/DONE) go to stdout only; anything
 * else this program logs goes to stderr.
 */

#include <dds/DCPS/Marked_Default_Qos.h>
#include <dds/DCPS/Service_Participant.h>
#include <dds/DCPS/WaitSet.h>
#include <dds/DCPS/RTPS/RtpsDiscovery.h>
#include <dds/DCPS/transport/framework/TransportRegistry.h>
#include <dds/DCPS/transport/framework/TransportConfig.h>
#include <dds/DCPS/transport/framework/TransportInst.h>
#include <dds/DCPS/transport/rtps_udp/RtpsUdp.h>
#include <dds/DCPS/transport/rtps_udp/RtpsUdpInst.h>
#include <dds/DCPS/transport/rtps_udp/RtpsUdpInst_rch.h>

#include "InteropPingTypeSupportImpl.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <csignal>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

namespace {

const char* const DEFAULT_TOPIC = "InteropSmoke";
const int DEFAULT_COUNT = 100;
const int DEFAULT_KEY = 42;
const int DEFAULT_TIMEOUT = 30;

struct CliArgs {
    std::string mode;
    int domain = -1;
    std::string topic = DEFAULT_TOPIC;
    std::string reliability = "best_effort";
    int count = DEFAULT_COUNT;
    int key = DEFAULT_KEY;
    int timeout = DEFAULT_TIMEOUT;
    int challenge = 0;
};

/* Settle duration after a publisher sees EVENT matched, before the
 * first write, read from INTEROP_SMOKE_SETTLE_MS (default 500 if
 * unset or unparseable). Lets the orchestrator run a no-settle
 * investigation against the same built image without a rebuild. */
int settle_ms() {
    const char* v = std::getenv("INTEROP_SMOKE_SETTLE_MS");
    if (!v || !*v) return 500;
    char* end = nullptr;
    long parsed = std::strtol(v, &end, 10);
    if (end == v || *end != '\0' || parsed < 0) return 500;
    return static_cast<int>(parsed);
}

/* Hard watchdog: if normal control flow ever fails to finish in time,
 * force the process to report and exit rather than hang forever. Only
 * used by the sub role, per the contract's receive-loop requirement.
 * Async-signal-safe: raw write + _exit only. */
void on_watchdog_alarm(int /*sig*/) {
    static const char msg[] = "DONE timeout_forced\n";
    ssize_t written = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    (void)written;
    _exit(0);
}

double now_seconds() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

void usage(const char* prog) {
    std::fprintf(stderr,
        "usage: %s --mode pub|sub --domain N [--topic NAME] "
        "--reliability reliable|best_effort [--count N] [--key N] "
        "[--timeout N] [--challenge 0-255]\n",
        prog);
}

int parse_args(int argc, char** argv, CliArgs& a) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) return nullptr;
            return argv[++i];
        };
        if (arg == "--mode") {
            const char* v = next();
            if (!v) return -1;
            a.mode = v;
        } else if (arg == "--domain") {
            const char* v = next();
            if (!v) return -1;
            a.domain = std::atoi(v);
        } else if (arg == "--topic") {
            const char* v = next();
            if (!v) return -1;
            a.topic = v;
        } else if (arg == "--reliability") {
            const char* v = next();
            if (!v) return -1;
            a.reliability = v;
        } else if (arg == "--count") {
            const char* v = next();
            if (!v) return -1;
            a.count = std::atoi(v);
        } else if (arg == "--key") {
            const char* v = next();
            if (!v) return -1;
            a.key = std::atoi(v);
        } else if (arg == "--timeout") {
            const char* v = next();
            if (!v) return -1;
            a.timeout = std::atoi(v);
        } else if (arg == "--challenge") {
            const char* v = next();
            if (!v) return -1;
            a.challenge = std::atoi(v);
        } else {
            /* Leave anything unrecognized alone; OpenDDS's own argument
             * parsing (via TheParticipantFactoryWithArgs) may consume
             * its own ORB- or DCPS-related flags from the same argv
             * before this function runs; this app only validates its
             * own flags. */
        }
    }

    if (a.mode != "pub" && a.mode != "sub") {
        std::fprintf(stderr, "--mode must be pub or sub\n");
        return -1;
    }
    if (a.domain < 0) {
        std::fprintf(stderr, "--domain is required\n");
        return -1;
    }
    if (a.reliability != "reliable" && a.reliability != "best_effort") {
        std::fprintf(stderr, "--reliability must be reliable or best_effort\n");
        return -1;
    }
    if (a.count <= 0) {
        std::fprintf(stderr, "--count must be positive\n");
        return -1;
    }
    if (a.challenge < 0 || a.challenge > 255) {
        std::fprintf(stderr, "--challenge must be 0-255\n");
        return -1;
    }
    return 0;
}

/* Register RTPS discovery and the RTPS/UDP transport as global defaults.
 * No peer addresses are configured: SPDP relies on the standard
 * multicast group, which is enough for two containers (or a container
 * and a host process) run with --network host on the same machine. */
bool setup_rtps() {
    OpenDDS::DCPS::RcHandle<OpenDDS::RTPS::RtpsDiscovery> disc =
        OpenDDS::DCPS::make_rch<OpenDDS::RTPS::RtpsDiscovery>("rtps_discovery");
    TheServiceParticipant->add_discovery(disc);
    TheServiceParticipant->set_default_discovery("rtps_discovery");

    OpenDDS::DCPS::TransportInst_rch transport_inst =
        TheTransportRegistry->create_inst("rtps_udp_transport", "rtps_udp");
    if (!transport_inst) {
        std::fprintf(stderr, "create_inst(rtps_udp) failed\n");
        return false;
    }
    OpenDDS::DCPS::TransportConfig_rch config =
        TheTransportRegistry->create_config("rtps_udp_config");
    if (!config) {
        std::fprintf(stderr, "create_config failed\n");
        return false;
    }
    config->instances_.push_back(transport_inst);
    TheTransportRegistry->global_config(config);
    return true;
}

void fill_payload(InteropPing& sample, uint32_t seq, int challenge) {
    for (int i = 0; i < 32; ++i) {
        sample.payload[i] = static_cast<CORBA::Octet>(
            (seq + static_cast<uint32_t>(i) + static_cast<uint32_t>(challenge)) % 256);
    }
}

DDS::Duration_t remaining_duration(double budget_seconds, double elapsed_seconds) {
    DDS::Duration_t d;
    double remaining = budget_seconds - elapsed_seconds;
    if (remaining < 0.0) remaining = 0.0;
    d.sec = static_cast<CORBA::Long>(remaining);
    d.nanosec = static_cast<CORBA::ULong>((remaining - d.sec) * 1e9);
    return d;
}

int run_pub(const CliArgs& a, DDS::DomainParticipant_ptr participant) {
    InteropPingTypeSupport_var ts = new InteropPingTypeSupportImpl;
    if (ts->register_type(participant, "") != DDS::RETCODE_OK) {
        std::fprintf(stderr, "register_type failed\n");
        return 2;
    }
    CORBA::String_var type_name = ts->get_type_name();

    DDS::Topic_var topic = participant->create_topic(
        a.topic.c_str(), type_name, TOPIC_QOS_DEFAULT, nullptr,
        OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!topic) {
        std::fprintf(stderr, "create_topic failed\n");
        return 2;
    }

    DDS::Publisher_var publisher = participant->create_publisher(
        PUBLISHER_QOS_DEFAULT, nullptr, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!publisher) {
        std::fprintf(stderr, "create_publisher failed\n");
        return 2;
    }

    DDS::DataWriterQos writer_qos;
    publisher->get_default_datawriter_qos(writer_qos);
    writer_qos.reliability.kind = (a.reliability == "reliable")
        ? DDS::RELIABLE_RELIABILITY_QOS
        : DDS::BEST_EFFORT_RELIABILITY_QOS;
    /* KEEP_LAST depth >= --count satisfies the contract for both
     * reliability kinds; no separate resource-limits branch needed. */
    writer_qos.history.kind = DDS::KEEP_LAST_HISTORY_QOS;
    writer_qos.history.depth = a.count;

    DDS::DataWriter_var writer = publisher->create_datawriter(
        topic, writer_qos, nullptr, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!writer) {
        std::fprintf(stderr, "create_datawriter failed\n");
        return 2;
    }

    InteropPingDataWriter_var ping_writer = InteropPingDataWriter::_narrow(writer);
    if (!ping_writer) {
        std::fprintf(stderr, "narrow writer failed\n");
        return 2;
    }

    DDS::StatusCondition_var match_cond = writer->get_statuscondition();
    match_cond->set_enabled_statuses(DDS::PUBLICATION_MATCHED_STATUS);
    DDS::WaitSet_var match_ws = new DDS::WaitSet;
    match_ws->attach_condition(match_cond);

    bool matched = false;
    double start = now_seconds();
    while (!matched) {
        double elapsed = now_seconds() - start;
        if (elapsed >= static_cast<double>(a.timeout)) break;
        DDS::ConditionSeq conditions;
        DDS::Duration_t wait_timeout = remaining_duration(a.timeout, elapsed);
        if (match_ws->wait(conditions, wait_timeout) == DDS::RETCODE_OK) {
            DDS::PublicationMatchedStatus status;
            writer->get_publication_matched_status(status);
            if (status.current_count > 0) matched = true;
        }
    }
    match_ws->detach_condition(match_cond);

    if (!matched) {
        std::printf("EVENT no_match\n");
        std::fflush(stdout);
        return 3;
    }
    std::printf("EVENT matched\n");
    std::fflush(stdout);

    /* Short settle after the match before the first write. A
     * best-effort writer gives no delivery guarantee for samples sent
     * while the remote reader's association is still being set up;
     * this keeps the first samples from racing that setup. Duration is
     * read from INTEROP_SMOKE_SETTLE_MS so the orchestrator can run a
     * no-settle investigation against the same built image. */
    std::this_thread::sleep_for(std::chrono::milliseconds(settle_ms()));

    int sent_count = 0;
    for (int seq = 0; seq < a.count; ++seq) {
        InteropPing sample;
        sample.key = a.key;
        sample.seq = static_cast<CORBA::ULong>(seq);
        fill_payload(sample, static_cast<uint32_t>(seq), a.challenge);

        DDS::ReturnCode_t rc = ping_writer->write(sample, DDS::HANDLE_NIL);
        if (rc != DDS::RETCODE_OK) {
            std::fprintf(stderr, "write failed at seq=%d rc=%d\n", seq,
                          static_cast<int>(rc));
        } else {
            ++sent_count;
            std::printf("SENT seq=%d\n", seq);
            std::fflush(stdout);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::printf("DONE sent=%d\n", sent_count);
    std::fflush(stdout);
    return 0;
}

int run_sub(const CliArgs& a, DDS::DomainParticipant_ptr participant) {
    InteropPingTypeSupport_var ts = new InteropPingTypeSupportImpl;
    if (ts->register_type(participant, "") != DDS::RETCODE_OK) {
        std::fprintf(stderr, "register_type failed\n");
        return 2;
    }
    CORBA::String_var type_name = ts->get_type_name();

    DDS::Topic_var topic = participant->create_topic(
        a.topic.c_str(), type_name, TOPIC_QOS_DEFAULT, nullptr,
        OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!topic) {
        std::fprintf(stderr, "create_topic failed\n");
        return 2;
    }

    DDS::Subscriber_var subscriber = participant->create_subscriber(
        SUBSCRIBER_QOS_DEFAULT, nullptr, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!subscriber) {
        std::fprintf(stderr, "create_subscriber failed\n");
        return 2;
    }

    DDS::DataReaderQos reader_qos;
    subscriber->get_default_datareader_qos(reader_qos);
    reader_qos.reliability.kind = (a.reliability == "reliable")
        ? DDS::RELIABLE_RELIABILITY_QOS
        : DDS::BEST_EFFORT_RELIABILITY_QOS;
    reader_qos.history.kind = DDS::KEEP_LAST_HISTORY_QOS;
    reader_qos.history.depth = a.count;

    DDS::DataReader_var reader = subscriber->create_datareader(
        topic, reader_qos, nullptr, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!reader) {
        std::fprintf(stderr, "create_datareader failed\n");
        return 2;
    }

    InteropPingDataReader_var ping_reader = InteropPingDataReader::_narrow(reader);
    if (!ping_reader) {
        std::fprintf(stderr, "narrow reader failed\n");
        return 2;
    }

    /* Overall safety cap in case the match-wait or receive loop itself
     * never progresses (e.g. an unexpected blocking call). Re-armed
     * after match, below. */
    std::signal(SIGALRM, on_watchdog_alarm);
    alarm(static_cast<unsigned int>(a.timeout + 15));

    DDS::StatusCondition_var match_cond = reader->get_statuscondition();
    match_cond->set_enabled_statuses(DDS::SUBSCRIPTION_MATCHED_STATUS);
    DDS::WaitSet_var match_ws = new DDS::WaitSet;
    match_ws->attach_condition(match_cond);

    bool matched = false;
    double start = now_seconds();
    while (!matched) {
        double elapsed = now_seconds() - start;
        if (elapsed >= static_cast<double>(a.timeout)) break;
        DDS::ConditionSeq conditions;
        DDS::Duration_t wait_timeout = remaining_duration(a.timeout, elapsed);
        if (match_ws->wait(conditions, wait_timeout) == DDS::RETCODE_OK) {
            DDS::SubscriptionMatchedStatus status;
            reader->get_subscription_matched_status(status);
            if (status.current_count > 0) matched = true;
        }
    }
    match_ws->detach_condition(match_cond);

    if (!matched) {
        alarm(0);
        std::printf("EVENT no_match\n");
        std::fflush(stdout);
        return 3;
    }
    std::printf("EVENT matched\n");
    std::fflush(stdout);

    /* Re-arm for the receive loop: --timeout + 10s hard cap measured
     * from the match, per the contract. */
    alarm(static_cast<unsigned int>(a.timeout + 10));

    DDS::StatusCondition_var data_cond = reader->get_statuscondition();
    data_cond->set_enabled_statuses(DDS::DATA_AVAILABLE_STATUS);
    DDS::WaitSet_var data_ws = new DDS::WaitSet;
    data_ws->attach_condition(data_cond);

    std::vector<bool> seen(static_cast<size_t>(a.count), false);
    int distinct = 0;
    int total_msgs = 0;
    double match_time = now_seconds();

    while (distinct < a.count) {
        double elapsed = now_seconds() - match_time;
        if (elapsed >= static_cast<double>(a.timeout)) break;

        DDS::ConditionSeq conditions;
        DDS::Duration_t wait_timeout = remaining_duration(a.timeout, elapsed);
        data_ws->wait(conditions, wait_timeout);

        InteropPingSeq samples;
        DDS::SampleInfoSeq infos;
        DDS::ReturnCode_t rc = ping_reader->take(
            samples, infos, DDS::LENGTH_UNLIMITED,
            DDS::ANY_SAMPLE_STATE, DDS::ANY_VIEW_STATE, DDS::ANY_INSTANCE_STATE);
        if (rc == DDS::RETCODE_OK) {
            for (CORBA::ULong i = 0; i < samples.length(); ++i) {
                if (!infos[i].valid_data) continue;
                ++total_msgs;
                const InteropPing& s = samples[i];

                char hex[65];
                for (int b = 0; b < 32; ++b) {
                    std::snprintf(hex + b * 2, 3, "%02x", s.payload[b]);
                }
                hex[64] = '\0';

                std::printf("SAMPLE seq=%u key=%d payload=%s\n",
                             static_cast<unsigned>(s.seq),
                             static_cast<int>(s.key), hex);
                std::fflush(stdout);

                if (s.seq < static_cast<CORBA::ULong>(a.count) && !seen[s.seq]) {
                    seen[s.seq] = true;
                    ++distinct;
                }
            }
            ping_reader->return_loan(samples, infos);
        }
    }

    data_ws->detach_condition(data_cond);
    alarm(0);
    std::printf("DONE received=%d distinct=%d\n", total_msgs, distinct);
    std::fflush(stdout);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    CliArgs args;
    if (parse_args(argc, argv, args) != 0) {
        usage(argv[0]);
        return 2;
    }

    DDS::DomainParticipantFactory_var dpf = TheParticipantFactoryWithArgs(argc, argv);
    if (!dpf) {
        std::fprintf(stderr, "failed to initialize DomainParticipantFactory\n");
        return 2;
    }

    if (!setup_rtps()) {
        TheServiceParticipant->shutdown();
        return 2;
    }

    DDS::DomainParticipant_var participant = dpf->create_participant(
        args.domain, PARTICIPANT_QOS_DEFAULT, nullptr,
        OpenDDS::DCPS::DEFAULT_STATUS_MASK);
    if (!participant) {
        std::fprintf(stderr, "create_participant failed\n");
        TheServiceParticipant->shutdown();
        return 2;
    }

    int rc = 2;
    if (args.mode == "pub") {
        rc = run_pub(args, participant.in());
    } else if (args.mode == "sub") {
        rc = run_sub(args, participant.in());
    }

    participant->delete_contained_entities();
    dpf->delete_participant(participant.in());
    TheServiceParticipant->shutdown();
    return rc;
}
