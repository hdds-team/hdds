// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file hdds.hpp
 * @brief HDDS C++ SDK - High-performance DDS bindings
 *
 * RAII wrappers around the C FFI layer for safe, idiomatic C++ usage.
 *
 * Example:
 * @code
 *     hdds::Participant participant("my_app");
 *     auto writer = participant.create_writer<MyType>("topic",
 *         hdds::QoS::reliable().transient_local());
 *     writer.write(MyType{.value = 42});
 * @endcode
 */

#pragma once

#include <array>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

// Forward declaration of C FFI types (opaque pointers only)
extern "C" {
    struct HddsParticipant;
    struct HddsDataWriter;
    struct HddsDataReader;
    struct HddsQoS;
    struct HddsWaitSet;
    struct HddsGuardCondition;
    struct HddsStatusCondition;
    struct HddsPublisher;
    struct HddsSubscriber;
    struct HddsMetrics;
    struct HddsTelemetryExporter;
}

namespace hdds {

/** @brief Subscription matched status. */
struct SubscriptionMatchedStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t current_count;
    int32_t current_count_change;
};

/** @brief Publication matched status. */
struct PublicationMatchedStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t current_count;
    int32_t current_count_change;
};

/** @brief Liveliness changed status. */
struct LivelinessChangedStatus {
    uint32_t alive_count;
    int32_t alive_count_change;
    uint32_t not_alive_count;
    int32_t not_alive_count_change;
};

/** @brief Liveliness lost status (MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC only). */
struct LivelinessLostStatus {
    uint32_t total_count;
    int32_t total_count_change;
};

/** @brief Sample lost status. */
struct SampleLostStatus {
    uint32_t total_count;
    int32_t total_count_change;
};

/** @brief Sample rejected status. */
struct SampleRejectedStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t last_reason;
};

/** @brief Deadline missed status. */
struct DeadlineMissedStatus {
    uint32_t total_count;
    int32_t total_count_change;
};

/** @brief Incompatible QoS status. */
struct IncompatibleQosStatus {
    uint32_t total_count;
    int32_t total_count_change;
    /// QosPolicyId_t of the last incompatible policy (DDS v1.4 Sec.2.3.3:
    /// DURABILITY 2, PRESENTATION 3, DEADLINE 4, LATENCY_BUDGET 5,
    /// OWNERSHIP 6, LIVELINESS 8, RELIABILITY 11, DESTINATION_ORDER 12;
    /// DDS-XTypes v1.3: DATA_REPRESENTATION 23).
    uint32_t last_policy_id;
};

using InstanceHandle = std::array<uint8_t, 16>;

/**
 * @brief Get HDDS library version string
 * @return Version string (e.g., "1.0.5")
 */
std::string version();

/**
 * @brief Transport mode for participant creation
 *
 * The C++ SDK currently supports IntraProcess and UdpMulticast transports.
 * Additional transports (TCP, QUIC, LowBandwidth) are available through
 * the Rust and C APIs. For TCP/QUIC from C++, use the C FFI directly
 * or configure transport via the HDDS_TRANSPORT environment variable.
 */
enum class TransportMode {
    IntraProcess = 0,
    UdpMulticast = 1,
};

/**
 * @brief DDS error exception
 */
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief Liveliness QoS kind
 */
enum class LivelinessKind {
    Automatic = 0,
    ManualByParticipant = 1,
    ManualByTopic = 2,
};

/**
 * @brief Ownership QoS kind
 */
enum class OwnershipKind {
    Shared,
    Exclusive,
};

/**
 * @brief DSCP (Differentiated Services Code Point) traffic class
 *
 * Used to mark IP packets for QoS prioritization by network routers/switches.
 * Values per RFC 4594 (Configuration Guidelines for DiffServ Service Classes).
 */
enum class DscpClass : uint8_t {
    /// Best Effort (CS0) - Default traffic, no priority
    BestEffort = 0,
    /// AF11 - High-throughput data (bulk transfers)
    Af11 = 10,
    /// AF21 - Low-latency data (standard DDS)
    Af21 = 18,
    /// AF31 - Streaming media
    Af31 = 26,
    /// AF41 - Video streaming, important telemetry
    Af41 = 34,
    /// EF (Expedited Forwarding) - Real-time, safety-critical, lowest latency
    Ef = 46,
    /// CS6 - Network control (routing protocols)
    Cs6 = 48,
    /// CS7 - Network control (highest priority)
    Cs7 = 56,
};

/// Convert DSCP class to TOS byte value (DSCP << 2)
inline constexpr uint8_t dscp_to_tos(DscpClass dscp) {
    return static_cast<uint8_t>(dscp) << 2;
}

// Note: DscpConfig (per-participant DSCP settings) is not yet available
// via the C++ API. Use the HDDS_DSCP environment variable instead:
//   export HDDS_DSCP=ef          # Expedited Forwarding for all traffic
//   export HDDS_DSCP=af21        # Low-latency data (default DDS)
// See DscpClass enum above for available classes.

/**
 * @brief Quality of Service configuration
 *
 * Fluent builder API for configuring DDS QoS policies.
 *
 * Example:
 * @code
 *     auto qos = hdds::QoS::reliable()
 *         .transient_local()
 *         .history_depth(10)
 *         .deadline(std::chrono::milliseconds(100));
 * @endcode
 */
class QoS {
public:
    /**
     * @brief Create default QoS (BestEffort, Volatile)
     */
    static QoS default_qos();

    /**
     * @brief Create Reliable QoS
     */
    static QoS reliable();

    /**
     * @brief Create BestEffort QoS
     */
    static QoS best_effort();

    /**
     * @brief Create the interoperability QoS preset (Reliable, Volatile, KeepLast(10))
     */
    static QoS rti_defaults();

    /**
     * @brief Load QoS from FastDDS XML profile file
     * @param path Path to FastDDS XML profile file
     * @return QoS populated from the XML profile
     * @throws hdds::Error if the file does not exist or contains invalid XML
     */
    static QoS from_file(const std::string& path);

    /**
     * @brief Load QoS from vendor XML file (auto-detect vendor format)
     * @param path Path to XML profile file
     * @return QoS populated from the XML profile
     * @throws hdds::Error if the file does not exist or contains invalid XML
     */
    static QoS from_xml(const std::string& path);

    /**
     * @brief Clone this QoS into a new independent copy
     * @return New QoS copy
     */
    QoS clone() const;

    // Fluent builder methods

    /** @brief Set reliability to RELIABLE */
    QoS& set_reliable();
    /** @brief Set reliability to BEST_EFFORT */
    QoS& set_best_effort();
    /** @brief Set durability to VOLATILE */
    QoS& set_volatile();

    /** @brief Set durability to TRANSIENT_LOCAL (cache for late joiners) */
    QoS& transient_local();
    /** @brief Set durability to VOLATILE (no caching, alias for set_volatile) */
    QoS& volatile_();
    /** @brief Set durability to PERSISTENT (disk storage) */
    QoS& persistent();
    /**
     * @brief Set history depth (KEEP_LAST policy)
     * @param depth Number of samples to keep per instance
     */
    QoS& history_depth(uint32_t depth);
    /** @brief Set history policy to KEEP_ALL (unbounded) */
    QoS& history_keep_all();

    /**
     * @brief Set deadline period
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param d Maximum interval between successive samples
     */
    template<typename Rep, typename Period>
    QoS& deadline(std::chrono::duration<Rep, Period> d) {
        deadline_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
        return *this;
    }

    /**
     * @brief Set lifespan duration (samples older than this are discarded)
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param d Maximum age of a sample before it is discarded
     */
    template<typename Rep, typename Period>
    QoS& lifespan(std::chrono::duration<Rep, Period> d) {
        lifespan_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
        return *this;
    }

    /**
     * @brief Set RELIABILITY max_blocking_time (DDS v1.4 Sec.2.2.3.14)
     *
     * How long a RELIABLE writer's write() may block for room before it
     * returns a timeout. Default 100ms (the DDS spec's default); ignored by
     * BEST_EFFORT writers.
     *
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param d Maximum time a write() may block
     */
    template<typename Rep, typename Period>
    QoS& max_blocking_time(std::chrono::duration<Rep, Period> d) {
        max_blocking_time_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
        return *this;
    }

    /**
     * @brief Set liveliness to AUTOMATIC with given lease duration
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param lease Lease duration (infrastructure asserts liveliness automatically)
     */
    template<typename Rep, typename Period>
    QoS& liveliness_automatic(std::chrono::duration<Rep, Period> lease) {
        liveliness_kind_ = LivelinessKind::Automatic;
        liveliness_lease_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(lease).count();
        liveliness_configured_ = true;
        return *this;
    }

    /**
     * @brief Set liveliness to MANUAL_BY_PARTICIPANT with given lease duration
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param lease Lease duration (application must assert per participant)
     */
    template<typename Rep, typename Period>
    QoS& liveliness_manual_participant(std::chrono::duration<Rep, Period> lease) {
        liveliness_kind_ = LivelinessKind::ManualByParticipant;
        liveliness_lease_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(lease).count();
        liveliness_configured_ = true;
        return *this;
    }

    /**
     * @brief Set liveliness to MANUAL_BY_TOPIC with given lease duration
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param lease Lease duration (application must assert per topic/writer)
     */
    template<typename Rep, typename Period>
    QoS& liveliness_manual_topic(std::chrono::duration<Rep, Period> lease) {
        liveliness_kind_ = LivelinessKind::ManualByTopic;
        liveliness_lease_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(lease).count();
        liveliness_configured_ = true;
        return *this;
    }

    /** @brief Set ownership to SHARED (multiple writers per instance) */
    QoS& ownership_shared();
    /**
     * @brief Set ownership to EXCLUSIVE with given strength
     * @param strength Ownership strength (highest value wins)
     */
    QoS& ownership_exclusive(int32_t strength);
    /**
     * @brief Add a partition name for logical isolation
     * @param name Partition name string
     */
    QoS& partition(const std::string& name);

    /**
     * @brief Set time-based filter (rate-limit sample delivery)
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param min_sep Minimum separation between delivered samples
     */
    template<typename Rep, typename Period>
    QoS& time_based_filter(std::chrono::duration<Rep, Period> min_sep) {
        time_based_filter_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(min_sep).count();
        return *this;
    }

    /**
     * @brief Set latency budget hint
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param budget Maximum acceptable delivery delay (hint, not guarantee)
     */
    template<typename Rep, typename Period>
    QoS& latency_budget(std::chrono::duration<Rep, Period> budget) {
        latency_budget_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(budget).count();
        return *this;
    }

    /**
     * @brief Set transport priority (higher = more important)
     * @param priority Priority value for network QoS mechanisms
     */
    QoS& transport_priority(int32_t priority);
    /**
     * @brief Set resource limits
     * @param max_samples Maximum total samples across all instances (SIZE_MAX = unlimited)
     * @param max_instances Maximum number of instances (SIZE_MAX = unlimited)
     * @param max_per_instance Maximum samples per instance (SIZE_MAX = unlimited)
     */
    QoS& resource_limits(size_t max_samples, size_t max_instances, size_t max_per_instance);

    /**
     * @brief DATA_REPRESENTATION (DDS-XTypes 1.3 7.6.3.1.1)
     *
     * Representation identifiers, in order: XCDR_DATA_REPRESENTATION (0)
     * and XCDR2_DATA_REPRESENTATION (2) are accepted (Error otherwise, when
     * the QoS is used). A writer offers the first; a reader requests them
     * all. Empty (the default): a writer offers XCDR2 and a reader requests
     * XCDR2, except a reader create_reader<T>() makes for a type whose
     * decoders read XCDR1 (decode_by_encapsulation), which requests both.
     */
    QoS& data_representation(std::vector<int16_t> ids);

    // Inspection

    /** @brief Check if reliability is RELIABLE */
    bool is_reliable() const { return reliable_; }
    /** @brief Check if durability is TRANSIENT_LOCAL */
    bool is_transient_local() const { return transient_local_; }
    /** @brief Get history depth (KEEP_LAST count) */
    uint32_t get_history_depth() const { return history_depth_; }
    /** @brief Get latency budget in nanoseconds (0 = none) */
    uint64_t get_latency_budget_ns() const { return latency_budget_ns_; }
    /** @brief Get max samples resource limit (SIZE_MAX = unlimited) */
    size_t get_max_samples() const { return max_samples_; }
    /** @brief Get max instances resource limit (SIZE_MAX = unlimited) */
    size_t get_max_instances() const { return max_instances_; }
    /** @brief Get max samples per instance resource limit (SIZE_MAX = unlimited) */
    size_t get_max_samples_per_instance() const { return max_samples_per_instance_; }
    /** @brief Get time-based filter minimum separation in nanoseconds (0 = no filter) */
    uint64_t get_time_based_filter_ns() const { return time_based_filter_ns_; }
    const std::vector<int16_t>& get_data_representation() const { return data_representation_; }

    /** @brief Get raw C handle (for FFI interop, lazily materializes the handle) */
    HddsQoS* c_handle() const;

    // Copy/move support for builder pattern
    QoS(const QoS& other);
    QoS& operator=(const QoS& other);
    QoS(QoS&& other) noexcept = default;
    QoS& operator=(QoS&& other) noexcept = default;

private:
    QoS() = default;

    bool reliable_ = false;
    bool transient_local_ = false;
    bool persistent_ = false;
    bool history_keep_all_ = false;
    uint32_t history_depth_ = 100;
    uint64_t deadline_ns_ = 0;
    uint64_t lifespan_ns_ = 0;
    uint64_t max_blocking_time_ns_ = 0;
    LivelinessKind liveliness_kind_ = LivelinessKind::Automatic;
    uint64_t liveliness_lease_ns_ = 0;
    bool liveliness_configured_ = false;
    OwnershipKind ownership_kind_ = OwnershipKind::Shared;
    int32_t ownership_strength_ = 0;
    std::vector<std::string> partitions_;
    uint64_t time_based_filter_ns_ = 0;
    uint64_t latency_budget_ns_ = 0;
    int32_t transport_priority_ = 0;
    size_t max_samples_ = SIZE_MAX;
    size_t max_instances_ = SIZE_MAX;
    size_t max_samples_per_instance_ = SIZE_MAX;
    std::vector<int16_t> data_representation_;

    mutable std::unique_ptr<HddsQoS, void(*)(HddsQoS*)> handle_{nullptr, nullptr};
};

/**
 * @brief Extensibility of an IDL type (DDS-XTypes 1.3 7.2.2.4.4)
 */
enum class Extensibility : uint32_t {
    Final = 0,
    Appendable = 1,
    Mutable = 2,
};

// Forward declarations
class DataWriter;
class DataReader;
class WaitSet;
class Publisher;
class Subscriber;
class Metrics;
class TelemetryExporter;

// Forward declare telemetry namespace functions
namespace telemetry {
    Metrics init();
    Metrics get();
    TelemetryExporter start_exporter(const std::string& bind_addr, uint16_t port);
}

// Forward declarations for typed wrappers (defined after DataWriter/DataReader)
template<typename T> class TypedDataWriter;
template<typename T> class TypedDataReader;

/**
 * @brief DDS Domain Participant
 *
 * Entry point for all DDS operations. RAII managed.
 *
 * Example:
 * @code
 *     hdds::Participant participant("my_app");
 *     auto writer = participant.create_writer<MyType>("topic");
 *     writer.write(MyType{42, "hello"});
 * @endcode
 */
class Participant {
public:
    /**
     * @brief Create a participant with UDP multicast transport
     * @param name Application/participant name
     * @param domain_id DDS domain ID. Unset (default): HDDS_DOMAIN_ID if set
     *        and valid, else 0. A value given here always wins.
     */
    explicit Participant(const std::string& name,
                         std::optional<uint32_t> domain_id = std::nullopt);

    /**
     * @brief Create a participant with specified transport mode
     * @param name Application/participant name
     * @param transport Transport mode (IntraProcess or UdpMulticast)
     * @param domain_id DDS domain ID. Unset (default): HDDS_DOMAIN_ID if set
     *        and valid, else 0. A value given here always wins.
     */
    Participant(const std::string& name, TransportMode transport,
                std::optional<uint32_t> domain_id = std::nullopt);

    /**
     * @brief Destructor - cleans up all resources
     */
    ~Participant();

    // Non-copyable
    Participant(const Participant&) = delete;
    Participant& operator=(const Participant&) = delete;

    // Movable
    Participant(Participant&& other) noexcept;
    Participant& operator=(Participant&& other) noexcept;

    /**
     * @brief Create a typed DataWriter with default QoS
     *
     * A type hddsgen 2.0 or later generated says its extensibility
     * (T::hdds_extensibility): every sample's encapsulation identifier
     * names it (DDS-XTypes 1.3 Table 60: D_CDR2_LE for an APPENDABLE type,
     * the hddsgen default, PL_CDR2_LE for a MUTABLE one, CDR2_LE for a
     * FINAL one). A type without it is labelled CDR2_LE, as before.
     * @tparam T Type to publish (must have CDR2 serialization via hddsgen)
     * @param topic_name Topic name
     * @return TypedDataWriter<T> with write(const T&) method
     */
    template<typename T>
    TypedDataWriter<T> create_writer(
        const std::string& topic_name);

    /**
     * @brief Create a typed DataWriter with custom QoS
     * @tparam T Type to publish (must have CDR2 serialization via hddsgen)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return TypedDataWriter<T> with write(const T&) method
     */
    template<typename T>
    TypedDataWriter<T> create_writer(
        const std::string& topic_name,
        const QoS& qos);

    /**
     * @brief Create a typed DataReader with default QoS
     * @tparam T Type to subscribe (must have CDR2 deserialization via hddsgen)
     * @param topic_name Topic name
     * @return TypedDataReader<T> with take() method
     */
    template<typename T>
    TypedDataReader<T> create_reader(
        const std::string& topic_name);

    /**
     * @brief Create a typed DataReader with custom QoS
     * @tparam T Type to subscribe (must have CDR2 deserialization via hddsgen)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return TypedDataReader<T> with take() method
     */
    template<typename T>
    TypedDataReader<T> create_reader(
        const std::string& topic_name,
        const QoS& qos);

    /**
     * @brief Create a raw DataWriter with default QoS (untyped)
     *
     * @param type_name The DDS type name to announce. `nullptr` (the default)
     * is for a genuinely raw endpoint, which has no type of its own: it
     * announces the type name its topic's other endpoints already announce
     * (exactly one name), else the placeholder "RawBytes" (XTypes 1.3
     * Sec.7.6.3.4.2 Step 2). Creation then blocks for up to
     * HDDS_TYPE_ADOPT_WAIT_MS when that variable is set and no name is
     * known yet. create_writer<T>() / create_reader<T>() pass the type's own
     * name: an endpoint created for a type never takes a peer's.
     */
    std::unique_ptr<DataWriter> create_writer_raw(
        const std::string& topic_name,
        const char* type_name = nullptr);

    /**
     * @brief Create a raw DataWriter with custom QoS (untyped)
     */
    std::unique_ptr<DataWriter> create_writer_raw(
        const std::string& topic_name,
        const QoS& qos,
        const char* type_name = nullptr);

    /**
     * @brief Create a raw DataWriter whose samples carry their type's
     * extensibility (hdds_writer_create_with_extensibility)
     *
     * The encapsulation identifier of a sample names the extensibility of
     * the IDL type its body is encoded from (DDS-XTypes 1.3 Table 60:
     * D_CDR2_LE APPENDABLE, PL_CDR2_LE MUTABLE); the other constructors
     * label every body FINAL (CDR2_LE). hddsgen makes a type without an
     * annotation APPENDABLE.
     */
    std::unique_ptr<DataWriter> create_writer_raw(
        const std::string& topic_name,
        const QoS& qos,
        Extensibility extensibility,
        const char* type_name = nullptr);

    /**
     * @brief create_writer_raw(topic_name, qos, extensibility) with the
     * default QoS
     */
    std::unique_ptr<DataWriter> create_writer_raw(
        const std::string& topic_name,
        Extensibility extensibility,
        const char* type_name = nullptr);

    /**
     * @brief Create a raw DataReader with default QoS (untyped)
     *
     * With no type_name the reader has no type of its own: see
     * create_writer_raw for the name it announces and the wait.
     */
    std::unique_ptr<DataReader> create_reader_raw(
        const std::string& topic_name,
        const char* type_name = nullptr);

    /**
     * @brief Create a raw DataReader with custom QoS (untyped)
     */
    std::unique_ptr<DataReader> create_reader_raw(
        const std::string& topic_name,
        const QoS& qos,
        const char* type_name = nullptr);

    /**
     * @brief Create a raw DataReader that requests XCDR as well as XCDR2
     *
     * What create_reader<T>() uses for a type whose decoders read XCDR1
     * (decode_by_encapsulation): the reader requests [XCDR, XCDR2] unless
     * `qos` sets a DATA_REPRESENTATION of its own, which is kept. `qos`
     * NULL: the default QoS. Take with take_raw_sample() to learn each
     * sample's representation.
     */
    std::unique_ptr<DataReader> create_reader_raw_decoding_xcdr1(
        const std::string& topic_name,
        const QoS* qos,
        const char* type_name = nullptr);

    /**
     * @brief Create a Publisher with default QoS
     */
    std::unique_ptr<Publisher> create_publisher();

    /**
     * @brief Create a Publisher with custom QoS
     */
    std::unique_ptr<Publisher> create_publisher(const QoS& qos);

    /**
     * @brief Create a Subscriber with default QoS
     */
    std::unique_ptr<Subscriber> create_subscriber();

    /**
     * @brief Create a Subscriber with custom QoS
     */
    std::unique_ptr<Subscriber> create_subscriber(const QoS& qos);

    /** @brief Get participant name (via FFI) */
    std::string get_name() const;

    /** @brief Get participant domain ID (via FFI) */
    uint32_t get_domain_id() const;

    /** @brief Get cached participant name */
    const std::string& name() const { return name_; }
    /** @brief Get cached domain ID */
    uint32_t domain_id() const { return domain_id_; }
    /** @brief Get participant ID (unique within domain, 0-119) */
    uint8_t participant_id() const;

    /**
     * @brief Get graph guard condition for discovery notifications
     * @return Raw guard condition handle (owned by participant)
     */
    HddsGuardCondition* graph_guard_condition();

    /**
     * @brief Manually assert this participant's liveliness (DDS v1.4
     * Sec.2.2.3.11, Sec.2.2.2.2.4.19): renews the lease every
     * MANUAL_BY_PARTICIPANT writer of this participant shares, with
     * nothing to write. A no-op on a participant with no such writer yet.
     */
    void assert_liveliness();

#ifdef HDDS_WITH_ROS2
    /**
     * @brief Register a ROS2 type support with the participant
     * @param distro ROS2 distro (0=Humble, 1=Iron, 2=Jazzy)
     * @param type_support Pointer to rosidl type support struct
     * @return Opaque type object handle (must be released with hdds_type_object_release)
     */
    const void* register_type_support(uint32_t distro, const void* type_support);
#endif

    std::unique_ptr<DataWriter> create_keyed_writer_raw(const std::string& topic_name, Extensibility extensibility, const char* type_name = nullptr);
    std::unique_ptr<DataWriter> create_keyed_writer_raw(const std::string& topic_name, const QoS& qos, Extensibility extensibility, const char* type_name = nullptr);

    HddsParticipant* c_handle() const { return handle_; }

private:
    std::string name_;
    uint32_t domain_id_;
    HddsParticipant* handle_ = nullptr;
};

// =============================================================================
// Type detection traits (C++17) for hddsgen CDR2 codec methods
// =============================================================================

namespace detail {

template<typename T, typename = void>
struct has_encode_cdr2_le : std::false_type {};
template<typename T>
struct has_encode_cdr2_le<T, std::void_t<
    decltype(std::declval<const T&>().encode_cdr2_le(
        std::declval<std::uint8_t*>(), std::declval<std::size_t>()))
>> : std::true_type {};

template<typename T, typename = void>
struct has_decode_cdr2_le : std::false_type {};
template<typename T>
struct has_decode_cdr2_le<T, std::void_t<
    decltype(std::declval<T&>().decode_cdr2_le(
        std::declval<const std::uint8_t*>(), std::declval<std::size_t>()))
>> : std::true_type {};

/// A type whose decoders read XCDR1 as well as XCDR2 and pick one by the
/// sample's encapsulation identifier (hddsgen 2.0 and later:
/// decode_by_encapsulation(uint16_t, const uint8_t*, size_t) -> int). A
/// reader of such a type requests [XCDR, XCDR2]; a reader of any other
/// type requests XCDR2 only (DDS-XTypes 1.3 7.6.3.1.1).
template<typename T, typename = void>
struct has_decode_by_encapsulation : std::false_type {};
template<typename T>
struct has_decode_by_encapsulation<T, std::void_t<
    decltype(std::declval<T&>().decode_by_encapsulation(
        std::declval<std::uint16_t>(), std::declval<const std::uint8_t*>(),
        std::declval<std::size_t>()))
>> : std::true_type {};

/// A type that says its extensibility (hddsgen 2.0 and later: `static
/// constexpr std::uint32_t hdds_extensibility`, 0 FINAL, 1 APPENDABLE, 2
/// MUTABLE, the values of Extensibility). create_writer<T>() of such a type
/// labels every sample with it (DDS-XTypes 1.3 7.6.3.1.2, Table 60:
/// CDR2_LE, D_CDR2_LE, PL_CDR2_LE); a writer of any other type labels every
/// sample CDR2_LE, as earlier releases did.
template<typename T, typename = void>
struct has_hdds_extensibility : std::false_type {};
template<typename T>
struct has_hdds_extensibility<T, std::enable_if_t<
    std::is_convertible<decltype(T::hdds_extensibility), std::uint32_t>::value
>> : std::true_type {};

/// A type that says its qualified IDL name (hddsgen: `static constexpr const
/// char* hdds_type_name`, module scopes joined with "::", the name the Rust
/// backend's type_descriptor() carries). create_writer<T>() / create_reader<T>()
/// of such a type announce it in discovery, so the endpoint matches a peer of
/// the same type under XTypes 1.3 Sec.7.6.3.4.2 Step 2; a type without it
/// (code generated by an older hddsgen) announces the placeholder "RawBytes"
/// explicitly, as earlier releases did. Never the generated
/// `FooPubSubType::type_name()`, which older hddsgen releases emitted
/// unscoped.
template<typename T, typename = void>
struct has_hdds_type_name : std::false_type {};
template<typename T>
struct has_hdds_type_name<T, std::enable_if_t<
    std::is_convertible<decltype(T::hdds_type_name), const char*>::value
>> : std::true_type {};

/// The type name create_writer<T>() / create_reader<T>() announce. A type
/// whose hdds_type_name is nullptr or empty says no name, and announces the
/// placeholder too: a NULL or empty name at the C ABI is an endpoint with no
/// type, which would adopt a peer's name.
template<typename T>
constexpr const char* type_name_of() noexcept {
    if constexpr (has_hdds_type_name<T>::value) {
        const char* declared = T::hdds_type_name;
        return (declared != nullptr && declared[0] != '\0') ? declared : "RawBytes";
    } else {
        return "RawBytes";
    }
}

struct SerializedKey {
    std::array<std::uint8_t, 16> hash{};
    std::array<std::uint8_t, 16> protected_hash{};
    std::vector<std::uint8_t> payload;
};

template<typename T, typename = void>
struct has_hdds_key : std::false_type {};
template<typename T>
struct has_hdds_key<T, std::void_t<
    decltype(T::hdds_has_key()),
    decltype(std::declval<const T&>().hdds_compute_key(nullptr, false)),
    decltype(std::declval<const T&>().encode_key_cdr2_le(nullptr, std::size_t{}))
>> : std::true_type {};

/// The extensibility a hddsgen type says it has (has_hdds_extensibility).
template<typename T>
constexpr Extensibility extensibility_of() noexcept {
    return static_cast<Extensibility>(static_cast<std::uint32_t>(T::hdds_extensibility));
}

/// CDR2_LE: the identifier hdds_reader_take_ex reports for an XCDR2 sample.
constexpr std::uint16_t ENCAPSULATION_CDR2_LE = 0x0007;

/// The C QoS of a reader that decodes XCDR1: `qos` (the C default when
/// NULL) requesting [XCDR, XCDR2], unless `qos` sets a DATA_REPRESENTATION
/// of its own. The caller destroys it (hdds_qos_destroy).
HddsQoS* qos_requesting_xcdr1(const QoS* qos);

} // namespace detail

/**
 * @brief DDS DataWriter for publishing
 */
class DataWriter {
public:
    ~DataWriter();

    // Non-copyable, movable
    DataWriter(const DataWriter&) = delete;
    DataWriter& operator=(const DataWriter&) = delete;
    DataWriter(DataWriter&& other) noexcept;
    DataWriter& operator=(DataWriter&& other) noexcept;

    /**
     * @brief Write typed data
     *
     * Supports two interfaces:
     * - hddsgen types with encode_cdr2_le(uint8_t*, size_t) -> int (preferred)
     * - Custom types with serialize() -> vector<uint8_t> (fallback)
     */
    template<typename T>
    void write(const T& data) {
        with_serialized(data, [this, &data](const uint8_t* bytes, size_t size) {
            with_key(data, [&](const detail::SerializedKey* key) {
                if (key) keyed_operation(bytes, size, *key, 0);
                else write_raw(bytes, size);
            });
        });
    }

    /**
     * @brief Write raw bytes
     */
    void write_raw(const uint8_t* data, size_t size);
    void write_raw(const std::vector<uint8_t>& data);

    /**
     * @brief Manually assert this writer's liveliness (DDS v1.4
     * Sec.2.2.3.11, Sec.2.2.2.4.2.22): renews its LIVELINESS lease without
     * writing a sample. A no-op for AUTOMATIC or an infinite lease.
     */
    void assert_liveliness();

    /** @brief Get cached topic name */
    const std::string& topic_name() const { return topic_name_; }

    /** @brief Get topic name from FFI layer (slower, round-trips to C) */
    std::string get_topic_name_ffi() const;

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataWriter* c_handle() const { return handle_; }

    /**
     * @brief Get status condition for WaitSet integration
     */
    HddsStatusCondition* get_status_condition();

    // DDS v1.4 Sec.2.2.4.2.1: read status and reset its change counters.
    PublicationMatchedStatus get_publication_matched_status();
    DeadlineMissedStatus get_offered_deadline_missed_status();
    IncompatibleQosStatus get_offered_incompatible_qos_status();
    LivelinessLostStatus get_liveliness_lost_status();

    // Explicit timestamps use nanoseconds since the Unix epoch.
    void write_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns);
    void dispose(const uint8_t* data, size_t size);
    void dispose_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns);
    void unregister_instance(const uint8_t* data, size_t size);
    void unregister_instance_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns);
    InstanceHandle register_instance(const uint8_t* data, size_t size);
    InstanceHandle register_instance_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns);
    void write_w_timestamp(const std::vector<uint8_t>& data, uint64_t source_timestamp_ns) {
        return write_w_timestamp(data.data(), data.size(), source_timestamp_ns);
    }
    void dispose(const std::vector<uint8_t>& data) {
        return dispose(data.data(), data.size());
    }
    void dispose_w_timestamp(const std::vector<uint8_t>& data, uint64_t source_timestamp_ns) {
        return dispose_w_timestamp(data.data(), data.size(), source_timestamp_ns);
    }
    void unregister_instance(const std::vector<uint8_t>& data) {
        return unregister_instance(data.data(), data.size());
    }
    void unregister_instance_w_timestamp(const std::vector<uint8_t>& data, uint64_t source_timestamp_ns) {
        return unregister_instance_w_timestamp(data.data(), data.size(), source_timestamp_ns);
    }
    InstanceHandle register_instance(const std::vector<uint8_t>& data) {
        return register_instance(data.data(), data.size());
    }
    InstanceHandle register_instance_w_timestamp(const std::vector<uint8_t>& data, uint64_t source_timestamp_ns) {
        return register_instance_w_timestamp(data.data(), data.size(), source_timestamp_ns);
    }
    bool wait_for_acknowledgments(std::chrono::milliseconds timeout = std::chrono::seconds(10));

    template<typename T>
    void write_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return with_serialized(data, [this, &data, source_timestamp_ns](const uint8_t* bytes, size_t size) {
            return with_key(data, [&](const detail::SerializedKey* key) {
                if (key) keyed_operation(bytes, size, *key, 1, source_timestamp_ns);
                else write_w_timestamp(bytes, size, source_timestamp_ns);
            });
        });
    }

    template<typename T>
    void dispose(const T& data) {
        return with_key(data, [&](const detail::SerializedKey* key) {
            if (key) { keyed_operation(nullptr, 0, *key, 2); return; }
            return with_serialized(data, [&](const uint8_t* bytes, size_t size) {
                return dispose(bytes, size);
            });
        });
    }

    template<typename T>
    void dispose_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return with_key(data, [&](const detail::SerializedKey* key) {
            if (key) { keyed_operation(nullptr, 0, *key, 3, source_timestamp_ns); return; }
            return with_serialized(data, [&](const uint8_t* bytes, size_t size) {
                return dispose_w_timestamp(bytes, size, source_timestamp_ns);
            });
        });
    }

    template<typename T>
    void unregister_instance(const T& data) {
        return with_key(data, [&](const detail::SerializedKey* key) {
            if (key) { keyed_operation(nullptr, 0, *key, 4); return; }
            return with_serialized(data, [&](const uint8_t* bytes, size_t size) {
                return unregister_instance(bytes, size);
            });
        });
    }

    template<typename T>
    void unregister_instance_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return with_key(data, [&](const detail::SerializedKey* key) {
            if (key) { keyed_operation(nullptr, 0, *key, 5, source_timestamp_ns); return; }
            return with_serialized(data, [&](const uint8_t* bytes, size_t size) {
                return unregister_instance_w_timestamp(bytes, size, source_timestamp_ns);
            });
        });
    }

    template<typename T>
    InstanceHandle register_instance(const T& data) {
        return with_key(data, [&](const detail::SerializedKey* key) -> InstanceHandle {
            if (key) return keyed_operation(nullptr, 0, *key, 6);
            return with_serialized(data, [&](const uint8_t* bytes, size_t size) {
                return register_instance(bytes, size);
            });
        });
    }

    template<typename T>
    InstanceHandle register_instance_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return with_key(data, [&](const detail::SerializedKey* key) -> InstanceHandle {
            if (key) return keyed_operation(nullptr, 0, *key, 7, source_timestamp_ns);
            return with_serialized(data, [&](const uint8_t* bytes, size_t size) {
                return register_instance_w_timestamp(bytes, size, source_timestamp_ns);
            });
        });
    }


    /**
     * @brief Keep the state of an installed listener alive with this writer.
     *
     * Used by hdds_listener.hpp, which releases a state (by the pointer it
     * passed as the C user_data) once hdds_writer_exchange_listener reports
     * it replaced; every state still held is released after the writer is
     * destroyed (hdds_writer_destroy waits for running callbacks). Not
     * needed for direct use of the C API. Thread-safe.
     */
    void hold_listener_state(std::shared_ptr<void> state) {
        std::lock_guard<std::mutex> guard(listener_mu_);
        listener_states_.push_back(std::move(state));
    }

    /** @brief Release the held listener state whose pointer is `key` (no-op if none). */
    void release_listener_state(const void* key) {
        std::shared_ptr<void> released;  // destroyed after the lock is dropped
        std::lock_guard<std::mutex> guard(listener_mu_);
        for (auto it = listener_states_.begin(); it != listener_states_.end(); ++it) {
            if (it->get() == key) {
                released = std::move(*it);
                listener_states_.erase(it);
                break;
            }
        }
    }

private:
    InstanceHandle keyed_operation(const uint8_t* data, size_t size,
                                   const detail::SerializedKey& key,
                                   unsigned operation, uint64_t timestamp = 0);

    template<typename T, typename F>
    auto with_key(const T& data, F operation) {
        if (!keyed_) return operation(nullptr);
        return with_type_key(data, operation);
    }

    template<typename T, typename F>
    static auto with_type_key(const T& data, F operation) {
        if constexpr (detail::has_hdds_key<T>::value) {
            if (T::hdds_has_key()) {
                detail::SerializedKey key{};
                if (!data.hdds_compute_key(key.hash.data(), false) ||
                    !data.hdds_compute_key(key.protected_hash.data(), true))
                    throw Error("unsupported keyed type");
                for (std::size_t sz = 1024; sz <= 16 * 1024 * 1024; sz *= 2) {
                    std::vector<std::uint8_t> bytes(sz);
                    int n = data.encode_key_cdr2_le(bytes.data(), bytes.size());
                    if (n >= 0) {
                        bytes.resize(static_cast<std::size_t>(n));
                        key.payload = std::move(bytes);
                        return operation(&key);
                    }
                }
                throw Error("key serialization failed");
            }
        }
        return operation(nullptr);
    }

    template<typename T, typename F>
    static auto with_serialized(const T& data, F operation) {
        if constexpr (detail::has_encode_cdr2_le<T>::value) {
            // Fast path: stack buffer for small messages (zero heap alloc)
            std::uint8_t stack_buf[16384];
            int n = data.encode_cdr2_le(stack_buf, sizeof(stack_buf));
            if (n > 0) {
                return operation(stack_buf, static_cast<std::size_t>(n));
            }
            // Slow path: heap allocation for messages > 16KB
            for (std::size_t sz = 65536; sz <= 16 * 1024 * 1024; sz *= 2) {
                std::vector<std::uint8_t> heap_buf(sz);
                n = data.encode_cdr2_le(heap_buf.data(), heap_buf.size());
                if (n > 0) {
                    return operation(heap_buf.data(), static_cast<std::size_t>(n));
                }
            }
            throw Error("CDR2 serialization failed (message exceeds 16MB)");
        } else {
            auto bytes = data.serialize();
            return operation(bytes.data(), bytes.size());
        }
    }


    friend class Participant;
    friend class Publisher;
    template<typename> friend class TypedDataWriter;
    template<typename T>
    void configure_codec() {
        if constexpr (detail::has_hdds_key<T>::value && detail::has_decode_cdr2_le<T>::value &&
                      std::is_default_constructible<T>::value) {
            if (keyed_) key_from_bytes_ = [](const uint8_t* bytes, size_t size) {
                T value{};
                if (value.decode_cdr2_le(bytes, size) < 0) throw Error("invalid CDR2 body");
                return with_type_key(value, [](const detail::SerializedKey* key) {
                    if (!key) throw Error("encoded body has no instance key");
                    return *key;
                });
            };
        }
    }
    DataWriter(const std::string& topic, HddsDataWriter* handle, bool keyed = false);

    std::string topic_name_;
    HddsDataWriter* handle_ = nullptr;
    bool keyed_ = false;
    std::function<detail::SerializedKey(const uint8_t*, size_t)> key_from_bytes_;
    HddsStatusCondition* cached_status_condition_ = nullptr;
    // Declared last: destroyed after the destructor body has destroyed the
    // C writer (which waits for running callbacks).
    std::mutex listener_mu_;
    std::vector<std::shared_ptr<void>> listener_states_;
};

/**
 * @brief DDS DataReader for subscribing
 */
class DataReader {
public:
    ~DataReader();

    // Non-copyable, movable
    DataReader(const DataReader&) = delete;
    DataReader& operator=(const DataReader&) = delete;
    DataReader(DataReader&& other) noexcept;
    DataReader& operator=(DataReader&& other) noexcept;

    /**
     * @brief Take typed data (non-blocking)
     *
     * Supports two interfaces:
     * - hddsgen types with decode_cdr2_le(const uint8_t*, size_t) -> int (preferred)
     * - Custom types with static T::deserialize(const uint8_t*, size_t) (fallback)
     *
     * @return Data if available, std::nullopt otherwise
     */
    template<typename T>
    std::optional<T> take() {
        if constexpr (detail::has_decode_by_encapsulation<T>::value) {
            // The decoder the sample's representation names (XCDR1 or XCDR2).
            auto sample = take_raw_sample();
            if (!sample) return std::nullopt;
            T result{};
            if (result.decode_by_encapsulation(sample->encapsulation_id,
                                               sample->data.data(),
                                               sample->data.size()) < 0)
                throw Error("deserialization failed (encapsulation " +
                            std::to_string(sample->encapsulation_id) + ")");
            return result;
        } else if constexpr (detail::has_decode_cdr2_le<T>::value) {
            auto sample = take_raw_sample();
            if (!sample) return std::nullopt;
            // T reads XCDR2 only. A reader whose QoS requested XCDR too can
            // receive XCDR1: refuse it rather than misread it.
            if (sample->encapsulation_id != detail::ENCAPSULATION_CDR2_LE)
                throw Error("an XCDR1 sample, and T decodes XCDR2 only "
                            "(regenerate it with hddsgen 2.0 or request XCDR2 only)");
            T result{};
            if (result.decode_cdr2_le(sample->data.data(), sample->data.size()) < 0)
                throw Error("CDR2 deserialization failed");
            return result;
        } else {
            auto raw = take_raw();
            if (!raw) return std::nullopt;
            return T::deserialize(raw->data(), raw->size());
        }
    }

    /**
     * @brief Take raw bytes (non-blocking)
     */
    std::optional<std::vector<uint8_t>> take_raw();

    /** @brief A sample's body and the representation it is in. */
    struct RawSample {
        /** The serialized body, without its encapsulation header. */
        std::vector<uint8_t> data;
        /**
         * CDR_LE (0x0001) for XCDR1, CDR2_LE (0x0007) for XCDR2: the
         * encapsulation identifier decode_by_encapsulation() takes (the
         * encoding version; the extensibility framing is not reported).
         */
        uint16_t encapsulation_id = 0;
    };

    /**
     * @brief Take raw bytes and their representation (non-blocking)
     *
     * hdds_reader_take_ex. A reader receives XCDR1 only when it requests it
     * (QoS::data_representation, or create_reader<T>() for a type that
     * decodes XCDR1).
     */
    std::optional<RawSample> take_raw_sample();

    /**
     * @brief Get status condition for WaitSet integration
     */
    HddsStatusCondition* get_status_condition();

    // DDS v1.4 Sec.2.2.4.2.1: read status and reset its change counters.
    SubscriptionMatchedStatus get_subscription_matched_status();
    DeadlineMissedStatus get_requested_deadline_missed_status();
    IncompatibleQosStatus get_requested_incompatible_qos_status();
    LivelinessChangedStatus get_liveliness_changed_status();
    SampleLostStatus get_sample_lost_status();
    SampleRejectedStatus get_sample_rejected_status();

    /** @brief Get cached topic name */
    const std::string& topic_name() const { return topic_name_; }

    /** @brief Get topic name from FFI layer (slower, round-trips to C) */
    std::string get_topic_name_ffi() const;

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataReader* c_handle() const { return handle_; }

    /**
     * @brief Keep the state of an installed listener alive with this reader.
     *
     * Used by hdds_listener.hpp, which releases a state (by the pointer it
     * passed as the C user_data) once hdds_reader_exchange_listener reports
     * it replaced; every state still held is released after the reader is
     * destroyed (hdds_reader_destroy waits for running callbacks). Not
     * needed for direct use of the C API. Thread-safe.
     */
    void hold_listener_state(std::shared_ptr<void> state) {
        std::lock_guard<std::mutex> guard(listener_mu_);
        listener_states_.push_back(std::move(state));
    }

    /** @brief Release the held listener state whose pointer is `key` (no-op if none). */
    void release_listener_state(const void* key) {
        std::shared_ptr<void> released;  // destroyed after the lock is dropped
        std::lock_guard<std::mutex> guard(listener_mu_);
        for (auto it = listener_states_.begin(); it != listener_states_.end(); ++it) {
            if (it->get() == key) {
                released = std::move(*it);
                listener_states_.erase(it);
                break;
            }
        }
    }

private:
    friend class Participant;
    friend class Subscriber;
    DataReader(const std::string& topic, HddsDataReader* handle);

    std::string topic_name_;
    HddsDataReader* handle_ = nullptr;
    HddsStatusCondition* cached_status_condition_ = nullptr;
    // Declared last: destroyed after the destructor body has destroyed the
    // C reader (which waits for running callbacks).
    std::mutex listener_mu_;
    std::vector<std::shared_ptr<void>> listener_states_;
};

// =============================================================================
// Typed wrappers -- returned by create_writer<T>() / create_reader<T>()
// Eliminate redundant template arguments: writer.write(msg) and reader.take()
// =============================================================================

/**
 * @brief Typed DataWriter wrapper
 *
 * Returned by Participant::create_writer<T>(). Provides write(const T&)
 * without needing to re-specify the type on each call.
 *
 * @tparam T hddsgen type (must have encode_cdr2_le)
 */
template<typename T>
class TypedDataWriter {
public:
    explicit TypedDataWriter(std::unique_ptr<DataWriter> writer)
        : inner_(std::move(writer)) { inner_->template configure_codec<T>(); }

    // Non-copyable, movable
    TypedDataWriter(const TypedDataWriter&) = delete;
    TypedDataWriter& operator=(const TypedDataWriter&) = delete;
    TypedDataWriter(TypedDataWriter&&) = default;
    TypedDataWriter& operator=(TypedDataWriter&&) = default;

    /** @brief Write typed data (CDR2 serialization handled automatically) */
    void write(const T& data) { inner_->write<T>(data); }

    /** @brief Manually assert this writer's liveliness; see DataWriter::assert_liveliness(). */
    void assert_liveliness() { inner_->assert_liveliness(); }

    /** @brief Get topic name */
    const std::string& topic_name() const { return inner_->topic_name(); }

    /** @brief Access underlying DataWriter for raw operations or FFI */
    DataWriter* raw() { return inner_.get(); }
    const DataWriter* raw() const { return inner_.get(); }

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataWriter* c_handle() const { return inner_->c_handle(); }

    PublicationMatchedStatus get_publication_matched_status() { return inner_->get_publication_matched_status(); }
    DeadlineMissedStatus get_offered_deadline_missed_status() { return inner_->get_offered_deadline_missed_status(); }
    IncompatibleQosStatus get_offered_incompatible_qos_status() { return inner_->get_offered_incompatible_qos_status(); }
    LivelinessLostStatus get_liveliness_lost_status() { return inner_->get_liveliness_lost_status(); }
    void write_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        inner_->write_w_timestamp<T>(data, source_timestamp_ns);
    }
    bool wait_for_acknowledgments(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
        return inner_->wait_for_acknowledgments(timeout);
    }

    void dispose(const T& data) {
        return inner_->dispose<T>(data);
    }
    void dispose_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return inner_->dispose_w_timestamp<T>(data, source_timestamp_ns);
    }
    void unregister_instance(const T& data) {
        return inner_->unregister_instance<T>(data);
    }
    void unregister_instance_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return inner_->unregister_instance_w_timestamp<T>(data, source_timestamp_ns);
    }
    InstanceHandle register_instance(const T& data) {
        return inner_->register_instance<T>(data);
    }
    InstanceHandle register_instance_w_timestamp(const T& data, uint64_t source_timestamp_ns) {
        return inner_->register_instance_w_timestamp<T>(data, source_timestamp_ns);
    }

private:
    std::unique_ptr<DataWriter> inner_;
};

/**
 * @brief Typed DataReader wrapper
 *
 * Returned by Participant::create_reader<T>(). Provides take()
 * without needing to re-specify the type on each call.
 *
 * @tparam T hddsgen type (must have decode_cdr2_le)
 */
template<typename T>
class TypedDataReader {
public:
    explicit TypedDataReader(std::unique_ptr<DataReader> reader)
        : inner_(std::move(reader)) {}

    // Non-copyable, movable
    TypedDataReader(const TypedDataReader&) = delete;
    TypedDataReader& operator=(const TypedDataReader&) = delete;
    TypedDataReader(TypedDataReader&&) = default;
    TypedDataReader& operator=(TypedDataReader&&) = default;

    /** @brief Take typed data (CDR2 deserialization handled automatically) */
    std::optional<T> take() { return inner_->take<T>(); }

    /** @brief Get status condition for WaitSet integration */
    HddsStatusCondition* get_status_condition() { return inner_->get_status_condition(); }

    /** @brief Get topic name */
    const std::string& topic_name() const { return inner_->topic_name(); }

    /** @brief Access underlying DataReader for raw operations or FFI */
    DataReader* raw() { return inner_.get(); }
    const DataReader* raw() const { return inner_.get(); }

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataReader* c_handle() const { return inner_->c_handle(); }

    SubscriptionMatchedStatus get_subscription_matched_status() { return inner_->get_subscription_matched_status(); }
    DeadlineMissedStatus get_requested_deadline_missed_status() { return inner_->get_requested_deadline_missed_status(); }
    IncompatibleQosStatus get_requested_incompatible_qos_status() { return inner_->get_requested_incompatible_qos_status(); }
    LivelinessChangedStatus get_liveliness_changed_status() { return inner_->get_liveliness_changed_status(); }
    SampleLostStatus get_sample_lost_status() { return inner_->get_sample_lost_status(); }
    SampleRejectedStatus get_sample_rejected_status() { return inner_->get_sample_rejected_status(); }

private:
    std::unique_ptr<DataReader> inner_;
};

/**
 * @brief Guard condition for manual triggering
 */
class GuardCondition {
public:
    GuardCondition();
    ~GuardCondition();

    GuardCondition(const GuardCondition&) = delete;
    GuardCondition& operator=(const GuardCondition&) = delete;
    GuardCondition(GuardCondition&& other) noexcept;
    GuardCondition& operator=(GuardCondition&& other) noexcept;

    /** @brief Set the guard condition trigger value to true (wakes attached WaitSets) */
    void trigger();
    /** @brief Get raw C handle (for advanced usage or FFI interop) */
    HddsGuardCondition* c_handle() const { return handle_; }

private:
    HddsGuardCondition* handle_ = nullptr;
};

/**
 * @brief WaitSet for blocking synchronization
 */
class WaitSet {
public:
    WaitSet();
    ~WaitSet();

    WaitSet(const WaitSet&) = delete;
    WaitSet& operator=(const WaitSet&) = delete;
    WaitSet(WaitSet&& other) noexcept;
    WaitSet& operator=(WaitSet&& other) noexcept;

    /**
     * @brief Attach a status condition to this WaitSet
     * @param cond Status condition handle (from DataReader::get_status_condition()
     *             or DataWriter::get_status_condition())
     */
    void attach(HddsStatusCondition* cond);
    /**
     * @brief Attach a guard condition to this WaitSet
     * @param cond Guard condition to attach
     */
    void attach(GuardCondition& cond);
    /**
     * @brief Detach a status condition from this WaitSet
     * @param cond Status condition handle to detach
     */
    void detach(HddsStatusCondition* cond);
    /**
     * @brief Detach a guard condition from this WaitSet
     * @param cond Guard condition to detach
     */
    void detach(GuardCondition& cond);

    /**
     * @brief Wait for conditions
     * @param timeout Max wait time (std::nullopt = infinite)
     * @return true if conditions triggered, false on timeout
     */
    template<typename Rep, typename Period>
    bool wait(std::chrono::duration<Rep, Period> timeout) {
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count();
        return wait_impl(ns);
    }

    /** @brief Wait indefinitely for conditions to trigger */
    bool wait() { return wait_impl(-1); }

private:
    bool wait_impl(int64_t timeout_ns);
    HddsWaitSet* handle_ = nullptr;
};

// =============================================================================
// Logging
// =============================================================================

/**
 * @brief Log level for HDDS
 */
enum class LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
};

namespace logging {

/**
 * @brief Initialize logging with specified level
 */
void init(LogLevel level);

/**
 * @brief Initialize logging with environment variable fallback
 */
void init_env(LogLevel default_level = LogLevel::Info);

/**
 * @brief Initialize logging with custom filter string
 */
void init_filter(const std::string& filter);

} // namespace logging

// =============================================================================
// Telemetry
// =============================================================================

/**
 * @brief Metrics snapshot
 */
struct MetricsSnapshot {
    uint64_t timestamp_ns = 0;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    uint64_t messages_dropped = 0;
    uint64_t bytes_sent = 0;
    uint64_t latency_p50_ns = 0;
    uint64_t latency_p99_ns = 0;
    uint64_t latency_p999_ns = 0;
    uint64_t merge_full_count = 0;
    uint64_t would_block_count = 0;

    // Convenience getters
    double latency_p50_ms() const { return latency_p50_ns / 1e6; }
    double latency_p99_ms() const { return latency_p99_ns / 1e6; }
    double latency_p999_ms() const { return latency_p999_ns / 1e6; }
};

/**
 * @brief Metrics collector handle
 */
class Metrics {
public:
    ~Metrics();

    Metrics(const Metrics&) = delete;
    Metrics& operator=(const Metrics&) = delete;
    Metrics(Metrics&& other) noexcept;
    Metrics& operator=(Metrics&& other) noexcept;

    /**
     * @brief Take snapshot of current metrics
     */
    MetricsSnapshot snapshot();

    /**
     * @brief Record a latency sample
     */
    void record_latency(uint64_t start_ns, uint64_t end_ns);

private:
    friend class TelemetryExporter;
    friend Metrics telemetry::init();
    friend Metrics telemetry::get();
    explicit Metrics(HddsMetrics* handle);

    HddsMetrics* handle_ = nullptr;
};

/**
 * @brief Telemetry TCP exporter for HDDS Viewer
 */
class TelemetryExporter {
public:
    ~TelemetryExporter();

    TelemetryExporter(const TelemetryExporter&) = delete;
    TelemetryExporter& operator=(const TelemetryExporter&) = delete;
    TelemetryExporter(TelemetryExporter&& other) noexcept;
    TelemetryExporter& operator=(TelemetryExporter&& other) noexcept;

    /** @brief Stop the exporter and close connections */
    void stop();

private:
    friend TelemetryExporter telemetry::start_exporter(const std::string& addr, uint16_t port);
    explicit TelemetryExporter(HddsTelemetryExporter* handle);

    HddsTelemetryExporter* handle_ = nullptr;
};

namespace telemetry {

/**
 * @brief Initialize global metrics collector
 */
Metrics init();

/**
 * @brief Get existing global metrics collector (if initialized)
 * @return Metrics handle
 * @throws Error if metrics not yet initialized
 */
Metrics get();

/**
 * @brief Start telemetry exporter server
 */
TelemetryExporter start_exporter(const std::string& bind_addr = "127.0.0.1", uint16_t port = 4242);

} // namespace telemetry

// =============================================================================
// Publisher / Subscriber
// =============================================================================

/**
 * @brief DDS Publisher entity
 */
class Publisher {
public:
    ~Publisher();

    Publisher(const Publisher&) = delete;
    Publisher& operator=(const Publisher&) = delete;
    Publisher(Publisher&& other) noexcept;
    Publisher& operator=(Publisher&& other) noexcept;

    /**
     * @brief Create a typed DataWriter from this Publisher with default QoS
     * @tparam T Type to publish (must have CDR2 serialization via hddsgen)
     * @param topic_name Topic name
     * @return TypedDataWriter<T> with write(const T&) method
     */
    template<typename T>
    TypedDataWriter<T> create_writer(const std::string& topic_name);

    /**
     * @brief Create a typed DataWriter from this Publisher with custom QoS
     * @tparam T Type to publish (must have CDR2 serialization via hddsgen)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return TypedDataWriter<T> with write(const T&) method
     */
    template<typename T>
    TypedDataWriter<T> create_writer(const std::string& topic_name, const QoS& qos);

    /**
     * @brief Create a raw DataWriter from this Publisher with default QoS (untyped)
     * @param topic_name Topic name
     * @return Unique pointer to DataWriter
     */
    std::unique_ptr<DataWriter> create_writer_raw(const std::string& topic_name,
                                                  const char* type_name = nullptr);

    /**
     * @brief Create a raw DataWriter from this Publisher with custom QoS (untyped)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return Unique pointer to DataWriter
     */
    std::unique_ptr<DataWriter> create_writer_raw(const std::string& topic_name, const QoS& qos,
                                                  const char* type_name = nullptr);

    /**
     * @brief Create a raw DataWriter from this Publisher whose samples carry
     * their type's extensibility; see Participant::create_writer_raw
     * (hdds_publisher_create_writer_with_extensibility)
     */
    std::unique_ptr<DataWriter> create_writer_raw(const std::string& topic_name, const QoS& qos,
                                                  Extensibility extensibility,
                                                  const char* type_name = nullptr);

    /**
     * @brief create_writer_raw(topic_name, qos, extensibility) with the
     * default QoS
     */
    std::unique_ptr<DataWriter> create_writer_raw(const std::string& topic_name,
                                                  Extensibility extensibility,
                                                  const char* type_name = nullptr);

    std::unique_ptr<DataWriter> create_keyed_writer_raw(const std::string& topic_name, Extensibility extensibility, const char* type_name = nullptr);
    std::unique_ptr<DataWriter> create_keyed_writer_raw(const std::string& topic_name, const QoS& qos, Extensibility extensibility, const char* type_name = nullptr);

    /**
     * @brief Block until the data of every DataWriter of this Publisher has
     * been acknowledged by every matched RELIABLE reader (DDS v1.4
     * Sec.2.2.2.4.1.12)
     * @param timeout Maximum time to wait for the whole Publisher, not for
     * each writer
     * @return true once acknowledged, false on timeout. A BEST_EFFORT writer
     * owes nothing, and a Publisher without a writer returns true at once.
     * @throws Error if the Publisher has been destroyed, or the timeout is
     * negative
     */
    bool wait_for_acknowledgments(std::chrono::milliseconds timeout = std::chrono::seconds(10));

    HddsPublisher* c_handle() const { return handle_; }

private:
    friend class Participant;
    explicit Publisher(HddsPublisher* handle);

    HddsPublisher* handle_ = nullptr;
};

/**
 * @brief DDS Subscriber entity
 */
class Subscriber {
public:
    ~Subscriber();

    Subscriber(const Subscriber&) = delete;
    Subscriber& operator=(const Subscriber&) = delete;
    Subscriber(Subscriber&& other) noexcept;
    Subscriber& operator=(Subscriber&& other) noexcept;

    /**
     * @brief Create a typed DataReader from this Subscriber with default QoS
     * @tparam T Type to subscribe (must have CDR2 deserialization via hddsgen)
     * @param topic_name Topic name
     * @return TypedDataReader<T> with take() method
     */
    template<typename T>
    TypedDataReader<T> create_reader(const std::string& topic_name);

    /**
     * @brief Create a typed DataReader from this Subscriber with custom QoS
     * @tparam T Type to subscribe (must have CDR2 deserialization via hddsgen)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return TypedDataReader<T> with take() method
     */
    template<typename T>
    TypedDataReader<T> create_reader(const std::string& topic_name, const QoS& qos);

    /**
     * @brief Create a raw DataReader from this Subscriber with default QoS (untyped)
     * @param topic_name Topic name
     * @return Unique pointer to DataReader
     */
    std::unique_ptr<DataReader> create_reader_raw(const std::string& topic_name,
                                                  const char* type_name = nullptr);

    /**
     * @brief Create a raw DataReader from this Subscriber with custom QoS (untyped)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return Unique pointer to DataReader
     */
    std::unique_ptr<DataReader> create_reader_raw(const std::string& topic_name, const QoS& qos,
                                                  const char* type_name = nullptr);

    /**
     * @brief Create a raw DataReader from this Subscriber that requests
     * XCDR as well as XCDR2; see Participant::create_reader_raw_decoding_xcdr1
     */
    std::unique_ptr<DataReader> create_reader_raw_decoding_xcdr1(const std::string& topic_name,
                                                                 const QoS* qos,
                                                                 const char* type_name = nullptr);

    /**
     * @brief Open an access bracket (DDS v1.4 Sec.2.2.2.5.2.8)
     *
     * When this Subscriber's PRESENTATION access scope is GROUP, its readers
     * are read only inside a bracket: outside, take() throws Error
     * (PRECONDITION_NOT_MET). Brackets nest: each begin_access() is closed by
     * its own end_access(). For any other access scope a bracket has no
     * effect. Prefer access(), which closes the bracket on scope exit.
     */
    void begin_access();

    /**
     * @brief Close the bracket begin_access() opened
     * @throws Error when no bracket is open (PRECONDITION_NOT_MET)
     */
    void end_access();

    /**
     * @brief An access bracket held for the guard's lifetime (RAII)
     *
     * @code
     *     {
     *         auto bracket = subscriber->access();
     *         auto a = reader_a.take();
     *         auto b = reader_b.take();
     *     } // end_access()
     * @endcode
     */
    class AccessGuard {
    public:
        explicit AccessGuard(Subscriber& subscriber) : subscriber_(&subscriber) {
            subscriber_->begin_access();
        }
        ~AccessGuard() {
            if (subscriber_) {
                try {
                    subscriber_->end_access();
                } catch (...) {
                    // A destructor does not throw; the bracket is closed or
                    // the Subscriber gone.
                }
            }
        }
        AccessGuard(const AccessGuard&) = delete;
        AccessGuard& operator=(const AccessGuard&) = delete;
        AccessGuard(AccessGuard&& other) noexcept : subscriber_(other.subscriber_) {
            other.subscriber_ = nullptr;
        }
        AccessGuard& operator=(AccessGuard&&) = delete;

    private:
        Subscriber* subscriber_;
    };

    /**
     * @brief Open an access bracket closed when the returned guard goes
     */
    AccessGuard access() { return AccessGuard(*this); }

    HddsSubscriber* c_handle() const { return handle_; }

private:
    friend class Participant;
    explicit Subscriber(HddsSubscriber* handle);

    HddsSubscriber* handle_ = nullptr;
};

// =============================================================================
// Template method implementations (require complete DataWriter/DataReader types)
// =============================================================================

template<typename T>
TypedDataWriter<T> Participant::create_writer(
    const std::string& topic_name) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_hdds_extensibility<T>::value) {
        if constexpr (detail::has_hdds_key<T>::value) {
            if (T::hdds_has_key()) return TypedDataWriter<T>(create_keyed_writer_raw(topic_name, detail::extensibility_of<T>(), detail::type_name_of<T>()));
        }
        return TypedDataWriter<T>(create_writer_raw(topic_name, detail::extensibility_of<T>(), detail::type_name_of<T>()));
    } else {
        return TypedDataWriter<T>(create_writer_raw(topic_name, detail::type_name_of<T>()));
    }
}

template<typename T>
TypedDataWriter<T> Participant::create_writer(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_hdds_extensibility<T>::value) {
        if constexpr (detail::has_hdds_key<T>::value) {
            if (T::hdds_has_key()) return TypedDataWriter<T>(create_keyed_writer_raw(topic_name, qos, detail::extensibility_of<T>(), detail::type_name_of<T>()));
        }
        return TypedDataWriter<T>(create_writer_raw(topic_name, qos, detail::extensibility_of<T>(), detail::type_name_of<T>()));
    } else {
        return TypedDataWriter<T>(create_writer_raw(topic_name, qos, detail::type_name_of<T>()));
    }
}

template<typename T>
TypedDataReader<T> Participant::create_reader(
    const std::string& topic_name) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_decode_by_encapsulation<T>::value) {
        return TypedDataReader<T>(create_reader_raw_decoding_xcdr1(topic_name, nullptr, detail::type_name_of<T>()));
    } else {
        return TypedDataReader<T>(create_reader_raw(topic_name, detail::type_name_of<T>()));
    }
}

template<typename T>
TypedDataReader<T> Participant::create_reader(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_decode_by_encapsulation<T>::value) {
        return TypedDataReader<T>(create_reader_raw_decoding_xcdr1(topic_name, &qos, detail::type_name_of<T>()));
    } else {
        return TypedDataReader<T>(create_reader_raw(topic_name, qos, detail::type_name_of<T>()));
    }
}

// Publisher typed template implementations
template<typename T>
TypedDataWriter<T> Publisher::create_writer(
    const std::string& topic_name) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_hdds_extensibility<T>::value) {
        if constexpr (detail::has_hdds_key<T>::value) {
            if (T::hdds_has_key()) return TypedDataWriter<T>(create_keyed_writer_raw(topic_name, detail::extensibility_of<T>(), detail::type_name_of<T>()));
        }
        return TypedDataWriter<T>(create_writer_raw(topic_name, detail::extensibility_of<T>(), detail::type_name_of<T>()));
    } else {
        return TypedDataWriter<T>(create_writer_raw(topic_name, detail::type_name_of<T>()));
    }
}

template<typename T>
TypedDataWriter<T> Publisher::create_writer(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_hdds_extensibility<T>::value) {
        if constexpr (detail::has_hdds_key<T>::value) {
            if (T::hdds_has_key()) return TypedDataWriter<T>(create_keyed_writer_raw(topic_name, qos, detail::extensibility_of<T>(), detail::type_name_of<T>()));
        }
        return TypedDataWriter<T>(create_writer_raw(topic_name, qos, detail::extensibility_of<T>(), detail::type_name_of<T>()));
    } else {
        return TypedDataWriter<T>(create_writer_raw(topic_name, qos, detail::type_name_of<T>()));
    }
}

// Subscriber typed template implementations
template<typename T>
TypedDataReader<T> Subscriber::create_reader(
    const std::string& topic_name) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_decode_by_encapsulation<T>::value) {
        return TypedDataReader<T>(create_reader_raw_decoding_xcdr1(topic_name, nullptr, detail::type_name_of<T>()));
    } else {
        return TypedDataReader<T>(create_reader_raw(topic_name, detail::type_name_of<T>()));
    }
}

template<typename T>
TypedDataReader<T> Subscriber::create_reader(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    if constexpr (detail::has_decode_by_encapsulation<T>::value) {
        return TypedDataReader<T>(create_reader_raw_decoding_xcdr1(topic_name, &qos, detail::type_name_of<T>()));
    } else {
        return TypedDataReader<T>(create_reader_raw(topic_name, qos, detail::type_name_of<T>()));
    }
}

#ifdef HDDS_WITH_ROS2
/**
 * @brief Release a type object handle obtained from register_type_support
 * @param handle Type object handle to release
 */
void release_type_object(const void* handle);

/**
 * @brief Get the hash from a type object handle
 * @param handle Type object handle
 * @param out_version Output: hash version byte
 * @param out_value Output: hash value buffer (must be at least 8 bytes)
 * @param value_len Length of out_value buffer
 * @return true on success
 */
bool get_type_object_hash(const void* handle, uint8_t* out_version,
                          uint8_t* out_value, size_t value_len);
#endif

} // namespace hdds
