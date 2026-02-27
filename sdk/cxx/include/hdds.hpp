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

#include <memory>
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
     * @brief Create RTI Connext-compatible QoS
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
     * @brief Set liveliness to AUTOMATIC with given lease duration
     * @tparam Rep Duration representation type
     * @tparam Period Duration period type
     * @param lease Lease duration (infrastructure asserts liveliness automatically)
     */
    template<typename Rep, typename Period>
    QoS& liveliness_automatic(std::chrono::duration<Rep, Period> lease) {
        liveliness_kind_ = LivelinessKind::Automatic;
        liveliness_lease_ns_ = std::chrono::duration_cast<std::chrono::nanoseconds>(lease).count();
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
    LivelinessKind liveliness_kind_ = LivelinessKind::Automatic;
    uint64_t liveliness_lease_ns_ = 0;
    OwnershipKind ownership_kind_ = OwnershipKind::Shared;
    int32_t ownership_strength_ = 0;
    std::vector<std::string> partitions_;
    uint64_t time_based_filter_ns_ = 0;
    uint64_t latency_budget_ns_ = 0;
    int32_t transport_priority_ = 0;
    size_t max_samples_ = SIZE_MAX;
    size_t max_instances_ = SIZE_MAX;
    size_t max_samples_per_instance_ = SIZE_MAX;

    mutable std::unique_ptr<HddsQoS, void(*)(HddsQoS*)> handle_{nullptr, nullptr};
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
     * @param domain_id DDS domain ID (default: 0)
     */
    explicit Participant(const std::string& name, uint32_t domain_id = 0);

    /**
     * @brief Create a participant with specified transport mode
     * @param name Application/participant name
     * @param transport Transport mode (IntraProcess or UdpMulticast)
     * @param domain_id DDS domain ID (default: 0)
     */
    Participant(const std::string& name, TransportMode transport, uint32_t domain_id = 0);

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
     */
    std::unique_ptr<DataWriter> create_writer_raw(
        const std::string& topic_name);

    /**
     * @brief Create a raw DataWriter with custom QoS (untyped)
     */
    std::unique_ptr<DataWriter> create_writer_raw(
        const std::string& topic_name,
        const QoS& qos);

    /**
     * @brief Create a raw DataReader with default QoS (untyped)
     */
    std::unique_ptr<DataReader> create_reader_raw(
        const std::string& topic_name);

    /**
     * @brief Create a raw DataReader with custom QoS (untyped)
     */
    std::unique_ptr<DataReader> create_reader_raw(
        const std::string& topic_name,
        const QoS& qos);

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

#ifdef HDDS_WITH_ROS2
    /**
     * @brief Register a ROS2 type support with the participant
     * @param distro ROS2 distro (0=Humble, 1=Iron, 2=Jazzy)
     * @param type_support Pointer to rosidl type support struct
     * @return Opaque type object handle (must be released with hdds_type_object_release)
     */
    const void* register_type_support(uint32_t distro, const void* type_support);
#endif

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
        if constexpr (detail::has_encode_cdr2_le<T>::value) {
            // Fast path: stack buffer for small messages (zero heap alloc)
            std::uint8_t stack_buf[16384];
            int n = data.encode_cdr2_le(stack_buf, sizeof(stack_buf));
            if (n > 0) {
                write_raw(stack_buf, static_cast<std::size_t>(n));
                return;
            }
            // Slow path: heap allocation for messages > 16KB
            for (std::size_t sz = 65536; sz <= 16 * 1024 * 1024; sz *= 2) {
                std::vector<std::uint8_t> heap_buf(sz);
                n = data.encode_cdr2_le(heap_buf.data(), heap_buf.size());
                if (n > 0) {
                    write_raw(heap_buf.data(), static_cast<std::size_t>(n));
                    return;
                }
            }
            throw Error("CDR2 serialization failed (message exceeds 16MB)");
        } else {
            auto bytes = data.serialize();
            write_raw(bytes.data(), bytes.size());
        }
    }

    /**
     * @brief Write raw bytes
     */
    void write_raw(const uint8_t* data, size_t size);
    void write_raw(const std::vector<uint8_t>& data);

    /** @brief Get cached topic name */
    const std::string& topic_name() const { return topic_name_; }

    /** @brief Get topic name from FFI layer (slower, round-trips to C) */
    std::string get_topic_name_ffi() const;

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataWriter* c_handle() const { return handle_; }

private:
    friend class Participant;
    friend class Publisher;
    DataWriter(const std::string& topic, HddsDataWriter* handle);

    std::string topic_name_;
    HddsDataWriter* handle_ = nullptr;
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
        auto raw = take_raw();
        if (!raw) return std::nullopt;
        if constexpr (detail::has_decode_cdr2_le<T>::value) {
            T result{};
            if (result.decode_cdr2_le(raw->data(), raw->size()) < 0)
                throw Error("CDR2 deserialization failed");
            return result;
        } else {
            return T::deserialize(raw->data(), raw->size());
        }
    }

    /**
     * @brief Take raw bytes (non-blocking)
     */
    std::optional<std::vector<uint8_t>> take_raw();

    /**
     * @brief Get status condition for WaitSet integration
     */
    HddsStatusCondition* get_status_condition();

    /** @brief Get cached topic name */
    const std::string& topic_name() const { return topic_name_; }

    /** @brief Get topic name from FFI layer (slower, round-trips to C) */
    std::string get_topic_name_ffi() const;

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataReader* c_handle() const { return handle_; }

private:
    friend class Participant;
    friend class Subscriber;
    DataReader(const std::string& topic, HddsDataReader* handle);

    std::string topic_name_;
    HddsDataReader* handle_ = nullptr;
    HddsStatusCondition* cached_status_condition_ = nullptr;
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
        : inner_(std::move(writer)) {}

    // Non-copyable, movable
    TypedDataWriter(const TypedDataWriter&) = delete;
    TypedDataWriter& operator=(const TypedDataWriter&) = delete;
    TypedDataWriter(TypedDataWriter&&) = default;
    TypedDataWriter& operator=(TypedDataWriter&&) = default;

    /** @brief Write typed data (CDR2 serialization handled automatically) */
    void write(const T& data) { inner_->write<T>(data); }

    /** @brief Get topic name */
    const std::string& topic_name() const { return inner_->topic_name(); }

    /** @brief Access underlying DataWriter for raw operations or FFI */
    DataWriter* raw() { return inner_.get(); }
    const DataWriter* raw() const { return inner_.get(); }

    /** @brief Get raw C handle (for listener setup or FFI interop) */
    HddsDataWriter* c_handle() const { return inner_->c_handle(); }

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
     * @param cond Status condition handle (from DataReader::get_status_condition())
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
    std::unique_ptr<DataWriter> create_writer_raw(const std::string& topic_name);

    /**
     * @brief Create a raw DataWriter from this Publisher with custom QoS (untyped)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return Unique pointer to DataWriter
     */
    std::unique_ptr<DataWriter> create_writer_raw(const std::string& topic_name, const QoS& qos);

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
    std::unique_ptr<DataReader> create_reader_raw(const std::string& topic_name);

    /**
     * @brief Create a raw DataReader from this Subscriber with custom QoS (untyped)
     * @param topic_name Topic name
     * @param qos QoS configuration
     * @return Unique pointer to DataReader
     */
    std::unique_ptr<DataReader> create_reader_raw(const std::string& topic_name, const QoS& qos);

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
    return TypedDataWriter<T>(create_writer_raw(topic_name));
}

template<typename T>
TypedDataWriter<T> Participant::create_writer(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataWriter<T>(create_writer_raw(topic_name, qos));
}

template<typename T>
TypedDataReader<T> Participant::create_reader(
    const std::string& topic_name) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataReader<T>(create_reader_raw(topic_name));
}

template<typename T>
TypedDataReader<T> Participant::create_reader(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataReader<T>(create_reader_raw(topic_name, qos));
}

// Publisher typed template implementations
template<typename T>
TypedDataWriter<T> Publisher::create_writer(
    const std::string& topic_name) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataWriter<T>(create_writer_raw(topic_name));
}

template<typename T>
TypedDataWriter<T> Publisher::create_writer(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_encode_cdr2_le<T>::value,
        "T must provide encode_cdr2_le(uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataWriter<T>(create_writer_raw(topic_name, qos));
}

// Subscriber typed template implementations
template<typename T>
TypedDataReader<T> Subscriber::create_reader(
    const std::string& topic_name) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataReader<T>(create_reader_raw(topic_name));
}

template<typename T>
TypedDataReader<T> Subscriber::create_reader(
    const std::string& topic_name,
    const QoS& qos) {
    static_assert(
        detail::has_decode_cdr2_le<T>::value,
        "T must provide decode_cdr2_le(const uint8_t*, size_t) -> int. "
        "Generate your type with: hddsgen gen cpp MyType.idl -o MyType.hpp");
    return TypedDataReader<T>(create_reader_raw(topic_name, qos));
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
