// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file hdds_listener.hpp
 * @brief HDDS C++ SDK - Listener wrappers
 *
 * Virtual-method-based listeners that wrap the C callback API.
 * Override methods in ReaderListener or WriterListener to receive events.
 *
 * Example:
 * @code
 *     class MyListener : public hdds::ReaderListener {
 *     public:
 *         void on_data_available(const uint8_t* data, size_t len) override {
 *             std::cout << "Received " << len << " bytes" << std::endl;
 *         }
 *         void on_subscription_matched(const hdds::SubscriptionMatchedStatus& s) override {
 *             std::cout << "Matched: " << s.current_count << " writers" << std::endl;
 *         }
 *     };
 *
 *     MyListener listener;
 *     hdds::set_listener(reader.c_handle(), &listener);
 * @endcode
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2025-2026 naskel.com
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

// =============================================================================
// C FFI types (forward declarations matching hdds-c)
// =============================================================================

extern "C" {

// Opaque handles (defined in hdds-c)
struct HddsDataReader;
struct HddsDataWriter;

// --- Status structs (must match hdds-c repr(C) layout exactly) ---

struct HddsSubscriptionMatchedStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t current_count;
    int32_t current_count_change;
};

struct HddsPublicationMatchedStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t current_count;
    int32_t current_count_change;
};

struct HddsLivelinessChangedStatus {
    uint32_t alive_count;
    int32_t alive_count_change;
    uint32_t not_alive_count;
    int32_t not_alive_count_change;
};

struct HddsSampleLostStatus {
    uint32_t total_count;
    int32_t total_count_change;
};

struct HddsSampleRejectedStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t last_reason;
};

struct HddsDeadlineMissedStatus {
    uint32_t total_count;
    int32_t total_count_change;
};

struct HddsIncompatibleQosStatus {
    uint32_t total_count;
    int32_t total_count_change;
    uint32_t last_policy_id;
};

// --- Callback function pointer types ---

typedef void (*HddsOnDataAvailableFn)(const uint8_t* data, size_t len, void* user_data);
typedef void (*HddsOnSubscriptionMatchedFn)(const HddsSubscriptionMatchedStatus* status, void* user_data);
typedef void (*HddsOnPublicationMatchedFn)(const HddsPublicationMatchedStatus* status, void* user_data);
typedef void (*HddsOnLivelinessChangedFn)(const HddsLivelinessChangedStatus* status, void* user_data);
typedef void (*HddsOnSampleLostFn)(const HddsSampleLostStatus* status, void* user_data);
typedef void (*HddsOnSampleRejectedFn)(const HddsSampleRejectedStatus* status, void* user_data);
typedef void (*HddsOnDeadlineMissedFn)(const HddsDeadlineMissedStatus* status, void* user_data);
typedef void (*HddsOnIncompatibleQosFn)(const HddsIncompatibleQosStatus* status, void* user_data);
typedef void (*HddsOnSampleWrittenFn)(const uint8_t* data, size_t len, uint64_t sequence_number, void* user_data);
typedef void (*HddsOnOfferedDeadlineMissedFn)(uint64_t instance_handle, void* user_data);
typedef void (*HddsOnOfferedIncompatibleQosFn)(uint32_t policy_id, const char* policy_name, void* user_data);
typedef void (*HddsOnLivelinessLostFn)(void* user_data);

// --- Listener structs (must match hdds-c repr(C) layout exactly) ---

struct HddsReaderListener {
    HddsOnDataAvailableFn on_data_available;
    HddsOnSubscriptionMatchedFn on_subscription_matched;
    HddsOnLivelinessChangedFn on_liveliness_changed;
    HddsOnSampleLostFn on_sample_lost;
    HddsOnSampleRejectedFn on_sample_rejected;
    HddsOnDeadlineMissedFn on_deadline_missed;
    HddsOnIncompatibleQosFn on_incompatible_qos;
    void* user_data;
};

struct HddsWriterListener {
    HddsOnSampleWrittenFn on_sample_written;
    HddsOnPublicationMatchedFn on_publication_matched;
    HddsOnOfferedDeadlineMissedFn on_offered_deadline_missed;
    HddsOnOfferedIncompatibleQosFn on_offered_incompatible_qos;
    HddsOnLivelinessLostFn on_liveliness_lost;
    void* user_data;
};

// --- FFI functions ---

int hdds_reader_set_listener(HddsDataReader* reader, const HddsReaderListener* listener);
int hdds_reader_clear_listener(HddsDataReader* reader);
int hdds_writer_set_listener(HddsDataWriter* writer, const HddsWriterListener* listener);
int hdds_writer_clear_listener(HddsDataWriter* writer);

} // extern "C"

namespace hdds {

// =============================================================================
// C++ status structs (nicer API, same layout)
// =============================================================================

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
    uint32_t last_policy_id;
};

// =============================================================================
// ReaderListener base class
// =============================================================================

/**
 * @brief Base class for DataReader listeners.
 *
 * Override the methods you care about. Unoverridden methods are no-ops.
 * The listener must outlive the reader it is attached to.
 */
class ReaderListener {
public:
    virtual ~ReaderListener() = default;

    /** @brief Called when new data is available to read. */
    virtual void on_data_available(const uint8_t* data, size_t len) {
        (void)data; (void)len;
    }

    /** @brief Called when the reader matches/unmatches with a writer. */
    virtual void on_subscription_matched(const SubscriptionMatchedStatus& status) {
        (void)status;
    }

    /** @brief Called when liveliness of a matched writer changes. */
    virtual void on_liveliness_changed(const LivelinessChangedStatus& status) {
        (void)status;
    }

    /** @brief Called when samples are lost (gap in sequence numbers). */
    virtual void on_sample_lost(const SampleLostStatus& status) {
        (void)status;
    }

    /** @brief Called when samples are rejected due to resource limits. */
    virtual void on_sample_rejected(const SampleRejectedStatus& status) {
        (void)status;
    }

    /** @brief Called when the requested deadline is missed. */
    virtual void on_deadline_missed(const DeadlineMissedStatus& status) {
        (void)status;
    }

    /** @brief Called when QoS is incompatible with a matched writer. */
    virtual void on_incompatible_qos(const IncompatibleQosStatus& status) {
        (void)status;
    }
};

// =============================================================================
// WriterListener base class
// =============================================================================

/**
 * @brief Base class for DataWriter listeners.
 *
 * Override the methods you care about. Unoverridden methods are no-ops.
 * The listener must outlive the writer it is attached to.
 */
class WriterListener {
public:
    virtual ~WriterListener() = default;

    /** @brief Called after a sample is successfully written. */
    virtual void on_sample_written(const uint8_t* data, size_t len, uint64_t seq) {
        (void)data; (void)len; (void)seq;
    }

    /** @brief Called when the writer matches/unmatches with a reader. */
    virtual void on_publication_matched(const PublicationMatchedStatus& status) {
        (void)status;
    }

    /** @brief Called when an offered deadline is missed. */
    virtual void on_offered_deadline_missed(uint64_t instance_handle) {
        (void)instance_handle;
    }

    /** @brief Called when QoS is incompatible with a matched reader. */
    virtual void on_offered_incompatible_qos(uint32_t policy_id, const char* policy_name) {
        (void)policy_id; (void)policy_name;
    }

    /** @brief Called when liveliness is lost (MANUAL_BY_* only). */
    virtual void on_liveliness_lost() {}
};

// =============================================================================
// Internal: static trampoline functions
// =============================================================================

namespace detail {

// --- Reader trampolines ---

static void reader_on_data_available(const uint8_t* data, size_t len, void* ud) {
    static_cast<ReaderListener*>(ud)->on_data_available(data, len);
}

static void reader_on_subscription_matched(
    const HddsSubscriptionMatchedStatus* c_status, void* ud)
{
    SubscriptionMatchedStatus status;
    status.total_count = c_status->total_count;
    status.total_count_change = c_status->total_count_change;
    status.current_count = c_status->current_count;
    status.current_count_change = c_status->current_count_change;
    static_cast<ReaderListener*>(ud)->on_subscription_matched(status);
}

static void reader_on_liveliness_changed(
    const HddsLivelinessChangedStatus* c_status, void* ud)
{
    LivelinessChangedStatus status;
    status.alive_count = c_status->alive_count;
    status.alive_count_change = c_status->alive_count_change;
    status.not_alive_count = c_status->not_alive_count;
    status.not_alive_count_change = c_status->not_alive_count_change;
    static_cast<ReaderListener*>(ud)->on_liveliness_changed(status);
}

static void reader_on_sample_lost(const HddsSampleLostStatus* c_status, void* ud) {
    SampleLostStatus status;
    status.total_count = c_status->total_count;
    status.total_count_change = c_status->total_count_change;
    static_cast<ReaderListener*>(ud)->on_sample_lost(status);
}

static void reader_on_sample_rejected(const HddsSampleRejectedStatus* c_status, void* ud) {
    SampleRejectedStatus status;
    status.total_count = c_status->total_count;
    status.total_count_change = c_status->total_count_change;
    status.last_reason = c_status->last_reason;
    static_cast<ReaderListener*>(ud)->on_sample_rejected(status);
}

static void reader_on_deadline_missed(const HddsDeadlineMissedStatus* c_status, void* ud) {
    DeadlineMissedStatus status;
    status.total_count = c_status->total_count;
    status.total_count_change = c_status->total_count_change;
    static_cast<ReaderListener*>(ud)->on_deadline_missed(status);
}

static void reader_on_incompatible_qos(const HddsIncompatibleQosStatus* c_status, void* ud) {
    IncompatibleQosStatus status;
    status.total_count = c_status->total_count;
    status.total_count_change = c_status->total_count_change;
    status.last_policy_id = c_status->last_policy_id;
    static_cast<ReaderListener*>(ud)->on_incompatible_qos(status);
}

// --- Writer trampolines ---

static void writer_on_sample_written(
    const uint8_t* data, size_t len, uint64_t seq, void* ud)
{
    static_cast<WriterListener*>(ud)->on_sample_written(data, len, seq);
}

static void writer_on_publication_matched(
    const HddsPublicationMatchedStatus* c_status, void* ud)
{
    PublicationMatchedStatus status;
    status.total_count = c_status->total_count;
    status.total_count_change = c_status->total_count_change;
    status.current_count = c_status->current_count;
    status.current_count_change = c_status->current_count_change;
    static_cast<WriterListener*>(ud)->on_publication_matched(status);
}

static void writer_on_offered_deadline_missed(uint64_t instance_handle, void* ud) {
    static_cast<WriterListener*>(ud)->on_offered_deadline_missed(instance_handle);
}

static void writer_on_offered_incompatible_qos(
    uint32_t policy_id, const char* policy_name, void* ud)
{
    static_cast<WriterListener*>(ud)->on_offered_incompatible_qos(policy_id, policy_name);
}

static void writer_on_liveliness_lost(void* ud) {
    static_cast<WriterListener*>(ud)->on_liveliness_lost();
}

} // namespace detail

// =============================================================================
// Helper functions: install C++ listeners via C FFI
// =============================================================================

/**
 * @brief Install a C++ ReaderListener on a reader (wraps C FFI).
 *
 * The caller must ensure the listener outlives the reader.
 *
 * @param reader Opaque reader handle from participant.create_reader_raw()
 * @param listener Pointer to a ReaderListener subclass instance
 * @return 0 on success, non-zero on error
 */
inline int set_listener(HddsDataReader* reader, ReaderListener* listener) {
    HddsReaderListener c_listener;
    std::memset(&c_listener, 0, sizeof(c_listener));

    c_listener.on_data_available = detail::reader_on_data_available;
    c_listener.on_subscription_matched = detail::reader_on_subscription_matched;
    c_listener.on_liveliness_changed = detail::reader_on_liveliness_changed;
    c_listener.on_sample_lost = detail::reader_on_sample_lost;
    c_listener.on_sample_rejected = detail::reader_on_sample_rejected;
    c_listener.on_deadline_missed = detail::reader_on_deadline_missed;
    c_listener.on_incompatible_qos = detail::reader_on_incompatible_qos;
    c_listener.user_data = static_cast<void*>(listener);

    return hdds_reader_set_listener(reader, &c_listener);
}

/**
 * @brief Remove the listener from a reader.
 *
 * @param reader Opaque reader handle
 * @return 0 on success, non-zero on error
 */
inline int clear_listener(HddsDataReader* reader) {
    return hdds_reader_clear_listener(reader);
}

/**
 * @brief Install a C++ WriterListener on a writer (wraps C FFI).
 *
 * The caller must ensure the listener outlives the writer.
 *
 * @param writer Opaque writer handle from participant.create_writer_raw()
 * @param listener Pointer to a WriterListener subclass instance
 * @return 0 on success, non-zero on error
 */
inline int set_listener(HddsDataWriter* writer, WriterListener* listener) {
    HddsWriterListener c_listener;
    std::memset(&c_listener, 0, sizeof(c_listener));

    c_listener.on_sample_written = detail::writer_on_sample_written;
    c_listener.on_publication_matched = detail::writer_on_publication_matched;
    c_listener.on_offered_deadline_missed = detail::writer_on_offered_deadline_missed;
    c_listener.on_offered_incompatible_qos = detail::writer_on_offered_incompatible_qos;
    c_listener.on_liveliness_lost = detail::writer_on_liveliness_lost;
    c_listener.user_data = static_cast<void*>(listener);

    return hdds_writer_set_listener(writer, &c_listener);
}

/**
 * @brief Remove the listener from a writer.
 *
 * @param writer Opaque writer handle
 * @return 0 on success, non-zero on error
 */
inline int clear_listener(HddsDataWriter* writer) {
    return hdds_writer_clear_listener(writer);
}

// --- Convenience overloads for TypedDataReader<T> / TypedDataWriter<T> ---
// These allow: hdds::set_listener(reader, &listener) without .c_handle()

/**
 * @brief Install a ReaderListener on a TypedDataReader.
 */
template<typename T>
inline int set_listener(TypedDataReader<T>& reader, ReaderListener* listener) {
    return set_listener(reader.c_handle(), listener);
}

/**
 * @brief Remove the listener from a TypedDataReader.
 */
template<typename T>
inline int clear_listener(TypedDataReader<T>& reader) {
    return clear_listener(reader.c_handle());
}

/**
 * @brief Install a WriterListener on a TypedDataWriter.
 */
template<typename T>
inline int set_listener(TypedDataWriter<T>& writer, WriterListener* listener) {
    return set_listener(writer.c_handle(), listener);
}

/**
 * @brief Remove the listener from a TypedDataWriter.
 */
template<typename T>
inline int clear_listener(TypedDataWriter<T>& writer) {
    return clear_listener(writer.c_handle());
}

// =============================================================================
// Per-callback convenience setters (for simple "one callback" use cases)
// =============================================================================
//
// These set ONLY the specified callback, replacing any previously installed
// listener. For multiple callbacks, use the full ReaderListener/WriterListener
// class approach above.

/**
 * @brief Set a single on_data_available callback on a reader.
 *
 * Replaces any previously installed listener. The callback receives raw
 * serialized bytes -- use T::decode_cdr2_le() to deserialize if needed.
 *
 * @param reader Opaque reader handle
 * @param callback Function called when data arrives
 * @param user_data Optional context pointer passed to callback
 * @return 0 on success, non-zero on error
 */
inline int set_on_data_available(HddsDataReader* reader,
    HddsOnDataAvailableFn callback, void* user_data = nullptr)
{
    HddsReaderListener c_listener;
    std::memset(&c_listener, 0, sizeof(c_listener));
    c_listener.on_data_available = callback;
    c_listener.user_data = user_data;
    return hdds_reader_set_listener(reader, &c_listener);
}

/** @brief Typed overload for TypedDataReader<T>. */
template<typename T>
inline int set_on_data_available(TypedDataReader<T>& reader,
    HddsOnDataAvailableFn callback, void* user_data = nullptr)
{
    return set_on_data_available(reader.c_handle(), callback, user_data);
}

/**
 * @brief Set a single on_subscription_matched callback on a reader.
 *
 * Replaces any previously installed listener.
 */
inline int set_on_subscription_matched(HddsDataReader* reader,
    HddsOnSubscriptionMatchedFn callback, void* user_data = nullptr)
{
    HddsReaderListener c_listener;
    std::memset(&c_listener, 0, sizeof(c_listener));
    c_listener.on_subscription_matched = callback;
    c_listener.user_data = user_data;
    return hdds_reader_set_listener(reader, &c_listener);
}

/** @brief Typed overload for TypedDataReader<T>. */
template<typename T>
inline int set_on_subscription_matched(TypedDataReader<T>& reader,
    HddsOnSubscriptionMatchedFn callback, void* user_data = nullptr)
{
    return set_on_subscription_matched(reader.c_handle(), callback, user_data);
}

/**
 * @brief Set a single on_publication_matched callback on a writer.
 *
 * Replaces any previously installed listener.
 */
inline int set_on_publication_matched(HddsDataWriter* writer,
    HddsOnPublicationMatchedFn callback, void* user_data = nullptr)
{
    HddsWriterListener c_listener;
    std::memset(&c_listener, 0, sizeof(c_listener));
    c_listener.on_publication_matched = callback;
    c_listener.user_data = user_data;
    return hdds_writer_set_listener(writer, &c_listener);
}

/** @brief Typed overload for TypedDataWriter<T>. */
template<typename T>
inline int set_on_publication_matched(TypedDataWriter<T>& writer,
    HddsOnPublicationMatchedFn callback, void* user_data = nullptr)
{
    return set_on_publication_matched(writer.c_handle(), callback, user_data);
}

} // namespace hdds
