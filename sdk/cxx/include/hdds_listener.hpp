// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file hdds_listener.hpp
 * @brief HDDS C++ SDK - Listener wrappers
 *
 * Two ways to receive DataReader / DataWriter events, both on top of the C
 * listener API (hdds_reader_set_listener / hdds_writer_set_listener):
 *
 * 1. std::function callbacks, owned by the entity (recommended):
 * @code
 *     hdds::ReaderCallbacks cb;
 *     cb.on_data_available = [](const uint8_t* data, size_t len) { ... };
 *     cb.on_subscription_matched = [](const hdds::SubscriptionMatchedStatus& s) { ... };
 *     hdds::set_listener(reader, std::move(cb));   // DataReader& or TypedDataReader<T>&
 *     ...
 *     hdds::clear_listener(reader);
 * @endcode
 *    Only the callbacks you set are installed: an unset one is not reported
 *    (an unset on_sample_rejected leaves SAMPLE_REJECTED on the status
 *    condition).
 *
 * 2. A virtual interface: derive from ReaderListener / WriterListener,
 *    override what you need, then
 *    hdds::set_listener(reader, std::make_shared<MyListener>()).
 *    Every callback is installed (an override cannot be detected), so this
 *    listener consumes SAMPLE_REJECTED.
 *
 * Threading contract (the full one is in crates/hdds-c/src/listener.rs):
 * - Callbacks run on HDDS threads (router / discovery threads, or the
 *   thread calling write() for a reader of the same participant), possibly
 *   several at once: synchronize what they share.
 * - No HDDS lock is held across a callback: a callback may take() from its
 *   reader, write, or set / clear listeners, including its own.
 * - clear_listener / set_listener (replacing) and the entity's destruction
 *   return only once no callback of the previous listener runs on another
 *   thread. The callback objects stay alive until then, and a callback that
 *   clears its own listener finishes safely. Owned listeners may be set and
 *   cleared concurrently: the C layer reports which listener each call
 *   replaced (hdds_*_exchange_listener) and exactly that one is released.
 * - Do not destroy a reader or writer from inside its own callback: the C
 *   layer leaks it (and logs an error) rather than free it under the code
 *   that called back.
 * - An exception escaping a callback is caught at the C boundary (it must
 *   never unwind into HDDS) and reported to the handler installed with
 *   set_listener_exception_handler (default: a line on std::cerr).
 * - Data and status pointers are valid only during the callback.
 *
 * The raw-pointer overloads (set_listener(HddsDataReader*, ReaderListener*))
 * remain for C interop: the caller then keeps the listener alive until it
 * is cleared or the entity destroyed.
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2025-2026 naskel.com
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include "hdds.hpp"

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

struct HddsLivelinessLostStatus {
    uint32_t total_count;
    int32_t total_count_change;
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
typedef void (*HddsOnLivelinessLostFn)(const HddsLivelinessLostStatus* status, void* user_data);

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
int hdds_reader_exchange_listener(HddsDataReader* reader, const HddsReaderListener* listener,
                                  void** out_previous_user_data);
int hdds_writer_exchange_listener(HddsDataWriter* writer, const HddsWriterListener* listener,
                                  void** out_previous_user_data);

} // extern "C"

namespace hdds {

// =============================================================================
// ReaderListener base class
// =============================================================================

/**
 * @brief Base class for DataReader listeners.
 *
 * Override the methods you care about. Unoverridden methods are no-ops.
 * Installed with set_listener(reader, std::shared_ptr<ReaderListener>), the
 * reader keeps it alive; installed through the raw-pointer overload, it must
 * outlive the installation.
 *
 * on_liveliness_changed reports the matched writers alive and not alive.
 * on_sample_lost is never called yet (the core does not raise that status).
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
 * Ownership as for ReaderListener. on_liveliness_lost reports this writer
 * (MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC only) failing to assert within
 * its lease.
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

    /** @brief Called when liveliness is lost (MANUAL_BY_* only): this
     * writer did not assert (write, dispose, unregister or
     * assert_liveliness) within its offered LIVELINESS lease. */
    virtual void on_liveliness_lost(const LivelinessLostStatus& status) {
        (void)status;
    }
};

// =============================================================================
// Exceptions escaping a callback
// =============================================================================

/**
 * @brief Called with the callback name and the exception's what() (or
 * "unknown exception") when a listener callback throws. The exception is
 * swallowed at the C boundary: it must never unwind into HDDS.
 */
using ListenerExceptionHandler = void (*)(const char* callback, const char* what);

namespace detail {

inline void default_listener_exception_handler(const char* callback, const char* what) {
    std::cerr << "[hdds] exception escaped listener callback " << callback << ": " << what
              << std::endl;
}

inline ListenerExceptionHandler& listener_exception_handler() {
    static ListenerExceptionHandler handler = &default_listener_exception_handler;
    return handler;
}

/** Run `f`; report and swallow anything it throws. */
template<typename F>
inline void guarded(const char* callback, F&& f) noexcept {
    try {
        f();
    } catch (const std::exception& e) {
        try {
            listener_exception_handler()(callback, e.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            listener_exception_handler()(callback, "unknown exception");
        } catch (...) {
        }
    }
}

} // namespace detail

/**
 * @brief Replace the handler of exceptions escaping listener callbacks
 * (nullptr restores the default, a line on std::cerr). Not synchronized with
 * running callbacks: install it before installing listeners.
 */
inline void set_listener_exception_handler(ListenerExceptionHandler handler) {
    detail::listener_exception_handler() =
        handler ? handler : &detail::default_listener_exception_handler;
}

// =============================================================================
// std::function callbacks
// =============================================================================

/** @brief DataReader callbacks; leave a member empty to not receive it. */
struct ReaderCallbacks {
    std::function<void(const uint8_t* data, size_t len)> on_data_available;
    std::function<void(const SubscriptionMatchedStatus&)> on_subscription_matched;
    /** The matched writers alive and not alive (LIVELINESS_CHANGED). */
    std::function<void(const LivelinessChangedStatus&)> on_liveliness_changed;
    /** Never called yet (the core does not raise SAMPLE_LOST). */
    std::function<void(const SampleLostStatus&)> on_sample_lost;
    std::function<void(const SampleRejectedStatus&)> on_sample_rejected;
    std::function<void(const DeadlineMissedStatus&)> on_deadline_missed;
    std::function<void(const IncompatibleQosStatus&)> on_incompatible_qos;
};

/** @brief DataWriter callbacks; leave a member empty to not receive it. */
struct WriterCallbacks {
    std::function<void(const uint8_t* data, size_t len, uint64_t seq)> on_sample_written;
    std::function<void(const PublicationMatchedStatus&)> on_publication_matched;
    std::function<void(uint64_t instance_handle)> on_offered_deadline_missed;
    std::function<void(uint32_t policy_id, const char* policy_name)> on_offered_incompatible_qos;
    /** How many times this writer failed to assert within its lease. */
    std::function<void(const LivelinessLostStatus&)> on_liveliness_lost;
};

namespace detail {

/**
 * The installed callbacks, owned by the entity (hold_listener_state). The C
 * user_data points here. A trampoline first takes a strong reference
 * through `self`, so a callback that clears or replaces its own listener
 * (which drops the entity's reference) runs to its end on a live object.
 * No other thread can free the box while a trampoline runs: the C layer
 * makes clear / replace / destroy wait for callbacks running elsewhere.
 */
template<typename Callbacks>
struct ListenerBox {
    std::weak_ptr<ListenerBox> self;
    Callbacks callbacks;
};

template<typename Callbacks>
inline std::shared_ptr<ListenerBox<Callbacks>> make_box(Callbacks callbacks) {
    auto box = std::make_shared<ListenerBox<Callbacks>>();
    box->callbacks = std::move(callbacks);
    box->self = box;
    return box;
}

template<typename Callbacks>
inline std::shared_ptr<ListenerBox<Callbacks>> lock_box(void* ud) {
    return static_cast<ListenerBox<Callbacks>*>(ud)->self.lock();
}

using ReaderBox = ListenerBox<ReaderCallbacks>;
using WriterBox = ListenerBox<WriterCallbacks>;

inline SubscriptionMatchedStatus to_cxx(const HddsSubscriptionMatchedStatus& c) {
    return {c.total_count, c.total_count_change, c.current_count, c.current_count_change};
}
inline PublicationMatchedStatus to_cxx(const HddsPublicationMatchedStatus& c) {
    return {c.total_count, c.total_count_change, c.current_count, c.current_count_change};
}
inline LivelinessChangedStatus to_cxx(const HddsLivelinessChangedStatus& c) {
    return {c.alive_count, c.alive_count_change, c.not_alive_count, c.not_alive_count_change};
}
inline LivelinessLostStatus to_cxx(const HddsLivelinessLostStatus& c) {
    return {c.total_count, c.total_count_change};
}
inline SampleLostStatus to_cxx(const HddsSampleLostStatus& c) {
    return {c.total_count, c.total_count_change};
}
inline SampleRejectedStatus to_cxx(const HddsSampleRejectedStatus& c) {
    return {c.total_count, c.total_count_change, c.last_reason};
}
inline DeadlineMissedStatus to_cxx(const HddsDeadlineMissedStatus& c) {
    return {c.total_count, c.total_count_change};
}
inline IncompatibleQosStatus to_cxx(const HddsIncompatibleQosStatus& c) {
    return {c.total_count, c.total_count_change, c.last_policy_id};
}

// --- std::function trampolines (user_data = ReaderBox* / WriterBox*) ---

inline void box_on_data_available(const uint8_t* data, size_t len, void* ud) {
    guarded("on_data_available", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_data_available(data, len);
    });
}
inline void box_on_subscription_matched(const HddsSubscriptionMatchedStatus* s, void* ud) {
    guarded("on_subscription_matched", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_subscription_matched(to_cxx(*s));
    });
}
inline void box_on_liveliness_changed(const HddsLivelinessChangedStatus* s, void* ud) {
    guarded("on_liveliness_changed", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_liveliness_changed(to_cxx(*s));
    });
}
inline void box_on_sample_lost(const HddsSampleLostStatus* s, void* ud) {
    guarded("on_sample_lost", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_sample_lost(to_cxx(*s));
    });
}
inline void box_on_sample_rejected(const HddsSampleRejectedStatus* s, void* ud) {
    guarded("on_sample_rejected", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_sample_rejected(to_cxx(*s));
    });
}
inline void box_on_deadline_missed(const HddsDeadlineMissedStatus* s, void* ud) {
    guarded("on_deadline_missed", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_deadline_missed(to_cxx(*s));
    });
}
inline void box_on_incompatible_qos(const HddsIncompatibleQosStatus* s, void* ud) {
    guarded("on_incompatible_qos", [&] {
        if (auto box = lock_box<ReaderCallbacks>(ud)) box->callbacks.on_incompatible_qos(to_cxx(*s));
    });
}

inline void box_on_sample_written(const uint8_t* data, size_t len, uint64_t seq, void* ud) {
    guarded("on_sample_written", [&] {
        if (auto box = lock_box<WriterCallbacks>(ud)) box->callbacks.on_sample_written(data, len, seq);
    });
}
inline void box_on_publication_matched(const HddsPublicationMatchedStatus* s, void* ud) {
    guarded("on_publication_matched", [&] {
        if (auto box = lock_box<WriterCallbacks>(ud)) box->callbacks.on_publication_matched(to_cxx(*s));
    });
}
inline void box_on_offered_deadline_missed(uint64_t handle, void* ud) {
    guarded("on_offered_deadline_missed", [&] {
        if (auto box = lock_box<WriterCallbacks>(ud)) box->callbacks.on_offered_deadline_missed(handle);
    });
}
inline void box_on_offered_incompatible_qos(uint32_t policy_id, const char* name, void* ud) {
    guarded("on_offered_incompatible_qos", [&] {
        if (auto box = lock_box<WriterCallbacks>(ud)) box->callbacks.on_offered_incompatible_qos(policy_id, name);
    });
}
inline void box_on_liveliness_lost(const HddsLivelinessLostStatus* s, void* ud) {
    guarded("on_liveliness_lost", [&] {
        if (auto box = lock_box<WriterCallbacks>(ud)) box->callbacks.on_liveliness_lost(to_cxx(*s));
    });
}

// --- Raw-pointer trampolines (user_data = ReaderListener* / WriterListener*) ---

inline void reader_on_data_available(const uint8_t* data, size_t len, void* ud) {
    guarded("on_data_available", [&] { static_cast<ReaderListener*>(ud)->on_data_available(data, len); });
}
inline void reader_on_subscription_matched(const HddsSubscriptionMatchedStatus* s, void* ud) {
    guarded("on_subscription_matched", [&] { static_cast<ReaderListener*>(ud)->on_subscription_matched(to_cxx(*s)); });
}
inline void reader_on_liveliness_changed(const HddsLivelinessChangedStatus* s, void* ud) {
    guarded("on_liveliness_changed", [&] { static_cast<ReaderListener*>(ud)->on_liveliness_changed(to_cxx(*s)); });
}
inline void reader_on_sample_lost(const HddsSampleLostStatus* s, void* ud) {
    guarded("on_sample_lost", [&] { static_cast<ReaderListener*>(ud)->on_sample_lost(to_cxx(*s)); });
}
inline void reader_on_sample_rejected(const HddsSampleRejectedStatus* s, void* ud) {
    guarded("on_sample_rejected", [&] { static_cast<ReaderListener*>(ud)->on_sample_rejected(to_cxx(*s)); });
}
inline void reader_on_deadline_missed(const HddsDeadlineMissedStatus* s, void* ud) {
    guarded("on_deadline_missed", [&] { static_cast<ReaderListener*>(ud)->on_deadline_missed(to_cxx(*s)); });
}
inline void reader_on_incompatible_qos(const HddsIncompatibleQosStatus* s, void* ud) {
    guarded("on_incompatible_qos", [&] { static_cast<ReaderListener*>(ud)->on_incompatible_qos(to_cxx(*s)); });
}

inline void writer_on_sample_written(const uint8_t* data, size_t len, uint64_t seq, void* ud) {
    guarded("on_sample_written", [&] { static_cast<WriterListener*>(ud)->on_sample_written(data, len, seq); });
}
inline void writer_on_publication_matched(const HddsPublicationMatchedStatus* s, void* ud) {
    guarded("on_publication_matched", [&] { static_cast<WriterListener*>(ud)->on_publication_matched(to_cxx(*s)); });
}
inline void writer_on_offered_deadline_missed(uint64_t handle, void* ud) {
    guarded("on_offered_deadline_missed", [&] { static_cast<WriterListener*>(ud)->on_offered_deadline_missed(handle); });
}
inline void writer_on_offered_incompatible_qos(uint32_t policy_id, const char* name, void* ud) {
    guarded("on_offered_incompatible_qos", [&] { static_cast<WriterListener*>(ud)->on_offered_incompatible_qos(policy_id, name); });
}
inline void writer_on_liveliness_lost(const HddsLivelinessLostStatus* s, void* ud) {
    guarded("on_liveliness_lost", [&] { static_cast<WriterListener*>(ud)->on_liveliness_lost(to_cxx(*s)); });
}

inline HddsReaderListener c_listener_for(ReaderBox* box) {
    HddsReaderListener c;
    std::memset(&c, 0, sizeof(c));
    const ReaderCallbacks& cb = box->callbacks;
    if (cb.on_data_available) c.on_data_available = box_on_data_available;
    if (cb.on_subscription_matched) c.on_subscription_matched = box_on_subscription_matched;
    if (cb.on_liveliness_changed) c.on_liveliness_changed = box_on_liveliness_changed;
    if (cb.on_sample_lost) c.on_sample_lost = box_on_sample_lost;
    if (cb.on_sample_rejected) c.on_sample_rejected = box_on_sample_rejected;
    if (cb.on_deadline_missed) c.on_deadline_missed = box_on_deadline_missed;
    if (cb.on_incompatible_qos) c.on_incompatible_qos = box_on_incompatible_qos;
    c.user_data = static_cast<void*>(box);
    return c;
}

inline HddsWriterListener c_listener_for(WriterBox* box) {
    HddsWriterListener c;
    std::memset(&c, 0, sizeof(c));
    const WriterCallbacks& cb = box->callbacks;
    if (cb.on_sample_written) c.on_sample_written = box_on_sample_written;
    if (cb.on_publication_matched) c.on_publication_matched = box_on_publication_matched;
    if (cb.on_offered_deadline_missed) c.on_offered_deadline_missed = box_on_offered_deadline_missed;
    if (cb.on_offered_incompatible_qos) c.on_offered_incompatible_qos = box_on_offered_incompatible_qos;
    if (cb.on_liveliness_lost) c.on_liveliness_lost = box_on_liveliness_lost;
    c.user_data = static_cast<void*>(box);
    return c;
}

/** Every callback of `listener`, owning it. */
inline ReaderCallbacks callbacks_of(std::shared_ptr<ReaderListener> l) {
    ReaderCallbacks cb;
    cb.on_data_available = [l](const uint8_t* d, size_t n) { l->on_data_available(d, n); };
    cb.on_subscription_matched = [l](const SubscriptionMatchedStatus& s) { l->on_subscription_matched(s); };
    cb.on_liveliness_changed = [l](const LivelinessChangedStatus& s) { l->on_liveliness_changed(s); };
    cb.on_sample_lost = [l](const SampleLostStatus& s) { l->on_sample_lost(s); };
    cb.on_sample_rejected = [l](const SampleRejectedStatus& s) { l->on_sample_rejected(s); };
    cb.on_deadline_missed = [l](const DeadlineMissedStatus& s) { l->on_deadline_missed(s); };
    cb.on_incompatible_qos = [l](const IncompatibleQosStatus& s) { l->on_incompatible_qos(s); };
    return cb;
}

/** Every callback of `listener`, owning it. */
inline WriterCallbacks callbacks_of(std::shared_ptr<WriterListener> l) {
    WriterCallbacks cb;
    cb.on_sample_written = [l](const uint8_t* d, size_t n, uint64_t seq) { l->on_sample_written(d, n, seq); };
    cb.on_publication_matched = [l](const PublicationMatchedStatus& s) { l->on_publication_matched(s); };
    cb.on_offered_deadline_missed = [l](uint64_t h) { l->on_offered_deadline_missed(h); };
    cb.on_offered_incompatible_qos = [l](uint32_t id, const char* name) { l->on_offered_incompatible_qos(id, name); };
    cb.on_liveliness_lost = [l](const LivelinessLostStatus& s) { l->on_liveliness_lost(s); };
    return cb;
}

inline void check_listener_rc(int rc, const char* what) {
    if (rc != 0) {
        throw Error(std::string(what) + " failed with error " + std::to_string(rc));
    }
}

} // namespace detail

// =============================================================================
// Owned listeners: the entity keeps the callbacks alive
// =============================================================================

/**
 * @brief Install std::function callbacks on a reader, replacing any listener.
 *
 * The reader owns the callbacks. Returns once the previous listener's
 * callbacks running on other threads have returned.
 * @throws hdds::Error if the C call fails.
 */
inline void set_listener(DataReader& reader, ReaderCallbacks callbacks) {
    auto box = detail::make_box(std::move(callbacks));
    HddsReaderListener c = detail::c_listener_for(box.get());
    // Held before the C call: a callback may fire before it returns.
    reader.hold_listener_state(box);
    void* previous = nullptr;
    int rc = hdds_reader_exchange_listener(reader.c_handle(), &c, &previous);
    if (rc != 0) {
        reader.release_listener_state(box.get());
        detail::check_listener_rc(rc, "hdds_reader_exchange_listener");
    }
    // The C call drained exactly the listener it replaced: release that one
    // (whatever order concurrent installs reached HDDS in).
    if (previous != nullptr) reader.release_listener_state(previous);
}

/** @brief Install a ReaderListener the reader shares ownership of. */
inline void set_listener(DataReader& reader, std::shared_ptr<ReaderListener> listener) {
    set_listener(reader, detail::callbacks_of(std::move(listener)));
}

/**
 * @brief Remove the reader's listener.
 *
 * Returns once its callbacks running on other threads have returned (a
 * callback of that listener may call this; it finishes safely).
 * @throws hdds::Error if the C call fails.
 */
inline void clear_listener(DataReader& reader) {
    void* previous = nullptr;
    detail::check_listener_rc(
        hdds_reader_exchange_listener(reader.c_handle(), nullptr, &previous),
        "hdds_reader_exchange_listener");
    if (previous != nullptr) reader.release_listener_state(previous);
}

/** @brief Install std::function callbacks on a writer, replacing any listener. */
inline void set_listener(DataWriter& writer, WriterCallbacks callbacks) {
    auto box = detail::make_box(std::move(callbacks));
    HddsWriterListener c = detail::c_listener_for(box.get());
    writer.hold_listener_state(box);
    void* previous = nullptr;
    int rc = hdds_writer_exchange_listener(writer.c_handle(), &c, &previous);
    if (rc != 0) {
        writer.release_listener_state(box.get());
        detail::check_listener_rc(rc, "hdds_writer_exchange_listener");
    }
    if (previous != nullptr) writer.release_listener_state(previous);
}

/** @brief Install a WriterListener the writer shares ownership of. */
inline void set_listener(DataWriter& writer, std::shared_ptr<WriterListener> listener) {
    set_listener(writer, detail::callbacks_of(std::move(listener)));
}

/** @brief Remove the writer's listener (same waiting contract as for a reader). */
inline void clear_listener(DataWriter& writer) {
    void* previous = nullptr;
    detail::check_listener_rc(
        hdds_writer_exchange_listener(writer.c_handle(), nullptr, &previous),
        "hdds_writer_exchange_listener");
    if (previous != nullptr) writer.release_listener_state(previous);
}

template<typename T>
inline void set_listener(TypedDataReader<T>& reader, ReaderCallbacks callbacks) {
    set_listener(*reader.raw(), std::move(callbacks));
}
template<typename T>
inline void set_listener(TypedDataReader<T>& reader, std::shared_ptr<ReaderListener> listener) {
    set_listener(*reader.raw(), std::move(listener));
}
template<typename T>
inline void set_listener(TypedDataWriter<T>& writer, WriterCallbacks callbacks) {
    set_listener(*writer.raw(), std::move(callbacks));
}
template<typename T>
inline void set_listener(TypedDataWriter<T>& writer, std::shared_ptr<WriterListener> listener) {
    set_listener(*writer.raw(), std::move(listener));
}

// =============================================================================
// Raw-pointer listeners (C interop): the caller keeps the listener alive
// =============================================================================

/**
 * @brief Install a C++ ReaderListener on a reader handle (wraps C FFI).
 *
 * The caller keeps `listener` alive until clear_listener(reader) or the
 * reader's destruction returns (both wait for running callbacks).
 *
 * @return 0 on success, non-zero HddsError value on error
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
 * @brief Remove the listener from a reader handle (waits for running callbacks).
 *
 * @return 0 on success, non-zero on error
 */
inline int clear_listener(HddsDataReader* reader) {
    return hdds_reader_clear_listener(reader);
}

/**
 * @brief Install a C++ WriterListener on a writer handle (wraps C FFI).
 *
 * The caller keeps `listener` alive until clear_listener(writer) or the
 * writer's destruction returns.
 *
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
 * @brief Remove the listener from a writer handle (waits for running callbacks).
 *
 * @return 0 on success, non-zero on error
 */
inline int clear_listener(HddsDataWriter* writer) {
    return hdds_writer_clear_listener(writer);
}

// --- Raw-pointer overloads for TypedDataReader<T> / TypedDataWriter<T> ---

/** @brief Install a caller-owned ReaderListener on a TypedDataReader. */
template<typename T>
inline int set_listener(TypedDataReader<T>& reader, ReaderListener* listener) {
    return set_listener(reader.c_handle(), listener);
}

/**
 * @brief Remove the listener from a TypedDataReader (owned or not).
 * @return 0 on success, non-zero on error
 */
template<typename T>
inline int clear_listener(TypedDataReader<T>& reader) {
    void* previous = nullptr;
    int rc = hdds_reader_exchange_listener(reader.c_handle(), nullptr, &previous);
    if (rc == 0 && previous != nullptr) {
        reader.raw()->release_listener_state(previous);
    }
    return rc;
}

/** @brief Install a caller-owned WriterListener on a TypedDataWriter. */
template<typename T>
inline int set_listener(TypedDataWriter<T>& writer, WriterListener* listener) {
    return set_listener(writer.c_handle(), listener);
}

/**
 * @brief Remove the listener from a TypedDataWriter (owned or not).
 * @return 0 on success, non-zero on error
 */
template<typename T>
inline int clear_listener(TypedDataWriter<T>& writer) {
    void* previous = nullptr;
    int rc = hdds_writer_exchange_listener(writer.c_handle(), nullptr, &previous);
    if (rc == 0 && previous != nullptr) {
        writer.raw()->release_listener_state(previous);
    }
    return rc;
}

// =============================================================================
// Per-callback convenience setters (C function pointers)
// =============================================================================
//
// These set ONLY the specified callback, replacing any previously installed
// listener. For several callbacks, or for lambdas, use ReaderCallbacks /
// WriterCallbacks above.

/**
 * @brief Set a single on_data_available callback on a reader.
 *
 * Replaces any previously installed listener. The callback receives raw
 * serialized bytes -- use T::decode_cdr2_le() to deserialize if needed (the
 * reader requests XCDR2 unless its QoS asks for XCDR too; for such a reader
 * use hdds_reader_set_listener_ex, whose callback also receives the
 * encapsulation identifier to pass to T::decode_by_encapsulation()). It
 * must not throw (it is called from C).
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
 * Replaces any previously installed listener. Must not throw.
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
 * Replaces any previously installed listener. Must not throw.
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
