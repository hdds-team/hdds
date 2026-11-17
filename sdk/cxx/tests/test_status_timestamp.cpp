// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <hdds.hpp>
extern "C" {
#include <hdds.h>
}
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <thread>

// A bounded condition wait, with no guessed discovery delay.
template<class F> auto until(F f) {
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    for (;;) {
        auto result = f();
        if (result) return result;
        assert(std::chrono::steady_clock::now() < end);
        std::this_thread::yield();
    }
}

struct Message {
    int encode_cdr2_le(uint8_t* out, size_t len) const {
        if (len < 4) return -1;
        out[0] = 1; out[1] = 2; out[2] = 3; out[3] = 4;
        return 4;
    }
};

int main() {
    hdds::Participant wp("cpp_status_writer", hdds::TransportMode::UdpMulticast, 214);
    hdds::Participant rp("cpp_status_reader", hdds::TransportMode::UdpMulticast, 214);
    auto w = wp.create_writer_raw("cpp_status_timestamp", hdds::QoS::reliable());
    auto r = rp.create_reader_raw("cpp_status_timestamp", hdds::QoS::reliable());
    hdds::PublicationMatchedStatus pub{};
    hdds::SubscriptionMatchedStatus sub{};
    until([&] { pub = w->get_publication_matched_status(); return pub.current_count == 1; });
    assert(pub.total_count == 1 && pub.total_count_change == 1 && pub.current_count_change == 1);
    until([&] { sub = r->get_subscription_matched_status(); return sub.current_count == 1; });
    assert(sub.total_count == 1 && sub.total_count_change == 1 && sub.current_count_change == 1);
    pub = w->get_publication_matched_status();
    sub = r->get_subscription_matched_status();
    assert(pub.total_count == 1 && pub.total_count_change == 0 && pub.current_count_change == 0);
    assert(sub.total_count == 1 && sub.total_count_change == 0 && sub.current_count_change == 0);
    auto requested_deadline_missed = r->get_requested_deadline_missed_status();
    assert(requested_deadline_missed.total_count == 0);
    assert(requested_deadline_missed.total_count_change == 0);
    assert(r->get_requested_deadline_missed_status().total_count_change == 0);
    auto offered_deadline_missed = w->get_offered_deadline_missed_status();
    assert(offered_deadline_missed.total_count == 0);
    assert(offered_deadline_missed.total_count_change == 0);
    assert(w->get_offered_deadline_missed_status().total_count_change == 0);
    auto requested_incompatible_qos = r->get_requested_incompatible_qos_status();
    assert(requested_incompatible_qos.total_count == 0);
    assert(requested_incompatible_qos.total_count_change == 0);
    assert(requested_incompatible_qos.last_policy_id == 0);
    assert(r->get_requested_incompatible_qos_status().total_count_change == 0);
    auto offered_incompatible_qos = w->get_offered_incompatible_qos_status();
    assert(offered_incompatible_qos.total_count == 0);
    assert(offered_incompatible_qos.total_count_change == 0);
    assert(offered_incompatible_qos.last_policy_id == 0);
    assert(w->get_offered_incompatible_qos_status().total_count_change == 0);
    auto liveliness_changed = r->get_liveliness_changed_status();
    assert(liveliness_changed.alive_count == 1);
    assert(liveliness_changed.alive_count_change == 1);
    assert(liveliness_changed.not_alive_count == 0);
    assert(liveliness_changed.not_alive_count_change == 0);
    assert(r->get_liveliness_changed_status().alive_count_change == 0);
    auto liveliness_lost = w->get_liveliness_lost_status();
    assert(liveliness_lost.total_count == 0);
    assert(liveliness_lost.total_count_change == 0);
    assert(w->get_liveliness_lost_status().total_count_change == 0);
    auto sample_lost = r->get_sample_lost_status();
    assert(sample_lost.total_count == 0);
    assert(sample_lost.total_count_change == 0);
    assert(r->get_sample_lost_status().total_count_change == 0);
    auto sample_rejected = r->get_sample_rejected_status();
    assert(sample_rejected.total_count == 0);
    assert(sample_rejected.total_count_change == 0);
    assert(sample_rejected.last_reason == 0);
    assert(r->get_sample_rejected_status().total_count_change == 0);
    const uint8_t data[] = {1, 2, 3, 4};
    const uint64_t stamp = UINT64_C(1700000000500000000);
    auto handle = w->register_instance(data, sizeof(data));
    assert(handle == hdds::InstanceHandle{});
    assert(w->register_instance_w_timestamp(data, sizeof(data), 1) == handle);
    auto cond = hdds_create_read_condition(r->c_handle(), 3, 3, 7);
    assert(cond);
    uint8_t output[32];
    size_t size = 0;
    HddsSampleInfo info{};
    assert(hdds_reader_take_w_condition(r->c_handle(), cond, output, sizeof(output), &size, &info) == HDDS_NOT_FOUND);
    w->write_w_timestamp(Message{}, stamp);
    until([&] {
        auto err = hdds_reader_take_w_condition(r->c_handle(), cond, output, sizeof(output), &size, &info);
        assert(err == HDDS_OK || err == HDDS_NOT_FOUND);
        return err == HDDS_OK;
    });
    assert(info.VALID_DATA && info.SOURCE_TIMESTAMP_NS == stamp);
    assert(size == sizeof(data) && std::equal(std::begin(data), std::end(data), output));
    w->write_w_timestamp(std::vector<uint8_t>{1, 2, 3, 4}, stamp + 1000000000);
    until([&] { return hdds_reader_take_w_condition(r->c_handle(), cond, output, sizeof(output), &size, &info) == HDDS_OK; });
    assert(info.VALID_DATA && info.SOURCE_TIMESTAMP_NS == stamp + 1000000000);
    assert(w->wait_for_acknowledgments(std::chrono::seconds(10)));
    w->write(Message{});
    until([&] { return hdds_reader_take_w_condition(r->c_handle(), cond, output, sizeof(output), &size, &info) == HDDS_OK; });
    assert(info.VALID_DATA && info.SOURCE_TIMESTAMP_NS > stamp);
    w->dispose_w_timestamp(Message{}, stamp);
    until([&] { return hdds_reader_take_w_condition(r->c_handle(), cond, output, sizeof(output), &size, &info) == HDDS_OK; });
    assert(!info.VALID_DATA && info.INSTANCE_STATE == 2);
    w->unregister_instance_w_timestamp(Message{}, stamp);
    w->dispose(data, sizeof(data));
    w->unregister_instance(data, sizeof(data));
    hdds_read_condition_delete(cond);
    r.reset();
    until([&] { pub = w->get_publication_matched_status(); return pub.current_count == 0; });
    assert(pub.total_count == 1 && pub.current_count_change == -1);
    assert(w->get_publication_matched_status().current_count_change == 0);
    r = rp.create_reader_raw("cpp_status_timestamp", hdds::QoS::reliable());
    until([&] { return r->get_subscription_matched_status().current_count == 1; });
    w.reset();
    until([&] { sub = r->get_subscription_matched_status(); return sub.current_count == 0; });
    assert(sub.total_count == 1 && sub.current_count_change == -1);
    assert(r->get_subscription_matched_status().current_count_change == 0);
    // Publisher::wait_for_acknowledgments waits for the writers of the
    // Publisher, whose data a matched reliable reader acknowledges.
    auto publisher = wp.create_publisher();
    assert(publisher->wait_for_acknowledgments(std::chrono::milliseconds(0)));
    auto pw = publisher->create_writer_raw("cpp_publisher_wait", hdds::QoS::reliable());
    auto pr = rp.create_reader_raw("cpp_publisher_wait", hdds::QoS::reliable());
    until([&] { return pw->get_publication_matched_status().current_count == 1; });
    pw->write(Message{});
    assert(publisher->wait_for_acknowledgments(std::chrono::seconds(10)));
    bool refused = false;
    try {
        publisher->wait_for_acknowledgments(std::chrono::milliseconds(-1));
    } catch (const hdds::Error&) {
        refused = true;
    }
    assert(refused);
    std::puts("C++ status/timestamp tests passed");
}
