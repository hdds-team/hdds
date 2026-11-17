// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <hdds.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sched.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}

static HddsParticipant* participant(const char* name) {
    HddsParticipantConfig* config = hdds_config_create(name);
    assert(config);
    assert(hdds_config_set_domain_id(config, 213) == HDDS_OK);
    HddsParticipant* p = hdds_config_build(config);
    assert(p);
    return p;
}

int main(void) {
    HddsParticipant* wp = participant("c_status_writer");
    HddsParticipant* rp = participant("c_status_reader");
    HddsQoS* qos = hdds_qos_reliable();
    HddsDataWriter* w = hdds_writer_create_with_qos(wp, "c_status_timestamp", qos);
    HddsDataReader* r = hdds_reader_create_with_qos(rp, "c_status_timestamp", qos);
    assert(w && r);
    assert(hdds_writer_wait_for_matched_readers(w, 1, 10000) == HDDS_OK);
    HddsPublicationMatchedStatus pub = {0};
    HddsSubscriptionMatchedStatus sub = {0};
    double until = now() + 10;
    do {
        assert(hdds_reader_get_subscription_matched_status(r, &sub) == HDDS_OK);
        assert(now() < until);
        sched_yield();
    } while (sub.CURRENT_COUNT != 1);
    assert(sub.TOTAL_COUNT == 1 && sub.TOTAL_COUNT_CHANGE == 1 && sub.CURRENT_COUNT_CHANGE == 1);
    assert(hdds_writer_get_publication_matched_status(w, &pub) == HDDS_OK);
    assert(pub.TOTAL_COUNT == 1 && pub.TOTAL_COUNT_CHANGE == 1 && pub.CURRENT_COUNT_CHANGE == 1);
    assert(hdds_reader_get_subscription_matched_status(r, &sub) == HDDS_OK);
    assert(sub.TOTAL_COUNT == 1 && sub.TOTAL_COUNT_CHANGE == 0 && sub.CURRENT_COUNT_CHANGE == 0);
    assert(hdds_writer_get_publication_matched_status(w, &pub) == HDDS_OK);
    assert(pub.TOTAL_COUNT == 1 && pub.TOTAL_COUNT_CHANGE == 0 && pub.CURRENT_COUNT_CHANGE == 0);
    HddsDeadlineMissedStatus requested_deadline_missed = {0};
    assert(hdds_reader_get_requested_deadline_missed_status(r, &requested_deadline_missed) == HDDS_OK);
    assert(hdds_reader_get_requested_deadline_missed_status(r, &requested_deadline_missed) == HDDS_OK);
    assert(requested_deadline_missed.TOTAL_COUNT == 0);
    assert(requested_deadline_missed.TOTAL_COUNT_CHANGE == 0);
    HddsDeadlineMissedStatus offered_deadline_missed = {0};
    assert(hdds_writer_get_offered_deadline_missed_status(w, &offered_deadline_missed) == HDDS_OK);
    assert(hdds_writer_get_offered_deadline_missed_status(w, &offered_deadline_missed) == HDDS_OK);
    assert(offered_deadline_missed.TOTAL_COUNT == 0);
    assert(offered_deadline_missed.TOTAL_COUNT_CHANGE == 0);
    HddsIncompatibleQosStatus requested_incompatible_qos = {0};
    assert(hdds_reader_get_requested_incompatible_qos_status(r, &requested_incompatible_qos) == HDDS_OK);
    assert(hdds_reader_get_requested_incompatible_qos_status(r, &requested_incompatible_qos) == HDDS_OK);
    assert(requested_incompatible_qos.TOTAL_COUNT == 0);
    assert(requested_incompatible_qos.TOTAL_COUNT_CHANGE == 0);
    assert(requested_incompatible_qos.LAST_POLICY_ID == 0);
    HddsIncompatibleQosStatus offered_incompatible_qos = {0};
    assert(hdds_writer_get_offered_incompatible_qos_status(w, &offered_incompatible_qos) == HDDS_OK);
    assert(hdds_writer_get_offered_incompatible_qos_status(w, &offered_incompatible_qos) == HDDS_OK);
    assert(offered_incompatible_qos.TOTAL_COUNT == 0);
    assert(offered_incompatible_qos.TOTAL_COUNT_CHANGE == 0);
    assert(offered_incompatible_qos.LAST_POLICY_ID == 0);
    HddsLivelinessChangedStatus liveliness_changed = {0};
    assert(hdds_reader_get_liveliness_changed_status(r, &liveliness_changed) == HDDS_OK);
    assert(liveliness_changed.ALIVE_COUNT == 1 && liveliness_changed.ALIVE_COUNT_CHANGE == 1);
    assert(hdds_reader_get_liveliness_changed_status(r, &liveliness_changed) == HDDS_OK);
    assert(liveliness_changed.ALIVE_COUNT == 1 && liveliness_changed.ALIVE_COUNT_CHANGE == 0);
    assert(liveliness_changed.NOT_ALIVE_COUNT == 0 && liveliness_changed.NOT_ALIVE_COUNT_CHANGE == 0);
    HddsLivelinessLostStatus liveliness_lost = {0};
    assert(hdds_writer_get_liveliness_lost_status(w, &liveliness_lost) == HDDS_OK);
    assert(hdds_writer_get_liveliness_lost_status(w, &liveliness_lost) == HDDS_OK);
    assert(liveliness_lost.TOTAL_COUNT == 0);
    assert(liveliness_lost.TOTAL_COUNT_CHANGE == 0);
    HddsSampleLostStatus sample_lost = {0};
    assert(hdds_reader_get_sample_lost_status(r, &sample_lost) == HDDS_OK);
    assert(hdds_reader_get_sample_lost_status(r, &sample_lost) == HDDS_OK);
    assert(sample_lost.TOTAL_COUNT == 0);
    assert(sample_lost.TOTAL_COUNT_CHANGE == 0);
    HddsSampleRejectedStatus sample_rejected = {0};
    assert(hdds_reader_get_sample_rejected_status(r, &sample_rejected) == HDDS_OK);
    assert(hdds_reader_get_sample_rejected_status(r, &sample_rejected) == HDDS_OK);
    assert(sample_rejected.TOTAL_COUNT == 0);
    assert(sample_rejected.TOTAL_COUNT_CHANGE == 0);
    assert(sample_rejected.LAST_REASON == 0);
    const uint8_t payload[] = {1, 2, 3, 4};
    HddsInstanceHandle handle = {0};
    assert(hdds_writer_register_instance(w, payload, sizeof(payload), &handle) == HDDS_OK);
    const uint8_t nil[16] = {0};
    assert(memcmp(handle.VALUE, nil, sizeof(nil)) == 0);
    memset(handle.VALUE, 0xff, sizeof(handle.VALUE));
    assert(hdds_writer_register_instance_w_timestamp(w, payload, sizeof(payload), 500000000, &handle) == HDDS_OK);
    assert(memcmp(handle.VALUE, nil, sizeof(nil)) == 0);
    HddsReadCondition* cond = hdds_create_read_condition(r, 3, 3, 7);
    assert(cond);
    uint8_t output[32];
    size_t len = 0;
    HddsSampleInfo info = {0};
    assert(hdds_reader_take_w_condition(r, cond, output, sizeof(output), &len, &info) == HDDS_NOT_FOUND);
    /* Exactly representable RTPS fraction: half a second. */
    const uint64_t stamp = UINT64_C(1700000000500000000);
    assert(hdds_writer_write_w_timestamp(w, payload, sizeof(payload), stamp) == HDDS_OK);
    until = now() + 10;
    HddsError err;
    do {
        err = hdds_reader_take_w_condition(r, cond, output, sizeof(output), &len, &info);
        assert(err == HDDS_OK || err == HDDS_NOT_FOUND);
        assert(now() < until);
        sched_yield();
    } while (err == HDDS_NOT_FOUND);
    assert(info.VALID_DATA && info.SOURCE_TIMESTAMP_NS == stamp);
    assert(len == sizeof(payload) && memcmp(output, payload, len) == 0);
    assert(hdds_writer_wait_for_acknowledgments(w, 10000) == HDDS_OK);
    assert(hdds_writer_write(w, payload, sizeof(payload)) == HDDS_OK);
    until = now() + 10;
    do {
        err = hdds_reader_take_w_condition(r, cond, output, sizeof(output), &len, &info);
        assert(err == HDDS_OK || err == HDDS_NOT_FOUND);
        assert(now() < until);
        sched_yield();
    } while (err == HDDS_NOT_FOUND);
    assert(info.VALID_DATA && info.SOURCE_TIMESTAMP_NS > stamp);
    assert(hdds_writer_dispose_w_timestamp(w, payload, sizeof(payload), stamp) == HDDS_OK);
    until = now() + 10;
    do {
        err = hdds_reader_take_w_condition(r, cond, output, sizeof(output), &len, &info);
        assert(err == HDDS_OK || err == HDDS_NOT_FOUND);
        assert(now() < until);
        sched_yield();
    } while (err == HDDS_NOT_FOUND);
    assert(!info.VALID_DATA && info.INSTANCE_STATE == 2);
    assert(hdds_writer_unregister_instance_w_timestamp(w, payload, sizeof(payload), stamp) == HDDS_OK);
    assert(hdds_writer_register_instance(w, payload, sizeof(payload), &handle) == HDDS_OK);
    assert(hdds_writer_dispose(w, payload, sizeof(payload)) == HDDS_OK);
    assert(hdds_writer_unregister_instance(w, payload, sizeof(payload)) == HDDS_OK);
    hdds_read_condition_delete(cond);
    hdds_reader_destroy(r);
    until = now() + 10;
    do {
        assert(hdds_writer_get_publication_matched_status(w, &pub) == HDDS_OK);
        assert(now() < until);
        sched_yield();
    } while (pub.CURRENT_COUNT != 0);
    assert(pub.TOTAL_COUNT == 1 && pub.CURRENT_COUNT_CHANGE == -1);
    assert(hdds_writer_get_publication_matched_status(w, &pub) == HDDS_OK);
    assert(pub.TOTAL_COUNT_CHANGE == 0 && pub.CURRENT_COUNT_CHANGE == 0);
    /* Mirror the departure on the reader side with a fresh endpoint pair. */
    r = hdds_reader_create_with_qos(rp, "c_status_timestamp", qos);
    assert(r);
    assert(hdds_writer_wait_for_matched_readers(w, 1, 10000) == HDDS_OK);
    until = now() + 10;
    do {
        assert(hdds_reader_get_subscription_matched_status(r, &sub) == HDDS_OK);
        assert(now() < until);
        sched_yield();
    } while (sub.CURRENT_COUNT != 1);
    hdds_writer_destroy(w);
    until = now() + 10;
    do {
        assert(hdds_reader_get_subscription_matched_status(r, &sub) == HDDS_OK);
        assert(now() < until);
        sched_yield();
    } while (sub.CURRENT_COUNT != 0);
    assert(sub.TOTAL_COUNT == 1 && sub.CURRENT_COUNT_CHANGE == -1);
    assert(hdds_reader_get_subscription_matched_status(r, &sub) == HDDS_OK);
    assert(sub.TOTAL_COUNT_CHANGE == 0 && sub.CURRENT_COUNT_CHANGE == 0);
    hdds_reader_destroy(r);
    /* Publisher::wait_for_acknowledgments waits for the writers of the
     * Publisher, whose data a matched reliable reader acknowledges. */
    assert(hdds_publisher_wait_for_acknowledgments(NULL, 10) == HDDS_INVALID_ARGUMENT);
    HddsPublisher* publisher = hdds_publisher_create(wp);
    assert(publisher);
    assert(hdds_publisher_wait_for_acknowledgments(publisher, 0) == HDDS_OK);
    HddsDataWriter* pw = hdds_publisher_create_writer_with_qos(publisher, "c_publisher_wait", qos);
    HddsDataReader* pr = hdds_reader_create_with_qos(rp, "c_publisher_wait", qos);
    assert(pw && pr);
    assert(hdds_writer_wait_for_matched_readers(pw, 1, 10000) == HDDS_OK);
    assert(hdds_writer_write(pw, payload, sizeof(payload)) == HDDS_OK);
    assert(hdds_publisher_wait_for_acknowledgments(publisher, 10000) == HDDS_OK);
    hdds_reader_destroy(pr);
    hdds_writer_destroy(pw);
    hdds_publisher_destroy(publisher);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(rp);
    hdds_participant_destroy(wp);
    puts("C status/timestamp tests passed");
    return 0;
}
