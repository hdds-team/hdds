#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# DNS-SD discovery gate (decision codes DNSSD-1, DNSSD-2).
#
# Runs every named proof of the DNS-SD backend and prints the ones it
# expects, so a silently-renamed or silently-removed test is visible as a
# missing line rather than as a green run.
#
# Hermetic: every nameserver is an in-process UdpSocket on 127.0.0.1:0,
# /etc/resolv.conf is never read (nameservers are passed explicitly), no
# container, no credential, no outbound packet.
#
# Usage:  scripts/check-dns-sd.sh
set -euo pipefail

cd "$(dirname "$0")/.."

FEATURES="dns-sd,test-support"

EXPECTED_UNIT=(
  "discovery::dnssd::wire::tests::encodes_srv_query_matching_a_hand_built_rfc1035_vector"
  "discovery::dnssd::wire::tests::encode_name_refuses_labels_a_server_would_reject"
  "discovery::dnssd::wire::tests::decodes_srv_answers_with_compression_pointers_and_a_aaaa_glue"
  "discovery::dnssd::wire::tests::decoder_survives_every_truncation_of_a_valid_answer"
  "discovery::dnssd::wire::tests::rejects_pointer_loops_and_hostile_names"
  "discovery::dnssd::wire::tests::unknown_record_types_decode_as_other_and_are_skipped"
  "discovery::dnssd::wire::tests::decodes_cname_and_refuses_a_target_past_its_rdlength"
  "discovery::dnssd::wire::tests::normalise_name_is_case_and_trailing_dot_insensitive"
  "discovery::dnssd::resolver::tests::resolves_srv_and_a_records_against_a_fake_nameserver"
  "discovery::dnssd::resolver::tests::a_record_is_queried_before_aaaa_when_no_glue_is_offered"
  "discovery::dnssd::resolver::tests::nxdomain_timeout_and_truncation_yield_no_peers_without_panic"
  "discovery::dnssd::resolver::tests::a_resolver_without_a_nameserver_fails_instead_of_querying_nothing"
  "discovery::dnssd::resolver::tests::an_unencodable_service_name_is_refused_before_any_datagram"
  "discovery::dnssd::resolver::tests::message_ids_vary_and_a_mismatched_answer_is_ignored"
  "discovery::dnssd::resolver::tests::answers_that_do_not_match_the_question_are_refused"
  "discovery::dnssd::resolver::tests::addresses_follow_a_cname_chain_from_the_queried_name"
  "discovery::dnssd::resolver::tests::an_oversized_answer_is_truncated_not_a_shorter_list"
  "discovery::dnssd::resolver::tests::a_target_without_an_address_makes_the_answer_incomplete"
  "discovery::dnssd::resolver::tests::a_cancelled_lookup_returns_between_two_questions"
  "discovery::dnssd::resolv_conf::tests::parses_nameserver_lines_and_ignores_everything_else"
  "discovery::dnssd::resolv_conf::tests::an_empty_or_missing_file_yields_no_nameserver"
  "discovery::dnssd::tests::service_name_and_validation_refuse_what_cannot_be_resolved"
  "discovery::dnssd::tests::a_config_without_any_nameserver_is_refused_before_a_thread_exists"
  "discovery::dnssd::tests::discovery_thread_reports_peers_and_survives_a_failing_zone"
  "discovery::dnssd::tests::an_incomplete_zone_is_reported_as_partial_not_as_a_shorter_membership"
  "dds::participant::builder::dnssd_runtime::tests::resolved_peers_reach_the_cloud_origin_and_vanish_with_their_record"
  "dds::participant::builder::dnssd_runtime::tests::own_locators_and_unusable_addresses_are_excluded"
  "dds::participant::builder::dnssd_runtime::tests::stopping_clears_only_the_cloud_origin"
  "dds::participant::builder::dnssd_runtime::tests::synthetic_prefixes_are_stable_and_address_specific"
  "dds::participant::builder::dnssd_runtime::tests::the_lease_is_three_lookups_with_a_floor"
  "dds::participant::builder::dnssd_runtime::tests::an_incomplete_answer_keeps_the_peers_it_could_not_reconfirm"
)

EXPECTED_E2E=(
  "dns_sd_peers_receive_unicast_spdp_without_multicast"
  "an_unresolvable_zone_never_produces_a_peer"
  "an_incomplete_zone_still_reaches_the_peers_it_could_resolve"
  "dns_sd_build_refuses_a_configuration_that_could_never_resolve"
  "dns_sd_participant_is_multicast_disabled_by_default_unless_overridden"
  "the_resolver_is_usable_standalone_through_the_public_api"
  "dns_sd_is_listed_in_the_feature_summary"
)

# Compiled out of the dns-sd-only build by its own cfg: the guard that keeps
# a cloud registry and DNS-SD off the one leased peer origin only exists
# when both features are on, so it gets its own leg below.
CLOUD_FEATURES="dns-sd,cloud-discovery,test-support"
EXPECTED_E2E_CLOUD=(
  "a_cloud_registry_and_dns_sd_cannot_share_one_participant"
)

echo "== DNS-SD gate: expected named proofs =="
printf '  %s\n' "${EXPECTED_UNIT[@]}" "${EXPECTED_E2E[@]}"
echo

missing=0
check_present() {
  local listing="$1"
  shift
  for name in "$@"; do
    if ! grep -qF -- "$name" "$listing"; then
      echo "MISSING: $name"
      missing=1
    fi
  done
}

unit_listing="$(mktemp)"
e2e_listing="$(mktemp)"
cloud_listing="$(mktemp)"
trap 'rm -f "$unit_listing" "$e2e_listing" "$cloud_listing"' EXIT

cargo test -p hdds --lib --features "$FEATURES" -- --list >"$unit_listing"
cargo test -p hdds --test cloud_dnssd --features "$FEATURES" -- --list >"$e2e_listing"
cargo test -p hdds --test cloud_dnssd --features "$CLOUD_FEATURES" -- --list >"$cloud_listing"
check_present "$unit_listing" "${EXPECTED_UNIT[@]}"
check_present "$e2e_listing" "${EXPECTED_E2E[@]}"
check_present "$cloud_listing" "${EXPECTED_E2E_CLOUD[@]}"
if [ "$missing" -ne 0 ]; then
  echo "FAIL: a named DNS-SD proof is gone from the suite"
  exit 1
fi

echo "== DNS-SD gate: running =="
cargo test -p hdds --lib --features "$FEATURES" -- dnssd
cargo test -p hdds --test cloud_dnssd --features "$FEATURES"
cargo test -p hdds --test cloud_dnssd --features "$CLOUD_FEATURES" -- \
  a_cloud_registry_and_dns_sd_cannot_share_one_participant

echo
echo "== DNS-SD dependency cost (DNSSD-2: the number and the command that made it) =="
echo "\$ cargo tree -p hdds -e normal --prefix none --locked | sed 's/ (.*//' | sort -u | wc -l"
cargo tree -p hdds -e normal --prefix none --locked 2>/dev/null | sed 's/ (.*//' | sort -u | wc -l
echo "\$ cargo tree -p hdds -e normal --prefix none --locked --features dns-sd | sed 's/ (.*//' | sort -u | wc -l"
cargo tree -p hdds -e normal --prefix none --locked --features dns-sd 2>/dev/null | sed 's/ (.*//' | sort -u | wc -l

echo
echo "== DNS-SD size, with the command that measured it =="
echo "\$ wc -l crates/hdds/src/discovery/dnssd/*.rs"
wc -l crates/hdds/src/discovery/dnssd/*.rs | sed 's|crates/hdds/src/discovery/dnssd/||'

echo
echo "PASS: every named DNS-SD proof is present and green"
