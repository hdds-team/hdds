// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
#pragma once

#include <cstdint>
#include <cstring>

namespace hdds_cpp {

enum class CodecKind : uint8_t {
  None = 0,
  String = 1,
  Log = 2,
  ParameterEvent = 3,
};

inline const char * normalize_topic(const char *topic) noexcept {
  if (!topic) { return nullptr; }
  if (topic[0] == '/' && topic[1] != '\0') { return topic + 1; }
  return topic;
}

inline CodecKind select_codec_for_topic(const char *topic) noexcept {
  const char *t = normalize_topic(topic);
  if (!t) { return CodecKind::None; }
  if (std::strcmp(t, "chatter") == 0) { return CodecKind::String; }
  if (std::strcmp(t, "rosout") == 0) { return CodecKind::Log; }
  if (std::strcmp(t, "parameter_events") == 0) { return CodecKind::ParameterEvent; }
  return CodecKind::None;
}

} // namespace hdds_cpp

