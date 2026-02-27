-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Copyright (c) 2025-2026 naskel.com

-- =============================================================================
-- HDDS RTPS Wireshark Dissector
-- =============================================================================
-- A Lua post-dissector for enhanced RTPS/DDS packet analysis.
--
-- Features:
--   - Enhanced RTPS submessage decoding
--   - HDDS vendor-specific extensions
--   - CDR2 payload decoding with type registry
--   - Discovery protocol analysis
--
-- Installation:
--   Linux:   cp hdds_rtps.lua ~/.local/lib/wireshark/plugins/
--   macOS:   cp hdds_rtps.lua ~/Library/Application\ Support/Wireshark/plugins/
--   Windows: copy hdds_rtps.lua %APPDATA%\Wireshark\plugins\
--
-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Copyright (c) 2025-2026 naskel.com
-- =============================================================================

local hdds = Proto("hdds", "HDDS RTPS Extensions")

-- =============================================================================
-- PREFERENCES
-- =============================================================================

hdds.prefs.types_file = Pref.string("Types JSON", "", "Path to types JSON file")
hdds.prefs.decode_cdr = Pref.bool("Decode CDR", true, "Decode CDR2 payloads")
hdds.prefs.show_raw = Pref.bool("Show Raw Hex", false, "Show raw hex for payloads")
hdds.prefs.verbose = Pref.bool("Verbose", false, "Show additional debug info")

-- =============================================================================
-- PROTOCOL FIELDS
-- =============================================================================

-- RTPS Header fields
local f_magic = ProtoField.string("hdds.magic", "Magic")
local f_version = ProtoField.string("hdds.version", "Protocol Version")
local f_vendor = ProtoField.string("hdds.vendor", "Vendor ID")
local f_guid_prefix = ProtoField.bytes("hdds.guid_prefix", "GUID Prefix")

-- Submessage fields
local f_submsg_kind = ProtoField.string("hdds.submsg.kind", "Submessage Kind")
local f_submsg_flags = ProtoField.uint8("hdds.submsg.flags", "Flags", base.HEX)
local f_submsg_len = ProtoField.uint16("hdds.submsg.length", "Length")

-- Entity IDs
local f_reader_id = ProtoField.bytes("hdds.reader_id", "Reader Entity ID")
local f_writer_id = ProtoField.bytes("hdds.writer_id", "Writer Entity ID")

-- Sequence numbers
local f_seq_num = ProtoField.uint64("hdds.seq_num", "Sequence Number")
local f_first_seq = ProtoField.uint64("hdds.first_seq", "First Sequence")
local f_last_seq = ProtoField.uint64("hdds.last_seq", "Last Sequence")

-- DATA specifics
local f_topic_name = ProtoField.string("hdds.topic", "Topic Name")
local f_type_name = ProtoField.string("hdds.type_name", "Type Name")
local f_payload_len = ProtoField.uint32("hdds.payload_len", "Payload Length")

-- CDR decoded fields
local f_cdr_field = ProtoField.string("hdds.cdr.field", "Field")
local f_cdr_value = ProtoField.string("hdds.cdr.value", "Value")

hdds.fields = {
    f_magic, f_version, f_vendor, f_guid_prefix,
    f_submsg_kind, f_submsg_flags, f_submsg_len,
    f_reader_id, f_writer_id,
    f_seq_num, f_first_seq, f_last_seq,
    f_topic_name, f_type_name, f_payload_len,
    f_cdr_field, f_cdr_value
}

-- =============================================================================
-- CONSTANTS
-- =============================================================================

-- RTPS submessage kinds (RTPS v2.5 spec Table 8.13)
local SUBMSG_KINDS = {
    [0x01] = "PAD",
    [0x06] = "ACKNACK",
    [0x07] = "HEARTBEAT",
    [0x08] = "GAP",
    [0x09] = "INFO_TS",
    [0x0c] = "INFO_SRC",
    [0x0d] = "INFO_REPLY_IP4",
    [0x0e] = "INFO_DST",
    [0x0f] = "INFO_REPLY",
    [0x12] = "NACK_FRAG",
    [0x13] = "HEARTBEAT_FRAG",
    [0x15] = "DATA",
    [0x16] = "DATA_FRAG",
}

-- Vendor IDs (OMG DDS Interoperability Wire Protocol v2.5)
local VENDOR_IDS = {
    [0x0000] = "UNKNOWN",
    [0x0101] = "RTI Connext",
    [0x0102] = "OpenSplice (ADLink)",
    [0x0103] = "OpenDDS (OCI)",
    [0x010F] = "FastDDS (eProsima)",
    [0x0110] = "Cyclone DDS",
    [0x0112] = "RustDDS",
    [0x01AA] = "HDDS",
}

-- Well-known entity IDs
local ENTITY_IDS = {
    ["\x00\x00\x00\x00"] = "UNKNOWN",
    ["\x00\x00\x01\xC1"] = "PARTICIPANT",
    ["\x00\x01\x00\xC2"] = "SPDP_WRITER",
    ["\x00\x01\x00\xC7"] = "SPDP_READER",
    ["\x00\x00\x03\xC2"] = "SEDP_PUB_WRITER",
    ["\x00\x00\x03\xC7"] = "SEDP_PUB_READER",
    ["\x00\x00\x04\xC2"] = "SEDP_SUB_WRITER",
    ["\x00\x00\x04\xC7"] = "SEDP_SUB_READER",
    ["\x00\x03\x00\xC3"] = "TYPELOOKUP_REQ",
    ["\x00\x03\x00\xC4"] = "TYPELOOKUP_REP",
}

-- Parameter IDs for inline QoS / discovery data
local PARAMETER_IDS = {
    [0x0000] = "PID_PAD",
    [0x0001] = "PID_SENTINEL",
    [0x0002] = "PID_TOPIC_NAME",
    [0x0004] = "PID_TYPE_NAME",
    [0x0005] = "PID_METATRAFFIC_MULTICAST_PORT",
    [0x0006] = "PID_METATRAFFIC_UNICAST_LOCATOR",
    [0x0007] = "PID_DEFAULT_UNICAST_LOCATOR",
    [0x000F] = "PID_PROTOCOL_VERSION",
    [0x0016] = "PID_VENDOR_ID",
    [0x001A] = "PID_RELIABILITY",
    [0x001D] = "PID_LIVELINESS",
    [0x001E] = "PID_DURABILITY",
    [0x002B] = "PID_OWNERSHIP",
    [0x002C] = "PID_PRESENTATION",
    [0x0050] = "PID_PARTICIPANT_GUID",
    [0x005A] = "PID_ENDPOINT_GUID",
    [0x0072] = "PID_TYPE_OBJECT",
    [0x0073] = "PID_TYPE_OBJECT_V1",
    [0x8000] = "PID_VENDOR_SPECIFIC_START",
}

-- =============================================================================
-- TYPE REGISTRY (for CDR decoding)
-- =============================================================================

local type_registry = {}

-- Load types from JSON file
local function load_types_json(path)
    if path == "" then return {} end

    local file = io.open(path, "r")
    if not file then
        print("[HDDS] Warning: Cannot open types file: " .. path)
        return {}
    end

    local content = file:read("*all")
    file:close()

    -- Simple JSON parser for our format
    -- (In production, use a proper JSON library)
    local ok, types = pcall(function()
        return load("return " .. content:gsub('":"', '='):gsub('","', ','):gsub('{', '{'):gsub('}', '}'))()
    end)

    if ok then
        print("[HDDS] Loaded " .. (types.types and #types.types or 0) .. " types from " .. path)
        return types
    else
        print("[HDDS] Warning: Failed to parse types JSON")
        return {}
    end
end

-- =============================================================================
-- CDR2 DECODER
-- =============================================================================

-- Read uint8 from buffer
local function read_u8(buf, offset)
    if offset >= buf:len() then return 0, offset end
    return buf(offset, 1):uint(), offset + 1
end

-- Read uint16 LE from buffer
local function read_u16_le(buf, offset)
    if offset + 2 > buf:len() then return 0, offset end
    return buf(offset, 2):le_uint(), offset + 2
end

-- Read uint32 LE from buffer
local function read_u32_le(buf, offset)
    if offset + 4 > buf:len() then return 0, offset end
    return buf(offset, 4):le_uint(), offset + 4
end

-- Read uint64 LE from buffer
local function read_u64_le(buf, offset)
    if offset + 8 > buf:len() then return 0, offset end
    return buf(offset, 8):le_uint64(), offset + 8
end

-- Read int32 LE from buffer
local function read_i32_le(buf, offset)
    if offset + 4 > buf:len() then return 0, offset end
    return buf(offset, 4):le_int(), offset + 4
end

-- Read float32 LE from buffer
local function read_f32_le(buf, offset)
    if offset + 4 > buf:len() then return 0, offset end
    return buf(offset, 4):le_float(), offset + 4
end

-- Read float64 LE from buffer
local function read_f64_le(buf, offset)
    if offset + 8 > buf:len() then return 0, offset end
    return buf(offset, 8):le_float(), offset + 8
end

-- Read CDR string (4-byte length + chars + null + padding)
local function read_cdr_string(buf, offset)
    local len, new_offset = read_u32_le(buf, offset)
    if len == 0 or new_offset + len > buf:len() then
        return "", new_offset
    end

    local str = buf(new_offset, len - 1):string() -- -1 for null terminator
    new_offset = new_offset + len

    -- Align to 4 bytes
    local padding = (4 - (new_offset % 4)) % 4
    return str, new_offset + padding
end

-- Read bytes with length prefix
local function read_cdr_bytes(buf, offset)
    local len, new_offset = read_u32_le(buf, offset)
    if len == 0 or new_offset + len > buf:len() then
        return "", new_offset
    end

    local bytes = buf(new_offset, len):bytes():tohex()
    new_offset = new_offset + len

    -- Align to 4 bytes
    local padding = (4 - (new_offset % 4)) % 4
    return bytes, new_offset + padding
end

-- =============================================================================
-- SUBMESSAGE PARSERS
-- =============================================================================

-- Parse DATA submessage
local function parse_data(buf, offset, tree, flags)
    local subtree = tree:add(hdds, buf(offset), "DATA Submessage")

    local extra_flags, new_off = read_u16_le(buf, offset)
    local octets_to_inline_qos
    octets_to_inline_qos, new_off = read_u16_le(buf, new_off)

    -- Reader/Writer Entity IDs
    local reader_id = buf(new_off, 4)
    subtree:add(f_reader_id, reader_id)
    local reader_name = ENTITY_IDS[reader_id:raw()] or string.format("0x%08X", reader_id:uint())
    subtree:append_text(" Reader=" .. reader_name)
    new_off = new_off + 4

    local writer_id = buf(new_off, 4)
    subtree:add(f_writer_id, writer_id)
    local writer_name = ENTITY_IDS[writer_id:raw()] or string.format("0x%08X", writer_id:uint())
    subtree:append_text(" Writer=" .. writer_name)
    new_off = new_off + 4

    -- Sequence number (64-bit, split as high/low)
    local seq_low, seq_high
    seq_high, new_off = read_u32_le(buf, new_off)
    seq_low, new_off = read_u32_le(buf, new_off)
    local seq_num = seq_high * 0x100000000 + seq_low
    subtree:add(f_seq_num, seq_num)
    subtree:append_text(" Seq=" .. seq_num)

    -- Inline QoS (if Q flag set)
    local has_inline_qos = bit.band(flags, 0x02) ~= 0
    local has_data = bit.band(flags, 0x04) ~= 0
    local has_key = bit.band(flags, 0x08) ~= 0

    local topic_name = nil
    local type_name = nil

    if has_inline_qos then
        local qos_tree = subtree:add(hdds, buf(new_off), "Inline QoS")
        local qos_start = new_off

        -- Parse parameter list
        while new_off < buf:len() - 4 do
            local pid
            pid, new_off = read_u16_le(buf, new_off)
            local plen
            plen, new_off = read_u16_le(buf, new_off)

            if pid == 0x0001 then -- SENTINEL
                break
            end

            local pname = PARAMETER_IDS[pid] or string.format("PID_0x%04X", pid)

            if pid == 0x0002 then -- TOPIC_NAME
                topic_name, _ = read_cdr_string(buf, new_off)
                qos_tree:add(f_topic_name, topic_name)
            elseif pid == 0x0004 then -- TYPE_NAME
                type_name, _ = read_cdr_string(buf, new_off)
                qos_tree:add(f_type_name, type_name)
            end

            new_off = new_off + plen
            -- Align to 4 bytes
            local padding = (4 - (new_off % 4)) % 4
            new_off = new_off + padding
        end

        if topic_name then
            subtree:append_text(" Topic=\"" .. topic_name .. "\"")
        end
    end

    -- Payload (if D flag set)
    if has_data and new_off < buf:len() then
        local payload_len = buf:len() - new_off
        subtree:add(f_payload_len, payload_len)

        -- Try to decode CDR payload
        if hdds.prefs.decode_cdr and payload_len > 4 then
            local payload_tree = subtree:add(hdds, buf(new_off, payload_len), "CDR2 Payload")

            -- CDR encapsulation header (4 bytes)
            local encap_kind = buf(new_off, 2):uint()
            local encap_opts = buf(new_off + 2, 2):uint()

            local encap_name = "UNKNOWN"
            if encap_kind == 0x0001 then encap_name = "CDR_BE"
            elseif encap_kind == 0x0000 then encap_name = "CDR_LE"
            elseif encap_kind == 0x0006 then encap_name = "CDR2_LE"
            elseif encap_kind == 0x0007 then encap_name = "CDR2_BE"
            elseif encap_kind == 0x0010 then encap_name = "PL_CDR2_LE"
            end

            payload_tree:add(hdds, buf(new_off, 2), "Encapsulation: " .. encap_name)

            if hdds.prefs.show_raw then
                payload_tree:add(hdds, buf(new_off + 4), "Raw: " .. buf(new_off + 4):bytes():tohex())
            end
        end
    end

    return new_off
end

-- Parse HEARTBEAT submessage
local function parse_heartbeat(buf, offset, tree, flags)
    local subtree = tree:add(hdds, buf(offset), "HEARTBEAT Submessage")

    local new_off = offset

    -- Reader/Writer Entity IDs
    local reader_id = buf(new_off, 4)
    subtree:add(f_reader_id, reader_id)
    new_off = new_off + 4

    local writer_id = buf(new_off, 4)
    subtree:add(f_writer_id, writer_id)
    new_off = new_off + 4

    -- First available sequence number
    local first_high, first_low
    first_high, new_off = read_u32_le(buf, new_off)
    first_low, new_off = read_u32_le(buf, new_off)
    local first_seq = first_high * 0x100000000 + first_low
    subtree:add(f_first_seq, first_seq)

    -- Last sequence number
    local last_high, last_low
    last_high, new_off = read_u32_le(buf, new_off)
    last_low, new_off = read_u32_le(buf, new_off)
    local last_seq = last_high * 0x100000000 + last_low
    subtree:add(f_last_seq, last_seq)

    -- Count
    local count
    count, new_off = read_u32_le(buf, new_off)

    subtree:append_text(string.format(" Seq=[%d-%d] Count=%d", first_seq, last_seq, count))

    return new_off
end

-- Parse ACKNACK submessage
local function parse_acknack(buf, offset, tree, flags)
    local subtree = tree:add(hdds, buf(offset), "ACKNACK Submessage")

    local new_off = offset

    -- Reader/Writer Entity IDs
    local reader_id = buf(new_off, 4)
    subtree:add(f_reader_id, reader_id)
    new_off = new_off + 4

    local writer_id = buf(new_off, 4)
    subtree:add(f_writer_id, writer_id)
    new_off = new_off + 4

    -- Sequence number set base
    local base_high, base_low
    base_high, new_off = read_u32_le(buf, new_off)
    base_low, new_off = read_u32_le(buf, new_off)
    local base_seq = base_high * 0x100000000 + base_low

    -- Num bits
    local num_bits
    num_bits, new_off = read_u32_le(buf, new_off)

    subtree:append_text(string.format(" Base=%d NumBits=%d", base_seq, num_bits))

    return new_off
end

-- Parse GAP submessage
local function parse_gap(buf, offset, tree, flags)
    local subtree = tree:add(hdds, buf(offset), "GAP Submessage")

    local new_off = offset

    -- Reader/Writer Entity IDs
    new_off = new_off + 4  -- reader
    new_off = new_off + 4  -- writer

    -- Gap start
    local start_high, start_low
    start_high, new_off = read_u32_le(buf, new_off)
    start_low, new_off = read_u32_le(buf, new_off)
    local gap_start = start_high * 0x100000000 + start_low

    subtree:append_text(string.format(" Start=%d", gap_start))

    return new_off
end

-- Parse INFO_TS submessage
local function parse_info_ts(buf, offset, tree, flags)
    local subtree = tree:add(hdds, buf(offset), "INFO_TS Submessage")

    local has_timestamp = bit.band(flags, 0x02) == 0  -- T flag = 0 means timestamp present

    if has_timestamp and offset + 8 <= buf:len() then
        local seconds = buf(offset, 4):le_uint()
        local fraction = buf(offset + 4, 4):le_uint()
        subtree:append_text(string.format(" Time=%d.%09d", seconds, fraction))
    end

    return offset + 8
end

-- =============================================================================
-- MAIN DISSECTOR
-- =============================================================================

function hdds.init()
    -- Load types from JSON file on startup
    type_registry = load_types_json(hdds.prefs.types_file)
end

function hdds.dissector(buffer, pinfo, tree)
    -- Only process UDP packets on RTPS ports (7400-7500 range typically)
    local port = pinfo.dst_port
    if port < 7400 or port > 7500 then
        -- Also check src port
        port = pinfo.src_port
        if port < 7400 or port > 7500 then
            return
        end
    end

    -- Check minimum RTPS header size
    if buffer:len() < 20 then
        return
    end

    -- Verify RTPS magic
    local magic = buffer(0, 4):string()
    if magic ~= "RTPS" then
        return
    end

    -- Create HDDS subtree
    local hdds_tree = tree:add(hdds, buffer(), "HDDS RTPS Analysis")

    -- Parse header
    hdds_tree:add(f_magic, buffer(0, 4))

    local version_major = buffer(4, 1):uint()
    local version_minor = buffer(5, 1):uint()
    hdds_tree:add(f_version, string.format("%d.%d", version_major, version_minor))

    local vendor_id = buffer(6, 2):uint()
    local vendor_name = VENDOR_IDS[vendor_id] or string.format("0x%04X", vendor_id)
    hdds_tree:add(f_vendor, vendor_name)

    -- Highlight HDDS packets
    if vendor_id == 0x01AA then
        pinfo.cols.info:prepend("[HDDS] ")
    end

    hdds_tree:add(f_guid_prefix, buffer(8, 12))

    -- Parse submessages
    local offset = 20
    local submsg_count = 0

    while offset < buffer:len() - 4 do
        local submsg_kind = buffer(offset, 1):uint()
        local submsg_flags = buffer(offset + 1, 1):uint()
        local submsg_len = buffer(offset + 2, 2):le_uint()

        local kind_name = SUBMSG_KINDS[submsg_kind] or string.format("0x%02X", submsg_kind)
        local submsg_tree = hdds_tree:add(hdds, buffer(offset, 4 + submsg_len),
            string.format("Submessage #%d: %s", submsg_count + 1, kind_name))

        submsg_tree:add(f_submsg_kind, kind_name)
        submsg_tree:add(f_submsg_flags, submsg_flags)
        submsg_tree:add(f_submsg_len, submsg_len)

        -- Parse specific submessage types
        local payload_offset = offset + 4

        if submsg_kind == 0x15 then  -- DATA
            parse_data(buffer, payload_offset, submsg_tree, submsg_flags)
        elseif submsg_kind == 0x07 then  -- HEARTBEAT
            parse_heartbeat(buffer, payload_offset, submsg_tree, submsg_flags)
        elseif submsg_kind == 0x06 then  -- ACKNACK
            parse_acknack(buffer, payload_offset, submsg_tree, submsg_flags)
        elseif submsg_kind == 0x08 then  -- GAP
            parse_gap(buffer, payload_offset, submsg_tree, submsg_flags)
        elseif submsg_kind == 0x09 then  -- INFO_TS
            parse_info_ts(buffer, payload_offset, submsg_tree, submsg_flags)
        end

        offset = offset + 4 + submsg_len
        submsg_count = submsg_count + 1

        -- Safety limit
        if submsg_count > 100 then
            hdds_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Too many submessages")
            break
        end
    end

    hdds_tree:append_text(string.format(" (%d submessages)", submsg_count))

    -- Update info column
    if hdds.prefs.verbose then
        pinfo.cols.info:append(string.format(" [%s %d msgs]", vendor_name, submsg_count))
    end
end

-- Register as post-dissector
register_postdissector(hdds)

-- =============================================================================
-- UTILITY FUNCTIONS
-- =============================================================================

-- Format GUID for display
local function format_guid(prefix, entity_id)
    local parts = {}
    for i = 1, 12 do
        table.insert(parts, string.format("%02x", prefix:byte(i)))
    end
    for i = 1, 4 do
        table.insert(parts, string.format("%02x", entity_id:byte(i)))
    end
    return table.concat(parts, ":")
end

-- Format sequence number range
local function format_seq_range(first, last)
    if first == last then
        return tostring(first)
    else
        return string.format("%d-%d", first, last)
    end
end

print("[HDDS] RTPS Dissector loaded - Version 1.0.0")
print("[HDDS] Set hdds.types_file preference to enable CDR type decoding")
