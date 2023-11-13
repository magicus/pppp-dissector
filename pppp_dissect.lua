-- Copyright (C) 2023, Magnus Ihse Bursie <mag@icus.se>
-- Licensed under the MIT license, see LICENSE for details.
--
-- WireShark dissector for the P2P protocol used by various IoT devices,
-- typically cheap Chinese IP cameras.

-- I am standing on the shoulder of giants. This would not have been possible
-- without the work of Paul Marrapese (https://github.com/pmarrapese/iot) and
-- datenstau (https://github.com/datenstau/A9_PPPP).
-- In learning to write a Lua WireShark dissector, this post from Mika's tech blog
-- was incredibly helpful:
-- https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html

pppp_protocol = Proto("PPPP", "PPPP Protocol")

pppp_protocol.prefs.psk = Pref.string("Pre-shared Key", "", "The PSK used for PPPP encryption")

local fields = {}

-- inspired by https://github.com/Lekensteyn/kdnet
function add_field(proto_field_constructor, name, desc, ...)
  local field_name = "pppp." .. name
  -- If the description is omitted, use the name as label
  if type(desc) == "string" then
    fields[name] = proto_field_constructor(field_name, desc, ...)
  else
    fields[name] = proto_field_constructor(field_name, name, desc, ...)
  end
end

add_field(ProtoField.uint8, "magic", "Magic Byte", base.HEX)
add_field(ProtoField.bytes, "decrypted", "Decrypted Packet")
add_field(ProtoField.uint8, "opcode", "Opcode", base.HEX)
add_field(ProtoField.uint8, "len", "Payload Length")
add_field(ProtoField.bytes, "payload", "Payload")
add_field(ProtoField.bytes, "uid_raw", "Raw UID")
add_field(ProtoField.string, "uid", "UID")

add_field(ProtoField.uint8, "data_magic", "Data Magic Byte", base.HEX)
add_field(ProtoField.uint8, "channel", "Data Channel ID")
add_field(ProtoField.uint16, "index", "Data Message Index")
add_field(ProtoField.bytes, "data", "Data")

add_field(ProtoField.uint16, "ack_count", "Number of ACKs")
add_field(ProtoField.uint16, "index_ack", "Data Message Index ACK")

add_field(ProtoField.uint32, "cmd_flags", "Command Flags", base.HEX)
add_field(ProtoField.uint32, "cmd_flags.reply", "Direction", base.HEX, { [0] = "Request", [0x305] = "Reply" }, 0x060a0000)
add_field(ProtoField.uint32, "cmd_flags.admin", "Admin", base.HEX, { [0] = "False", [1] = "True" }, 0x00000100)
add_field(ProtoField.uint32, "cmd_flags.unknown", "Unknown", base.HEX, { [0xa080] = "Expected" }, 0xf9f5feff)
add_field(ProtoField.uint16, "cmd_len", "Command Length")
add_field(ProtoField.string, "cmd", "Command")

add_field(ProtoField.uint32, "frame_magic", "Frame Magic Bytes", base.HEX)
add_field(ProtoField.uint8, "frame_codec", "Codec", base.HEX)
add_field(ProtoField.uint8, "frame_type", "Media Type", base.HEX)
add_field(ProtoField.uint16, "frame_millis", "Milliseconds", base.HEX)
add_field(ProtoField.absolute_time, "frame_timestamp", "Timestamp")
add_field(ProtoField.uint32, "frame_index", "Index")
add_field(ProtoField.uint32, "frame_len", "Frame Length")
add_field(ProtoField.bytes, "frame_unknown", "Unknown")

pppp_protocol.fields = fields

local psk_magic_byte = 0x00 -- Only valid if PSK is set

function pppp_protocol.dissector(buffer, pinfo, tree)
  local bufferlen = buffer:len()
  if bufferlen == 0 then
    return 0
  end

  -- Check our magic byte
  local magic = buffer(0, 1):uint()

  if magic == 0xf1 then
    -- Unencrypted data, just do the actual dissection
    pppp_dissect(buffer, pinfo, tree, tree)
    return bufferlen
  end

  -- It is either an encrypted PPPP packet, or not a PPPP packet at all
  local psk = pppp_protocol.prefs.psk

  if psk ~= "" then
    -- We have a PSK set, so use it
    if magic == psk_magic_byte then
      buffer = pppp_handle_decryption(psk, buffer, tree)
      pppp_dissect(buffer, pinfo, tree, tree)
      return bufferlen
    else
      -- The packet does not match our expected magic byte; not a PPPP packet
      return 0
    end
  end

  -- No PSK set, so check if using one of the three most common PSKs
  if magic == 0x2c then
    buffer = pppp_handle_decryption("camera", buffer, tree)
    pppp_dissect(buffer, pinfo, tree, tree)
    return bufferlen
  elseif magic == 0x9f then
    buffer = pppp_handle_decryption("SHIX", buffer, tree)
    pppp_dissect(buffer, pinfo, tree, tree)
    return bufferlen
  elseif magic == 0xb1 then
    buffer = pppp_handle_decryption("SSD@cs2-network.", buffer, tree)
    pppp_dissect(buffer, pinfo, tree, tree)
    return bufferlen
  end

  -- No, this is not a PPPP packet
  return 0
end

pppp_protocol:register_heuristic("udp", pppp_protocol.dissector)

function pppp_protocol.init()
  pppp_update_magic_byte()
end

function pppp_protocol.prefs_changed()
  pppp_update_magic_byte()
end

function pppp_update_magic_byte()
  local psk = pppp_protocol.prefs.psk

  if psk ~= "" then
    -- We have a PSK set, so calculate and cache the magic byte value for it
    local clear_magic_byte = ByteArray.new("f1")
    psk_magic_byte = pppp_encrypt(psk, clear_magic_byte):get_index(0)
  end
end

function pppp_handle_decryption(psk, buffer, tree)
  local decrypted_buffer = pppp_decrypt(psk, buffer:bytes()):tvb("Decrypted PPPP Packet")
  local subtree = tree:add(pppp_protocol, buffer(), "PPPP Packet (encrypted)")
  subtree:add(fields.decrypted, decrypted_buffer())
  return decrypted_buffer
end

function pppp_dissect(buffer, pinfo, tree, roottree)
  local extra_info = get_extra_info(buffer)
  pinfo.cols.info:append(extra_info)
  local subtree = tree:add(pppp_protocol, buffer(), "PPPP Packet" .. extra_info)

  pinfo.cols.protocol = pppp_protocol.name

  subtree:add(fields.magic, buffer(0, 1))

  local opcode = buffer(1, 1):uint()
  local opcode_name = get_opcode_name(opcode)
  subtree:add(fields.opcode, buffer(1, 1)):append_text(" (" .. opcode_name .. ")")

  local payload_length = buffer(2, 2):uint()
  subtree:add(fields.len, buffer(2, 2))
  if payload_length > 0 then
    subtree:add(fields.payload, buffer(4))
    local payload_subtree = roottree:add(buffer(4), "PPPP Payload")

    -- Dissect the payload, if we have a dissector for this opcode
    local opcode_dissector = opcode_dissectors[opcode]
    if opcode_dissector then
      opcode_dissector(buffer(4), pinfo, payload_subtree, roottree)
    end
  end
end

---- Opcode-specfic dissectors

function dissect_opcode_uid(buffer, pinfo, subtree, roottree)
  local prefix = buffer(0, 8):stringz()
  local serial = buffer(8, 4):uint()
  local check = buffer(12, 8):stringz()
  local uid = prefix .. "-" .. string.format("%06s", serial) .. "-" .. check
  subtree:add(fields.uid, uid)
  subtree:add(fields.uid_raw, buffer(0, 20))
end

function dissect_opcode_drw(buffer, pinfo, subtree, roottree)
  subtree:add(fields.data_magic, buffer(0, 1))
  subtree:add(fields.channel, buffer(1, 1))
  subtree:add(fields.index, buffer(2, 2))
  local data_channel = buffer(1, 1):uint()
  subtree:add(fields.data, buffer(4))
  if data_channel == 0 then
    dissect_opcode_drw_command(buffer(4), pinfo, subtree, roottree)
  elseif buffer(4, 4):uint() == 0x55aa15a8 then
    dissect_opcode_drw_frame(buffer(4), pinfo, subtree, roottree)
  end
end

function dissect_opcode_drw_command(buffer, pinfo, subtree, roottree)
  local commands_channel_subtree = roottree:add(buffer(), "PPPP Command Channel")

  while buffer:len() > 0 do
    local command_block_length = buffer(4, 4):le_uint()
    local command_subtree = commands_channel_subtree:add(buffer(0, 8 + command_block_length), "Command Block")
    local flag_tree = command_subtree:add(fields.cmd_flags, buffer(0, 4))
    flag_tree:add(fields["cmd_flags.reply"], buffer(0, 4))
    flag_tree:add(fields["cmd_flags.admin"], buffer(0, 4))
    flag_tree:add(fields["cmd_flags.unknown"], buffer(0, 4))

    command_subtree:add_le(fields.cmd_len, buffer(4, 4))
    command_subtree:add(fields.cmd, buffer(8, command_block_length))

    if buffer:len() <= 8 + command_block_length then
      break
    end
    buffer = buffer(8 + command_block_length)
  end
end

function dissect_opcode_drw_frame(buffer, pinfo, subtree, roottree)
  local frame_subtree = roottree:add(buffer(), "PPPP Frame Header")

  frame_subtree:add(fields.frame_magic, buffer(0, 4))
  frame_subtree:add(fields.frame_codec, buffer(4, 1))
  frame_subtree:add(fields.frame_type, buffer(5, 1))

  frame_subtree:add_le(fields.frame_millis, buffer(6, 2))

  frame_subtree:add_le(fields.frame_timestamp, buffer(8, 4))
  frame_subtree:add_le(fields.frame_index, buffer(12, 4))
  frame_subtree:add_le(fields.frame_len, buffer(16, 4))

  frame_subtree:add(fields.frame_unknown, buffer(20, 12))
end

function dissect_opcode_drw_ack(buffer, pinfo, subtree, roottree)
  subtree:add(fields.data_magic, buffer(0, 1))
  subtree:add(fields.channel, buffer(1, 1))
  subtree:add(fields.ack_count, buffer(2, 2))

  subtree:add(fields.data, buffer(4))

  local ack_count = buffer(2, 2):uint()
  local acks_subtree = subtree:add(buffer(4), "ACKed Packets")
  buffer = buffer(4)
  while buffer:len() > 0 do
    local ack_index = buffer(0, 2):uint()
    acks_subtree:add(fields.index_ack, buffer(0, 2))
    if ack_count == 1 then
      break
    end
    if buffer:len() <= 2 then
      print("Warning: PPPP MSG_DRW_ACK packet is too short")
      break
    end
    buffer = buffer(2)
    ack_count = ack_count - 1
  end
end

opcode_dissectors = ({
  [0x41] = dissect_opcode_uid,     -- MSG_PUNCH_PKT
  [0x42] = dissect_opcode_uid,     -- MSG_P2P_RDY
  [0xd0] = dissect_opcode_drw,     -- MSG_DRW
  [0xd1] = dissect_opcode_drw_ack, -- MSG_DRW_ACK
})

---- Helper functions

function get_extra_info(buffer)
  local opcode = buffer(1, 1):uint()
  local opcode_name = get_opcode_name(opcode)

  if opcode_name == "Unknown" then
    return ""
  end

  local extra_info
  if opcode == 0xD0 then
    -- for MSG_DRW, add channel and index
    local channel = buffer(5, 1):uint()
    local index = buffer(6, 2):uint()

    extra_info = opcode_name .. ":" .. channel .. ";" .. index
  elseif opcode == 0xD1 then
    -- for MSG_DRW_ACK, add channel
    local channel = buffer(5, 1):uint()

    extra_info = opcode_name .. ":" .. channel
  else
    extra_info = opcode_name
  end

  return " (" .. extra_info .. ")"
end

function get_opcode_name(opcode)
  local opcode_name = opcode_names[opcode]
  if opcode_name == nil then
    return "Unknown"
  end

  return opcode_name
end

-- from https://github.com/pmarrapese/iot/blob/master/p2p/dissector/pppp.fdesc
opcode_names = {
  [0x00] = "MSG_HELLO",
  [0x01] = "MSG_HELLO_ACK",
  [0x02] = "MSG_HELLO_TO",
  [0x03] = "MSG_HELLO_TO_ACK",
  [0x08] = "MSG_QUERY_DID",
  [0x09] = "MSG_QUERY_DID_ACK",
  [0x10] = "MSG_DEV_LGN",
  [0x11] = "MSG_DEV_LGN_ACK",
  [0x12] = "MSG_DEV_LGN_CRC",
  [0x13] = "MSG_DEV_LGN_ACK_CRC",
  [0x14] = "MSG_DEV_LGN_KEY",
  [0x15] = "MSG_DEV_LGN_ACK_KEY",
  [0x16] = "MSG_DEV_LGN_DSK",
  [0x18] = "MSG_DEV_ONLINE_REQ",
  [0x19] = "MSG_DEV_ONLINE_REQ_ACK",
  [0x20] = "MSG_P2P_REQ",
  [0x21] = "MSG_P2P_REQ_ACK",
  [0x26] = "MSG_P2P_REQ_DSK",
  [0x30] = "MSG_LAN_SEARCH",
  [0x31] = "MSG_LAN_NOTIFY",
  [0x32] = "MSG_LAN_NOTIFY_ACK",
  [0x40] = "MSG_PUNCH_TO",
  [0x41] = "MSG_PUNCH_PKT",
  [0x42] = "MSG_P2P_RDY",
  [0x43] = "MSG_P2P_RDY_ACK",
  [0x60] = "MSG_RS_LGN",
  [0x61] = "MSG_RS_LGN_ACK",
  [0x62] = "MSG_RS_LGN1",
  [0x63] = "MSG_RS_LGN1_ACK",
  [0x67] = "MSG_LIST_REQ1",
  [0x68] = "MSG_LIST_REQ",
  [0x69] = "MSG_LIST_REQ_ACK",
  [0x6A] = "MSG_LIST_REQ_DSK",
  [0x70] = "MSG_RLY_HELLO",
  [0x71] = "MSG_RLY_HELLO_ACK",
  [0x72] = "MSG_RLY_PORT",
  [0x73] = "MSG_RLY_PORT_ACK",
  [0x74] = "MSG_RLY_PORT_KEY",
  [0x75] = "MSG_RLY_PORT_ACK_KEY",
  [0x78] = "MSG_RLY_BYTE_COUNT",
  [0x80] = "MSG_RLY_REQ",
  [0x81] = "MSG_RLY_REQ_ACK",
  [0x82] = "MSG_RLY_TO",
  [0x83] = "MSG_RLY_PKT",
  [0x84] = "MSG_RLY_RDY",
  [0x85] = "MSG_RLY_TO_ACK",
  [0x87] = "MSG_RLY_SERVER_REQ",
  -- [0x87] = "MSG_RLY_SERVER_REQ_ACK", -- has the same value as MSG_RLY_SERVER_REQ
  [0x90] = "MSG_SDEV_RUN",
  [0x91] = "MSG_SDEV_LGN",
  -- [0x91] = "MSG_SDEV_LGN_ACK", -- has the same value as MSG_SDEV_LGN
  [0x92] = "MSG_SDEV_LGN_CRC",
  -- [0x92] = "MSG_SDEV_LGN_ACK_CRC", -- has the same value as MSG_SDEV_LGN_CRC
  [0x93] = "MSG_SDEV_LGN_KEY",
  [0x94] = "MSG_SDEV_REPORT",
  [0xA0] = "MSG_CONNECT_REPORT",
  [0xA1] = "MSG_REPORT_REQ",
  [0xA2] = "MSG_REPORT",
  [0xD0] = "MSG_DRW",
  [0xD1] = "MSG_DRW_ACK",
  [0xD8] = "MSG_PSR",
  [0xE0] = "MSG_ALIVE",
  [0xE1] = "MSG_ALIVE_ACK",
  [0xF0] = "MSG_CLOSE",
  [0xF4] = "MSG_MGM_DUMP_LOGIN_DID",
  [0xF5] = "MSG_MGM_DUMP_LOGIN_DID_DETAIL",
  [0xF6] = "MSG_MGM_DUMP_LOGIN_DID_1",
  [0xF7] = "MSG_MGM_LOG_CONTROL",
  [0xF8] = "MSG_MGM_REMOTE_MANAGEMENT",
  [0xF9] = "MSG_REPORT_SESSION_READY",
}

---- "Decryption" functionality

-- Inspired from https://github.com/datenstau/A9_PPPP/blob/master/crypt.js
-- and https://github.com/fbertone/lib32100/issues/7

function pppp_create_psk_hash(psk)
  local psk_hash = { 0x00, 0x00, 0x00, 0x00 }

  for i = 0, psk:len() - 1 do
    local psk_byte = psk:sub(i + 1, i + 1):byte()

    psk_hash[1] = bit32.band(255, psk_hash[1] + psk_byte)
    psk_hash[2] = bit32.band(255, psk_hash[2] - psk_byte)
    psk_hash[3] = bit32.band(255, psk_hash[3] + math.floor(psk_byte / 3))
    psk_hash[4] = bit32.band(255, bit32.bxor(psk_hash[4], psk_byte))
  end

  return psk_hash
end

function pppp_lookup(psk_hash, byte)
  local psk_hash_index = bit32.band(byte, 3)
  local index = bit32.band(psk_hash[psk_hash_index + 1] + byte, 255)

  return shuffle_table[index + 1]
end

function pppp_decrypt(psk, encrypted)
  local clear = ByteArray.new()
  clear:set_size(encrypted:len())

  local psk_hash = pppp_create_psk_hash(psk)
  local prev_enc_byte = 0
  for position = 0, encrypted:len() - 1 do
    local key_byte = pppp_lookup(psk_hash, prev_enc_byte)

    local old_byte = encrypted:get_index(position)
    local new_byte = bit32.bxor(old_byte, key_byte)
    clear:set_index(position, new_byte)

    prev_enc_byte = old_byte
  end

  return clear
end

function pppp_encrypt(psk, clear)
  local encrypted = ByteArray.new()
  encrypted:set_size(clear:len())

  local psk_hash = pppp_create_psk_hash(psk)
  local prev_enc_byte = 0

  for position = 0, clear:len() - 1 do
    local key_byte = pppp_lookup(psk_hash, prev_enc_byte)

    local old_byte = clear:get_index(position)
    local new_byte = bit32.bxor(old_byte, key_byte)
    encrypted:set_index(position, new_byte)

    prev_enc_byte = new_byte
  end

  return encrypted
end

shuffle_table = {
  0x7C, 0x9C, 0xE8, 0x4A, 0x13, 0xDE, 0xDC, 0xB2, 0x2F, 0x21, 0x23, 0xE4, 0x30, 0x7B, 0x3D, 0x8C,
  0xBC, 0x0B, 0x27, 0x0C, 0x3C, 0xF7, 0x9A, 0xE7, 0x08, 0x71, 0x96, 0x00, 0x97, 0x85, 0xEF, 0xC1,
  0x1F, 0xC4, 0xDB, 0xA1, 0xC2, 0xEB, 0xD9, 0x01, 0xFA, 0xBA, 0x3B, 0x05, 0xB8, 0x15, 0x87, 0x83,
  0x28, 0x72, 0xD1, 0x8B, 0x5A, 0xD6, 0xDA, 0x93, 0x58, 0xFE, 0xAA, 0xCC, 0x6E, 0x1B, 0xF0, 0xA3,
  0x88, 0xAB, 0x43, 0xC0, 0x0D, 0xB5, 0x45, 0x38, 0x4F, 0x50, 0x22, 0x66, 0x20, 0x7F, 0x07, 0x5B,
  0x14, 0x98, 0x1D, 0x9B, 0xA7, 0x2A, 0xB9, 0xA8, 0xCB, 0xF1, 0xFC, 0x49, 0x47, 0x06, 0x3E, 0xB1,
  0x0E, 0x04, 0x3A, 0x94, 0x5E, 0xEE, 0x54, 0x11, 0x34, 0xDD, 0x4D, 0xF9, 0xEC, 0xC7, 0xC9, 0xE3,
  0x78, 0x1A, 0x6F, 0x70, 0x6B, 0xA4, 0xBD, 0xA9, 0x5D, 0xD5, 0xF8, 0xE5, 0xBB, 0x26, 0xAF, 0x42,
  0x37, 0xD8, 0xE1, 0x02, 0x0A, 0xAE, 0x5F, 0x1C, 0xC5, 0x73, 0x09, 0x4E, 0x69, 0x24, 0x90, 0x6D,
  0x12, 0xB3, 0x19, 0xAD, 0x74, 0x8A, 0x29, 0x40, 0xF5, 0x2D, 0xBE, 0xA5, 0x59, 0xE0, 0xF4, 0x79,
  0xD2, 0x4B, 0xCE, 0x89, 0x82, 0x48, 0x84, 0x25, 0xC6, 0x91, 0x2B, 0xA2, 0xFB, 0x8F, 0xE9, 0xA6,
  0xB0, 0x9E, 0x3F, 0x65, 0xF6, 0x03, 0x31, 0x2E, 0xAC, 0x0F, 0x95, 0x2C, 0x5C, 0xED, 0x39, 0xB7,
  0x33, 0x6C, 0x56, 0x7E, 0xB4, 0xA0, 0xFD, 0x7A, 0x81, 0x53, 0x51, 0x86, 0x8D, 0x9F, 0x77, 0xFF,
  0x6A, 0x80, 0xDF, 0xE2, 0xBF, 0x10, 0xD7, 0x75, 0x64, 0x57, 0x76, 0xF3, 0x55, 0xCD, 0xD0, 0xC8,
  0x18, 0xE6, 0x36, 0x41, 0x62, 0xCF, 0x99, 0xF2, 0x32, 0x4C, 0x67, 0x60, 0x61, 0x92, 0xCA, 0xD3,
  0xEA, 0x63, 0x7D, 0x16, 0xB6, 0x8E, 0xD4, 0x68, 0x35, 0xC3, 0x52, 0x9D, 0x46, 0x44, 0x1E, 0x17,
}

---- Debug helpers

-- from https://stackoverflow.com/a/27028488
function dump(o)
  if type(o) == 'table' then
    local s = '{ '
    for k, v in pairs(o) do
      if type(k) ~= 'number' then k = '"' .. k .. '"' end
      s = s .. '[' .. k .. '] = ' .. dump(v) .. ','
    end
    return s .. '} '
  else
    return tostring(o)
  end
end
