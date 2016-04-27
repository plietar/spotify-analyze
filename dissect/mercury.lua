mercury = Proto("mercury", "Mercury")

local mercury_dt = DissectorTable.new ("mercury.content_type", "Mercury", ftypes.STRING)

local f = mercury.fields
f.seq_length = ProtoField.uint16("mercury.seq_length", "Sequence number size")
f.seq = ProtoField.bytes("mercury.seq", "Sequence number")
f.flags = ProtoField.uint8("mercury.flags", "Flags")
f.part_count = ProtoField.uint16("mercury.part_count", "Part count")

local header_method = Field.new("header.method")
local header_uri = Field.new("header.uri")
local header_status_code = Field.new("header.status_code")
local header_content_type = Field.new("header.content_type")

function parse_payload(buffer, offset)
    local size = buffer(offset, 2)
    offset = offset + 2
    local data = buffer(offset, size:uint()):tvb()
    offset = offset + size:uint()

    return data, offset
end

function mercury.dissector(buffer, pinfo, tree)
    local subtree = tree:add (mercury, buffer(), "Mercury")
    pinfo.cols.protocol = "Mercury"

    local offset = 0;
    local seq_length = buffer(offset, 2)
    offset = offset + 2
    local seq = buffer(offset, seq_length:uint())
    offset = offset + seq_length:uint()
    local flags = buffer(offset, 1)
    offset = offset + 1
    local part_count = buffer(offset, 2)
    offset = offset + 2

    subtree:add(f.seq_length, seq_length)
    subtree:add(f.seq, seq)
    subtree:add(f.flags, flags)
    subtree:add(f.part_count, part_count)

    local header_data
    header_data, offset = parse_payload(buffer, offset)

    DissectorTable.get("protobuf"):try("Header", header_data, pinfo, subtree)

    pinfo.cols.info = (header_method() or header_status_code()).value .. " " .. header_uri().value

    local part_count = part_count:uint()

    local content_type = header_content_type()
    if part_count > 1 and content_type ~= nil then
        local payload_data
        payload_data, offset = parse_payload(buffer, offset)
        mercury_dt:try(content_type.value, payload_data, pinfo, subtree)
        part_count = part_count - 1
    end

    for i=1, part_count-1 do
        local payload_data
        payload_data, offset = parse_payload(buffer, offset)
        DissectorTable.get("protobuf"):try("Generic", payload_data, pinfo, subtree)
    end
end

DissectorTable.get("spotify.cmd"):add(0xb2, mercury)
DissectorTable.get("spotify.cmd"):add(0xb3, mercury)
DissectorTable.get("spotify.cmd"):add(0xb4, mercury)
DissectorTable.get("spotify.cmd"):add(0xb5, mercury)

function add_payload_type(content_type, proto)
    local dissector = DissectorTable.get("protobuf"):get_dissector(proto)
    if dissector ~= nil then
        mercury_dt:add(content_type, dissector)
    end
end

add_payload_type("vnd.spotify/mercury-mget-request", "MercuryMultiGetRequest")
add_payload_type("vnd.spotify/mercury-mget-reply", "MercuryMultiGetReply")
add_payload_type("application/x-protobuf", "Generic")
mercury_dt:add("vnd.spotify/abba-feature-flags+json", Dissector.get("json"))
