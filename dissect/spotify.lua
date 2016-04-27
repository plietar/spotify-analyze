spotify = Proto("spotify", "Spotify")

local spotify_dt = DissectorTable.new ("spotify.cmd", "Spotify")

local f = spotify.fields
f.direction = ProtoField.uint8("spotify.direction", "Direction")
f.cmd = ProtoField.uint8("spotify.cmd", "Command", base.HEX)
f.length = ProtoField.uint32("spotify.length", "Length")

function spotify.dissector(buffer, pinfo, tree)
    local subtree = tree:add (spotify, buffer(), "Spotify")
    pinfo.cols.protocol = "Spotify"

    local direction = buffer(0, 1)
    local cmd = buffer(1, 1)
    local length = buffer(2, 2)
    local payload = buffer(4):tvb()

    if direction:uint() == 0 then
        pinfo.cols.src = "Client"
        pinfo.cols.dst = "Server"
    else
        pinfo.cols.src = "Server"
        pinfo.cols.dst = "Client"
    end

    subtree:add(f.direction, direction)
    subtree:add(f.cmd, cmd)
    subtree:add(f.length, length)

    if cmd:uint() == 0xab then
        DissectorTable.get("protobuf"):try("ClientResponseEncrypted", payload, pinfo, tree)
    elseif cmd:uint() == 0xac then
        DissectorTable.get("protobuf"):try("APWelcome", payload, pinfo, tree)
    elseif cmd:uint() == 0xad then
        DissectorTable.get("protobuf"):try("APLoginFailed", payload, pinfo, tree)
    else
        DissectorTable.get("spotify.cmd"):try(cmd:uint(), payload, pinfo, tree)
    end
end

DissectorTable.get("wtap_encap"):add(wtap.USER0, spotify)

spotify_dt:add(0x50, Dissector.get("xml"))
