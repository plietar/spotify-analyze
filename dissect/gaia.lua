gaia = Proto("gaia", "Gaia")

function gaia.dissector(buffer, pinfo, tree)
    local subtree = tree:add (gaia, buffer(), "Gaia")
    pinfo.cols.protocol = "Gaia"
end

DissectorTable.get("spotify.cmd"):add(0x48, gaia)
