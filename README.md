# Spotify Reverse Engineering tools and scripts
This repository contains tools and scripts used to reverse engineer the Spotify Protocol.
They are used to develop [librespot](https://github.com/plietar/librespot), an open source client implementation.

## spotify-dump
The `spotify-dump` tool intercepts packets by the Spotify desktop client before they are encrypted or after they are decrypted.
It works by patching the `shn_encrypt` and `shn_decrypt` routines of the client at run time.

This currently only works on 64 bit OS X.

To use, quit the Spotify application, and execute the `dump.sh` script with the path the spotify binary.

```
~/spotify-analyze/dump> ./dump.sh /Applications/Spotify.app/Contents/MacOS/Spotify
```

This will produce a `dump.pcap` in the current directory, which can be analyzed by the `spotify-dissect` tool.

## spotify-dissect
The `spotify-dissect` tool is a set of Wireshark dissectors used to analyze packet dumps.

To use, run the `dissect.sh` script with the packet dump as an argument.

```
~/spotify-analyze/dissect> ./dissect.sh ../dump/dump.pcap
```

This will start wireshark with the right plugins loaded, and open the packet dump.
