# Update iosshn.c with file path for where to write dump.pcap
# run 'make' to build required object files

# Requires SpotifyAudioPlayback file from spotify ios sdk be copied into
# this directory.  Produces a new replacement library spotNew.
# Once script finishes, rename spotNew to SpotifyAudioPlayback and replace the old SpotifyAudioPlayback
# in the ios-sdk directory.

# Extract the x86 archive static library from fat file
lipo SpotifyAudioPlayback -thin x86_64 -output spotifyThin
# Remove the shannon object file from the archive
ar -d spotifyThin shannon.c.o
# Add in our new shannon implementation and logging code
ar -r spotifyThin pcap.o shn.o iosshn.o
# Package the archive back into a fat file
lipo spotifyThin -create -output spotNew