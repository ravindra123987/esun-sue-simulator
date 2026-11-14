#!/bin/sh
# Fetch third-party UET test vectors into tests/vectors/ (git-ignored).
# uet-generated-crc-encaps.pcap: Wireshark test capture (GPL-2.0-or-later), 48 UET frames
# over IPv4/IPv6, with and without UDP, plain and tunnelled; all CRCs are good.
set -e
cd "$(dirname "$0")/../tests/vectors"
curl -fsSL -o uet-generated-crc-encaps.pcap \
  "https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/uet-generated-crc-encaps.pcap"
echo "fetched: $(pwd)/uet-generated-crc-encaps.pcap"
