#!/usr/bin/env bash

set -e

echo "Starting CTF stream server"
cat /ctf_stream | netcat -v -N -l 0.0.0.0 8888
echo "Done"

exit 0
