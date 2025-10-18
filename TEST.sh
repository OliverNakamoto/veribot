#!/bin/bash
cd /home/oliverz/humanoid_labs/hacks
clear
echo "🤖 Testing Robot Attestation System"
echo "===================================="
echo
cargo test -p attestation-core --lib 2>&1 | grep -E "running|test result"
echo
echo "Done! Project is at: /home/oliverz/humanoid_labs/hacks"
