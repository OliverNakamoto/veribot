#!/bin/bash
# Open the demo in your browser

cd /home/oliverz/humanoid_labs/hacks/demo

echo "🚀 Starting Robot Attestation Demo..."
echo

# Check if we can open browser
if command -v xdg-open &> /dev/null; then
    xdg-open index.html
elif command -v open &> /dev/null; then
    open index.html
else
    echo "📁 Demo file: file://$(pwd)/index.html"
    echo
    echo "Open this file in your browser to see the audit viewer!"
fi

echo "✅ Demo ready!"
echo
echo "What you'll see:"
echo "  • Mission timeline with all events"
echo "  • Cryptographic verification checks"
echo "  • Merkle proof visualization"
echo "  • Live replay functionality"
