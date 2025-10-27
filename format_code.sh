#!/bin/bash

# Format all C++ code in the project

echo "🎨 Formatting C++ code..."

find src h tests -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) \
    -exec clang-format -i {} \;

echo "✨ Formatting complete!"

if git rev-parse --git-dir > /dev/null 2>&1; then
    echo ""
    echo "📊 Changed files:"
    git diff --name-only
fi
