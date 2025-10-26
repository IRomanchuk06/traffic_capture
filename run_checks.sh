#!/bin/bash

# Local development script for running tests and analysis
# Place this in your project root as: run_checks.sh
# Usage: chmod +x run_checks.sh && ./run_checks.sh

set -e

echo "🔨 Building project..."
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTS=ON
cmake --build build

echo ""
echo "✅ Running tests..."
cd build
ctest --output-on-failure
cd ..

echo ""
echo "🔍 Running clang-tidy..."
if command -v clang-tidy &> /dev/null; then
  clang-tidy -p build \
    --checks=-*,readability-*,performance-*,bugprone-*,-readability-magic-numbers \
    --header-filter='.*' \
    $(find src -name '*.cpp' -o -name '*.c') 2>&1 | head -50
else
  echo "⚠️  clang-tidy not found. Install with: sudo apt-get install clang-tidy"
fi

echo ""
echo "📊 Running cppcheck..."
if command -v cppcheck &> /dev/null; then
  cppcheck --enable=all \
    --suppress=missingIncludeSystem \
    --suppress=missingInclude \
    --inline-suppr \
    --quiet \
    src/
else
  echo "⚠️  cppcheck not found. Install with: sudo apt-get install cppcheck"
fi

echo ""
echo "✨ All checks completed!"
