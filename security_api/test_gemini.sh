#!/bin/bash

# Test script to verify Gemini provider works

echo "Testing Gemini Provider Configuration..."
echo ""

# Temporarily switch to Gemini
export LLM_PROVIDER=gemini
export LLM_MODEL=gemini-1.5-flash
export GEMINI_API_KEY=AIzaSyAAr1nR0gtrhOKFUvOte8ZSRZU3vSnxLZU

# Create a simple test log
TEST_LOG='192.168.1.100 - - [10/Feb/2026:20:00:00 +0000] "GET /admin/login.php HTTP/1.1" 200 1234'

echo "Test log: $TEST_LOG"
echo ""
echo "Starting server with Gemini provider..."
echo "Visit http://localhost:3000 and paste the test log in Simple Mode"
echo ""

cd /Users/senaraufi/Desktop/Startup/security_api
cargo run -p security-api --release
