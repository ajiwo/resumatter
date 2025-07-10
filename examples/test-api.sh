#!/bin/bash

# Test script for the resumatter HTTP API
# Make sure the server is running with: make example-serve

BASE_URL="http://localhost:8080"

echo "Testing resumatter HTTP API..."
echo "================================"

# Test health endpoint
echo "1. Testing health endpoint..."
curl -s "$BASE_URL/health" | jq '.' || echo "Health check failed"
echo ""

# Test tailor endpoint
echo "2. Testing tailor endpoint..."
RESUME_CONTENT=$(cat examples/resume.txt)
JOB_CONTENT=$(cat examples/job.txt)

curl -s -X POST "$BASE_URL/tailor" \
  -H "Content-Type: application/json" \
  -d "{
    \"baseResume\": $(echo "$RESUME_CONTENT" | jq -R -s '.'),
    \"jobDescription\": $(echo "$JOB_CONTENT" | jq -R -s '.')
  }" | jq '.' > examples/api-tailor-result.json

if [ $? -eq 0 ]; then
  echo "Tailor request successful. Result saved to examples/api-tailor-result.json"
else
  echo "Tailor request failed"
fi
echo ""

# Test evaluate endpoint (using the tailored resume from the previous call)
echo "3. Testing evaluate endpoint..."
if [ -f examples/api-tailor-result.json ]; then
  TAILORED_RESUME=$(jq -r '.tailoredResume' examples/api-tailor-result.json)
  
  curl -s -X POST "$BASE_URL/evaluate" \
    -H "Content-Type: application/json" \
    -d "{
      \"baseResume\": $(echo "$RESUME_CONTENT" | jq -R -s '.'),
      \"tailoredResume\": $(echo "$TAILORED_RESUME" | jq -R -s '.')
    }" | jq '.' > examples/api-evaluate-result.json
  
  if [ $? -eq 0 ]; then
    echo "Evaluate request successful. Result saved to examples/api-evaluate-result.json"
  else
    echo "Evaluate request failed"
  fi
else
  echo "Skipping evaluate test - no tailored resume available"
fi

echo ""
echo "API testing complete!"
echo "Check examples/api-tailor-result.json and examples/api-evaluate-result.json for results"