#!/bin/bash

set -e  # Exit on error

# Paths
POLICY_DIR="src/main/resources/policy"
REGO_FILE="$POLICY_DIR/policy.rego"
BUNDLE_OUTPUT="bundle.tar.gz"
TARGET_BUNDLE="$POLICY_DIR/bundle.tar.gz"

# Check if policy.rego exists
if [[ ! -f "$REGO_FILE" ]]; then
  echo "❌ ERROR: Rego policy file not found at: $REGO_FILE"
  exit 1
fi

echo "🛠️ Compiling Rego policy to WebAssembly (WASM)..."
opa build -t wasm -e scim.authz/allow -o "$BUNDLE_OUTPUT" "$REGO_FILE"

echo "📦 Copying bundle.tar.gz to $TARGET_BUNDLE"
cp "$BUNDLE_OUTPUT" "$TARGET_BUNDLE"

# Optionally clean up root bundle
rm "$BUNDLE_OUTPUT"

echo "✅ Done. Bundle copied to: $TARGET_BUNDLE"

