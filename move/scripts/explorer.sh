#!/bin/bash

# Check if at least two arguments are provided
if [ $# -lt 2 ]; then
  echo "Usage: $0 <network> <function_name> [additional_args...]"
  echo "Example: $0 testnet create_manager"
  exit 1
fi

# Parse arguments
NETWORK=$1
FUNCTION_NAME=$2

# Define module addresses based on network
if [ "$NETWORK" == "testnet" ]; then
  MODULE_ADDRESS="0xcfe1e4daeb7e102150b9df9fca45aff7becd631b546dd19ab2af3dfaa5208913"
elif [ "$NETWORK" == "mainnet" ]; then
  echo "Mainnet not supported yet"
  exit 1
else
  echo "Unsupported network: $NETWORK. Only 'testnet' is currently supported."
  exit 1
fi

# Construct the URL
URL="https://explorer.aptoslabs.com/account/${MODULE_ADDRESS}/modules/run/subdomain_manager/${FUNCTION_NAME}?network=${NETWORK}"

# Open the URL in the default browser
if command -v open &> /dev/null; then
  # macOS
  open "$URL"
elif command -v xdg-open &> /dev/null; then
  # Linux
  xdg-open "$URL"
elif command -v cmd.exe &> /dev/null; then
  # Windows
  cmd.exe /c start "$URL"
else
  # Just print the URL if we can't open it
  echo "Please open the following URL in your browser:"
  echo "$URL"
fi
