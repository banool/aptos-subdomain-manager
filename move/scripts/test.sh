#!/bin/sh

set -e

APTOS_NAMES="0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c"
APTOS_NAMES_V2_1="0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c"
ADMIN="0x91945b4672607a327019e768dd6045d1254d1102d882df434ca734250bb3581d"
FUNDS="0x78ee3915e67ef5d19fa91d1e05e60ae08751efd12ce58e23fc1109de87ea7865"
ROUTER="0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c"
ROUTER_SIGNER=0x$(aptos account derive-resource-account-address \
  --address $ROUTER \
  --seed "ANS ROUTER" \
  --seed-encoding utf8 | \
  grep "Result" | \
  sed -n 's/.*"Result": "\([^"]*\)".*/\1/p')
BULK="0x53febacc40e549ced4132bf3c3313076c3a81c631c8deda28cad871e34f6de0b"

aptos move test --named-addresses addr=0x5,aptos_names=$APTOS_NAMES,aptos_names_v2_1=$APTOS_NAMES_V2_1,aptos_names_admin=$ADMIN,aptos_names_funds=$FUNDS,router=$ROUTER,router_signer="$ROUTER_SIGNER"
