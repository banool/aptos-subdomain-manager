# Subdomain Manager: Move Module

This module lets people create subdomain managers for ANS domains. By creating a manager, you transfer ownership of the domain to the manager. Callers, with the admin's approval (the owner of the manager object), can then claim subdomains.

## Usage
These script calls take you to the explorer page for running functions of the subdomain manager contracts.

To create a manager for a domain that you own (on testnet you can claim a domain [here](https://explorer.aptoslabs.com/account/0x5f8fd2347449685cf41d4db97926ec3a096eaf381332be4f1318ad4d16a8497c/modules/run/domains/register_domain?network=testnet) if you don't have one):
```
./scripts/explorer.sh testnet create_manager
```

Make sure to look at the txn and find the object address of the manager (look for the `to` field of the `object::TransferEvent` event).

## Development
To compile:
```
aptos move compile --named-addresses addr=0x5,aptos_names=0x5,aptos_names_v2_1=0x5,router=0x5,aptos_names_admin=0x5,aptos_names_funds=0x5,router_signer=0x5
```

To publish on testnet:
```
export ANS=0x5f8fd2347449685cf41d4db97926ec3a096eaf381332be4f1318ad4d16a8497c
aptos move publish --profile testnet --named-addresses addr=testnet,aptos_names=$ANS,aptos_names_v2_1=$ANS,router=$ANS,aptos_names_admin=$ANS,aptos_names_funds=$ANS,router_signer=$ANS
```
