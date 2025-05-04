# Subdomain Manager: Move Module

This module lets people create subdomain managers for ANS domains. By creating a manager, you transfer ownership of the domain to the manager. Callers, with the admin's approval (the owner of the manager object), can then claim subdomains.

## Development
To compile:
```
aptos move compile --named-addresses addr=0x5,aptos_names=0x5,aptos_names_v2_1=0x5,router=0x5,aptos_names_admin=0x5,aptos_names_funds=0x5,router_signer=0x5
```
