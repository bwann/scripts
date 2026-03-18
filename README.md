# scripts
Access to tools

Tools to scripts and utilities that I use to make life and infra better. Some
of these I wrote, some were AI assisted, some were entirely AI written.

These were written in an IPv6-first/only environment and tend to expect working
IPv6. All of them should have been passed through shellcheck/pylint/black/etc
for nits and consistency.

### DNS SOA serial number monitoring for Prometheus

**dns-soa-check.sh

I wanted to add several more authoritative nameservers for my domains and play
with the delivery mechanisms. I also wanted to make sure they were all serving
the same data and I didn't break anything. This script queries the SOA serial
number of all specified zones from all nameservers and writes them to a file.
Prometheus text-collector picks them up and does a min/max check to alert on
zones out of line. See also dns-soa-check-alertmanager.txt for example rule.

### AMI MegaRAC BMC TLS certificate uploader

**ami-bmc-cert-upload.py

Uploads a TLS certificate/key to the BMC/out-of-band management unit
on some system boards that use AMI MegaRAC. Originally I tried doing this via
Redfish but discovered my motherboard's BMC had its own cert store so I had to
do it via HTTP. It supports fetching of OOB credentials from a Hashicorp Vault
KV2 store (see VAULT_TOKEN_FILE/VAULT_BMC_PATH), but you can also supply
--username/--password on the command line too.

### Supermicro IPMI certificate updater

**smc-ipmi-updater.py

Uploads a TLS certificate/key to the BMC/out-of-band management unit of
Supermicro X10/X11 system boards. This is a fork of a fork of a fork, hopefully
I've retained owner notices. I added Hashicorp Vault KV2 support (see 
VAULT_TOKEN_FILE/VAULT_BMC_PATH), but you can also supply --username/-password
on the command line too.

I hear this may be superseded by the Supermicro SuperServer Automation Assistant
but I haven't tried it.
