# Cortex Analyzers

Collection of Cortex analyzers to enrich indicators using VirusTotal and LDAP.

## Disclaimer

This project is an **educational project**.

It is provided for learning and demonstration purposes, and **its use in production is not recommended** without proper security auditing, hardening, functional validation, and monitoring adapted to your environment.

## Repository Contents

- `hash_enrich`: hash enrichment (`md5`, `sha1`, `sha256`) via VirusTotal API v3
- `ip_enrich`: IP enrichment via VirusTotal API v3
- `ldap_user`: user lookup in an LDAP directory
- `ldap_machine`: machine (hostname) lookup in an LDAP directory
- `test_virustotal_analyzers.py`: local test script for VirusTotal analyzers

## Prerequisites

- Python 3.8+
- Cortex (with `cortexutils` available)
- Network access to required services:
  - `https://www.virustotal.com` for VirusTotal analyzers
  - LDAP server for LDAP analyzers
- `ldapsearch` binary available in `PATH` (for `ldap_user` and `ldap_machine`)

## Installation

```bash
pip install -r requirements.txt
```

## Available Analyzers

### 1) Hash_VirusTotal

- Folder: `hash_enrich`
- Data type: `hash`
- Cortex command: `hash_enrich/hash_enrich.py`
- Configuration parameters:
  - `api_key` (required)
  - `api_timeout` (default: `15`)
  - `enable_ssl_verify` (default: `true`)

Behavior:
- validates hash format (MD5 / SHA1 / SHA256)
- queries VirusTotal API v3 `/files/{hash}`
- returns detection stats, reputation, file metadata, and Cortex summary

### 2) IP_VirusTotal

- Folder: `ip_enrich`
- Data type: `ip`
- Cortex command: `ip_enrich/ip_enrich.py`
- Configuration parameters:
  - `api_key` (required)
  - `api_timeout` (default: `10`)
  - `enable_ssl_verify` (default: `true`)
  - `skip_private_ips` (default: `true`)

Behavior:
- validates IPv4/IPv6 address format
- skips private/reserved IPs if configured
- queries VirusTotal API v3 `/ip_addresses/{ip}`
- returns reputation, detection stats, ASN, owner, categories, and Cortex summary

### 3) LDAP_User_Enrichment

- Folder: `ldap_user`
- Data type: `username`
- Cortex command: `ldap_user/ldap_user.py`
- Configuration parameters:
  - `ldap_uri` (required)
  - `bind_dn` (required)
  - `bind_password` (required)
  - `base_dn` (required)
  - `timeout` (default: `30`)

Behavior:
- validates username format
- runs `ldapsearch` with filter `(uid=<username>)`
- parses LDIF output and returns key attributes (mail, cn, displayName, etc.)

### 4) LDAP_Machine_Enrichment

- Folder: `ldap_machine`
- Data type: `hostname`
- Cortex command: `ldap_machine/ldap_machine.py`
- Configuration parameters:
  - `ldap_uri` (required)
  - `bind_dn` (required)
  - `bind_password` (required)
  - `base_dn` (required)
  - `timeout` (default: `30`)

Behavior:
- validates hostname format
- runs `ldapsearch` with filter `(cn=<hostname>)`
- parses LDIF output and returns key attributes (cn, uid, description, ou)

## Cortex Configuration

1. Copy/import each analyzer into Cortex (`*.json` + its Python script).
2. Fill in required parameters in the Cortex UI:
   - VirusTotal API key for VT analyzers
   - LDAP settings for LDAP analyzers
3. Verify Cortex data types match:
   - `hash`, `ip`, `username`, `hostname`

## Local Tests (VirusTotal)

The test script runs both VirusTotal analyzers with test IOCs:

```bash
python test_virustotal_analyzers.py
```

The script prompts for your VirusTotal API key and then displays results.

## Security and Best Practices

- Do not commit secrets (API keys, LDAP passwords).
- Keep `enable_ssl_verify=true` in production.
- Use least-privilege permissions for the LDAP bind account (read-only minimum).
- Adjust timeouts to fit your environment.

## Quick Troubleshooting

- `VirusTotal API key is required`: check `api_key` configuration.
- `Hash not found in VirusTotal database`: hash is unknown to VT.
- `Cannot connect to LDAP server`: check URI/port/network.
- `LDAP authentication failed`: check `bind_dn` / `bind_password`.
