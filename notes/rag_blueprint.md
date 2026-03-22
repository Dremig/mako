# RAG Blueprint for Blackbox CTF

## What Knowledge You Need

1. Recon and attack surface discovery
2. Payload dictionaries and bypass patterns
3. Exploit verification patterns and response signatures
4. Protocol/framework behavior references
5. Post-exploitation and privilege escalation checklists

## Source Mapping

- Recon:
  - `SecLists/Discovery/Web-Content`
  - `hacktricks` recon sections
- Payload and bypass:
  - `PayloadsAllTheThings`
  - `fuzzdb`
  - `SecLists/Payloads`
- Validation and triage:
  - `nuclei-templates`
  - `OWASP-CheatSheetSeries`
- Credential attacks:
  - `SecLists/Passwords/Common-Credentials`
  - `SecLists/Usernames`

## Metadata for Each Chunk

- `source_repo`
- `relative_path`
- `attack_phase` (`recon|fuzz|exploit|post`)
- `vuln_type` (`sqli|xss|ssti|ssrf|rce|lfi|auth-bypass|...`)
- `tool_hint` (`ffuf|nuclei|curl|burp|custom`)

## Retrieval Strategy

1. Parse task into `(target, phase, vuln_hint, tool_constraint)`
2. Route query to phase-specific index first
3. Use hybrid retrieval (keyword + vector)
4. Rerank by `phase match`, `vuln match`, then `tool match`
5. Keep top-k diverse by source to reduce single-repo bias

## Online Sources Worth Adding Later

- CVE and exploit data:
  - NVD API feeds (for recent CVE context)
  - Exploit-DB git mirror
- CTF writeups:
  - CTFtime-linked writeups (web/misc tags)
  - public CTF writeup repositories by year/event
- Tool docs:
  - ffuf, nuclei, sqlmap, wfuzz official docs for accurate command generation
