# Security Policy

AWUS1900 Surveyor is a passive access-point inventory tool. It does not deauthenticate clients, inject frames, recover keys, or capture user payload traffic.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/KampaiDiscount/awus1900-surveyor/security/advisories/new) for software vulnerabilities. Include the affected version, impact, reproduction conditions, and a minimal sanitized proof. Do not post exploitable details in a public issue. If the private reporting form is unavailable, contact the repository owner privately first.

## Supported versions

Security fixes target the latest release. Older releases may require an update; no support period or response-time guarantee is implied.

## Handling survey data

Wireless inventories can contain sensitive environmental data. Treat SSIDs, BSSIDs, timestamps, vendor identifiers, and survey locations as assessment evidence. Sanitize them before opening public issues or publishing screenshots.
