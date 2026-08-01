# AWUS1900 Surveyor v1.0.1

## Highlights

- Clarifies that dashboard RSSI is received signal at the AWUS1900, not adapter transmit power.
- Adds simultaneous current and running-average RSSI columns to the live dashboard.
- Adds signal quality and total observed signal spread to structured reports.
- Expands RSSI diagnostics and AWUS1900 placement guidance.
- Adds GitHub Actions CI across Python 3.11–3.13.
- Adds repository contribution, security, line-ending, and release-packaging files.
- Documents the companion relationship with `kali-awus1900-deploy`.
- Removes an unreachable duplicate return statement.

The RF scan engine and stable passive `iw`/`nl80211` workflow remain unchanged from v1.0.0.
