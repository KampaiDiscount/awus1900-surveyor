# Changelog

## Unreleased

- Added release download, checksum verification, prerequisites, update, and uninstall instructions.
- Clarified service regulatory-domain configuration and recovery-file limits after reboot or power loss.
- Added project status links and distinguished automated tests from hardware validation.

## 1.0.1 — 2026-08-01

- Clarified that dashboard RSSI is received signal at the AWUS1900, not adapter transmit power.
- Added current and running-average RSSI columns to the terminal dashboard.
- Added signal-quality and observed-spread fields to JSON, CSV, HTML, and Markdown output.
- Added RSSI interpretation, antenna/USB placement guidance, and companion-deployment documentation.
- Added a synthetic, publication-safe dashboard illustration.
- Added GitHub Actions CI for Python 3.11–3.13 and shell syntax validation.
- Added repository contribution, security, line-ending, editor, ignore, and release-packaging files.
- Removed an unreachable duplicate return statement.

## 1.0.0 — 2026-07-31

- Initial stable passive survey engine using `iw`/`nl80211`, without `airmon-ng`.
- AWUS1900 auto-detection by USB ID, driver, and product metadata.
- Continuous 2.4 GHz and 5 GHz channel sweeps with band-specific chunking.
- Automatic NetworkManager release and exact interface-state restoration.
- Scan timeout, retry, adapter recovery, stale-state recovery, and process locking.
- Continuous atomic CSV, JSON, HTML, Markdown, JSONL, raw-scan, session, and log output.
- Security classification for Open, WEP, WPA, WPA2, WPA3, transition mode, OWE, enterprise, PMF, and WPS.
- Signal min/max/average/current tracking, SSID/security/channel history, BSS load, Wi-Fi generation, and OUI vendor lookup.
- Interactive terminal dashboard, one-shot mode, timed mode, self-test, and optional systemd service.
