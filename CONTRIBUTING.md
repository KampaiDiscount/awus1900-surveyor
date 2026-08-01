# Contributing

Bug reports and tested improvements are welcome.

Include the following with a reproducible report:

- Kali release and kernel from `uname -a`
- AWUS1900 USB visibility from `lsusb -d 0bda:8813`
- negotiated USB path from `lsusb -t`
- driver from `ethtool -i <interface>` or `readlink -f /sys/class/net/<interface>/device/driver`
- regulatory output from `iw reg get`
- sanitized `surveyor.log`
- exact command line used

Do not attach inventories or screenshots containing real SSIDs, BSSIDs, client identifiers, addresses, or location-sensitive data unless they have been sanitized.

## Local validation

```bash
python3 -m py_compile awus_surveyor.py
python3 -m unittest -v tests/test_parser.py
bash -n install.sh uninstall.sh run_awus_surveyor.sh scripts/package-release.sh
```

Keep the tool passive, dependency-light, reversible, and compatible with the in-kernel `rtw88_8814au` path.
