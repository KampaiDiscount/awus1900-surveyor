# RSSI, dBm, and why a nearby device can show `-60`

The dashboard's **RSSI** value is the signal level received by the AWUS1900 and reported by the Linux wireless driver. It is not the AWUS1900's transmit-power setting.

## Reading the number

Wi-Fi signal is displayed in dBm on a logarithmic scale. Values closer to zero are stronger.

| RSSI | Practical survey interpretation |
|---:|---|
| `-30` to `-49 dBm` | Excellent / very close |
| `-50` to `-59 dBm` | Strong |
| `-60` to `-67 dBm` | Good |
| `-68` to `-75 dBm` | Fair |
| `-76` to `-85 dBm` | Weak but often detectable |
| below `-85 dBm` | Very weak / edge of useful reception |

These are operational labels, not guarantees. Link quality also depends on noise, channel utilization, modulation, retries, antenna polarization, and the transmitting device.

`-60 dBm` is therefore not a bad result. It is normally a healthy received signal for discovery and ordinary data operation.

## Why the HP Wi-Fi Direct zone may be lower than a router

A nearby printer can legitimately appear 15–25 dB below a router because:

- the printer's Wi-Fi Direct radio may transmit at lower EIRP;
- the printer uses a small internal antenna inside a plastic-and-metal chassis;
- antenna orientation and polarization may not align with the AWUS1900 antennas;
- 5 GHz incurs about 6.5 dB more free-space path loss than 2.4 GHz at the same distance;
- desks, laptop bodies, walls, appliances, people, and multipath nulls can add substantial attenuation;
- driver-reported RSSI is suitable for relative comparison but is not a calibrated spectrum-analyzer measurement.

Moving either endpoint by 20–50 cm can materially change a 5 GHz reading because the receiver may move into or out of a multipath null.

## `RSSI` versus `AVG`

The live table shows two values:

- **RSSI** — the most recent accepted scan observation;
- **AVG** — the running average for that BSSID during the current session.

Use `AVG` for a stable comparison and `RSSI` for immediate movement or orientation testing. The reports also retain current, best, worst, average, sample count, and total spread.

## Hardware checks when every zone looks weak

Stop the survey cleanly, then check:

```bash
lsusb -d 0bda:8813
lsusb -t
ethtool -i wlan0
rfkill list
sudo iw reg get
```

Confirm that:

- all four RP-SMA antennas are fully seated;
- the adapter is on a stable USB 3.x path (`5000M` or better in `lsusb -t`);
- the adapter is clear of the laptop chassis, metal surfaces, and cable strain;
- the four dual-band antennas are initially vertical and similarly polarized;
- the intended `rtw88_8814au` or validated standalone driver is bound;
- the correct regulatory domain is active.

A short, shielded USB extension can move the AWUS1900 away from the laptop and often improves repeatability. USB 3 interference is primarily a 2.4 GHz concern, while physical shadowing and chassis proximity affect both bands.

## Simple diagnosis

- **Only one device is low:** the transmitter, its antenna, orientation, or local obstruction is the likely cause.
- **Every device is low:** inspect antenna seating, placement, USB stability, and driver state.
- **Readings fluctuate while average stays sensible:** normal multipath and scan-to-scan variation.
- **Networks disappear or scans fail:** investigate driver/USB stability rather than treating RSSI as the primary symptom.

## References

- [Linux Wireless: `iw` and nl80211 scanning](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html)
- [Linux kernel cfg80211 subsystem](https://docs.kernel.org/driver-api/80211/cfg80211.html)
- [ALFA AWUS1900 specifications](https://www.alfa.com.tw/products/awus1900_1)
- [Cisco Wireless RF Reference Guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/technical-reference/wireless-rf-reference-guide.html)
- [Intel: USB 3.0 radio-frequency interference impact on 2.4 GHz devices](https://www.intel.com/content/www/us/en/content-details/841692/usb-3-0-radio-frequency-interference-impact-on-2-4-ghz-wireless-devices-white-paper.html)
