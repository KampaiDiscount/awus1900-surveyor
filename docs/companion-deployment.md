# Companion deployment project

AWUS1900 Surveyor is designed to sit immediately after the `kali-awus1900-deploy` workflow:

```text
kali-awus1900-deploy
        |
        +--> confirms USB 0bda:8813
        +--> selects a working RTL8814AU driver path
        +--> validates interface and monitor capability
                    |
                    v
awus1900-surveyor
        |
        +--> releases only the selected adapter from NetworkManager
        +--> performs passive 2.4/5 GHz nl80211 sweeps
        +--> checkpoints clean RF inventory and evidence files
        +--> restores the original adapter state
```

The surveyor works with the in-kernel `rtw88_8814au` path shown in the tested dashboard and does not require the adapter to remain in monitor mode.

Companion repository:

`https://github.com/KampaiDiscount/kali-awus1900-deploy`
