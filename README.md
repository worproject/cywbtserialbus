# Cypress Bluetooth over UART Transport Driver for Windows
This project implements a Bluetooth HCI over UART transport (H4) driver for various Cypress/Broadcom Wi-Fi + BT combo chips.

## Supported hardware
The initialization sequence is virtually the same on all these combo chips, so as long as the proper firmware is provided, the driver should bring-up the device in a fully operational state.

We currently provide firmware/support for the following chips:
* CYW43455 (BCM4345C0.hcd) - extensively tested on a Raspberry Pi 4
* CYW43438 (BCM43430A1.hcd) - tested on a Raspberry Pi 3 model B at a baud rate of 460800 (but unreliable as the RTS/CTS lines are not exposed)

**Note:** since this driver uses the H4 protocol for communication, the UART link must support hardware flow control to prevent packet loss.

## Driver configuration
The registry settings can be found under `HKLM\System\CurrentControlSet\Services\cywbtserialbus\Parameters`:
* `BaudRate` [default=460800] - the UART baud rate for communication between the host and the BT device after firmware download

* `SkipFwDownload` [default=0] - use the existing ROM firmware (with limited functionality)

## Credits
This driver is based on the [serialhcibus sample](https://github.com/microsoft/Windows-driver-samples/tree/master/bluetooth/serialhcibus) provided by Microsoft.

The firmware files come from: https://github.com/RPi-Distro/bluez-firmware/tree/master/broadcom
