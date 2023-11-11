hid-minikb-libusb
=================

There are 3 key + rotary encoder knob macro pad / mini keyboards that are commonly available on sites like AliExpress and Ebay.  They show up in `lsusb` with USB id of `1189:8890`, use a WCH CH552G chip inside, and have a layered acrylic construction.  However, the Windows software supplied by the people selling these things is invariably awful - Windows only, has viruses reported on VirusTotal, many slightly differing versions, language barriers, doesn't support all possible USB HID HUT keycodes, etc etc.  This is a shame because the devices themselves are reasonably good.

![Keyboard](https://raw.githubusercontent.com/eccherda/ch552g_mini_keyboard/26b75c0c1a6dd054dadb68924cc616cfd2ed6ee2/img/keyboard.jpeg)

I went to the effort of sniffing the USB traffic (with [busdog](https://github.com/djpnewton/busdog)) while using the programming software in a Windows VM, and then writing a basic `libusb` program to send the same data patterns.  This solved my immediate need to have the mini keyboard send F13-F18, which weren't available in the Windows software, but are distinct from all other keys used on my system, so I can freely and easily bind them in software.  I tried using many incantations of `hidraw` to send the data, but could never get it to work, so switched to `libusb` instead.  I haven't bothered trying to sniff multi-key-sequence setting (and probably never will).

To use, customise the button-setting code at the end of `main()` to set the buttons to keys of your taste, then recompile (`make`) and run with elevated privileges (`sudo ./hid-minikb-libusb`).  Make sure you have a C devel environment and the libusb dev package installed on your system (eg. `sudo apt-get install build-essential libusb-1.0-0-dev` on Ubuntu/Debian).

The stock firmware isn't that great, eg. it doesn't make much good use of the LEDs.  [ch552g_mini_keyboard](https://github.com/eccherda/ch552g_mini_keyboard) looks like a much better alternative firmware, and regardless has great info about the build of these devices.  Everything else I found seems to be for custom/homebrew macropads that, while they use the CH55X, are similar-but-different (eg. different pinouts) to these mass produced things.
