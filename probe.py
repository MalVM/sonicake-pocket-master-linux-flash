#!/usr/bin/env python3
"""Dump USB interfaces/endpoints. Read-only: claims nothing, sends nothing.

Run it once with the pedal in normal mode and once in flash mode. The delta is
the answer to 'is flash mode USB-MIDI class (01/03) or vendor-specific (ff)?'
  class 01 subclass 03 -> use the ALSA transport, libusb is wrong (snd-usb-audio owns it)
  class ff             -> use the libusb transport
"""
import sys

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("needs pyusb:  pip install --user pyusb")

CLASS = {0x01: "AUDIO", 0x03: "HID", 0x08: "MASS-STORAGE", 0xFF: "VENDOR"}
SUB_AUDIO = {0x01: "AudioControl", 0x02: "AudioStreaming", 0x03: "MIDIStreaming"}


def show(dev):
    try:
        print("\n%04x:%04x  bus %s addr %s  bcdUSB %04x  bDeviceClass %02x"
              % (dev.idVendor, dev.idProduct, dev.bus, dev.address,
                 dev.bcdUSB, dev.bDeviceClass))
        for cfg in dev:
            print("  config %s" % cfg.bConfigurationValue)
            for intf in cfg:
                cn = CLASS.get(intf.bInterfaceClass, hex(intf.bInterfaceClass))
                sub = ""
                if intf.bInterfaceClass == 1:
                    sub = SUB_AUDIO.get(intf.bInterfaceSubClass, "")
                print("    intf %d.%d  class %02x %s %s  subclass %02x  proto %02x"
                      % (intf.bInterfaceNumber, intf.bAlternateSetting,
                         intf.bInterfaceClass, cn, sub,
                         intf.bInterfaceSubClass, intf.bInterfaceProtocol))
                for ep in intf:
                    print("      ep %02x %s %s maxpkt %d interval %d"
                          % (ep.bEndpointAddress,
                             "IN" if ep.bEndpointAddress & 0x80 else "OUT",
                             usb.util.endpoint_type(ep.bmAttributes),
                             ep.wMaxPacketSize, ep.bInterval))
    except usb.core.USBError as e:
        print("  [cannot read descriptors: %s]" % e)


def main(argv):
    want = set(int(x, 0) for x in argv)
    devs = list(usb.core.find(find_all=True))
    if not devs:
        print("no USB devices visible (permissions? try as root once)")
        return 1
    for dev in devs:
        if want and dev.idVendor not in want:
            continue
        show(dev)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
