#!/usr/bin/env python3

import dbus

DBUS_PATH      = "/com.example/bpfskeld"
DBUS_INTERFACE = "com.example.bpfskeld1"

def main():
    bus = dbus.SystemBus()
    obj = bus.get_object(DBUS_INTERFACE, DBUS_PATH)

    properties = obj.GetAll(DBUS_INTERFACE, dbus_interface="org.freedesktop.DBus.Properties")
    for name, value in properties.items():
        print("{name}: {value}")

if __name__ == '__main__':
    main()
