#!/usr/bin/env python3

import sys
import dbus
import dbus.mainloop.glib
from gi.repository import GLib

DBUS_INTERFACE = "com.example.bpfskeld1"

def process_exec_event(pid, uid, euid, gid, egid, interp, filename, argc, args, envc, env):
    print(f"ProcessExecEvent {filename} {argc} {args}")

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    bus = dbus.SystemBus()
    bus.add_signal_receiver(process_exec_event, dbus_interface=DBUS_INTERFACE, signal_name="ProcessExecEvent")

    GLib.MainLoop().run()

if __name__ == '__main__':
    main()
