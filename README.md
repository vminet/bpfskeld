bpfskeld
========

bpfskeld is a template for starting a new BPF daemon. It comes with

* Build system for BPF CO-RE program
* Boilerplate for a minimal systemd daemon
* Exposing BPF derived metrics over D-BUS
* Example scripts that fetch those metrics


Building
========
To build bpfskeld, run the following commands:
```bash
$ meson setup build && cd build
$ meson compile
```
