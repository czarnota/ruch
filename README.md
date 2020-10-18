![ruch logo](logo.svg?raw=true)

<p align="center">
  <code>ruch</code> is small, simple and yet effective traffic generator</br>
    <b>and it's also awesome</b>
</p>

# Building

```console
$ mkdir -p build
$ cd build
$ cmake .. && cmake --build .
```

The executable will be available at

```console
$ build/ruch
```

# Usage

```console
$ ruch
ruch - simple, yet effective traffic generator
Version 0.1.0
Copyright (C) 2020 by P. Czarnota <p@czarnota.io>
Licensed under GNU GPL version 3

Usage:

    ruch COMMANDS

COMMANDS is one of:

    eth        inserts Ethernet II header
    vlan       inserts VLAN header
    ip         inserts IP header
    udp        inserts UDP header
    zeros      inserts specified number of zeros
    len        inserts zeros to reach specific frame length
    timestamp  inserts a current timestamp
    str        inserts NULL terminated string into the frame
    dev        send frames through device
    count      limit number of packets that the generator will send in total
    send       
    rate       send packets at specified rate
    burst      specifies how many packets generator will be sending at once
    times      repeats the current frame definition N times
    forever    generate traffic until ruch is terminated

```

# License

`ruch` is licensed under GPL. See [LICENSE](LICENSE)
for details.
