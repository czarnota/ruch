![ruch logo](logo.svg?raw=true)

<p align="center">
  <code>ruch</code> is small, simple and yet effective traffic generator</br>
</p>

# Building

## Quick and fast with gcc

`ruch` has no dependencies and it is a single .c file.
You can simply build it using gcc
```
$ gcc ruch.c -o ruch
```

## CMake

You can also build it using [cmake](https://cmake.org).

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

Send 1000 UDP frames at 1mbit/s speed from `10.0.0.1:1234` to `10.0.0.2:4321` through `eth0_0` device
```
$ ruch eth type ip ip s 10.0.0.1 d 10.0.0.2 proto udp udp s 1234 d 4321 len 1000 dev eth0_0 rate 1073741824 count 1000
ruch: Ruch - simple, yet effective traffic generator
ruch: Version 0.1.0
ruch: Copyright (C) 2020 by P. Czarnota <p@czarnota.io>
ruch: Licensed under GNU GPL version 2
ruch: inf: generator initialized
ruch: inf: sending 1000 frames (1000000 bytes)...
ruch: inf: achieved data rate of 0.999985 Mbps
```

## Available options
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
