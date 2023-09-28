# UDP Server (C)

This is a simple example of UDP server written by C.

> Do not use this UDP server in the production environment.

## Build

Just use make tool to build it.

```
make
```

## Run

Start the UDP server and listen on port 8082:

```shell
./udp_serv 8082
```

When receiving a packet from the specified load balancer, the UDP server prints the real source address of the packet.

```
UDP server listening on 0.0.0.0:8082
UDP server listening on :::8082
Recv 11 bytes from 10.0.1.3:20000: Hello, UOA! --> RealAddr: 192.168.1.3:23333
Recv 11 bytes from 10.0.1.3:20000: Hello, UOA! --> RealAddr: 192.168.1.3:23333
Recv 11 bytes from 10.0.1.3:20000: Hello, UOA! --> RealAddr: 192.168.1.3:23333
Recv 11 bytes from 10.0.1.3:20000: Hello, UOA! --> RealAddr: 192.168.1.3:23333
```