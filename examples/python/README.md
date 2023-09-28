

# UDP Server (Python)

This is a simple example of UDP server written by Python uses a [C extension](https://docs.python.org/3/extending/extending.html#a-simple-example) to make system call. Note that it only works with python3.

> Do not use this UDP server in the production environment.

## Build

Before build the C extension, we should prepare the `Python.h` header.

For Ubuntu, we could install as follows:

```
sudo apt install python3.8-dev
```

Then build it:

```
cd uoa_module
make
```

## Run

Start the UDP server and listen on port 8082:

```shell
python3 udp_serv.py 8082
```

When receiving a packet from the specified load balancer, the UDP server prints the real source address of the packet.

```
UDP server listening on 0.0.0.0:8082
UDP server listening on :::8082
Receive 11 bytes from 10.0.1.3:20000 -- Hello, UOA!
  real client 192.168.1.3:23333
Receive 11 bytes from 10.0.1.3:20000 -- Hello, UOA!
  real client 192.168.1.3:23333
Receive 11 bytes from 10.0.1.3:20000 -- Hello, UOA!
  real client 192.168.1.3:23333
Receive 11 bytes from 10.0.1.3:20000 -- Hello, UOA!
  real client 192.168.1.3:23333
```
