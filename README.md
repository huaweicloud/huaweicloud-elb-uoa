

# UDP Option Address

The UDP Option Address (UOA) is a kernel module used to obtain the real source IP/port from the packets sent by load balancer. It is designed to transparently transmit source addresses in UDP load balancing scenarios.

The following UDP load balancing scenarios are supported:

- IPv4
- IPv6
- NAT46 & NAT64

## How to use

### Requirement

The requirements for compiling the kernel module consists of:

- GNU Compiler Collection
- GNU Make tool
- Kernel Headers

For Ubuntu, we could install the requirements as follows:

```shell
sudo apt-get install gcc
sudo apt-get install make
sudo apt-get install linux-headers-$(uname -r)
```

### Build & Install

Download the released source code then compile it:

```shell
cd src
make
```

Load the UOA kernel model:

```shell
sudo insmod uoa.ko
```

### Obtain the real source IP/port

In backend server, we could call `getsockopt()` to obtain the real source IP/port.

We have provided examples of backend servers written by several languages. Lookup the `examples` directory in source code for details.

## How does it work

**Step 1: Load Balancer inserts the real source IP/port information into the packet**

When the packet passed by, the specific load balancer will insert real source IP/port information into the packet by agreed format:

- For IPv4 packet, real source IP/port information will be inserted as a IPv4 Option
- For IPv6 packet, real source IP/port information will be inserted as a IPv6 Destination Extension Header Option

Both IPv4 and IPv6 Option Type are `0x1f` which has not been used by RFC.

Both IPv4 and IPv6 Option formats comply with RFC specifications which are as follows:

```
IPv4 Option: RFC7126

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
|  option-type  | option-length |  option-data
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

option-type      0x1f
option-length    8 (total length of option)
option-data      sport (2 Byte) + sip (4/16 Byte)



IPv6 Destination Extension Header Option: RFC2460

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |  Hdr Ext Len  |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
.                                                               .
.                            Options                            .
.                                                               .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
|  Option Type  |  Opt Data Len |  Option Data
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

Next Header      17 (UDP)
Hdr Ext Len      2
Option Type      0x1f
Opt Data Len     18 (length of option data)
Option Data      sport (2 Byte) + sip (4/16 Byte)
```

**Step 2: UOA parses the packet to obtain the real source IP/port information and stores in kernel cache**

**Step 3: Backend server makes a system call to obtion the real source IP/port from kernel cache**

When the UOA kernel module is inserted, it registers the `getsockopt()` system call, which is used to get the specific real source IP/port information stored in kernel cache.

## License

UOA is a kernel module based on [DPVS](https://github.com/iqiyi/dpvs/tree/master/kmod/uoa) to meet the requirements of cloud services.

UOA is [GNU General Public License, version 2 (GPLv2)](https://www.gnu.org/licenses/gpl-2.0.html) licensed.
