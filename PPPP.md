The PPPP Protocol
===

The PPPP protocol is a family of related, proprietary and non-documented P2P
protocols used by various IoT devices, typically cheap Chinese IP cameras. The
PPPP name is not an official name, but it is a tag that has been seen in the
disassembly of some of the libraries, and I will use it as the generic name for
this family of protocols. Other namnes include "CS2 Network" and "Yunni
iLnkP2P". A closely related protocol is "Kalay" from TroughTek (TUTK).

The official app accompanying these devices typically uses a native library
such as `libobject_jni.so` or `libvstc2_jni.so`, with bindings from Java in the
package `object.p2pipcam.nativecaller` or `vstc2.nativecaller`.

### ⚠️ Caution -- security concerns

These devices have a reputation for being insecure, and have been plagued by
security holes in the past. (See https://hacked.camera/ for more information.)
It is also highly likely that they will try to send data (such as the video
stream) to untrusted 3rd parties on the internet, due to the nature of the P2P
protocol, or that the network will try to use your device to proxy such private
data of other users.

If you own such a device and want to interoperate with it locally on your
network, I **strongly** recommend that you block UDP port 32100 for outgoing
packets in your firewall. The protocol mandates that connection to the P2P
directory servers happen on UDP port 32100, so by blocking that port, you will
ensure that your device is not registering with any outside party.

As an alternative, or complement, you can assign a fixed IP address to the
device, and block all outgoing traffic from that address. Note that this might
affect some functionality, like mobile push notifications.

### Terminology

In this document, I will use **device** for the IoT device (typically, a
camera) and **controller** for the other end. In the proprietary solution, this
is a mobile phone app.

## Device Unique Identifier (UID or DID)

Each device has a unique descriptor (UID, somtimes called DID) which serves to
identify it on the P2P network, or when communicating locally with it.

The UID consists of three parts: a prefix, a serial, and a check value. The
prefix and check value are string values, and the serial is an integer value.

In the protocol, the prefix and check values seem to allow up to 7 bytes long
strings, but in practice both prefix and check are made up of uppercase ASCII
letters (A-Z). The prefix has been observed to be between 3 and 7 letters,
where a length of 3 or 4 is by far the most common. The check has only been
observed with a length of 5. The check is calculated by a proprietary algorithm
from the prefix and the serial, and it is verified by the P2P servers when
trying to gain access to a device behind a firewall. This document will not
further disucss the check value, but it is assumed that the entire UID will be
known.

The UID is presented to the user as e.g. ABCD-012345-XYZUV, or sometimes
without the hyphen.

Every prefix is associated with a specific manufacturer. A single manufacturer
can apparently "own" several prefixes, maybe due to different models, or due to
fear of exhaustion of the serial range.

## Pre-shared Key

For some devices, the protocol is "encrypted" using a trivial XOR scheme. This
is based on a 256 byte long table, which is shared by all implementation of the
PPPP protocol, and a seed, which is calculated from a manufacturer-specific
pre-shared key (PSK).

When interacting with the larger P2P network and servers, the PSK is always
"SSD@cs2-network.". When communicating locally with the device, a different PSK
is used, that is determined by the prefix of the UID. The following list of
known prefixes and PSKs have been extracted from a decompiled Android app.

Prefixes | PSK
---|---
`AES`, `ASH`, `BRTC`, `BRTD`, `CTW`, `ESN`, `EST`, `GBE`, `HWAA`, `ICB`, `IKB`, `JWEV`, `KBC`, `LAM`, `MATE`, `MEYE`, `MIL`, `OBJ`, `OEMAAAA`, `OEMAAAB`, `OPCS`, `PPCN`, `PPCS`, `PROCAM`, `RTOS`, `SPCN`, `TSD`, `VSTB`, `VSTC`, `WXH`, `WXO`, `XHA`, `XLT`, `ZSKJ` | *no encryption used*
`DGB`, `DGHA`, `DGHG`, `DGKA`, `DGKB`, `DGKC`, `DGOA`, `DGOB`, `DGOC`, `DGOD`, `DGOE`, `DGOF`, `DGOG`, `DGOH`, `DGOI`, `DGOJ`, `DGOK`, `NMSA`, `NMSB`, `NMSZ`, `PETA`, `PETAA` | "camera"
`AAA`, `ABC`, `DDD`, `EEE`, `FFF`, `HBW`, `NNN`, `PIXA`, `PIXB`, `PIXC`, `PIXD`, `XIAODOU` | "SHIX"
`ACCQ`, `ACCR`, `ACCS`, `BCCQ` | "@@@@...."
`VMA`, `VMP`, `VMS`, `VMV` | "VMSV"
`FYIOT`, `FYPPCS`, `FYRTOS` | "FERRY@88"
`PPIL`, `PPLL`, `PPSL` | "mycamera"
`LIUX`, `PIR`, `TUT` | "Deng123abc"
`DUNIOTA`, `NANOIOT` | "Duncom"
`AYS`, `XYX` | "JX20130716"
`THPC` | "hyWHzyhtzH"
`JYDGZ` | "JYDGAOZHANP2P"
`XGAK` | "SZGMBESTER"

## Device discovery

To discover PPPP devices on the local network, the controller broadcasts a
`MSG_LAN_SEARCH` packet on UDP port **32108**.

The device, upon receiving this packet, will send `MSG_PUNCH_PKT`. The
controller will reply back with another `MSG_PUNCH_PKT`. At this point, the
communication channel is open, and the controller and device will communicate
back to each other on the UDP port and IP address that the respective punch
packet was sent from.

The next step in the initialization process is that the device sends a
`MSG_P2P_RDY` message. This contains the UID of the device. At this point, the
controller can determine if this is the device it wants to communicate, and if
it knows the security credentials. If so, it can start sending commands on
channel 0.

## Video and audio streams

The device can send and/or receive data streams using the `MSG_DRW` (data
read/write) packets. The following channels are used:

**channel** | **content**
---|---
1 | video from the device
2 | audio from the device
3 | audio to the device ("talk")

Data are sent in frames. If the payload of the `MSG_DRW` packet would exceed
1024 bytes, it will be split into multiple, consecutive packets. Only the first
packet in that sequence will have the header.

Each frame begins with a 32 byte long header. (Note that this leaves room only
for 992 bytes of data in the frame, if it should fit in a single packet.)

The structure of the frame header is only partially understood. Note that the
purpose of many fields are currently unknown, and that the `codec`/`type` and
`millis` fields are just guesswork. The purpose of the magic bytes is
presumably to help the receiver re-synchronize at the start of a new frame, if
some intermediate packets are lost. The only fields that have always seen being
respected are `magic`, `codec`/`type` and `len`. All other fields can, in
different circumstances, be set to e.g. all zeros or all `0xaa`, or some other
values.

**name** | **size (in bytes)** | **description**
---|---|---
`magic` | 4 | Magic bytes indicating start of a new header (always **0x55aa15a8**)
`codec` | 1 | A byte representing the A/V codec used
`type` | 1 | A byte representing the media type of the frame (**0** = video, **1** = audio)
`millis` | 2 | Presumably a millisecond offset from the timestamp
`timestamp` | 4 | The time in seconds since EPOCH, in little-endian order
`index` | 4 |  The 0-based index of this frame, in little-endian order
`len` | 4 |  The length of the frame data, in little-endian order
`unknown` | 12 | Unknown

The observed values for the codec (if that is indeed what the field represents)
are listed below. The 0xaa value is just assumed, but the 0x08 value is
confirmed.

**value** | **codec**
---|---
0x03 | MJPEG, with one JPEG image per frame
0x08 | Audio, IMA ADPCM DVI/4 (4-bits, 11.025 kHz, 1 channel)
0xaa | Audio, IMA ADPCM DVI/4 (4-bits, 11.025 kHz, 1 channel)

## Channel 0 commands and responses

On channel 0, the controller can send commands to the device, and the device
can reply to those commands. The communication is done by exchanging JSON
objects. As shown by the dissect script, each packet on channel 0 can contain
one or more command blocks. The typical use case is to have one command block
per packet, though.

All command requests and responses must have a minimal set of fields, but may
also contain additional fields. These additional fields are documented below in
the per-command sections.

### Commands

All commands must include the following fields in the JSON object:

**key** | **type**  | **description**
---|---|----
`cmd` | integer | The command number (see the table below)
`pro` | string  | The string representation of the command number
`user` | string  | The user name for authentication
`pwd` | string  | The password for the user, in clear text

For most devices, there is no sofisticated user handling, and the `user` name
is just the fixed value of `admin`.

The value of `cmd` and `pro` are both needed, and must correspond to each
other. This means that one of the fields are actually redundant, but they are
still both needed.

### Responses

All responses sent by the device must include the following fields in the JSON
object:

 **key** | **type**  | **description**
---|---|----
`cmd` | integer | The command number
`result` | integer  | A result code

The command number should be the same as in the command request. (Disturbingly,
some exceptions to this has been observed in the wild, where the device replies
with a different command number than the request.)

The result code signals the success of the command. A value of **0** means
**success**. A value of **-1** means **failure**. (It is possible that other
failure codes exist.)

### check_user (cmd 100)

This is like a login. This is typically the first packet sent in a conversation
between a controller and a device.

**Additional command fields:**

*none*

**Additional response fields:**

**key** | **type**  | **description**
---|---|----
`admin` | integer | Unknown
`restrict` | integer | Unknown
`mode` | integer | Unknown
`type` | integer | Unknown
`checkstr` | string  | Unknown
`cloud_key` | string  | Unknown

The value of these fields are unknown. The currently observed numerical values
are:

**key** | **observed values**
---|---
`admin` | Always 1
`restrict` | Always 0
`mode` | Always 110
`type` | Always 600

The `checkstr` and  `cloud_key` fields are presumably used in validating the
device on the P2P networks. The checkstr has been observed to be "SHIX", and
the cloud key to be a large integer.

In the underlying PPPP packet structure, the special "admin" flag (0x00000100
of the command block flag field) is set to 1 for this particular response (the
only observed instance of this flag being non-zero). It is speculated that this
corresponds to the value of `admin` being 1.

## Resources

* https://hacked.camera/
* https://github.com/pmarrapese/iot/tree/master/p2p/dissector
* https://github.com/fbertone/lib32100/issues/7
* https://github.com/datenstau/A9_PPPP
* https://github.com/K-Francis-H/little-stars-hack
* https://re-ws.pl/2018/05/security-analysis-of-spy-camera-sold-by-chinese-suppliers-iminicam-app/
* https://ppppdecodestring.ericbetts.dev/
* https://github.com/sol-vin/0x42424242.in/tree/master/_posts/vstarcam-journey
* https://github.com/sol-vin/vstarcam-investigational-journey/tree/master
