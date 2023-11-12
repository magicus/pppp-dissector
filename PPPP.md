The PPPP Protocol
===

The PPPP protocol is a family of related, proprietary and non-documented P2P
protocols used by various IoT devices, typically cheap Chinese IP cameras.
The PPPP name is not an official name, but it is a tag that has been seen
in the disassembly of some of the libraries, and I will use it as the generic
name for this family of protocols. Other namnes include "CS2 Network" and
"Yunni iLnkP2P". A closely related protocol is "Kalay" from TroughTek (TUTK).

### Terminology

In this document, I will use **device** for the IoT device (typically, a camera)
and **controller** for the other end. In the proprietary solution, this is a
mobile phone app.

## Device Unique Identifier (UID or DID)

Each device has a unique descriptor (UID, somtimes called DID) which serves to identify it on the P2P network, or when communicating locally with it.

The UID consists of three parts: a prefix, a serial, and a check value. The prefix and check value are string values, and the serial is an integer value.

In the protocol, the prefix and check values seem to allow up to 7 bytes long strings, but in practice both prefix and check are made up of uppercase ASCII letters (A-Z). The prefix has been observed to be between 3 and 7 letters, where a length of 3 or 4 is by far the most common. The check has only been observed with a length of 5. The check is calculated by a proprietary algorithm from the prefix and the serial, and it is verified by the P2P servers when trying to gain access to a device behind a firewall. This document will not further disucss the check value, but it is assumed that the entire UID will be known.

The UID is presented to the user as e.g. ABCD-012345-XYZUV, or sometimes without the hyphen.

Every prefix is associated with a specific manufacturer. A single manufacturer can apparently "own" several prefixes, maybe due to different models, or due to fear of exhaustion of the serial range.

## Pre-shared Key

For some devices, the protocol is "encrypted" using a trivial XOR scheme. This is based on a 256 byte long table, which is shared by all implementation of the PPPP protocol, and a seed, which is calculated from a manufacturer-specific pre-shared key (PSK).

The following list of known prefixes and PSKs have been extracted from a decompiled Android app.

| Prefixes | PSK |
|---|---|
| `AES`, `ASH`, `BRTC`, `BRTD`, `CTW`, `ESN`, `EST`, `GBE`, `HWAA`, `ICB`, `IKB`, `JWEV`, `KBC`, `LAM`, `MATE`, `MEYE`, `MIL`, `OBJ`, `OEMAAAA`, `OEMAAAB`, `OPCS`, `PPCN`, `PPCS`, `PROCAM`, `RTOS`, `SPCN`, `TSD`, `VSTB`, `VSTC`, `WXH`, `WXO`, `XHA`, `XLT`, `ZSKJ` | *no encryption used* |
| `DGB`, `DGHA`, `DGHG`, `DGKA`, `DGKB`, `DGKC`, `DGOA`, `DGOB`, `DGOC`, `DGOD`, `DGOE`, `DGOF`, `DGOG`, `DGOH`, `DGOI`, `DGOJ`, `DGOK`, `NMSA`, `NMSB`, `NMSZ`, `PETA`, `PETAA` | "camera" |
| `AAA`, `ABC`, `DDD`, `EEE`, `FFF`, `HBW`, `NNN`, `PIXA`, `PIXB`, `PIXC`, `PIXD`, `XIAODOU` | "SHIX" |
| `ACCQ`, `ACCR`, `ACCS`, `BCCQ` | "@@@@...." |
| `VMA`, `VMP`, `VMS`, `VMV` | "VMSV" |
| `FYIOT`, `FYPPCS`, `FYRTOS` | "FERRY@88" |
| `PPIL`, `PPLL`, `PPSL` | "mycamera" |
| `LIUX`, `PIR`, `TUT` | "Deng123abc" |
| `DUNIOTA`, `NANOIOT` | "Duncom" |
| `AYS`, `XYX` | "JX20130716" |
| `THPC` | "hyWHzyhtzH" |
| `JYDGZ` | "JYDGAOZHANP2P" |
| `XGAK` | "SZGMBESTER" |

## Channel 0 commands and responses

On channel 0, the controller can send commands to the device, and the device
can reply to those commands. The communication is done by exchanging JSON
objects.

All command requests and responses must have a minimal set of fields, but may also contain additional fields. These additional fields are documented below in the per-command sections.

### Commands

All commands must include the following fields in the JSON object:

| **key** | **type**  | **description**|
|---|---|----|
| `cmd` | integer | The command number (see the table below) |
| `pro` | string  | The string representation of the command number |
| `user` | string  | The user name for authentication |
| `pwd` | string  | The password for the user, in clear text |

For most devices, there is no sofisticated user handling, and the `user` name is just the fixed value of `admin`.

The value of `cmd` and `pro` are both needed, and must correspond to each other. This means that one of the fields are actually redundant, but they are still both needed.

### Responses

All responses sent by the device must include the following fields in the JSON object:

| **key** | **type**  | **description**|
|---|---|----|
| `cmd` | integer | The command number |
| `result` | integer  | A result code |

The command number should be the same as in the command request. (Disturbingly, some exceptions to this has been observed in the wild, where the device replies with a different command number than the request.)

The result code signals the success of the command. A value of **0** means **success**. A value of **-1** means **failure**. (It is possible that other failure codes exist.)

### check_user (cmd 100)

This is like a login. This is typically the first packet sent in a conversation between a controller and a device.

**Additional command fields:**

*none*

**Additional response fields:**

| **key** | **type**  | **description**|
|---|---|----|
| `admin` | integer | Unknown |
| `restrict` | integer | Unknown |
| `mode` | integer | Unknown |
| `type` | integer | Unknown |
| `checkstr` | integer  | Unknown |
| `cloud_key` | integer  | Unknown |

The value of these fields are unknown. The currently observed numerical values are:

| **key** | **observed values** |
|---|---|
| `admin` | Always 1. |
| `restrict` | Always 0. |
| `mode` | Always 110 |
| `type` | Always 600 |

The `checkstr` and  `cloud_key` fields are presumably used in validating the device on the P2P networks. The checkstr has been observed to be "SHIX", and the cloud key to be a large integer.

In the underlying PPPP packet structure, the special "admin" flag (0x00000100 of the command block flag field) is set to 1 for this particular response (the only observed instance of this flag being non-zero). It is speculated that this corresponds to the value of `admin` being 1.

## Resources

https://hacked.camera/
https://github.com/pmarrapese/iot/tree/master/p2p/dissector
