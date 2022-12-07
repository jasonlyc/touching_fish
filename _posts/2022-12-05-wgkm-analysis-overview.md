---
title: WireGuard Kernel Module Analysis - Overview
author: Yuchen Liu
date: 2022-12-05
layout: post
---

#### Preface

WireGuard is designed as a general purpose VPN for running on embedded interfaces and super computers alike, fit for many different circumstances. Initially released for the Linux kernel, it is now cross-platform (Windows, macOS, BSD, iOS, Android) and widely deployable.
The source code of WireGuard's Linux kernel module consists of no more than 5,000 lines of code. So it is a very good example for learning Linux kernel and network stack.

This series will consist of the following chapters:
* Interface Initialization
* Peers Initialization
* Data Reception
* Data Transmission

The source code analysis is based on wireguard-linux-compat[<sup>1</sup>](#refer-anchor-1) repository, which is a backport of WireGuard for kernels 3.10 to 5.5, as an out of tree module.

#### Interface Initialization
The entry point of the WireGuard kernel module is in main.c. The device initialization code is mainly in device.c. It initializes the `struct net_device` by implementing different hook functions in Netlink-based configuration API (`struct rtnl_link_ops`). It also utilizes the Generic Netlink protocol (struct genl_ops) to
register customized messages that will be used in userspace `wg` program. A UDP socket is created when the kernel module is loaded.

#### Peers Initialization
The peers initialization code is mainly in peer.c. It initializes all kinds of attributes in `struct wg_peer`. Specifically, I will focus on receive/trasmit queue of each peer, as well as the `struct napi_struct` of each peer, both of which will be used in data reception and transmission.

#### Data Reception
The data reception code is mainly in receive.c and peer.c. Workqueue is used to process the encrypted datagrams in an asynchronous way. I will dig into more details of `struct sk_buff` pointers manipulation, NAPI-based implementation in WireGuard, and how the decrypted packet is fed into the network layer. I will not dig into the cryptography that is used in encryption/decryption in this series though.


#### Data Transmission
The data transmission code is mainly in send.c. Similar to data reception, workqueue is used to encrypt packets in an asynchronous way. Since WireGuard device driver has flags indicating to the kernel that it supports generic segmentation offload (GSO), scatter gather I/O, and hardware checksum offloading, the kernel will hand packets that are over the MTU size to WireGuard. We will see how skb segmentations are implemented in kernel module code.


#### References
<div id="refer-anchor-1"></div>
- [1] [wireguard-linux-compat](https://github.com/WireGuard/wireguard-linux-compat)
