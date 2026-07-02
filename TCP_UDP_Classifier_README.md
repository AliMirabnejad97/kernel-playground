Markdown

# Linux Kernel Module: TCP vs UDP Traffic Classifier (M2)

## Project Overview
This repository contains the implementation of **M2 — TCP vs UDP Classifier**, developed as a Linux kernel module for the *Software Networks* course. 

The primary objective of this module is to intercept network traffic at the kernel level, inspect the IP layer headers, and accurately differentiate between **TCP** and **UDP** packets. It maintains traffic statistics using internal arrays and triggers real-time system alerts via `printk` when pre-defined traffic thresholds are breached.


## Implemented Features & Scope
This submission delivers the **Basic Level** requirements for the M2 assignment:
*   **Protocol Detection:** Inspects incoming IP packets to identify the transport layer protocol (TCP/UDP).
*   **Traffic Accounting:** Tracks per-port packet counts using efficient array structures.
*   **Threshold Alerting:** Emits kernel space warnings (`printk`) if a port's traffic exceeds the maximum limit.

*Note: Intermediate and Advanced milestones are excluded from this release.*


## Development & Test Environment
To ensure full reproducibility, the module was compiled and validated inside the official `kernel-playground` ecosystem using the following stack:

*   **Infrastructure:** DigitalOcean Droplet (Cloud Instance)
*   **Base OS:** Ubuntu 24.04 LTS x86_64
*   **Containerization:** Podman
*   **Emulation/Testing:** QEMU Virtual Machine
*   **Source File:** `kernel/modules/snf_lkm.c`

## Deep Dive: Implementation Details
The module hooks into the Netfilter framework at the **PRE_ROUTING** stage to inspect packets before they hit the local routing table. 

### Execution Flow:
1. Clone repository
2. Build Podman image
3. Setup environment
4. Run container
5. Build module
6. Run virtual machine
7. Load kernel module
8. Generate TCP traffic
9. Show TCP logs
10. Generate UDP traffic
11. Show UDP logs
12. Show TCP/UDP alerts
13. Remove module


### Expected Log Blueprint:
```text
[M2: TCP vs UDP classifier module registered]
[M2: netfilter hook registered]
[M2: netfilter hook unregistered]
[M2: TCP vs UDP classifier module unregistered]
[M2-basic] Example TCP: M2 TCP packet: src_port=40850 dst_port=443 count=3
[M2-basic] Example UDP: M2 UDP packet: src_port=53229 dst_port=53 count=5
```

> **Need Help?** For a complete step-by-step walkthrough of the activation and verification steps, check out our comprehensive GooGle Docs: https://docs.google.com/document/d/1bbjC1anoXx9RT56BUEnQDHPDRsvZOmrK6IwoE8OxLrc/edit?usp=sharing
