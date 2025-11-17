# TracerPid Hider Kernel Module

## Introduction

This is a basic kernel module for Linux 6.x that hooks the `proc_pid_status` function to hide the TracerPid in `/proc/*/status` files by setting it to 0 for a specific PID.
Really this is just an excuse for me to both:
* Learn C
* Learn how to write basic kernel modules
* Explore how an attacker may use anti-debugging methods

## Building

Run `make` in this directory. Requires kernel headers to be installed.

## Installation

As root: `insmod tracerhid.ko target_pid=1234` (replace 1234 with the desired PID, or do not specify to disable by default)

To change the PID without unloading: `echo 5678 > /sys/module/tracerhid/parameters/target_pid`

To disable: `echo 0 > /sys/module/tracerhid/parameters/target_pid`

## Removal

As root: `rmmod tracerhid`

## How it works

Uses kprobes to hook the `proc_pid_status` function and temporarily sets `task->ptrace` to 0 for the specified PID, causing TracerPid to be reported as 0 only for that process.

## Warning

Yes, an attacker could absolutely utilize this for anti-debugging protection, but there are many other ways to detect debugging that this does not address. This is just a simple example of kernel module development and function hooking.