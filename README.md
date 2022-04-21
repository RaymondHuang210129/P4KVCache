# P4KVCache
BMv2 Code for Purdue CS590 Final Project Demo:

Applying P4 switch as the cache of Key-Value Store

Presentation slides: [link](https://github.com/RaymondHuang210129/P4KVCache/blob/main/demo/presentation_slides.pdf)

## Get Started

This code can be compiled and loaded as a bmv2 application. Testing the code requires bmv2 installation and mininet environment.

### Install Environment

Download the VM image with preinstalled p4c and bmv2 environment from [here](https://github.com/p4lang/tutorials) and boot the VM.

### Config the Test Environment

To change the network topology in mininet, edit the configuration file `./pod-topo/topology.json`.

To modify the match-action rule installed in bmv2 switch when creating the environment (only have one switch in default topology), edit the configuration file `./pod-topo/s1-runtime.json`.

### Test the code

After booting the VM, Move the folders into `~/tutorials/exercises`.

Under `~/tutorials/exercises/<folder name>`, prompt
```sh
make run
```
then `basic.p4` will be compiled and the mininet environment will be set up.

In the mininet CLI, prompt
```sh
xterm h1
xterm h2
```
to open virtual host `h1` and `h2`'s CLI window.

For the host acting as a KVStore server, prompt
```sh
./kVStore.py
```
and the Key-Value Store server will start and print the received packets.

For the host acting as a client, prompt
```sh
./send.py <destination IP> (read|write) <key> <value>
```
to send the packet.

To observe the packet sent and received by client, open the new xterm window and prompt
```sh
tcpdump udp --nnvvXSs 1514
```
to monitor all UDP packet traffics.

### Test Demo

cache:

https://user-images.githubusercontent.com/12983673/163913459-9ea7c7e7-6cd6-421c-95d7-806181cd2aee.mp4

multi_cache:

(will be uploaded)


