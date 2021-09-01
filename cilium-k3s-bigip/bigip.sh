#!/bin/bash

#BIG-IP:

# 1. Create a VXLAN tunnel profile
tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type multipoint

# 2. Create Cilium VXLAN tunnel, recommend to use key 2
tmsh create net tunnels tunnel flannel_vxlan key 2 profile fl-vxlan local-address 10.169.72.34

# 3. Create the VXLAN tunnel self-IP, allow default service, allow none stops self ip ping.
#    also make sure selfip subnet is /16, if /24, it may lead to unresolved pod ARP
tmsh create net self 10.0.88.34 address 10.0.88.34/255.255.0.0 allow-service default vlan flannel_vxlan

# 4. Create partition "k8s" on BIG-IP
tmsh create auth partition k8s

# 5. save config on BIG-IP
tmsh save sys config

