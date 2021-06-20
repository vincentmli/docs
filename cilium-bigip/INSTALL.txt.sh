#!/bin/bash

BIG-IP:

# 1. Create a VXLAN tunnel profile 
tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type none

# 2. Create Cilium VXLAN tunnel, note VNI key 68, you should not use key 1 or key 2 as it 
# is reserved by Cilium
tmsh create net tunnels tunnel flannel_vxlan key 68 profile fl-vxlan local-address 10.169.72.34 

# 3. Create the VXLAN tunnel self-IP, allow default service, allow none stops self ip ping.
tmsh create net self 10.0.3.34 address 10.0.3.34/255.255.255.0 allow-service default vlan flannel_vxlan

# 4. Create partition "k8s" on BIG-IP
tmsh create auth partition k8s

Cilium:

# 1 kubeadm to init k8s without kube-proxy

#I have two network interfaces and two IP address, only 10.3 could reach to internet behand proxy
# if you in same situation, choose  which address for k8s api  and 
# which ip address for k8s node ip

# for ubuntu to specify node-ip in /etc/default/kubelet
# KUBELET_EXTRA_ARGS=--node-ip=10.169.72.128
# also running into problem with ubuntu when k8s apiserver ip not same as node ip
# had to re-run kubeadm init with --apiserver-advertise-address=10.169.72.128 
# so node ip and apiserer ip to be same as workaround
# kubectl logs -n kube-system  cilium-d4zqh  -f
#Error from server: Get "https://10.169.72.9:10250/containerLogs/kube-system/cilium-d4zqh/cilium-agent?follow=true": Service Unavailable


# for centos 8 cat /etc/sysconfig/kubelet
# KUBELET_EXTRA_ARGS=--node-ip=10.169.72.128

kubeadm init --v=5 --apiserver-advertise-address=10.3.72.239 --skip-phases=addon/kube-proxy

# 2. deploy cilium (image vli39/cilium:bigip), 
#    change following to match your network interface configured with
#    node ip 10.169.72.128 and k8s api server ip address setting

#    devices: "ens192"
#    - name: KUBERNETES_SERVICE_HOST
#         value: "10.3.72.239"
#

#    kubectl logs <cilium pod> -n kube-system -f and see if cilium get ready, change the "devices" 

kubectl apply -f cilium-bigip.yaml


# 3 update cilium tunnel map with bpftool for BIG-IP VXLAN tunnel subnet, VNI, VtepMAC
#   type in as the argument requires

./tunnel.sh -a add

# 4. deploy cluster service nginxservice and ngnix pod

kubectl apply -f nginx_pod_cluster_service.yaml

# 5 deploy CIS (image: vli39/k8s-bigip-ctlr:cilium) 

#create BIGIP login secret first

kubectl create secret generic bigip-login --namespace kube-system --from-literal=username=admin --from-literal=password=admin

#deploy rbac

kubectl apply -f rbac.yaml

#deploy CIS

kubectl apply -f cis-cilium.yaml

# 6 deploy simple ingress

kubectl apply -f f5-ingress.yaml

