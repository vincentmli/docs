#!/bin/bash

BIG-IP:

# 1. Create a VXLAN tunnel profile 
tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type none

# 2. Create Cilium VXLAN tunnel, note VNI key 68, you should not use key 1 or key 2 as it 
# is reserved by Cilium
tmsh create net tunnels tunnel flannel_vxlan key 68 profile fl-vxlan local-address 10.169.72.15

# 3. Create the VXLAN tunnel self-IP, allow default service, allow none stops self ip ping.
#    also make sure selfip subnet is /16, if /24, it may lead to unresolved pod ARP
tmsh create net self 10.0.88.15 address 10.0.88.15/255.255.0.0 allow-service default vlan flannel_vxlan

# 4. Create partition "k8s" on BIG-IP
tmsh create auth partition k8s

# 5. save config on BIG-IP
tmsh save sys config

Cilium:

# 1 kubeadm to init k8s without kube-proxy

#I have two network interfaces and two IP address, only 10.3 could reach to internet behand proxy
# if you in same situation, choose  which address for k8s api  and 
# which ip address for k8s node ip

# for ubuntu to specify node-ip in /etc/default/kubelet
# KUBELET_EXTRA_ARGS=--node-ip=10.169.72.9
# also running into problem with ubuntu when k8s apiserver ip not same as node ip
# had to re-run kubeadm init with --apiserver-advertise-address=10.169.72.9 
# so node ip and apiserer ip to be same as workaround
# kubectl logs -n kube-system  cilium-d4zqh  -f
#Error from server: Get "https://10.169.72.9:10250/containerLogs/kube-system/cilium-d4zqh/cilium-agent?follow=true": Service Unavailable


# for centos 8 cat /etc/sysconfig/kubelet
# KUBELET_EXTRA_ARGS=--node-ip=10.169.72.9

kubeadm init --v=5 --apiserver-advertise-address=10.3.72.9 --skip-phases=addon/kube-proxy

# 2. deploy cilium (image vli39/cilium:bigip), 
#    change following to match your network interface configured with
#    node ip 10.169.72.9 and k8s api server ip address setting
#    change the "devices" and KUBERNETES_SERVICE_HOST to match your lab

#    devices: "ens192"
#    - name: KUBERNETES_SERVICE_HOST
#         value: "10.3.72.9"
#

#    kubectl exec -it  <cilium agent pod> -n kube-system -- cilium status  if cilium get ready

kubectl apply -f cilium-bigip.yaml


# 3 update cilium tunnel map with bpftool for BIG-IP VXLAN tunnel subnet, VNI, VtepMAC
#   type in as the argument requires

./tunnel.sh -a add

# 4. deploy F5 hello world container, service, as3 configmap 

kubectl apply -f f5-hello-world-deployment.yaml
kubectl apply -f f5-hello-world-service.yaml
kubectl apply -f f5-hello-world-http-as3-configmap.yaml

# 5 deploy CIS (image: vli39/k8s-bigip-ctlr:vtep) 

#create BIGIP login secret first
# secret seems not needed if password specified directly in CIS deployment yaml
#kubectl create secret generic bigip-login --namespace kube-system --from-literal=username=admin --from-literal=password=admin

#deploy rbac

kubectl apply -f rbac.yaml

#deploy CIS

kubectl apply -f cis-cilium.yaml

#now the pod ARP and Cilium node FDB entry should automatically be populated in BIG-IP


