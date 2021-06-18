#!/bin/bash

for node in $(kubectl  get no  | awk '{print $1;}' | grep -v 'NAME') 

do
    echo "====================================="
    echo $node

    CA=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$node -o jsonpath='{.items[0].metadata.name}')

    tunnelid=$(kubectl  exec -it $CA -n kube-system -- bpftool map list --bpffs | grep -B2 'cilium_tunnel_map' | head -1 | awk '{print $1;}' | cut -d':' -f1) 

    echo $tunnelid

#on bigip do ip link list flannel_vxlan | grep ether | awk '{print $2;}' to get mac
#add BIG-IP 10.0.3.0 vtep ip 10.169.72.34 vni 68 vtep mac 00:50:56:a0:7d:d8

    kubectl exec -it $CA -n kube-system -- bpftool map update id $tunnelid \
	    key hex   0a 00 03 00 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00 \
	    value hex 0a a9 48 22 44 00 00 00  00 50 56 a0 7d d8 00 00 01 00 00 00

    kubectl exec -it $CA -n kube-system -- cilium bpf tunnel list


done


