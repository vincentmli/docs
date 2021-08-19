#!/bin/bash

helpFunction()
{
   echo ""
   echo "Usage: $0 -a add|delete 
	 add or delete BIG-IP tunnel"
   exit 1 # Exit script after printing help
}

if [ $# -eq 0 ]; then
     helpFunction 
    exit 1
fi

while getopts "a:h" opt
do
   case "$opt" in
      a ) argument="$OPTARG" ;;
      * ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done


if  [ $argument == "delete" ] 
then
	echo "Please input BIG-IP flannel_vxlan SUBNET, for example 10.0.99.0/24"
	read -r SUBNET 
fi

if  [ $argument == "add" ] 
then

echo "Please input BIG-IP flannel_vxlan SUBNET, for example 10.0.99.0/24"
read -r SUBNET 

echo "Please input BIG-IP vlan SELF IP, for example 10.169.72.14"
read -r SELFIP 

echo "Please input BIG-IP flannel_vxlan MAC, for example 52:54:00:3e:3f:c1"
read -r MAC 

echo "Please input BIG-IP flannel_vxlan VNI, recommend to use 2"
read -r VNI 

fi

#tunnel encrypt key
KEY=0

for node in $(kubectl  get no  | awk '{print $1;}' | grep -v 'NAME') 

do
    echo "====================================="
    echo "Cilium node $node"
    echo "====================================="

    CA=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$node -o jsonpath='{.items[0].metadata.name}')


	if [ $argument == "add" ]
	then
		echo "kubectl exec -it $CA -n kube-system -- cilium bpf tunnel update $SUBNET $SELFIP $MAC $VNI $KEY"  

		kubectl exec -it $CA -n kube-system -- cilium bpf tunnel update  $SUBNET $SELFIP $MAC $VNI $KEY  
        fi

 	if  [ $argument == "delete" ]
	then
      	    kubectl exec -it $CA -n kube-system -- cilium bpf tunnel delete $SUBNET
	fi


    kubectl exec -it $CA -n kube-system -- cilium bpf tunnel list

done


