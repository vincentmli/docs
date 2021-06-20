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
	echo "Please input BIG-IP flannel_vxlan SUBNET, for example 10.0.8.0"
	read -r SUBNET 
fi

if  [ $argument == "add" ] 
then

echo "Please input BIG-IP flannel_vxlan SUBNET, for example 10.0.8.0"
read -r SUBNET 

echo "Please input BIG-IP vlan SELF IP, for example 10.169.72.34"
read -r SELFIP 

echo "Please input BIG-IP flannel_vxlan VNI
  use value less than 65535, the script
  is not smart enough  with value bigger than 65535
                                                "

read -r VNI 

echo "Please input BIG-IP flannel_vxlan MAC, for example 00:50:56:86:6b:28"
read -r MAC 

fi

# Convert values to Hex
HEX_SUBNET=$(printf '%02x ' ${SUBNET//./ })
HEX_SELFIP=$(printf '%02x ' ${SELFIP//./ })
if [ $VNI -le 255 ]; then
	HEX_VNI=$(printf '%02x' ${VNI})
	HEX_VNI="$HEX_VNI 00 00 00"
else [ \($VNI -gt 255 -a $VNI -le 65535 \) ]
	HEX_VNI=$(printf '%02x' ${VNI} | sed 's/.\{2\}/& /g')
	HEX_VNI="$HEX_VNI 00 00"
fi

HEX_MAC=$(echo ${MAC//:/ })


#echo "$HEX_SUBNET"
#echo "$HEX_SELFIP"
echo "$HEX_VNI"
#echo "$HEX_MAC"

KEY=" 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00"


for node in $(kubectl  get no  | awk '{print $1;}' | grep -v 'NAME') 

do
    echo "====================================="
    echo "Cilium node $node"
    echo "====================================="

    CA=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$node -o jsonpath='{.items[0].metadata.name}')

    tunnelid=$(kubectl  exec -it $CA -n kube-system -- bpftool map list --bpffs | grep -B2 'cilium_tunnel_map' | head -1 | awk '{print $1;}' | cut -d':' -f1) 

    echo "cilium tunnel map id: $tunnelid"


	if [ $argument == "add" ]
	then
	    #add BIG-IP $HEX_SUBNET self IP $HEX_SELFIP  vni $SELF_VNI vtep mac $HEX_MAC
    	    kubectl exec -it $CA -n kube-system -- bpftool map update id $tunnelid \
	    key hex   $HEX_SUBNET $KEY \
	    value hex $HEX_SELFIP  $HEX_VNI $HEX_MAC 00 00 01 00 00 00
        fi

 	if  [ $argument == "delete" ]
	then
	    #delete BIG-IP  $HEX_SUBNET 
      	    kubectl exec -it $CA -n kube-system -- bpftool map delete id $tunnelid \
	    key hex   $HEX_SUBNET $KEY
	fi


    kubectl exec -it $CA -n kube-system -- cilium bpf tunnel list

done


