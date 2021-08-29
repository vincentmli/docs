#!/bin/bash

helpFunction()
{
   echo ""
   echo "Usage: $0 
         -n <k3s node ip>
         -s <BIGIP tunnel subnet>
         -i <BIGIP vlan selfip>
         -m <BIGIP flannel_vxlan mac>
         -v <BIGIP tunnel vni>
	 "
   exit 1 # Exit script after printing help
}

if [ $# -le 6  ]; then
     helpFunction
    exit 1
fi


while getopts n:s:i:m:v:h flag
do
    case "${flag}" in
        n) nodeip=${OPTARG};;
        s) subnet=${OPTARG};;
        i) selfip=${OPTARG};;
        m) mac=${OPTARG};;
        v) vni=${OPTARG};;
        h) helpFunction ;; # Print helpFunction in case parameter is non-existent
    esac
done
echo "K3S Node IP: $nodeip";
echo "BIGIP tunnel SUBNET: $subnet";
echo "BIGIP vlan SELFIP: $selfip";
echo "BIGIP flannel_vxlan MAC: $mac";
echo "BIGIP flannel_vxlan VNI: $vni";

interface=$(ip addr show  | grep $nodeip | awk '{print $7;}')

echo "Interface: $interface";

#install k3s
curl -sfL https://get.k3s.io | sh -s - --disable=traefik --no-flannel --node-ip=$nodeip

#check if k3s.service is active
echo "wait for k3s up..."

systemctl start k3s

sleep 5 

systemctl is-active k3s.service

if [ $? -eq 0 ]
then
  echo "k3s successfully started"
else
  echo "Could not start k3s" >&2
  exit;
fi

# set cilium device and K3S API server IP
sed "s/devices: .*/devices: \"$interface\"/; s/K3S-HOST/$nodeip/g" cilium-bigip.yaml > cilium-bigip-$nodeip.yaml

#deploy cilium
echo "==============="
echo "deploy cilium"
echo "==============="
kubectl apply -f cilium-bigip-$nodeip.yaml

ok=0

until [ $ok -eq 1 ]
do
    sleep 5

    for node in $(kubectl  get no  | awk '{print $1;}' | grep -v 'NAME')

    do
        CA=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$node -o jsonpath='{.items[0].metadata.name}')
    	kubectl exec -it $CA -n kube-system -- cilium status
        if [ $? -eq 0 ]
        then
	  ok=1
          echo "cilium agent is up" >&2
          #configure cilium vxlan to BIGIP tunnel 
          #tunnel encrypt key
          key=0
          kubectl exec -it $CA -n kube-system -- cilium bpf tunnel update  $subnet \
                         $selfip $mac $vni $key
          kubectl exec -it $CA -n kube-system -- cilium bpf tunnel list
        else
          echo "Wait for cilium agent to be up" >&2
	  ok=0
        fi


    done

done

#deploy CIS
echo "==============="
echo "deploy CIS"
echo "==============="

kubectl apply -f rbac.yaml

kubectl apply -f cis.yaml

#deploy app and configmap

kubectl apply -f f5-hello-world-deployment.yaml
kubectl apply -f f5-hello-world-service.yaml
kubectl apply -f f5-hello-world-http-as3-configmap.yaml

kubectl get po -o wide -A 

