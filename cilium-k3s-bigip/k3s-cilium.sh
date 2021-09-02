#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BROWN='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

helpFunction()
{
   echo ""
   echo "Usage: $0 
         -n <k3s node ip>
         -s <BIGIP tunnel subnet>
         -i <BIGIP vlan selfip>
         -m <BIGIP flannel_vxlan interface mac>
         -v <BIGIP tunnel vni>
         -h help 
	 "
   exit 1 # Exit script after printing help
}

if [ $# -eq 0  ]; then
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

echo -e "${BROWN}"
echo "K3S Node IP: $nodeip";
echo "BIGIP tunnel SUBNET: $subnet";
echo "BIGIP vlan SELFIP: $selfip";
echo "BIGIP flannel_vxlan MAC: $mac";
echo "BIGIP flannel_vxlan VNI: $vni";
echo -e "${NC}"

interface=$(ip addr show  | grep $nodeip | awk '{print $7;}')

echo "Interface: $interface";

#STEP 1  - install k3s

export INSTALL_K3S_SYMLINK=force

echo "===================================="
echo -e "${RED}STEP 1 - install k3s${NC}"
echo "===================================="

echo -e "${BLUE}"
curl -sfL https://get.k3s.io | sh -s - --disable=traefik --flannel-backend=none --node-ip=$nodeip
echo -e "${NC}"

#check if k3s.service is active

systemctl start k3s
ok=0
until [ $ok -eq 1 ]
do
    sleep 1 
	echo -e "${BLUE}"
	systemctl is-active k3s.service

        if [ $? -eq 0 ]
        then
	  echo -e "${NC}"
	  ok=1
	  echo -e "${GREEN}"
          echo "K3S  is up" >&2
	  echo -e "${NC}"
        else
          echo -e "${RED}Wait K3S to be up${NC}" >&2
	  ok=0
        fi

done

#STEP 2 - deploy cilium

# set cilium device and K3S API server IP
sed "s/devices: .*/devices: \"$interface\"/; s/K3S-HOST/$nodeip/g" cilium-bigip.yaml > cilium-bigip-$nodeip.yaml

echo "===================================="
echo -e "${RED}STEP 2 - deploy cilium${NC}"
echo "===================================="

kubectl apply -f cilium-bigip-$nodeip.yaml

ok=0

until [ $ok -eq 1 ]
do
    sleep 10 

    for node in $(kubectl  get no  | awk '{print $1;}' | grep -v 'NAME')

    do
        CA=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$node -o jsonpath='{.items[0].metadata.name}')

	echo -e "${BLUE}"
    	kubectl exec -it $CA -n kube-system -- cilium status 2>&1>>/dev/null

        if [ $? -eq 0 ]
        then
	  echo -e "${NC}"
	  ok=1
	  echo -e "${GREEN}"
          echo "cilium agent is up" >&2
          echo " " >&2
	  echo -e "${NC}"
          #configure cilium vxlan to BIGIP tunnel 
          #tunnel encrypt key
          key=0
	  echo -e "${BLUE}"
          kubectl exec -it $CA -n kube-system -- cilium bpf tunnel update  $subnet \
                         $selfip $mac $vni $key
	  echo -e "${NC}"
	  echo -e "${GREEN}"
          kubectl exec -it $CA -n kube-system -- cilium bpf tunnel list
	  echo -e "${NC}"
        else
          echo -e "${RED}Wait for cilium agent to be up${NC}" >&2
	  ok=0
        fi


    done

done

#STEP 3 - deploy CIS

echo "===================================="
echo -e "${RED}STEP 3 - deploy CIS${NC}"
echo "===================================="

kubectl apply -f rbac.yaml
kubectl apply -f cis.yaml
kubectl apply -f f5-hello-world-deployment.yaml
kubectl apply -f f5-hello-world-service.yaml

ok=0
until [ $ok -eq 1 ]
do
    sleep 10 

	echo -e "${BLUE}"
	kubectl  get po -A -l app=cis --field-selector=status.phase=Running | grep 'Running' >/dev/null 2>&1 

        if [ $? -eq 0 ]
        then
	  echo -e "${NC}"
	  ok=1
	  echo -e "${GREEN}"
          echo "CIS  is up" >&2
          echo " " >&2
          echo "Deploy configmap" >&2
          echo " " >&2
	  kubectl apply -f f5-hello-world-http-as3-configmap.yaml
	  echo -e "${NC}"
        else
          echo -e "${RED}Wait CIS to be up${NC}" >&2
	  ok=0
        fi

done

ok=0
until [ $ok -eq 1 ]
do
    sleep 1 

	echo -e "${BLUE}"
	kubectl  get po -A -l app=f5-hello-world --field-selector=status.phase=Running | grep 'Running' >/dev/null 2>&1 

        if [ $? -eq 0 ]
        then
	  echo -e "${NC}"
	  ok=1
	  echo -e "${GREEN}"
          echo "f5-hello-world pod is up" >&2
          echo " " >&2
	  kubectl get po -o wide -A 
	  echo -e "${NC}"
        else
          echo -e "${RED}Wait f5-hello-world to be up${NC}" >&2
	  ok=0
        fi

done

