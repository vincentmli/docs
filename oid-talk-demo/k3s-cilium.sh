#!/bin/bash

echo "Install k3s"
echo "curl -sfL https://get.k3s.io | INSTALL_K3S_SYMLINK=force INSTALL_K3S_VERSION='v1.24.1+k3s1' INSTALL_K3S_EXEC='--flannel-backend=none --node-ip=10.169.72.9 --node-external-ip=10.3.72.9 --disable=traefik --disable-network-policy --kube-apiserver-arg=kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname' sh -"

echo "only need --kube-apiserver-arg if VM behind company proxy server"
echo "only need --node-external-ip if VM has internal,external IP"
echo 

#curl -sfL https://get.k3s.io | INSTALL_K3S_SYMLINK=force INSTALL_K3S_VERSION='v1.24.1+k3s1' INSTALL_K3S_EXEC='--flannel-backend=none --node-ip=10.169.72.9 --node-external-ip=10.3.72.9 --disable=traefik --disable-network-policy --disable-kube-proxy --kube-apiserver-arg=kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname' sh -
curl -sfL https://get.k3s.io | INSTALL_K3S_SYMLINK=force INSTALL_K3S_VERSION='v1.24.1+k3s1' INSTALL_K3S_EXEC='--flannel-backend=none --node-ip=10.169.72.9 --node-external-ip=10.3.72.9 --disable=traefik --disable-network-policy --disable-kube-proxy -kube-apiserver-arg=kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname' sh -

echo
echo "Install cilium, Cilium cli https://github.com/cilium/cilium-cli/releases/tag/v0.11.7 is required"
echo "cilium install --version=v1.12.0-rc2 --kube-proxy-replacement strict --helm-set-string=k8sServiceHost=10.3.72.9,k8sServicePort=6443,l7Proxy=false,vtep.enabled=true,vtep.endpoint="10.169.72.14 10.169.72.15",vtep.cidr="10.1.14.0/24 10.1.15.0/24",vtep.mac="52:54:00:3e:3f:c1 52:54:00:4e:01:a6",vtep.mask="255.255.255.0" "
echo

#k3s agent node install

#curl -sfL https://get.k3s.io | K3S_URL='https://10.3.72.9:6443' INSTALL_K3S_SYMLINK=force INSTALL_K3S_VERSION='v1.24.1+k3s1' INSTALL_K3S_EXEC='--node-ip=10.169.72.19 --node-external-ip=10.3.72.19' K3S_TOKEN="K1047760bfa51d578138b55562fbb51a3b737a28be2f8f0269a58971ae8775e6723::server:f551e7cfa93f07d2947dd2e0e18ee2a7" sh -



cilium install --version=v1.12.0-rc3 --kube-proxy-replacement strict --helm-set-string=k8sServiceHost=10.3.72.9,k8sServicePort=6443,vtep.enabled=true,vtep.endpoint="10.169.72.14 10.169.72.15",vtep.cidr="10.1.14.0/24 10.1.15.0/24",vtep.mac="52:54:00:3e:3f:c1 52:54:00:4e:01:a6",vtep.mask="255.255.255.0"

sleep 10 

echo 
echo "Deploy CIS and App"

kubectl apply -f rbac-cis-2.5.yaml

kubectl create secret generic bigip-login --namespace kube-system --from-literal=username=admin --from-literal=password=testenv12

kubectl apply -f cis-14.yaml

kubectl apply -f f5-deployment.yaml

kubectl apply -f f5-service.yaml

kubectl apply -f f5-configmap-168.yaml

