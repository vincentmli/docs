#!/bin/bash


#start k8s master
#hack/cluster-master.sh -O -m 10.169.72.93

#create kubeconfig for worker node
#hack/kubeconfig.sh -m 10.169.72.93 -w 10.169.72.98

#worker node
#hack/cluster-worker.sh -m 10.169.72.93 -w 10.169.72.98 -O

#deploy kube-flannel daemonset
cluster/kubectl.sh apply -f kube-flannel.yml -n kube-system

#create fake bigip node
cluster/kubectl.sh apply -f f5-kctlr-bigip-node-10.169.72.34.yaml
#cluster/kubectl.sh apply -f f5-kctlr-bigip-node-vcmp-10.169.72.189.yaml

#create k8s secret for bigip login
cluster/kubectl.sh create secret generic bigip-login -n kube-system --from-literal=username=admin --from-literal=password=admin

#create bigip cc k8s service account
cluster/kubectl.sh apply -f f5-k8s-bigip-ctrl-cluster-serviceaccount.yaml -n kube-system

#deploy bigip cc
cluster/kubectl.sh apply  -f f5-k8s-bigip-ctrl-cluster-bigip-10.3.72.34.yaml -n kube-system
#cluster/kubectl.sh apply  -f f5-k8s-bigip-ctrl-cluster-bigip-vcmp-10.169.72.189.yaml -n kube-system

#create k8s nginx pod/service
cluster/kubectl.sh apply -f nginx_pod_cluster_service.yaml

#deploy config map
cluster/kubectl.sh apply -f f5-resource-vs-example.configmap-10.169.72.34.yaml
#cluster/kubectl.sh apply -f f5-ingress.yaml

#test vip on bigip
#curl http://10.169.72.136

