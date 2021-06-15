#bigip 10.0.3.0 10.169.72.34
kubectl exec -it $CA2 -n kube-system -- bpftool map update id 225 key hex 0a 00 03 00 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00 value hex 0a a9 48 22 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00
# 10.0.4.0 10.169.72.236
kubectl exec -it $CA2 -n kube-system -- bpftool map update id 89 key hex 0a 00 04 00 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00 value hex 0a a9 48 ec 42 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00
#add mac
#kubectl exec -it $CA2 -n kube-system -- bpftool map update id 83 key hex 0a 00 04 00 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00 value hex 0a a9 48 ec 42 00 00 00  12 88 9f 09 e4 c2 00 00 01 00 00 00
# 10.244.0.0 10.169.72.129
kubectl exec -it $CA2 -n kube-system -- bpftool map update id 89 key hex 0a f4 00 00 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00 value hex 0a a9 48 81 00 00 00 00  00 00 00 00 00 00 00 00 01 00 00 00
kubectl exec -it $CA2 -n kube-system -- cilium bpf tunnel list

kubectl exec -it $CA2 -n kube-system -- cilium bpf egress update 10.0.1.6 10.169.72.0/24 10.169.72.88 10.169.72.238
kubectl exec -it $CA2 -n kube-system -- bpftool map update id 90 key hex 38 00 00 00 0a 00 01 08  0a a9 48 00 value hex 0a a9 48 ee 0a a9 48 58

[root@cilium-dev home]# kubectl exec -it $CA2 -n kube-system -- cilium bpf egress list
Defaulted container "cilium-agent" out of: cilium-agent, clean-cilium-state (init)
SRC IP & DST CIDR         EGRESS INFO
10.0.1.7 10.169.72.0/24   10.169.72.88 10.169.72.238
10.0.1.8 10.169.72.0/24   10.169.72.88 10.169.72.238
10.0.1.6 10.169.72.0/24   10.169.72.88 10.169.72.238



# kubectl exec -it $CA2 -n kube-system -- bpftool map dump id 90
Defaulted container "cilium-agent" out of: cilium-agent, clean-cilium-state (init)
key: 38 00 00 00 0a 00 01 06  0a a9 48 00  value: 0a a9 48 ee 0a a9 48 58




ip link add vxlan66 type vxlan id 66 dstport 8472 local 10.169.72.236 dev ens192 nolearning l2miss l3miss proxy
ip link set dev vxlan66 address 12:88:9f:09:e4:c2
ip link set vxlan66 up
ip a add 10.0.4.236/24 dev vxlan66
ip route add 10.0.1.0/24 dev vxlan66  proto kernel  scope link  src 10.0.4.236
arp -i vxlan66 -s 10.0.1.165 36:f0:30:65:0f:0a
bridge fdb append 36:f0:30:65:0f:0a dst 10.169.72.238 dev vxlan66


