root@cilium-bigip:~# cat /root/.bash_profile 

CN=cilium-bigip

CA1=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$CN -o jsonpath='{.items[0].metadata.name}')

NGINX=$(kubectl get -l app=nginx pods -n default --field-selector spec.nodeName=$CN -o jsonpath='{.items[0].metadata.name}')

WN=cilium-fl-worker

CA2=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$WN -o jsonpath='{.items[0].metadata.name}')

BUSYBOX=$(kubectl get -l app=busybox pods -n default --field-selector spec.nodeName=$WN -o jsonpath='{.items[0].metadata.name}')

export CN WN CA1 CA2 NGINX BUSYBOX


root@cilium-bigip:~# kubectl  exec -it $CA2 -n kube-system -- /bin/bash

root@cilium-fl-worker:/home/cilium# bpftool net show
xdp:

tc:
ens192(3) clsact/ingress bpf_netdev_ens192.o:[from-netdev] id 2385
ens192(3) clsact/egress bpf_netdev_ens192.o:[to-netdev] id 2391
cilium_net(5) clsact/ingress bpf_host_cilium_net.o:[to-host] id 2379
cilium_host(6) clsact/ingress bpf_host.o:[to-host] id 2367
cilium_host(6) clsact/egress bpf_host.o:[from-host] id 2373
cilium_vxlan(7) clsact/ingress bpf_overlay.o:[from-overlay] id 2347
cilium_vxlan(7) clsact/egress bpf_overlay.o:[to-overlay] id 2352
lxc80a882bfd44a(19) clsact/ingress bpf_lxc.o:[from-container] id 2404

root@cilium-fl-worker:/home/cilium# tc filter show dev lxc80a882bfd44a ingress
filter protocol all pref 1 bpf chain 0 
filter protocol all pref 1 bpf chain 0 handle 0x1 bpf_lxc.o:[from-container] direct-action not_in_hw id 2404 tag a55c91b88bcdc6f1 jited 

https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
Understanding tc “direct action” mode for BPF"

flow_dissector:

root@cilium-fl-worker:/home/cilium# ip link list
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:50:56:86:95:f7 brd ff:ff:ff:ff:ff:ff
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:50:56:86:66:45 brd ff:ff:ff:ff:ff:ff
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default 
    link/ether 02:42:39:8c:09:a6 brd ff:ff:ff:ff:ff:ff
5: cilium_net@cilium_host: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 86:56:9f:8b:8b:3c brd ff:ff:ff:ff:ff:ff
6: cilium_host@cilium_net: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether ee:33:1a:5c:1d:6c brd ff:ff:ff:ff:ff:ff
7: cilium_vxlan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 4e:73:36:c0:8b:c3 brd ff:ff:ff:ff:ff:ff
19: lxc80a882bfd44a@if18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 56:c6:ab:91:96:77 brd ff:ff:ff:ff:ff:ff link-netnsid 0


root@cilium-fl-worker:/home/cilium# cilium endpoint list
ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6   IPv4        STATUS   
           ENFORCEMENT        ENFORCEMENT                                                                                       
2775       Disabled           Disabled          36249      k8s:app=busybox                                          10.0.2.70   ready   
                                                           k8s:io.cilium.k8s.policy.cluster=default                                     
                                                           k8s:io.cilium.k8s.policy.serviceaccount=default                              
                                                           k8s:io.kubernetes.pod.namespace=default                                      
3444       Disabled           Disabled          1          k8s:dedicated=worker                                                 ready   
                                                           reserved:host          

root@cilium-fl-worker:/home/cilium# cilium endpoint get 2775
[
  {
    "id": 2775,
.......
      "networking": {
        "addressing": [
          {
            "ipv4": "10.0.2.70"
          }
        ],
        "host-mac": "56:c6:ab:91:96:77",
        "interface-index": 19,
        "interface-name": "lxc80a882bfd44a",
        "mac": "be:c2:87:fa:d5:80"
      },
                                         
                                                   
                                                  +-------------------------------+
                   (ingress from-overlay          |                               |          ingress from-overlay
                    egress to-overlay)            |                               |          egress to-overlay 
                     bpf/bpf_overlay.c            |                               |
                                                  |                               |       
      +---------------cilium_vxlan-------------ens192-+-----------+         +---ens192----------cilium_vxlan-+--------+
      |                     |               (ingress from-netdev  |         |                      |                  |
      |                     |                egress to-netdev)    |         |                      |                  |
      |                     |                bpf/bpf_host.c       |         |                      |                  |
      |                     |                                     |         |                      |                  |
      |                     |                                     |         |                      |                  |
      |                     |                                     |         |                      |                  |
      | 		lxc80a882bfd44a@if18                      |         |                      |  to-container    |
      |                     |                                     |         |                      |                  |
      |                     | (ingress from-container             |         |               lxcae556c40f20c@if12      |             |                     |                                     |         |                      |                  |
      |                     |  egress  to-container)              |         |                      | from-container   |
      | 		    |  bpf/bpf_lxc.c                      |         |                      |                  |
      |    pod              |                                     |         |                 +-eth0@if13             |
      |   +-------+  +--eth0@if19-+                               |         |    pod          |  nginx  |             |             |   |cilium |  | busybox    |                               |         |  +-------+      |  pod    |             |
      |   |agent  |  | Pod        |                               |         |  |cilium |      +---------+             |
      |   +-------+  +------------+                               |         |  |agent  |                              |
      |                                                           |         |  +-------+                              |
      |                                                           |         |                                         |
      +-----------------------------------------------------------+         +-----------------------------------------+
                                                                                          


egress:

bpf_overlay.c

__section("from-container")

handle_xgress
  |-validate_ethertype(ctx, &proto)
  |
  |-switch (proto) {

       case bpf_htons(ETH_P_IPV6)

       case bpf_htons(ETH_P_IP):

            tail_handle_ipv4
                 | 
bpf/bpf_lxc.c    |-handle_ipv4_from_lxc(ctx, &dstID)
                      |
                      |-lb4_extract_key(ctx, ip4, l4_off, &key, &csum_off, CT_EGRESS)   
bpf/lib/lb.h          |-lb4_lookup_service(&key, is_defined(ENABLE_NODEPORT))
                      |    |-lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off...,$key,..)
                      |    |    |-ct_lookup4(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
                      |    |         |-switch
                      |    |              case CT_NEW 
                      |    |                   |-lb4_lookup_backend(ctx, backend_id)
                      |    |                   |-ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state,.)
                      |    |               |-lb4_xlate
                      |    |
bpf/lib/conntrack.h   |-ret=ct_lookup4(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor)
                      |
bpf/lib/eps.h         |-info=lookup_ip4_remote_endpoint(orig_dip)
                      |
bpf/lib/policy.h      |-verdict=policy_can_egress4(ctx, &tuple, SECLABEL, *dstID,..)
                      |
                      | switch(ret)
                      |     case CT_NEW:
                      |          ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx,
                      |
bpf/lib/proxy.h       |-ctx_redirect_to_proxy4(ctx, &tuple, verdict, false)
                      |
bpf/lib/eps.h         |-ep = lookup_ip4_endpoint(ip4); //local destination
bpf/lib/l3.h          |        |-if (ep) ipv4_local_delivery(ctx, l3_off, SECLABEL, ip4,
                      |
bpf/lib/encap.h       |-if tunnel encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,...)
                      |     |-__encap_and_redirect_with_nodeid(ctx, tunnel_endpoint, seclabel, monitor)
                      |     |    |-__encap_with_nodeid(ctx, tunnel_endpoint, seclabel, monitor)
bpf/ctx/skb.h         |          |    |-ctx_set_tunnel_key(ctx, &key, sizeof(key),...) 
bpf/lib/trace.h       |          |    |-send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel,...)
bpf/helpers_skb.h     |          |-redirect(ENCAP_IFINDEX, 0)
                      |      
                      |-if routing  //direct routing, pass to kernel stack (continue normal routing)
                      |    to_host:
bpf/lib/l3.h          |      |-ipv4_l3(ctx, l3_off, (__u8 *)&router_mac.addr
                      |      |-send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0 
                      |      |-redirect(HOST_IFINDEX, BPF_F_INGRESS)
                      |    pass_to_stack:
                      |      |-ipv4_l3(ctx, l3_off, NULL, (__u8 *) &router_mac.addr, ip4) 
                      |      |-send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0
                      |
                      | return CTX_ACT_OK;




Ingress:

__section("from-overlay")
  |
  |-validate_ethertype(ctx, &proto)
  |-send_trace_notify(ctx, TRACE_FROM_OVERLAY, 0, 0, 0...)
  |
  |-switch (proto)
  |    |- case bpf_htons(ETH_P_IPV6):
       |- case bpf_htons(ETH_P_IP):
           |-ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC)
               |
               |- __section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC)
bpf_overlay.c  |- handle_ipv4(ctx, &src_identity)
                     |
                     |- if enable nodeport
                     |      |- nodeport_lb4(ctx, *identity)
                     |
                     |- ctx_get_tunnel_key(ctx, &key, sizeof(key), 0)
                     |
                     |- ep = lookup_ip4_endpoint(ip4);
                     |       |   |- __lookup_ip4_endpoint(__u32 ip)
                     |       |        |-map_lookup_elem(&ENDPOINTS_MAP, &key)
                     |- if(ep)
                     |       |- ipv4_local_delivery(ctx, ETH_HLEN, *identity, ip4, ep,..)
                     |           |-ipv4_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac,ip4)
                     |           |- redirect_ep(ep->ifindex, from_host)
                     |           |    |- redirect(ifindex, 0)
                     |           |    |- redirect_peer(ifindex, 0)
                     |           |    |     |- __section("to-container")
                     |           |             handle_to_container(struct __ctx_buff *ctx)
                     |           |                 |- validate_ethertype(ctx, &proto)
                     |           |                 |- send_trace_notify(ctx, trace, identity, 0, 0,
                     |           |                 |- switch (proto)
                     |           |                      |- case bpf_htons(ETH_P_IP):
                     |           |                           |- tail_ipv4_to_endpoint
                     |           |                                |- ipv4_policy
                     |           |                                      |- redirect_ep(ifindex, from_host) 
                     |           |-tail_call_dynamic(ctx, &POLICY_CALL_MAP, ep->lxc_id)
                     |- to_host:
                                 |- ipv4_l3(ctx, ETH_HLEN, (__u8 *)&router_mac.addr,...)
                                 |- redirect(HOST_IFINDEX, 0);
                                      
