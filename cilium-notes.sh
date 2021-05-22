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
Understanding tc “direct action” mode for BPF

DIAGRAM 1: TC clsact

                                      +--------------------+
                                      |                    |
                                      |  clsact qdisc      |
                                      |                    |
                                      |                    |
                                      +-----+--------------+
                                            |
                                            |
      +----------------------------+-       |     +---------------------------------------------------------+
      |                            |        |     |__dev_queue_xmit()                                       |
      | __netif_receive_skb_core() |        |     |                                                         |
      |                            |        |     |                                                         |
      |  sch_handle_ingress()     <---------+-------->- sch_handle_egress()                                 |
      |                            |              |  |   |- switch (tcf_classify(skb, miniq->filter_list.)  |
      | 			   |    	  |  |   |   |- case TC_ACT_OK:                             |
      |                            |              |  |   |       break;                                     |
      | 			   |    	  |  |   |- return skb;                                     |
      |                            |              |  |- dev_hard_start_xmit(skb, dev, txq, &rc);            |
      +--------+-------------------+              +--------------+-----------------------+------------------+
               ^                                                 |                      
               |                                     TX path     |
               | RX path                                         |
               |                                                 v
               |                                                  

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

                                         
 DIAGRAM 2: Cilium datapath                                                  
                                                  +-------------------------------+
                   (ingress from-overlay          |                               |          ingress from-overlay
                    egress to-overlay)            |                               |          egress to-overlay 
                     bpf/bpf_overlay.c            |                               |
                                                  |                               |       
      +---------------cilium_vxlan-------------ens192-+-----------+         +---ens192----------cilium_vxlan-+--------+
      |                     |               (ingress from-netdev  |         |                      |                  |
      |                     |                egress to-netdev)    |         |                      |                  |
      |  Node               |                bpf/bpf_host.c       |         |   Node               |                  |
      |  cilium-bigip       |                                     |         |   cilium-fl-worker   |                  |
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

bpf_lxc.c

__section("from-container")

handle_xgress
  |-send_trace_notify(ctx, "TRACE_FROM_LXC", SECLABEL, 0, 0, 0, 0...) -> "from-endpoint:"
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
bpf/ctx/skb.h         |          |    |-ctx_set_tunnel_key(ctx, &key, sizeof(key),...) "encapuslate the packet" 
bpf/lib/trace.h       |          |    |-send_trace_notify(ctx, "TRACE_TO_OVERLAY", seclabel,...) -> "to-overlay:" 
bpf/helpers_skb.h     |          |-redirect(ENCAP_IFINDEX, 0) "redirected to tunnel device"
                      |
                      |           "here is the puzzle, what happens after redirected to tunnel device
		      |            how tunnel device forward the packet to physical network interface
		      |            that has BPF "to-netdev" attached to"
                      |
bpf/bpf_host.c	      |               |-__section("to-netdev")
                      |                   |-send_trace_notify(ctx, "TRACE_TO_NETWORK", src_id, 0, 0,...)
                      |                   |-return CTX_ACT_OK 
		      |                    "Here skb lastly processed by sch_handle_egress, returned skb to 
		      |                     device driver to deliver the skb, see above DIAGRAM 1"
		      |                                      
                      |-if routing  //direct routing, pass to kernel stack (continue normal routing)
                      |    to_host:
bpf/lib/l3.h          |      |-ipv4_l3(ctx, l3_off, (__u8 *)&router_mac.addr
                      |      |-send_trace_notify(ctx, "TRACE_TO_HOST", SECLABEL, HOST_ID, 0 
                      |      |-redirect(HOST_IFINDEX, BPF_F_INGRESS)
                      |    pass_to_stack:
                      |      |-ipv4_l3(ctx, l3_off, NULL, (__u8 *) &router_mac.addr, ip4) 
                      |      |-send_trace_notify(ctx, "TRACE_TO_STACK", SECLABEL, *dstID, 0, 0
                      |
                      | return CTX_ACT_OK;

------------------------------------------------------------------------------
Ethernet	{Contents=[..14..] Payload=[..86..] SrcMAC=36:66:92:6d:11:14 DstMAC=36:a6:04:74:9a:1e EthernetType=IPv4 Length=0}
IPv4	{Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=5678 Flags=DF FragOffset=0 TTL=64 Protocol=ICMPv4 Checksum=3656 SrcIP=10.0.1.218 DstIP=10.0.0.90 Options=[] Padding=[]}
ICMPv4	{Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=60070 Id=5632 Seq=0}
CPU 01: MARK 0x0 FROM 3349 from-endpoint: 98 bytes (98 captured), state newidentity 49798->unknown, orig-ip 0.0.0.0
CPU 01: MARK 0x0 FROM 3349 DEBUG: Conntrack lookup 1/2: src=10.0.1.218:5632 dst=10.0.0.90:0
CPU 01: MARK 0x0 FROM 3349 DEBUG: Conntrack lookup 2/2: nexthdr=1 flags=1
CPU 01: MARK 0x0 FROM 3349 DEBUG: CT verdict: New, revnat=0
CPU 01: MARK 0x0 FROM 3349 DEBUG: Successfully mapped addr=10.0.0.90 to identity=6076
CPU 01: MARK 0x0 FROM 3349 DEBUG: Conntrack create: proxy-port=0 revnat=0 src-identity=49798 lb=0.0.0.0
CPU 01: MARK 0x0 FROM 3349 DEBUG: Encapsulating to node 178866304 (0xaa94880) from seclabel 49798
------------------------------------------------------------------------------
Ethernet	{Contents=[..14..] Payload=[..86..] SrcMAC=36:66:92:6d:11:14 DstMAC=36:a6:04:74:9a:1e EthernetType=IPv4 Length=0}
IPv4	{Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=5678 Flags=DF FragOffset=0 TTL=64 Protocol=ICMPv4 Checksum=3656 SrcIP=10.0.1.218 DstIP=10.0.0.90 Options=[] Padding=[]}
ICMPv4	{Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=60070 Id=5632 Seq=0}
CPU 01: MARK 0x0 FROM 3349 to-overlay: 98 bytes (98 captured), state new, interface cilium_vxlanidentity 49798->unknown, orig-ip 0.0.0.0
CPU 01: MARK 0x0 FROM 2161 DEBUG: Conntrack lookup 1/2: src=10.169.72.129:48562 dst=10.169.72.128:8472
CPU 01: MARK 0x0 FROM 2161 DEBUG: Conntrack lookup 2/2: nexthdr=17 flags=1
CPU 01: MARK 0x0 FROM 2161 DEBUG: CT verdict: New, revnat=0
CPU 01: MARK 0x0 FROM 2161 DEBUG: Conntrack create: proxy-port=0 revnat=0 src-identity=0 lb=0.0.0.0
------------------------------------------------------------------------------
Ethernet	{Contents=[..14..] Payload=[..118..] SrcMAC=00:50:56:86:66:45 DstMAC=00:50:56:86:48:98 EthernetType=IPv4 Length=0}
IPv4	{Contents=[..20..] Payload=[..98..] Version=4 IHL=5 TOS=0 Length=134 Id=10473 Flags= FragOffset=0 TTL=64 Protocol=UDP Checksum=43819 SrcIP=10.169.72.129 DstIP=10.169.72.128 Options=[] Padding=[]}
UDP	{Contents=[..8..] Payload=[..90..] SrcPort=48562 DstPort=8472(otv) Length=114 Checksum=0}
  Packet has been truncated
CPU 01: MARK 0x0 FROM 2161 to-network: 148 bytes (128 captured), state new, orig-ip 0.0.0.0
------------------------------------------------------------------------------



Ingress:

bpf_overlay.c

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
bpf/lib/l3.h         |       |- ipv4_local_delivery(ctx, ETH_HLEN, *identity, ip4, ep,..)
                     |           |- ipv4_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac,ip4)
                     |           |- if #if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \
                     |           |          !defined(FORCE_LOCAL_POLICY_EVAL_AT_SOURCE)
                     |           |       redirect_ep(ep->ifindex, from_host)
                     |           |         |- redirect(ifindex, 0)
                     |           |         |- redirect_peer(ifindex, 0)
                     |           |- else 
		     |           |     tail_call_dynamic(ctx, &POLICY_CALL_MAP, ep->lxc_id)
                     |           |      |- __section("to-container")
                     |           |         handle_to_container(struct __ctx_buff *ctx)
                     |           |          |- validate_ethertype(ctx, &proto)
                     |           |             |- send_trace_notify(ctx, trace, identity, 0, 0,
                     |           |             |- switch (proto)
                     |           |                 |- case bpf_htons(ETH_P_IP):
                     |           |                     |- tail_ipv4_to_endpoint
                     |           |                         |- ipv4_policy
		     |           |                              |- ret = ct_lookup4(get_ct_map4(&tuple) 
		     |           |                              |- verdict = policy_can_access_ingress(ctx, src_label...)
		     |           |                              |- send_trace_notify4(ctx, TRACE_TO_LXC,
                     |           |                              |- redirect_ep(ifindex, from_host) 
                     |- to_host:
                                 |- ipv4_l3(ctx, ETH_HLEN, (__u8 *)&router_mac.addr,...)
                                 |- redirect(HOST_IFINDEX, 0);
                                      
------------------------------------------------------------------------------
Ethernet	{Contents=[..14..] Payload=[..118..] SrcMAC=00:50:56:86:48:98 DstMAC=00:50:56:86:66:45 EthernetType=IPv4 Length=0}
IPv4	{Contents=[..20..] Payload=[..98..] Version=4 IHL=5 TOS=0 Length=134 Id=41688 Flags= FragOffset=0 TTL=64 Protocol=UDP Checksum=12604 SrcIP=10.169.72.128 DstIP=10.169.72.129 Options=[] Padding=[]}
UDP	{Contents=[..8..] Payload=[..90..] SrcPort=60162 DstPort=8472(otv) Length=114 Checksum=0}
  Packet has been truncated
CPU 03: MARK 0x543b493 FROM 2161 from-network: 148 bytes (128 captured), state new, interface ens192, orig-ip 0.0.0.0
CPU 03: MARK 0x543b493 FROM 2161 DEBUG: Successfully mapped addr=10.169.72.128 to identity=6
------------------------------------------------------------------------------
Ethernet	{Contents=[..14..] Payload=[..86..] SrcMAC=ea:8f:76:28:3d:3f DstMAC=ee:2c:e1:5a:9e:86 EthernetType=IPv4 Length=0}
IPv4	{Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=11952 Flags= FragOffset=0 TTL=64 Protocol=ICMPv4 Checksum=13766 SrcIP=10.0.0.90 DstIP=10.0.1.218 Options=[] Padding=[]}
ICMPv4	{Contents=[..8..] Payload=[..56..] TypeCode=EchoReply Checksum=62118 Id=5632 Seq=0}
CPU 03: MARK 0x0 FROM 0 from-overlay: 98 bytes (98 captured), state new, interface cilium_vxlan, orig-ip 0.0.0.0
CPU 03: MARK 0x0 FROM 0 DEBUG: Tunnel decap: id=6076 flowlabel=0
CPU 03: MARK 0x0 FROM 0 DEBUG: Attempting local delivery for container id 3349 from seclabel 6076
CPU 03: MARK 0x0 FROM 3349 DEBUG: Conntrack lookup 1/2: src=10.0.0.90:0 dst=10.0.1.218:5632
CPU 03: MARK 0x0 FROM 3349 DEBUG: Conntrack lookup 2/2: nexthdr=1 flags=0
CPU 03: MARK 0x0 FROM 3349 DEBUG: CT entry found lifetime=16890953, revnat=0
CPU 03: MARK 0x0 FROM 3349 DEBUG: CT verdict: Reply, revnat=0
------------------------------------------------------------------------------
Ethernet	{Contents=[..14..] Payload=[..86..] SrcMAC=36:a6:04:74:9a:1e DstMAC=36:66:92:6d:11:14 EthernetType=IPv4 Length=0}
IPv4	{Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=11952 Flags= FragOffset=0 TTL=63 Protocol=ICMPv4 Checksum=14022 SrcIP=10.0.0.90 DstIP=10.0.1.218 Options=[] Padding=[]}
ICMPv4	{Contents=[..8..] Payload=[..56..] TypeCode=EchoReply Checksum=62118 Id=5632 Seq=0}
CPU 03: MARK 0x0 FROM 3349 to-endpoint: 98 bytes (98 captured), state reply, interface lxcf69c5e689142identity 6076->49798, orig-ip 10.0.0.90, to endpoint 3349
------------------------------------------------------------------------------
