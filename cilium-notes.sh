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
      +----------------------------+   |         +------------------------------------------------------------+
      |                            |   |         |__dev_queue_xmit()                                          |
      | __netif_receive_skb_core() |   |         |                                                            |
      |                            |   |         |                                                            |
      |                            |   |         |                                                            |
      |                            |   |         |                                                            |
      | sch_handle_ingress()     <----+-------->- sch_handle_egress()                                         |
      |  |- switch (tcf_classify_ingress(skb     |  |  |   |- switch (tcf_classify(skb, miniq->filter_list.)  |
      |    |- case TC_ACT_OK:      |             |  |  |   |- case TC_ACT_OK:                                 |
      |  |- return skb;            |             |  |  |       break;                                         |
      | 			   |   	         |  |      |- return skb;                                     |
      |                                          |  |- dev_hard_start_xmit(skb, dev, txq, &rc);               |
      +--------+-------------------+             +--------------+-----------------------+------------------+--+
               ^                                                 |                      
               |                                     TX path     |
               | RX path                                         |
               |                                                 v
               |                                                  

__netif_receive_skb_core() {

#ifdef CONFIG_NET_INGRESS
        if (static_branch_unlikely(&ingress_needed_key)) {
                bool another = false;

                skb = sch_handle_ingress(skb, &pt_prev, &ret, orig_dev,
                                         &another);
                if (another)
                        goto another_round;
                if (!skb)
                        goto out;

                if (nf_ingress(skb, &pt_prev, &ret, orig_dev) < 0)
                        goto out;
        }
#endif

}


tcf_classify(struct sk_buff *skb, const struct tcf_proto *tp,... )

struct tcf_proto {
        /* Fast access part */
        struct tcf_proto __rcu  *next;
        void __rcu              *root;

        /* called under RCU BH lock*/
        int                     (*classify)(struct sk_buff *,
                                            const struct tcf_proto *,
                                            struct tcf_result *);
        __be16                  protocol;

        /* All the rest */
        u32                     prio;
        void                    *data;
        const struct tcf_proto_ops      *ops;
        struct tcf_chain        *chain;

.....
}

static struct tcf_proto_ops cls_bpf_ops __read_mostly = {
        .kind           =       "bpf",
        .owner          =       THIS_MODULE,
        .classify       =       cls_bpf_classify,
        .init           =       cls_bpf_init,
        .destroy        =       cls_bpf_destroy,
        .get            =       cls_bpf_get,
        .change         =       cls_bpf_change,
        .delete         =       cls_bpf_delete,
        .walk           =       cls_bpf_walk,
        .reoffload      =       cls_bpf_reoffload,
        .dump           =       cls_bpf_dump,
        .bind_class     =       cls_bpf_bind_class,
};

struct cls_bpf_prog {
        struct bpf_prog *filter;
...
}
struct bpf_prog {
        u16                     pages;          /* Number of allocated pages */
        u16                     jited:1,
....
        /* Instructions for interpreter */
        struct sock_filter      insns[0];
        struct bpf_insn         insnsi[];
};

static int cls_bpf_classify(struct sk_buff *skb, const struct tcf_proto *tp,
                            struct tcf_result *res)
{
        struct cls_bpf_head *head = rcu_dereference_bh(tp->root);
        bool at_ingress = skb_at_tc_ingress(skb);
        struct cls_bpf_prog *prog;
        int ret = -1;
.....

                if (tc_skip_sw(prog->gen_flags)) {
                        filter_res = prog->exts_integrated ? TC_ACT_UNSPEC : 0;
                } else if (at_ingress) {
                        /* It is safe to push/pull even if skb_shared() */
                        __skb_push(skb, skb->mac_len);
                        bpf_compute_data_pointers(skb);
                        filter_res = BPF_PROG_RUN(prog->filter, skb);
                        __skb_pull(skb, skb->mac_len);
                } else {
                        bpf_compute_data_pointers(skb);
                        filter_res = BPF_PROG_RUN(prog->filter, skb);
                }
....
}


                                         
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
                      |           "what happens after redirect the VXLAN packet to cilium_vxlan? the VXLAN packet
		      |            will be processed by host netfilter system and host ip routing, find the physical
		      |            egress physical interface according to destination target node ip, and further trigger 
		      |            the BPF "to-netdev" attached to the physical interface ens192, iptables trace shows that "
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

bpf/bpf_host.c

/*
 * from-netdev is attached as a tc ingress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled
 */
__section("from-netdev")
int from_netdev(struct __ctx_buff *ctx)
{
        return handle_netdev(ctx, false);
		 |- return do_netdev(ctx, proto, from_host)
}

do_netdev(struct __ctx_buff *ctx, __u16 proto, const bool from_host)
  |- send_trace_notify(ctx, TRACE_FROM_NETWORK, 0, 0, 0, ctx->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
  |- switch (proto) {
  |    |- case bpf_htons(ETH_P_IP):
             |- ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC);
	         |- __section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC)
		    int tail_handle_ipv4_from_netdev(struct __ctx_buff *ctx)
		         |- return tail_handle_ipv4(ctx, 0, false);
			      |- ret = handle_ipv4(ctx, proxy_identity, ipcache_srcid, from_host);
			                |- ep = lookup_ip4_endpoint(ip4);
                                        |- if (ep) {
                                              if (ep->flags & ENDPOINT_F_HOST)
						      return CTX_ACT_OK;


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
                                      
Ethernet        {Contents=[..14..] Payload=[..118..] SrcMAC=00:50:56:86:48:98 DstMAC=00:50:56:86:66:45 EthernetType=IPv4 Length=0}
IPv4    {Contents=[..20..] Payload=[..98..] Version=4 IHL=5 TOS=0 Length=134 Id=17720 Flags= FragOffset=0 TTL=64 Protocol=UDP Checksum=36572 SrcIP=10.169.72.128 DstIP=10.169.72.129 Options=[] Padding=[]}
UDP     {Contents=[..8..] Payload=[..90..] SrcPort=47630 DstPort=8472(otv) Length=114 Checksum=0}
  Packet has been truncated

CPU 02: MARK 0x5a139e68 FROM 3650 from-network: 148 bytes (128 captured), state new, interface ens192, orig-ip 0.0.0.0

CPU 02: MARK 0x5a139e68 FROM 3650 DEBUG: Successfully mapped addr=10.169.72.128 to identity=6
CPU 02: MARK 0x5a139e68 FROM 3650 DEBUG: Tunnel decap: id=17 flowlabel=0

------------------------------------------------------------------------------
Ethernet        {Contents=[..14..] Payload=[..86..] SrcMAC=a6:5a:fb:c9:04:9e DstMAC=c6:28:e6:09:fd:96 EthernetType=IPv4 Length=0}
IPv4    {Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=36580 Flags=DF FragOffset=0 TTL=64 Protocol=ICMPv4 Checksum=38474 SrcIP=10.0.0.119 DstIP=10.0.1.4 Options=[] Padding=[]}
ICMPv4  {Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=43385 Id=15 Seq=0}

CPU 02: MARK 0x0 FROM 0 from-overlay: 98 bytes (98 captured), state new, interface cilium_vxlan, orig-ip 0.0.0.0

CPU 02: MARK 0x0 FROM 0 DEBUG: Tunnel decap: id=7997 flowlabel=0
CPU 02: MARK 0x0 FROM 0 DEBUG: Attempting local delivery for container id 4037 from seclabel 7997
CPU 02: MARK 0x0 FROM 0 DEBUG: Attempting local delivery for container id 15 from seclabel 7997
CPU 02: MARK 0x0 FROM 4037 DEBUG: Conntrack lookup 1/2: src=10.0.0.119:15 dst=10.0.1.4:0
CPU 02: MARK 0x0 FROM 4037 DEBUG: Conntrack lookup 2/2: nexthdr=1 flags=0
CPU 02: MARK 0x0 FROM 4037 DEBUG: CT verdict: New, revnat=0
CPU 02: MARK 0x0 FROM 4037 DEBUG: Conntrack create: proxy-port=0 revnat=0 src-identity=7997 lb=0.0.0.0
Ethernet        {Contents=[..14..] Payload=[..86..] SrcMAC=fe:3f:66:67:dd:f0 DstMAC=9e:d4:bb:86:69:cf EthernetType=IPv4 Length=0}
IPv4    {Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=36580 Flags=DF FragOffset=0 TTL=63 Protocol=ICMPv4 Checksum=38730 SrcIP=10.0.0.119 DstIP=10.0.1.4 Options=[] Padding=[]}
ICMPv4  {Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=43385 Id=15 Seq=0}

CPU 02: MARK 0x0 FROM 4037 to-endpoint: 98 bytes (98 captured), state new, interface lxcd34391ddb87bidentity 7997->7997, orig-ip 10.0.0.119, to endpoint 4037

------------------------------------------------------------------------------


--- a/bpf/bpf_host.c
+++ b/bpf/bpf_host.c
@@ -534,8 +534,10 @@ handle_ipv4(struct __ctx_buff *ctx, __u32 secctx,
                /* Let through packets to the node-ip so they are processed by
                 * the local ip stack.
                 */
-               if (ep->flags & ENDPOINT_F_HOST)
+               if (ep->flags & ENDPOINT_F_HOST) {
+                       cilium_dbg(ctx, DBG_DECAP, ip4->protocol, ipcache_srcid);
                        return CTX_ACT_OK;
+               }

                return ipv4_local_delivery(ctx, ETH_HLEN, secctx, ip4, ep,
                                           METRIC_INGRESS, from_host);
diff --git a/bpf/lib/l3.h b/bpf/lib/l3.h
index 4fbbed4ca..792ddbffd 100644
--- a/bpf/lib/l3.h
+++ b/bpf/lib/l3.h
@@ -147,7 +147,7 @@ static __always_inline int ipv4_local_delivery(struct __ctx_buff *ctx, int l3_of
        ctx_store_meta(ctx, CB_SRC_LABEL, seclabel);
        ctx_store_meta(ctx, CB_IFINDEX, ep->ifindex);
        ctx_store_meta(ctx, CB_FROM_HOST, from_host ? 1 : 0);
-
+       cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->ifindex, seclabel);
        tail_call_dynamic(ctx, &POLICY_CALL_MAP, ep->lxc_id);
        return DROP_MISSED_TAIL_CALL;

