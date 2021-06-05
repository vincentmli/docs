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

Cilium Tunnel Mode Ingress

1, Diagram overview

2,  How cilium_vxlan interface is created 
(bpf/init.sh, drivers/net/vxlan.c metadata and VNI key based implementation) 

3, how to build cilium

4, cilium datapath monitor log 

5,code path analysis with debug 
  bpf/bpf_host.c
  drivers/net/vxlan.c (vxlan_rcv)
  bpf/bpf_overlay.c
                                     
                                 
                      +--------------------------------------------------------------------------------+
                      |                                                                                |
                      |                                                                                |
                      |                                                                                |
                      |                                               +------------+                   |
                      +                                               |            |                   |
                      |                                               |  pod       |                   |
                      |             +----------+                      |            |                   |
                      |             | host udp |                      |            |                   |
                      |             + stack    +                      +-----eth0---+                   |
                      |             |vxlan     |                              ^                        |
                      |             |decap     |                              |                        |
                      |             |drivers/  |                              |                        |
                      |      +----->|net/      |--+                           | from/to-container      |
                      |      |      |vxlan.c   |  |                     lxcxxxxxx@if<#>                |
                      |      |      +----------+  |                           |                        |
                      |      |                    |                           |                        |
                      |      |                    |                           |                        |
                      |      |                    |                           |                        |
                      |      |                    |                           |                        |
         ingress      |      |                    V                           |                        |
      --------------->+----ens192---------------cilium_vxlan------------------------------+------------+
			from/to-netdev          from/to-overlay


Jun  3 20:53:39 cilium-worker kernel:       ens192: vxlan_rcv: tun_info key ipv4 dst  10.169.72.238
Jun  3 20:53:39 cilium-worker kernel: cilium_vxlan: vxlan_rcv: vxlan->dev
Jun  3 20:53:39 cilium-worker kernel: cilium_vxlan: vxlan_xmit: tun_info key ipv4 dst  10.169.72.239



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

"So here again, after do_netdev return CTX_ACT_OK, how the VXLAN UDP packet got directed to cilium_vxlan ?
the VXLAN UDP packet is processed by host UDP stack and based on the UDP destination port 8472
, is further processed by vxlan_rcv() drivers/net/vxlan.c.  

also debug log shows packet processed by handle_ipv4 in bpf_overlay.c (from-overlay)already got decapped 
so who decapped the packet, there is no decap function in cilium BPF, ctx_get_tunnel_key/ctx_set_tunnel_key seems to be just BPF helper functions to set the tunnel metadata, the actual packet encap/decap is processed in kernel driver/net/vxlan.c,
so in cilium tunnel mode the encap/decap is processed by host kernel stack, no complete kernel stack bypass by BPF like cilium route mode" 

bpf/init.sh

if [ "${TUNNEL_MODE}" != "<nil>" ]; then
        ENCAP_DEV="cilium_${TUNNEL_MODE}"
        ip link show $ENCAP_DEV || {
                ip link add name $ENCAP_DEV address $(rnd_mac_addr) type $TUNNEL_MODE external || encap_fail
        }
        ip link set $ENCAP_DEV mtu $MTU || encap_fail

        setup_dev $ENCAP_DEV || encap_fail

        ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)
        sed -i '/^#.*ENCAP_IFINDEX.*$/d' $RUNDIR/globals/node_config.h
        echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> $RUNDIR/globals/node_config.h

        CALLS_MAP="cilium_calls_overlay_${ID_WORLD}"
        COPTS="-DSECLABEL=${ID_WORLD} -DFROM_ENCAP_DEV=1"
        if [ "$NODE_PORT" = "true" ]; then
                COPTS="${COPTS} -DDISABLE_LOOPBACK_LB"
        fi
        bpf_load $ENCAP_DEV "$COPTS" "ingress" bpf_overlay.c bpf_overlay.o from-overlay ${CALLS_MAP}
        bpf_load $ENCAP_DEV "$COPTS" "egress" bpf_overlay.c bpf_overlay.o to-overlay ${CALLS_MAP}
else
        # Remove eventual existing encapsulation device from previous run
        ip link del cilium_vxlan 2> /dev/null || true
        ip link del cilium_geneve 2> /dev/null || true
fi


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
                     |- cilium_dbg(ctx, DBG_DECAP, key.tunnel_id, key.tunnel_label);
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
                                      

CPU 01: MARK 0x5a139e68 FROM 3650 from-network: 148 bytes (128 captured), state new, interface ens192, orig-ip 0.0.0.0

CPU 01: MARK 0x5a139e68 FROM 3650 DEBUG: Successfully mapped addr=10.169.72.128 to identity=6
CPU 01: MARK 0x5a139e68 FROM 3650 DEBUG: Tunnel decap: id=17 flowlabel=0
------------------------------------------------------------------------------

CPU 01: MARK 0x0 FROM 0 from-overlay: 98 bytes (98 captured), state new, interface cilium_vxlan, orig-ip 0.0.0.0

CPU 01: MARK 0x0 FROM 0 DEBUG: Tunnel decap: id=7997 flowlabel=0
CPU 01: MARK 0x0 FROM 0 DEBUG: Successfully mapped addr=10.0.1.99 to identity=7997
CPU 01: MARK 0x0 FROM 0 DEBUG: Attempting local delivery for container id 90 from seclabel 7997
CPU 01: MARK 0x0 FROM 0 DEBUG: Attempting local delivery for container id 17 from seclabel 7997
CPU 01: MARK 0x0 FROM 90 DEBUG: Conntrack lookup 1/2: src=10.0.0.209:16 dst=10.0.1.99:0
CPU 01: MARK 0x0 FROM 90 DEBUG: Conntrack lookup 2/2: nexthdr=1 flags=0
CPU 01: MARK 0x0 FROM 90 DEBUG: CT verdict: New, revnat=0
CPU 01: MARK 0x0 FROM 90 DEBUG: Conntrack create: proxy-port=0 revnat=0 src-identity=7997 lb=0.0.0.0
------------------------------------------------------------------------------
Ethernet        {Contents=[..14..] Payload=[..86..] SrcMAC=b2:b2:a7:4b:ed:97 DstMAC=02:08:b1:6f:88:50 EthernetType=IPv4 Length=0}
IPv4    {Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=15081 Flags=DF FragOffset=0 TTL=63 Protocol=ICMPv4 Checksum=60044 SrcIP=10.0.0.209 DstIP=10.0.1.99 Options=[] Padding=[]}
ICMPv4  {Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=27578 Id=16 Seq=0}

CPU 01: MARK 0x0 FROM 90 to-endpoint: 98 bytes (98 captured), state new, interface lxc407b222a6233identity 7997->7997, orig-ip 10.0.0.209, to endpoint 90


diff --git a/bpf/bpf_host.c b/bpf/bpf_host.c
index 2feaa7053..04548a69d 100644
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
diff --git a/bpf/bpf_overlay.c b/bpf/bpf_overlay.c
index 52121bc7b..6f4404735 100644
--- a/bpf/bpf_overlay.c
+++ b/bpf/bpf_overlay.c
@@ -207,6 +207,7 @@ static __always_inline int handle_ipv4(struct __ctx_buff *ctx, __u32 *identity)
        }

        cilium_dbg(ctx, DBG_DECAP, key.tunnel_id, key.tunnel_label);
+        cilium_dbg(ctx, DBG_IP_ID_MAP_SUCCEED4, ip4->daddr, key.tunnel_id);

 #ifdef ENABLE_IPSEC
        if (!decrypted) {
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
 #endif



Jun  3 20:53:39 cilium-worker kernel:       ens192: vxlan_rcv: tun_info key ipv4 dst  10.169.72.238
Jun  3 20:53:39 cilium-worker kernel: cilium_vxlan: vxlan_rcv: vxlan->dev
Jun  3 20:53:39 cilium-worker kernel: cilium_vxlan: vxlan_xmit: tun_info key ipv4 dst  10.169.72.239



diff --git a/drivers/net/vxlan.c b/drivers/net/vxlan.c
index 02a14f1b938a..71549d0cc9be 100644
--- a/drivers/net/vxlan.c
+++ b/drivers/net/vxlan.c
@@ -1882,6 +1882,7 @@ static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
 
        if (vxlan_collect_metadata(vs)) {
                struct metadata_dst *tun_dst;
+               __be32 daddr;
 
                tun_dst = udp_tun_rx_dst(skb, vxlan_get_sk_family(vs), TUNNEL_KEY,
                                         key32_to_tunnel_id(vni), sizeof(*md));
@@ -1889,6 +1890,8 @@ static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
                if (!tun_dst)
                        goto drop;
 
+               daddr = tun_dst->u.tun_info.key.u.ipv4.dst;
+               netdev_info(skb->dev, "vxlan_rcv: tun_info key ipv4 dst  %pI4\n", &daddr);
                md = ip_tunnel_info_opts(&tun_dst->u.tun_info);
 
                skb_dst_set(skb, (struct dst_entry *)tun_dst);
@@ -1941,6 +1944,7 @@ static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
        }
 
        dev_sw_netstats_rx_add(vxlan->dev, skb->len);
+       netdev_info(skb->dev, "vxlan_rcv: vxlan->dev\n");
        gro_cells_receive(&vxlan->gro_cells, skb);
 
        rcu_read_unlock();
@@ -2885,6 +2889,7 @@ static netdev_tx_t vxlan_xmit(struct sk_buff *skb, struct net_device *dev)
        struct vxlan_fdb *f;
        struct ethhdr *eth;
        __be32 vni = 0;
+       __be32 daddr;
 
        info = skb_tunnel_info(skb);
 
@@ -2895,8 +2900,11 @@ static netdev_tx_t vxlan_xmit(struct sk_buff *skb, struct net_device *dev)
                    info->mode & IP_TUNNEL_INFO_TX) {
                        vni = tunnel_id_to_key32(info->key.tun_id);
                } else {
-                       if (info && info->mode & IP_TUNNEL_INFO_TX)
+                       if (info && info->mode & IP_TUNNEL_INFO_TX) {
+                               daddr = info->key.u.ipv4.dst;
+                               netdev_info(skb->dev, "vxlan_xmit: tun_info key ipv4 dst  %pI4\n", &daddr);
                                vxlan_xmit_one(skb, dev, vni, NULL, false);
+                       }
                        else
                                kfree_skb(skb);
                        return NETDEV_TX_OK;



bpftrace -e 'kprobe:vxlan_rcv { @[kstack()] = count(); }'

@[
    vxlan_rcv+1
    udp_queue_rcv_one_skb+479
    udp_unicast_rcv_skb.isra.67+116
    __udp4_lib_rcv+1368
    ip_protocol_deliver_rcu+232
    ip_local_deliver_finish+68
    ip_local_deliver+247
    ip_sublist_rcv_finish+101
    ip_sublist_rcv+367
    ip_list_rcv+271
    __netif_receive_skb_list_core+598
    netif_receive_skb_list_internal+402
    gro_normal_list.part.157+25
    napi_complete_done+101
    vmxnet3_poll_rx_only+125
    __napi_poll+43
    net_rx_action+592
    __softirqentry_text_start+223
    irq_exit_rcu+218
    common_interrupt+119
    asm_common_interrupt+30
    native_safe_halt+14
    acpi_idle_do_entry+70
    acpi_idle_enter+90
    cpuidle_enter_state+140
    cpuidle_enter+41
    do_idle+616
    cpu_startup_entry+25
    start_secondary+289
    secondary_startup_64_no_verify+194
]: 1

