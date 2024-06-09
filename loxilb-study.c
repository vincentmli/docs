
SEC("tc_packet_hook0")
int tc_packet_func_fast(struct __sk_buff *md)
{
#ifdef LL_TC_EBPF_EHOOK
  if (DP_LLB_ISTAMPED(md) || DP_LLB_OSTAMPED(md)) {
    DP_LLB_RST_STAMP(md);
    return DP_PASS;
  } else {
    DP_LLB_OSTAMP(md);
  }
#else
  if (DP_LLB_OSTAMPED(md)) {
    return DP_PASS;
  }
  DP_LLB_ISTAMP(md);
#endif

#ifdef HAVE_DP_FC
  struct xfi *xf;

  DP_NEW_FCXF(xf);

  DP_IN_ACCOUNTING(ctx, xf);

  dp_parse_d0(md, xf, 1);

  return dp_ing_fc_main(md, xf);
#else
  return tc_packet_func__(md);
#endif
}

tc_packet_func__(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

#ifndef HAVE_DP_FC
  DP_IN_ACCOUNTING(ctx, xf);
#endif
  //if (xf->pm.phit & LLB_DP_FC_HIT) {
  //  memset(xf, 0, sizeof(*xf));
  //  xf->pm.phit |= LLB_DP_FC_HIT;
  //}

  memset(xf, 0, sizeof(*xf));
  xf->pm.phit |= LLB_DP_FC_HIT;
  xf->pm.tc = 1;

  return dp_ing_pkt_main(md, xf);
}

static int __always_inline
dp_ing_pkt_main(void *md, struct xfi *xf)
{
  LL_DBG_PRINTK("[PRSR] START cpu %d \n", bpf_get_smp_processor_id());
  LL_DBG_PRINTK("[PRSR] fi  %d\n", sizeof(*xf));
  LL_DBG_PRINTK("[PRSR] fm  %d\n", sizeof(xf->fm));
  LL_DBG_PRINTK("[PRSR] l2m %d\n", sizeof(xf->l2m));
  LL_DBG_PRINTK("[PRSR] l34m %d\n", sizeof(xf->l34m));
  LL_DBG_PRINTK("[PRSR] tm  %d\n", sizeof(xf->tm));
  LL_DBG_PRINTK("[PRSR] qm  %d\n", sizeof(xf->qm));

  if (xf->pm.phit & LLB_DP_FC_HIT) {
    dp_parse_d0(md, xf, 0);
  }

  /* Handle parser results */
  if (xf->pm.pipe_act & LLB_PIPE_REWIRE) {
    return dp_rewire_packet(md, xf);
  } else if (xf->pm.pipe_act & LLB_PIPE_RDR) {
    return dp_redir_packet(md, xf);
  }

  if (xf->pm.pipe_act & LLB_PIPE_PASS ||
      xf->pm.pipe_act & LLB_PIPE_TRAP) {
    xf->pm.rcode |= LLB_PIPE_RC_MPT_PASS;
    return DP_PASS;
  }

  return dp_ing_slow_main(md, xf);
}

static int __always_inline
dp_ing_slow_main(void *ctx,  struct xfi *xf)
{
  struct dp_fc_tacts *fa = NULL;
#ifdef HAVE_DP_FC
  int z = 0;

  fa = bpf_map_lookup_elem(&fcas, &z);
  if (!fa) return 0;

  /* No nonsense no loop */
  fa->ca.ftrap = 0;
  fa->ca.cidx = 0;
  fa->zone = 0;
  fa->its = bpf_ktime_get_ns();
#pragma clang loop unroll(full)
  for (z = 0; z < LLB_FCV4_MAP_ACTS; z++) {
    fa->fcta[z].ca.act_type = 0;
  }

  /* memset is too costly */
  /*memset(fa->fcta, 0, sizeof(fa->fcta));*/
#endif

  LL_DBG_PRINTK("[INGR] START--\n");

  /* If there are any packets marked for mirroring, we do
   * it here and immediately get it out of way without
   * doing any further processing
   */
  if (xf->pm.mirr != 0) {
    dp_do_mirr_lkup(ctx, xf);
    goto out;
  }

  dp_ing(ctx, xf);

  /* If there are pipeline errors at this stage,
   * we again skip any further processing
   */
  if (xf->pm.pipe_act || xf->pm.tc == 0) {
    goto out;
  }

  dp_ing_l2(ctx, xf, fa);

#ifdef HAVE_DP_FC
  /* fast-cache is used only when certain conditions are met */
  if (LL_PIPE_FC_CAP(xf)) {
    fa->zone = xf->pm.zone;
    dp_insert_fcv4(ctx, xf, fa);
  }
#endif

out:
  xf->pm.phit |= LLB_DP_RES_HIT;

  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);
  return DP_PASS;
}






SEC("tc_packet_hook2")
int tc_packet_func_slow(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_ing_ct_main(md, xf);
}

188  loxilb-ebpf/kernel/llb_kern_entry.c <<tc_packet_func_slow>>
             return dp_ing_ct_main(md, xf);

476  loxilb-ebpf/kernel/llb_kern_devif.c <<dp_ing_ct_main>>
             bpf_tail_call(ctx, &pgm_tbl, LLB_DP_FW_PGM_ID);

datapath tail call chain:

+--SEC("tc_packet_hook0")
   int tc_packet_func_fast(struct __sk_buff *md)
        |
        ->dp_ing_fc_main(md, xf);
	|      \
	|       ->__u32 idx = LLB_DP_PKT_SLOW_PGM_ID;
        |       ->bpf_tail_call(ctx, &pgm_tbl, idx);
	|            \
        |             ->SEC("tc_packet_hook1")
	|               int tc_packet_func(struct __sk_buff *md)
        |                      \
	|		        ->tc_packet_func__(md);
        |
	|
        ->tc_packet_func__(md);
          |
          ->dp_ing_pkt_main(md, xf);
              |
              ->dp_ing_slow_main(md, xf);
                |
                +->bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);
                      |
                      +> SEC("tc_packet_hook2")
                         int tc_packet_func_slow(struct __sk_buff *md)
                                |
                                +-->dp_ing_ct_main(md, xf);
                                      |
                                      +-> bpf_tail_call(ctx, &pgm_tbl, LLB_DP_FW_PGM_ID)
                                      |            |
                                      |            +-> SEC("tc_packet_hook3")
                                      |                int tc_packet_func_fw(struct __sk_buff *md)
                                      |
                                      +-> dp_do_nat(ctx, xf);


datapath init:

pkg/loxinet/loxinet.go

   loxiNetInit()
    |
    |                pkg/loxinet/dpebpf_linux.go
    +>mh.dpEbpf = DpEbpfInit(clusterMode, mh.rssEn, mh.eHooks, mh.lSockPolicy, mh.sockMapEn, mh.self, -1)
                     |
                     |   loxilb-ebpf/kernel/loxilb_libdp.c
                     +>C.loxilb_main(&cfg)
                           |
                           |
                           +>llb_xh_init(xh);
                                |
                                |xh->maps[LL_DP_PGM_MAP].map_name = "pgm_tbl";
                                |xh->maps[LL_DP_PGM_MAP].has_pb   = 0;
                                |xh->maps[LL_DP_PGM_MAP].max_entries = LLB_PGM_MAP_ENTRIES;
                                |
                                |
                                +>llb_dflt_sec_map2fd_all;

                                    if (i == LL_DP_PGM_MAP) {
                                     bpf_object__for_each_program(prog, bpf_obj) {
                                       bfd = bpf_program__fd(prog);

                                       section = bpf_program__section_name(prog);
                                       if (strcmp(section, "tc_packet_hook0") == 0) {
                                         key = 0;
                                       } else if (strcmp(section, "tc_packet_hook1") == 0) {
                                         key = 1;
                                       } else  if (strcmp(section, "tc_packet_hook2") == 0) {
                                         key = 2;
                                       } else  if (strcmp(section, "tc_packet_hook3") == 0) {
                                         key = 3;
                                       } else  if (strcmp(section, "tc_packet_hook4") == 0) {
                                         key = 4;
                                       } else  if (strcmp(section, "tc_packet_hook5") == 0) {
                                         key = 5;
                                       } else  if (strcmp(section, "tc_packet_hook6") == 0) {
                                         key = 6;
                                       } else  if (strcmp(section, "tc_packet_hook7") == 0) {
                                         key = 7;
                                       } else key = -1;
                                       if (key >= 0) {
                                         bpf_map_update_elem(fd, &key, &bfd, BPF_ANY);
                                       }
                                     }


loxilb-ebpf/common/llb_dpapi.h

#define LLB_DP_SUNP_PGM_ID2    (6)
#define LLB_DP_CRC_PGM_ID2     (5)
#define LLB_DP_CRC_PGM_ID1     (4)
#define LLB_DP_FW_PGM_ID       (3)
#define LLB_DP_CT_PGM_ID       (2)
#define LLB_DP_PKT_SLOW_PGM_ID (1)
#define LLB_DP_PKT_PGM_ID      (0)

grep -A1 'SEC' loxilb-ebpf/kernel/llb_kern_entry.c

SEC("xdp_packet_hook")
int  xdp_packet_func(struct xdp_md *ctx)
--
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
--
SEC("tc_packet_hook0")
int tc_packet_func_fast(struct __sk_buff *md)
--
SEC("tc_packet_hook1")
int tc_packet_func(struct __sk_buff *md)
--
SEC("tc_packet_hook2")
int tc_packet_func_slow(struct __sk_buff *md)
--
SEC("tc_packet_hook3")
int tc_packet_func_fw(struct __sk_buff *md)
--
SEC("tc_packet_hook4")
int tc_csum_func1(struct __sk_buff *md)
--
SEC("tc_packet_hook5")
int tc_csum_func2(struct __sk_buff *md)
--
SEC("tc_packet_hook6")
int tc_slow_unp_func(struct __sk_buff *md)
