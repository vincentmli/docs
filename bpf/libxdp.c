     libxdp user space

| lib/libxdp/libxdp.c
+-struct xdp_program {
|       /* one of prog or prog_fd should be set */
|       struct bpf_program *bpf_prog;
|       struct bpf_object *bpf_obj;
|       struct btf *btf;
|       enum bpf_prog_type prog_type;
|       int prog_fd;
|       int link_fd;
|       char *prog_name;
|       char *attach_name;
|       __u32 prog_id;
|       unsigned int run_prio;
|       unsigned int chain_call_actions; /* bitmap */
|       /* for building list of attached programs to multiprog */
|       struct xdp_program *next;
|  };
|
+-struct xdp_multiprog {
|       struct xdp_dispatcher_config config;
|       struct xdp_program *main_prog;  /* dispatcher or legacy prog pointer */
|       struct xdp_program *first_prog; /* uses xdp_program->next to build a list */
|
+----xdp_program__attach(struct xdp_program *prog, int ifindex,...)
|    |
     +--xdp_program__attach_multi(&prog, num_progs, ifindex,...)
           |
           +--xdp_multiprog__generate(progs, num_progs, ifindex, old_mp,...)
                +-dispatcher = __xdp_program__find_file("xdp-dispatcher.o",...
                +-mp->main_prog = dispatcher;
                +-xdp_multiprog__load(mp);
                | +-xdp_program__load(mp->main_prog)
                |
                +-xdp_multiprog__link_prog(mp, new_progs[i]);
                +-----btf_id = find_prog_btf_id(attach_func, mp->main_prog->prog_fd);
                +-----bpf_program__set_attach_target(prog->bpf_prog, mp->main_prog->prog_fd, attach_func);
                +-----bpf_program__set_type(prog->bpf_prog, BPF_PROG_TYPE_EXT); // BPF_PROG_TYPE_EXT
                +-----bpf_program__set_expected_attach_type(prog->bpf_prog, 0); // 0 
                +-----xdp_program__load(prog);
                +-----new_prog = xdp_program__clone(prog, 0);
                +-----opts.target_btf_id = btf_id;
                +-----lfd = bpf_link_create(new_prog->prog_fd, mp->main_prog->prog_fd, 0, &opts);
                      if (lfd < 0) {
                          lfd = bpf_raw_tracepoint_open(NULL, new_prog->prog_fd);
                      }

| lib/libbpf/src/bpf.c
+---int bpf_link_create(int prog_fd, int target_fd,
|            enum bpf_attach_type attach_type,
|            const struct bpf_link_create_opts *opts)
|        ...SNIP...
+-------- fd = sys_bpf_fd(BPF_LINK_CREATE, &attr, attr_sz); //bpf syscall with BPF_LINK_CREATE command


kernel space

+-kernel/bpf/syscall.c
|
+---static int __sys_bpf(int cmd, bpfptr_t uattr, unsigned int size)
|   {
|        switch (cmd) {
|        case BPF_LINK_CREATE:
|                err = link_create(&attr, uattr);
|                break;
|        }
|   }
|
+---static int link_create(union bpf_attr *attr, bpfptr_t uattr)
|   {
+-------prog = bpf_prog_get(attr->link_create.prog_fd);
+-------ret = bpf_prog_attach_check_attach_type(prog,
|                           attr->link_create.attach_type);
|       switch (prog->type) {
+-------case BPF_PROG_TYPE_EXT:
+-------ret = bpf_tracing_prog_attach(prog,
|                             attr->link_create.target_fd,
|                             attr->link_create.target_btf_id,
|                             attr->link_create.tracing.cookie);
|       }
|   }
|
|
+----static int bpf_tracing_prog_attach(struct bpf_prog *prog,
|                                  int tgt_prog_fd,
|                                  u32 btf_id,
|                                  u64 bpf_cookie)
|    {
|        struct bpf_link_primer link_primer;
|        struct bpf_prog *tgt_prog = NULL;
|        struct bpf_trampoline *tr = NULL;
|        struct bpf_tracing_link *link;
|        u64 key = 0;
|
+--------err = bpf_trampoline_link_prog(&link->link, tr);
|    }
|
| kernel/bpf/trampoline.c
|
+----int bpf_trampoline_link_prog(struct bpf_tramp_link *link, struct bpf_trampoline *tr)
|    {
+--------err = __bpf_trampoline_link_prog(link, tr);
|    }
|
|
|    static int __bpf_trampoline_link_prog(struct bpf_tramp_link *link, struct bpf_trampoline *tr)
|    {
|         enum bpf_tramp_prog_type kind;
|         struct bpf_tramp_link *link_exiting;
|
+---------kind = bpf_attach_type_to_tramp(link->link.prog);
|         if (tr->extension_prog)
|               /* cannot attach fentry/fexit if extension prog is attached.
|                * cannot overwrite extension prog either.
|                */
|               return -EBUSY;
|
|
+----------if (kind == BPF_TRAMP_REPLACE) {
|               /* Cannot attach extension if fentry/fexit are in use. */
|               if (cnt)
|                       return -EBUSY;
|               tr->extension_prog = link->link.prog;
+---------------return bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, NULL, //BPF_MOD_JUMP
|                                         link->link.prog->bpf_func);
|          }
|     }
|
|  arch/x86/net/bpf_jit_comp.c
|
+----int bpf_arch_text_poke(void *ip, enum bpf_text_poke_type t,
|                      void *old_addr, void *new_addr)
|    {
|       if (!is_kernel_text((long)ip) &&
|           !is_bpf_text_address((long)ip))
|               /* BPF poking in modules is not supported */
|               return -EINVAL;
|       
|       /*
|        * See emit_prologue(), for IBT builds the trampoline hook is preceded
|        * with an ENDBR instruction.
|        */
|       if (is_endbr(*(u32 *)ip))
|               ip += ENDBR_INSN_SIZE;
|
+-------return __bpf_arch_text_poke(ip, t, old_addr, new_addr);
|    }
|
+----static int __bpf_arch_text_poke(void *ip, enum bpf_text_poke_type t,
|                               void *old_addr, void *new_addr)
|    {
|       const u8 *nop_insn = x86_nops[5];
|       u8 old_insn[X86_PATCH_SIZE];
|       u8 new_insn[X86_PATCH_SIZE];
|       u8 *prog;
|       int ret;
|
|       memcpy(old_insn, nop_insn, X86_PATCH_SIZE);
|       if (old_addr) {
|               prog = old_insn;
|               ret = t == BPF_MOD_CALL ?
|                     emit_call(&prog, old_addr, ip) :
+---------------------emit_jump(&prog, old_addr, ip); //BPF_MOD_JUMP
|               if (ret)
|                       return ret;
|       }
|
|       memcpy(new_insn, nop_insn, X86_PATCH_SIZE);
|       if (new_addr) {
|               prog = new_insn;
|               ret = t == BPF_MOD_CALL ?
|                     emit_call(&prog, new_addr, ip) :
+---------------------emit_jump(&prog, new_addr, ip); //BPF_MOD_JUMP
|               if (ret)
|                       return ret;
|       }
+----}



AF_XDP

| lib/libxdp/xsk.c
|
+---xsk_socket__create(struct xsk_socket **xsk_ptr, const char *ifname,...)
|
+------xsk_socket__create_shared(xsk_ptr, ifname, queue_id, umem,...)
|
+---------__xsk_setup_xdp_prog(xsk, NULL); //Added by libxdp
+-------------const char *fallback_prog = "xsk_def_xdp_prog_5.3.o";
+-------------const char *default_prog = "xsk_def_xdp_prog.o"; // prog attached to dispatcher
|
+-------------xdp_program__attach(ctx->xdp_prog, ctx->ifindex,...)
|


Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
eno2                   xdp_dispatcher    native   739  90f686eb86991928
 =>              20     xsk_def_prog              748  8f9c40757cb0a6a2  XDP_PASS


root@r210:/usr/src/bpf-next/tools/bpf/bpftool# bpftool p d j i 739
int xdp_dispatcher(struct xdp_md * ctx):
bpf_prog_17d608957d1f805a_xdp_dispatcher:
; int xdp_dispatcher(struct xdp_md *ctx)
   0:	jmp    0x00000000000020cc <===========JUMP
   5:	xchg   %ax,%ax
   7:	push   %rbp
   8:	mov    %rsp,%rbp
   b:	push   %rbx
   c:	push   %r13
   e:	push   %r14
  10:	mov    %rdi,%rbx
  13:	mov    $0x2,%eax

