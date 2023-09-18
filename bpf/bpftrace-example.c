                err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, NULL,
                                         link->link.prog->bpf_func);


diff --git a/lib/libxdp/libxdp.c b/lib/libxdp/libxdp.c
index 13e2651..3a96871 100644
--- a/lib/libxdp/libxdp.c
+++ b/lib/libxdp/libxdp.c
@@ -2771,7 +2771,7 @@ static int xdp_multiprog__link_prog(struct xdp_multiprog *mp,
                return -EOPNOTSUPP;
        }
 
-       pr_debug("Linking prog %s as multiprog entry %zu\n",
+       pr_warn("Linking prog %s as multiprog entry %zu\n",
                 xdp_program__name(prog), mp->num_links);
 
        err = try_snprintf(buf, sizeof(buf), "prog%zu", mp->num_links);
@@ -2800,6 +2800,7 @@ static int xdp_multiprog__link_prog(struct xdp_multiprog *mp,
                        goto err;
                }
 
+               pr_warn("set prog %s type to BPF_PROG_TYPE_EXT.\n", xdp_program__name(prog));
                bpf_program__set_type(prog->bpf_prog, BPF_PROG_TYPE_EXT);
                bpf_program__set_expected_attach_type(prog->bpf_prog, 0);
                err = xdp_program__load(prog);
@@ -2870,7 +2871,7 @@ attach_ok:
                goto err_free;
        }
 
-       pr_debug(
+       pr_warn(
                "Attached prog '%s' with priority %d in dispatcher entry '%s' with fd %d\n",
                xdp_program__name(new_prog), xdp_program__run_prio(new_prog),
                new_prog->attach_name, lfd);
@@ -2931,7 +2932,7 @@ static struct xdp_multiprog *xdp_multiprog__generate(struct xdp_program **progs,
        if (num_new_progs > MAX_DISPATCHER_ACTIONS)
                return ERR_PTR(-E2BIG);
 
-       pr_debug("Generating multi-prog dispatcher for %zu programs\n",
+       pr_warn("Generating multi-prog dispatcher for %zu programs\n",
                 num_new_progs);


 libxdp: Generating multi-prog dispatcher for 1 programs
 libxdp: Linking prog xdp_pass as multiprog entry 0
 libxdp: set prog xdp_pass type to BPF_PROG_TYPE_EXT.
 libxdp: Attached prog 'xdp_pass' with priority 10 in dispatcher entry 'prog0' with fd 12


Kernel/bpf/syscall.c

#define BPF_LINK_CREATE_LAST_FIELD link_create.kprobe_multi.cookies
static int link_create(union bpf_attr *attr, bpfptr_t uattr)
{

        case BPF_PROG_TYPE_EXT:
                ret = bpf_tracing_prog_attach(prog,
                                              attr->link_create.target_fd,
                                              attr->link_create.target_btf_id,
                                              attr->link_create.tracing.cookie);
                break;
}


static int bpf_tracing_prog_attach(struct bpf_prog *prog,
                                   int tgt_prog_fd,
                                   u32 btf_id,
                                   u64 bpf_cookie)
{

        if (tgt_prog_fd) {
                /* For now we only allow new targets for BPF_PROG_TYPE_EXT */
                if (prog->type != BPF_PROG_TYPE_EXT) {
                        err = -EINVAL;
                        goto out_put_prog;
                }

                tgt_prog = bpf_prog_get(tgt_prog_fd);
                if (IS_ERR(tgt_prog)) {
                        err = PTR_ERR(tgt_prog);
                        tgt_prog = NULL;
                        goto out_put_prog;
                }

                key = bpf_trampoline_compute_key(tgt_prog, NULL, btf_id);
        }


        link = kzalloc(sizeof(*link), GFP_USER);
        if (!link) {
                err = -ENOMEM;
                goto out_put_prog;
        }
        bpf_link_init(&link->link.link, BPF_LINK_TYPE_TRACING,
                      &bpf_tracing_link_lops, prog);
        link->attach_type = prog->expected_attach_type;
        link->link.cookie = bpf_cookie;



        err = bpf_trampoline_link_prog(&link->link, tr);
        if (err) {
                bpf_link_cleanup(&link_primer);
                link = NULL;
                goto out_unlock;
        }

}


Kernel/bpf/trampoline.c



int bpf_trampoline_link_prog(struct bpf_tramp_link *link, struct bpf_trampoline *tr)
{
        enum bpf_tramp_prog_type kind;
        struct bpf_tramp_link *link_exiting;
        int err = 0;
        int cnt = 0, i;
                
        kind = bpf_attach_type_to_tramp(link->link.prog);
        mutex_lock(&tr->mutex);
        if (tr->extension_prog) {
                /* cannot attach fentry/fexit if extension prog is attached.
                 * cannot overwrite extension prog either.
                 */
                err = -EBUSY;
                goto out;
        }
        
        for (i = 0; i < BPF_TRAMP_MAX; i++)
                cnt += tr->progs_cnt[i];

        if (kind == BPF_TRAMP_REPLACE) {
                /* Cannot attach extension if fentry/fexit are in use. */
                if (cnt) {
                        err = -EBUSY;
                        goto out;
                }
                tr->extension_prog = link->link.prog;
                err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, NULL,  <===
                                         link->link.prog->bpf_func);
                goto out;
        }


Arch/x86/net/bpf_jit_comp.c

int bpf_arch_text_poke(void *ip, enum bpf_text_poke_type t,
                       void *old_addr, void *new_addr)
{                       
        if (!is_kernel_text((long)ip) &&
            !is_bpf_text_address((long)ip))
                /* BPF poking in modules is not supported */
                return -EINVAL;
                                         
        /*      
         * See emit_prologue(), for IBT builds the trampoline hook is preceded
         * with an ENDBR instruction.
         */     
        if (is_endbr(*(u32 *)ip))
                ip += ENDBR_INSN_SIZE;
        
        return __bpf_arch_text_poke(ip, t, old_addr, new_addr);
}               



int xdp_dispatcher(struct xdp_md * ctx):
bpf_prog_90f686eb86991928_xdp_dispatcher:
; int xdp_dispatcher(struct xdp_md *ctx)
   0:	jmp    0x0000000000000ef8
   5:	xchg   %ax,%ax
   7:	push   %rbp
   8:	mov    %rsp,%rbp
   b:	push   %rbx
   c:	push   %r13
   e:	push   %r14
  10:	mov    %rdi,%rbx
  13:	mov    $0x2,%eax

int xdp_dispatcher(struct xdp_md * ctx):
; int xdp_dispatcher(struct xdp_md *ctx)
   0: (bf) r6 = r1
   1: (b7) r0 = 2
; __u8 num_progs_enabled = conf.num_progs_enabled;
   2: (18) r8 = map[id:31][0]+0
   4: (71) r7 = *(u8 *)(r8 +2)
; if (num_progs_enabled < 1)
   5: (15) if r7 == 0x0 goto pc+11
; ret = prog0(ctx);
   6: (bf) r1 = r6
   7: (85) call pc+10#bpf_prog_4d74e362024fac8e_prog0
; if (!((1U << ret) & conf.chain_call_actions[0]))
   8: (61) r1 = *(u32 *)(r8 +4)


int xdp_pass(struct xdp_md * ctx):
bpf_prog_3b185187f1855c4c_xdp_pass:
; return XDP_PASS;
   0:	nopl   0x0(%rax,%rax,1)
   5:	xchg   %ax,%ax
   7:	push   %rbp
   8:	mov    %rsp,%rbp
   b:	mov    $0x2,%eax
  10:	leave  
  11:	ret    
  12:	int3   



root@r220:~# bpftrace -e 'kfunc:__bpf_arch_text_poke { printf("in here\n"); @[kstack] = count(); }'
Attaching 1 probe...
in here
in here
in here
in here
^C

@[
    bpf_prog_6deef7357e7b4530+17376
    bpf_prog_6deef7357e7b4530+17376
    ftrace_trampoline+8267
    __bpf_arch_text_poke+5
    __bpf_trampoline_link_prog+428
    bpf_trampoline_link_prog+44
    bpf_tracing_prog_attach+978
    link_create+216
    __sys_bpf+1943
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1
@[
    bpf_prog_6deef7357e7b4530+17376
    bpf_prog_6deef7357e7b4530+17376
    ftrace_trampoline+8267
    __bpf_arch_text_poke+5
    __bpf_trampoline_link_prog+428
    bpf_trampoline_link_prog+44
    bpf_tracing_prog_attach+978
    bpf_raw_tp_link_attach+429
    __sys_bpf+353
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1
@[
    bpf_prog_6deef7357e7b4530+17376
    bpf_prog_6deef7357e7b4530+17376
    ftrace_trampoline+8267
    __bpf_arch_text_poke+5
    bpf_trampoline_unlink_prog+266
    bpf_tracing_link_release+22
    bpf_link_free+85
    bpf_link_put_deferred+18
    process_one_work+543
    worker_thread+80
    kthread+238
    ret_from_fork+44
]: 2


struct bpf_ksym {
        unsigned long            start;
        unsigned long            end;
        char                     name[KSYM_NAME_LEN];
        struct list_head         lnode;
        struct latch_tree_node   tnode;
        bool                     prog;
};

enum bpf_tramp_prog_type {
        BPF_TRAMP_FENTRY,
        BPF_TRAMP_FEXIT,
        BPF_TRAMP_MODIFY_RETURN,
        BPF_TRAMP_MAX,
        BPF_TRAMP_REPLACE, /* more than MAX */
};

struct bpf_tramp_image {        
        void *image;            
        struct bpf_ksym ksym;   
        struct percpu_ref pcref;
        void *ip_after_call;
        void *ip_epilogue;
        union {
                struct rcu_head rcu;
                struct work_struct work; 
        };
};      


int arch_prepare_bpf_trampoline(struct bpf_tramp_image *im, void *image, void *image_end,
                                const struct btf_func_model *m, u32 flags,
                                struct bpf_tramp_links *tlinks,
                                void *func_addr)
{  
\

static int bpf_tracing_prog_attach(struct bpf_prog *prog,
                                   int tgt_prog_fd,
                                   u32 btf_id,
                                   u64 bpf_cookie)
{



root@r220:/usr/src/bpf-next# bpftrace -e 'kprobe:bpf_tracing_prog_attach { printf("opening: %s\n",  ((struct bpf_prog *)arg0)->aux->name);  @[kstack] = count(); }'
Attaching 1 probe...
opening: xdp_pass
opening: xdp_pass
opening: xdp_pass
^C

@[
    bpf_tracing_prog_attach+1
    __sys_bpf+353
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1
@[
    bpf_tracing_prog_attach+1
    __sys_bpf+1943
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 2



root@r220:/usr/src/bpf-next# bpftrace -e 'kprobe:__bpf_arch_text_poke { printf("text poke type: %d\n", arg1); @[kstack] = count(); }'

Attaching 1 probe...



text poke type: 1
text poke type: 1
text poke type: 1
^C

@[
    __bpf_arch_text_poke+1
    bpf_trampoline_unlink_prog+266
    bpf_tracing_link_release+22
    bpf_link_free+85
    bpf_link_put_deferred+18
    process_one_work+543
    worker_thread+80
    kthread+238
    ret_from_fork+44
]: 1
@[
    __bpf_arch_text_poke+1
    __bpf_trampoline_link_prog+428
    bpf_trampoline_link_prog+44
    bpf_tracing_prog_attach+978
    bpf_raw_tp_link_attach+429
    __sys_bpf+353
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1
@[
    __bpf_arch_text_poke+1
    __bpf_trampoline_link_prog+428
    bpf_trampoline_link_prog+44
    bpf_tracing_prog_attach+978
    link_create+216
    __sys_bpf+1943
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1


root@r220:/usr/src/bpf-next# bpftrace -e 'kprobe:bpf_tracing_prog_attach { printf("prog: %s attached to: %s\n",  ((struct bpf_prog *)arg0)->aux->name, ((struct bpf_prog *)arg0)->aux->dst_prog->aux->name);  @[kstack] = count(); }'
Attaching 1 probe...



prog: xdp_pass attached to: xdp_pass
prog: xdp_pass attached to: xdp_dispatcher
^C

@[
    bpf_tracing_prog_attach+1
    __sys_bpf+353
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1
@[
    bpf_tracing_prog_attach+1
    __sys_bpf+1943
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1


root@r220:/usr/src/bpf-next# bpftrace -e 'kprobe:bpf_tracing_prog_attach { printf("prog: %s\n target prog: %s\n stack depth: %d\n",  ((struct bpf_prog *)arg0)->aux->name, ((struct bpf_prog *)arg0)->aux->dst_prog->aux->name, ((struct bpf_prog *)arg0)->aux->stack_depth);  @[kstack] = count(); }'
Attaching 1 probe...





prog: xdp_pass
 target prog: xdp_pass
 stack depth: 0
prog: xdp_pass
 target prog: xdp_dispatcher
 stack depth: 0
^C

@[
    bpf_tracing_prog_attach+1
    __sys_bpf+1943
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1
@[
    bpf_tracing_prog_attach+1
    __sys_bpf+353
    __x64_sys_bpf+26
    do_syscall_64+92
    entry_SYSCALL_64_after_hwframe+114
]: 1

bpftrace -e 'kprobe:bpf_tracing_prog_attach { printf("prog: %s\n target prog: %s\n destination trampoline: %d\n",  ((struct bpf_prog *)arg0)->aux->name, ((struct bpf_prog *)arg0)->aux->dst_prog->aux->name, ((struct bpf_prog *)arg0)->aux->dst_trampoline->key);  }'



bpftrace -e 'kprobe:bpf_tracing_prog_attach { printf("prog: %s\n target prog: %s\n target prog id: %d\n destination trampoline: %d\n",  ((struct bpf_prog *)arg0)->aux->name, ((struct bpf_prog *)arg0)->aux->dst_prog->aux->name, ((struct bpf_prog *)arg0)->aux->dst_prog->aux->id, ((struct bpf_prog *)arg0)->aux->dst_trampoline->key);  }'



kprobe:vfs_open
{
	printf("open path: %s\n", str(((struct path *)arg0)->dentry->d_name.name));
}


struct path {
        struct vfsmount *mnt;
        struct dentry *dentry;
} __randomize_layout;

struct dentry {
        /* RCU lookup touched fields */
        unsigned int d_flags;           /* protected by d_lock */
        seqcount_spinlock_t d_seq;      /* per dentry seqlock */
        struct hlist_bl_node d_hash;    /* lookup hash list */
        struct dentry *d_parent;        /* parent directory */
        struct qstr d_name;
        struct inode *d_inode;          /* Where the name belongs to - NULL is
                                         * negative */


struct qstr { 
        union {
                struct {
                        u32 hash;
                        u32 len;
                };
                u64 hash_len;
        };
        const unsigned char *name;
};      

