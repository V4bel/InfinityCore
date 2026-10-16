<p align="center">
  <img src="../assets/tux.png" width="550" alt="tux">
</p>

# Intro

CVE-2026-97941 is a list corruption vulnerability caused by a race between returning a freelist and removing an entry from the node partial list during object refill in SLUB. The `slab_list` linked into the node partial list is overwritten with links for the private refill list, leaving the removed entry reachable from the head of the node partial list.

The public PoC demonstrates only the corruption of a SLUB list from an unprivileged user account and a fatal kernel panic on a vulnerable Arch Linux `7.2.4-arch1-2` system. It does not include a local privilege escalation chain.

This document explains the root cause of the vulnerability and the trigger sequence of the Arch Linux PoC.

# Background

SLUB manages kernel objects of the same size in units of `struct slab`. The `freelist` of each slab links its free objects, while counters including `inuse` describe its current usage state. A slab is full when `freelist` is `NULL` and every object is in use. A slab with free objects is partial.

The `struct kmem_cache_node` of each NUMA node stores partial slabs in `n->partial`. Each slab is linked into this list through its `slab_list`, and additions and removals are serialized by `n->list_lock`.

The per-CPU sheaf in Linux 7.2 refills multiple objects at once. `get_partial_node_bulk()` takes `n->list_lock` and moves slabs from the node partial list to a private list named `pc.slabs`. After the lock is released, `__refill_objects_node()` detaches the freelist from each slab and fills the sheaf with only the required objects.

If detached objects remain, the refill path checks whether the slab is still full and returns the remaining freelist. The vulnerable code uses cmpxchg to check only `{freelist, counters}`. It does not protect against another CPU linking the `slab_list` of the same slab back into the node partial list.

# Root Cause

In the vulnerable Arch Linux source, `__refill_objects_node()` takes a slab from the private list and detaches its entire freelist with `get_freelist_nofreeze()`. If objects remain after the sheaf is filled, it calls `__slab_try_return_freelist()` and links the slab back into `pc.slabs` on success.

```c
static unsigned int
__refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
		      unsigned int max, struct kmem_cache_node *n,
		      bool allow_spin)
{
	struct partial_bulk_context pc;
	struct slab *slab, *slab2;
	unsigned int refilled = 0;
	unsigned long flags;
	void *object;

	[...]
	if (!get_partial_node_bulk(s, n, &pc, allow_spin))
		return 0;

	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {

		unsigned int count;

		list_del(&slab->slab_list);

		object = get_freelist_nofreeze(s, slab, &count);

		while (count && refilled < max) {
			p[refilled] = object;
			object = get_freepointer(s, object);
			maybe_wipe_obj_freeptr(s, p[refilled]);

			refilled++;
			count--;
		}

		[...]
		if (unlikely(count)) {
			void *head = object;
			void *tail;

			if (__slab_try_return_freelist(s, slab, head, count)) {
				list_add(&slab->slab_list, &pc.slabs); // <=[1]
				break;
			}
			[...]
		}
		[...]
	}
	[...]
}
```

`[1]` links `slab_list` into the private list without taking `n->list_lock`. This operation assumes that the slab does not belong to another list if the optimistic return below succeeds.

```c
static bool __slab_try_return_freelist(struct kmem_cache *s, struct slab *slab,
				       void *head, int cnt)
{
	struct freelist_counters old, new;

	old.freelist = slab->freelist;
	old.counters = slab->counters;

	if (old.freelist)
		return false;

	new.freelist = head;
	new.counters = old.counters;
	new.inuse -= cnt;

	if (!slab_update_freelist(s, slab, &old, &new, "__slab_try_return_freelist")) // <=[2]
		return false;

	return true;
}
```

The cmpxchg at `[2]` updates only `freelist` and the counters. After refill detaches the freelist, another CPU can free one object and allocate it again, moving the slab through a partial state and back to a full state. The values appear identical to the initial state, so `[2]` succeeds even though `slab_list` was linked into the node partial list in the meantime.

When an object from a full slab is freed on a remote CPU, `__slab_free()` takes `n->list_lock` and adds the slab to the node partial list.

```c
static void __slab_free(struct kmem_cache *s, struct slab *slab,
			void *head, void *tail, int cnt,
			unsigned long addr)

{
	bool was_full;
	struct freelist_counters old, new;
	struct kmem_cache_node *n = NULL;
	unsigned long flags;
	bool on_node_partial;

	[...]
	do {
		[...]
		old.freelist = slab->freelist;
		old.counters = slab->counters;

		was_full = (old.freelist == NULL);
		[...]
		if (!new.inuse || was_full) {
			n = get_node(s, slab_nid(slab));
			[...]
			spin_lock_irqsave(&n->list_lock, flags);
			on_node_partial = slab_test_node_partial(slab);
		}

	} while (!slab_update_freelist(s, slab, &old, &new, "__slab_free"));
	[...]
	if (unlikely(was_full)) {
		add_partial(n, slab, ADD_TO_TAIL);              // <=[3]
		stat(s, FREE_ADD_PARTIAL);
	}
	spin_unlock_irqrestore(&n->list_lock, flags);
	return;
	[...]
}
```

At `[3]`, the slab is linked into `n->partial`. If another CPU then allocates the last free object from this slab, `get_from_partial_node()` attempts to remove the slab from the partial list while holding the same lock.

```c
static void *get_from_partial_node(struct kmem_cache *s,
				   struct kmem_cache_node *n,
				   gfp_t gfp_flags,
				   const struct slab_alloc_context *ac)
{
	struct slab *slab, *slab2;
	unsigned long flags;
	void *object = NULL;

	[...]
	if (alloc_flags_allow_spinning(ac->alloc_flags))
		spin_lock_irqsave(&n->list_lock, flags);
	else if (!spin_trylock_irqsave(&n->list_lock, flags))
		return NULL;
	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {

		struct freelist_counters old, new;

		[...]
		do {
			old.freelist = slab->freelist;
			old.counters = slab->counters;

			new.freelist = get_freepointer(s, old.freelist);
			new.counters = old.counters;
			new.inuse++;

		} while (!__slab_update_freelist(s, slab, &old, &new, "get_from_partial_node"));

		object = old.freelist;
		if (!new.freelist)
			remove_partial(n, slab);                   // <=[4]

		break;
	}
	spin_unlock_irqrestore(&n->list_lock, flags);
	return object;
}

```

The condition at `[4]` is based on the result of the cmpxchg that took the last object. The actual removal is performed by the following `remove_partial()`.

```c
static inline void remove_partial(struct kmem_cache_node *n,
					struct slab *slab)
{
	lockdep_assert_held(&n->list_lock);
	list_del(&slab->slab_list);                           // <=[5]
	clear_node_partial_state(n, slab);
}
```

Immediately after the last object is taken, the refill CPU can return the remaining freelist at `[2]` and link the same `slab_list` into the private list at `[1]`. In that case, `[5]` uses the overwritten private list links to remove the entry and replaces them with poison values, but the head of the node partial list still points to the slab. The next allocation removes this stale entry again and dereferences a poison pointer.

# Triggering

The PoC fills the `msg_msg-1k` cache with SysV message objects and assigns three CPUs to perform refill, remote freeing, and node partial allocation. The target environment is configured with four vCPUs, where CPUs 0 and 2 belong to NUMA node 0, CPU 1 belongs to node 1, and `slab_strict_numa` is present on the kernel command line.

## 1. Preparing the target slab and NUMA path

The `msgsnd()` payload in the PoC is 900 bytes. On the target kernel, `struct msg_msg` occupies 48 bytes, so the resulting allocation of 948 bytes uses the `msg_msg-1k` cache. The default sheaf capacity of this cache is 12, and the PoC also sets the refill batch to 12 objects.

```c
#define MESSAGE_FREE_CPU 0
#define REFILL_CPU 1
#define ALLOCATION_CPU 2
#define MESSAGE_TEXT_SIZE 900
#define REFILL_BATCH_SIZE 12
#define INITIAL_REFILL_MESSAGE_COUNT 96
[...]
#define TRIAL_COUNT 20004

[...]

static int bind_memory_to_node_one(void)
{
	unsigned long node_mask = 2;

	return (int)syscall(SYS_set_mempolicy, MPOL_BIND, &node_mask,
			    8UL * sizeof(node_mask));              // <=[6]
}
```

`[6]` restricts the memory allocation policy of the allocation worker pinned to CPU 2 to node 1. With `slab_strict_numa` enabled, the local sheaf of CPU 2 does not match the requested node, so the allocation enters the slow path for node 1. Freeing an object from node 1 on CPU 0 also uses `__slab_free()` instead of a per-CPU sheaf because the object is remote.

The main refill thread runs with `SCHED_IDLE` on CPU 1. The preemption worker on the same CPU uses a normal scheduling policy, wakes at a specified time to interrupt refill, and runs until CPU 2 publishes the allocation gate.

## 2. Racing refill against partial list removal

In each trial, CPU 0 frees a known message from node 1 with `msgrcv()` 8 microseconds after the reference time. This operation changes the target slab from full to partial and places it on the node partial list.

CPU 2 checks that the remote free has completed 25 microseconds after the reference time and publishes the allocation gate. It then waits 1,901 TSC cycles before allocating a new message.

```c
static _Noreturn void *message_free_worker(void *argument)
{
	[...]
	spin_until_ns(atomic_load_explicit(&preemption_wakeup_ns,
					   memory_order_acquire) +
		      MESSAGE_FREE_DELAY_NS);
	if (free_allocation_message_at_slot(ALLOCATION_SLOT_STRIDE *
					    (trial - 1)) !=
	    MESSAGE_TEXT_SIZE)                              // <=[7]
		atomic_store_explicit(&operation_failed, 1,
				      memory_order_relaxed);
	[...]
}

static _Noreturn void *allocation_worker(void *argument)
{
	[...]
	spin_until_ns(atomic_load_explicit(&allocation_start_ns,
					   memory_order_acquire));
	wait_for_sequence(&message_free_done_sequence, trial);
	atomic_store_explicit(&allocation_gate_time_ns,
			      monotonic_time_ns(),
			      memory_order_relaxed);
	tsc_deadline = rdtsc_ordered() + ALLOCATION_DELAY_CYCLES;
	atomic_store_explicit(&allocation_gate_sequence, trial,
			      memory_order_release);
	spin_until_tsc(tsc_deadline);
	if (send_message_at_slot(allocation_queues, base_slot + 2,
				 &allocation_message))              // <=[8]
		atomic_store_explicit(&operation_failed, 1,
				      memory_order_relaxed);
	[...]
}
```

When `[7]` returns one object to the full slab, the node partial insertion at `[3]` occurs. `[8]` takes that object again, creating a window between the cmpxchg in `get_from_partial_node()` and `remove_partial()`.

After observing the gate, the preemption worker on CPU 1 enters a futex sleep and the main refill thread resumes. The main thread continues the interrupted batch of 12 `msgsnd()` calls, racing the freelist return in `__slab_try_return_freelist()` against the partial list removal on CPU 2. In each trial, the allocation worker arms a timerfd for a single expiration and varies its expiration offset from 1,000 to 6,000 nanoseconds to repeatedly exercise this race window.

## 3. Triggering a kernel panic with a stale partial entry

After the critical allocation, CPU 2 allocates four more messages from the same cache.

```c
	[...]
	wait_for_sequence(&allocation_followup_fill_request_sequence,
			  trial);
	for (int i = 3; i <= 6; i++) {
		if (send_message_at_slot(allocation_queues, base_slot + i,
					 &allocation_message))          // <=[9]
			atomic_store_explicit(&operation_failed, 1,
					      memory_order_relaxed);
	}
	atomic_store_explicit(&allocation_followup_fill_done_sequence,
			      trial,
			      memory_order_release);
	[...]
```

The subsequent allocations at `[9]` consume the corrupted node partial list again. As `remove_partial()` processes a `slab_list` that has already been removed, it dereferences links corrupted with `LIST_POISON`, causing a general protection fault in `get_from_partial_node()`. The final result observed with the PoC is a fatal kernel panic caused by this fault.

# Patch

This vulnerability was fixed by upstream commit `4a724bcf5d70`. The patch changes `__slab_try_return_freelist()` to perform the freelist cmpxchg and the insertion into the node partial list while holding `n->list_lock`.

The essential change in the upstream patch is shown below.

```diff
diff --git a/mm/slub.c b/mm/slub.c
index 7a7e906a0e44..54ec12503357 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5680,10 +5680,12 @@ static noinline void free_to_partial_list(
  *
  * Fail if the slab isn't full anymore due to a concurrent free.
  */
-static bool __slab_try_return_freelist(struct kmem_cache *s, struct slab *slab,
-				       void *head, int cnt)
+static bool __slab_try_return_freelist(struct kmem_cache *s,
+				       struct kmem_cache_node *n,
+				       struct slab *slab, void *head, int cnt)
 {
 	struct freelist_counters old, new;
+	unsigned long flags;
 
 	old.freelist = slab->freelist;
 	old.counters = slab->counters;
@@ -5695,9 +5697,15 @@ static bool __slab_try_return_freelist(struct kmem_cache *s, struct slab *slab,
 	new.counters = old.counters;
 	new.inuse -= cnt;
 
-	if (!slab_update_freelist(s, slab, &old, &new, "__slab_try_return_freelist"))
+	spin_lock_irqsave(&n->list_lock, flags);
+
+	if (!slab_update_freelist(s, slab, &old, &new, "__slab_try_return_freelist")) {
+		spin_unlock_irqrestore(&n->list_lock, flags);
 		return false;
+	}
 
+	add_partial(n, slab, ADD_TO_TAIL);
+	spin_unlock_irqrestore(&n->list_lock, flags);
 	return true;
 }
 
@@ -7297,10 +7305,8 @@ __refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int mi
 			void *head = object;
 			void *tail;
 
-			if (__slab_try_return_freelist(s, slab, head, count)) {
-				list_add(&slab->slab_list, &pc.slabs);
+			if (__slab_try_return_freelist(s, n, slab, head, count))
 				break;
-			}
 
 			do {
 				tail = object;
@@ -7313,7 +7319,7 @@ __refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int mi
 			break;
 	}
 
-	if (!list_empty(&pc.slabs)) {
+	if (unlikely(!list_empty(&pc.slabs))) {
 		spin_lock_irqsave(&n->list_lock, flags);
 
 		list_for_each_entry(slab, &pc.slabs, slab_list)
```

The cmpxchg for the optimistic return and `add_partial()` now execute in the same `n->list_lock` critical section. A partial list removal on another CPU cannot occur between the two operations, and the refill path no longer links `slab_list` back into the private list, so no stale entry remains.
