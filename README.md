# Infinity Core: Linux Kernel Core LPEs

<p align="center">
  <img src="assets/tux.png" width="600" alt="tux">
</p>

# Abstract

This document describes six Linux kernel core vulnerabilities reported and patched by [Hyunwoo Kim (@v4bel)](https://x.com/v4bel).

The vulnerabilities covered here affect **Kernel Core** subsystems that have historically seen relatively few security issues. They enable LPE and container escape on Linux distributions, and some also allow an attacker to gain full root privileges from the Android `untrusted_app` domain.

This document excludes areas where vulnerabilities are common, such as networking, sockets, perf, and BPF, as well as bugs that require a user namespace to trigger.

> [!NOTE]
> After these vulnerabilities were reported to linux-distros@vs.openwall.org and the agreed embargo ended, the vulnerability details were posted to oss-security and this Infinity Core document was published.

# Vulnerability Summary

| Subsystem | CVE | Impact | Tested target | Introduced | Fixed | Stable 5.15 / 6.12 / 6.18 |
| --- | --- | --- | --- | --- | --- | --- |
| Timer | CVE-2026-98260 | LPE, Container escape, Android LPE | Ubuntu 26.04 7.0.0-30-generic, Galaxy S26 Ultra S948NKSS4BZIG | 55e8c8eb2c7b | acb03d388181 | unfixed / [6.12.112](https://git.kernel.org/stable/c/d9ae467e617ca29b825493a362bf0d75ad5f4ac3) / [6.18.54](https://git.kernel.org/stable/c/75aa08b93c65766040f9ca99f41ac85ad22596b6) |
| Signal | CVE-2026-98256 | LPE, Container escape | Ubuntu 26.04 7.0.0-30-generic | fb3bbcfe344e | d2710c8d938a | n/a / n/a / [6.18.54](https://git.kernel.org/stable/c/621c365739828900f32a0c1cdfe5387528a62176) |
| MM | CVE-2026-89754 | LPE, Container escape | Ubuntu 26.04 7.0.0-30-generic | 3b89863c3fa4 | aedf2efd1897 | n/a / n/a / [6.18.50](https://git.kernel.org/stable/c/895cd4ecbb2e03d7583103c65ee5adaae126ed6d) |
| Futex | CVE-2026-80775 | LPE, Container escape | Ubuntu 26.04 7.0.0-30-generic | d9b05321e21e | bde023808364 | n/a / n/a / [6.18.47](https://git.kernel.org/stable/c/86d12b34bafc9a4c271a9edefea88855a934d6e5) |
| Scheduler | CVE-2026-98385 | LPE, Container escape | Arch Linux 7.2.4-arch1-2 | df0d98475954 | 28f9c0e0a0b9, b636fef85bda | n/a / n/a / n/a |
| SLAB | CVE-2026-97941 | Kernel panic | Arch Linux 7.2.4-arch1-2 | ba7425312607 | 4a724bcf5d70 | n/a / n/a / n/a |

Stable column: first stable release containing the backported fix; *n/a*: the introducing commit is not in that branch; *unfixed*: affected, but no backport as of 5.15.223.

# Technical Analysis

## Timer (CVE-2026-98260): POSIX CPU timer UAF in exec()

<p align="center">
  <img src="assets/demo.gif" width="320" alt="demo">
</p>

**CVE-2026-98260** is a use-after-free vulnerability in the interaction between `exec()` in a thread other than the leader and POSIX CPU timer cleanup. If `exec()` fails after the TID of a thread with a CPU timer scoped to that thread has been exchanged, the node from the freed timer remains in the timerqueue of a live task. The node is referenced again during later task cleanup, corrupting kernel memory.

The public PoC turns this use-after-free into a full local privilege escalation. Starting as an unprivileged user, it exploits a vulnerable Ubuntu 26.04 `7.0.0-30-generic` system and launches a root shell.

This vulnerability can also be used to gain full root privileges on a **Samsung Galaxy S26 Ultra**, starting from the `untrusted_app` domain with no additional application privileges. The Android exploit will be published once the vulnerability has been patched on Galaxy devices or an unrelated third party has publicly released an exploit. (Android exploit hash: `713a294f72abc46b6e12633117d40e85629ca2b998698fd75c76e523e0d53253`)

For the detailed technical information, [see here](timer/).

## Signal (CVE-2026-98256): sigqueue UAF in exec()

**CVE-2026-98256** is a use-after-free vulnerability caused by a race between `exec()` in a thread other than the leader and cleanup of a private pending signal queue. While that thread inherits the old leader's TID, the path that flushes the dying leader's pending list without a lock and the path that follows the exchanged PID to link a signal entry into the new leader's queue can manipulate the same `sigqueue` concurrently. If the race corrupts the list links, the object containing the entry is freed while the entry remains on the new pending list. A later signal handling path references the freed entry again and corrupts kernel memory.

The public PoC uses the surviving entry as an oracle to detect when the freed object has been reclaimed, then exploits the path that dequeues the crafted signal queue to run a root shell from an unprivileged account.

For the detailed technical information, [see here](signal/).

## MM (CVE-2026-89754): OOB write in page table walk

**CVE-2026-89754** is an out-of-bounds write vulnerability caused by retry state leaking from a lower level of the page table walker, which makes `mincore()` walk the same PUD range more than once. When a race with `madvise(MADV_DONTNEED)` removes a PTE table, the lower level walker returns without resetting `ACTION_AGAIN`. The upper level walker interprets it as a request to retry the current PUD and walks the same range again. Because the `mincore()` result cursor has already advanced, it writes past the temporary buffer, which occupies one page, and into adjacent kernel memory.

The public PoC turns the repeated walk results into a controlled pattern spanning 40 bytes and places a credential slab in the physical page immediately after the temporary buffer. This write sets the UID and GID fields of `struct cred` to zero and runs a root shell from an unprivileged account.

For the detailed technical information, [see here](mm/).

## Futex (CVE-2026-80775): Private hash UAF in prctl()

**CVE-2026-80775** is a use-after-free vulnerability caused by a race between two tasks that share the same `mm_struct` while allocating the first reference counter for `FUTEX_PRIVATE_HASH`. If two tasks running through nested `vfork()` publish different per-CPU counter addresses to the same `mm->futex_ref`, a reference in the counter published first is lost from tracking. A live private futex hash is then freed during hash replacement, and a surviving bucket pointer is used to access the freed memory, corrupting kernel memory.

The public PoC reclaims the freed hash with a pipe ring, modifies a `pipe_buffer` flag, and overwrites the page cache of `/usr/bin/passwd` to achieve LPE.

For the detailed technical information, [see here](futex/).

## Scheduler (CVE-2026-98385): mm_struct UAF in scheduler cache accounting

**CVE-2026-98385** is a use-after-free vulnerability caused by the scheduler cache accounting code updating per-CPU statistics that belong to a task's old `mm_struct` without protecting its lifetime. Even after `exec()` replaces the address space on another CPU and frees the old statistics, the scheduler continues writing through the address it saved and corrupts reused kernel memory. The vulnerable path runs only when `CONFIG_SCHED_CACHE=y` and `sched_cache_active` is enabled at runtime. The topmost `SD_SHARE_LLC` domain must contain more than one CPU and have a wider parent domain, and `sysctl_sched_cache_user` must be nonzero. The public PoC assumes a topology with four vCPUs in which CPUs 0 and 1 share one LLC and CPUs 2 and 3 share another.

The public PoC uses the stale statistics write to corrupt the reference counter of a private futex hash, reclaims the freed hash with a pipe ring, and overwrites the page cache of `/usr/bin/newgrp` to achieve LPE.

For the detailed technical information, [see here](sched/).

## SLAB (CVE-2026-97941): Partial list corruption in object refill

**CVE-2026-97941** is an ABA race vulnerability caused by a race between optimistic freelist return and removal from a node partial list during SLUB object refill. While the refill CPU has detached a slab's freelist, another CPU can free and reallocate an object, allowing the slab to pass through the partial state and return to the same full state. The cmpxchg in the return path checks only the freelist and counters, so it does not detect that `slab_list` was linked into the node partial list in the meantime. It then links the same list node a second time, this time into the private list used by the refill path. When later removal from the partial list deletes the overwritten link, a stale entry remains in the node head and the list becomes corrupted. The next allocation removes the same entry again and dereferences a poison pointer.

The public PoC repeatedly creates this race with System V message objects, causing a poison pointer dereference and a fatal kernel panic. An LPE chain has not yet been written.

For the detailed technical information, [see here](slab/).
