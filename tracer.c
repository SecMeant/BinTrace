#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>

#include <sys/personality.h>

#define BLOCK_SIZE 4096ull
#define BLOCK_HIST_ENTRY_COUNT ((BLOCK_SIZE - sizeof(struct trace_block_header_t)) / sizeof(hist_entry_t))
#define CALC_HIST_SIZE_IN_BLOCK(block_size) (((block_size)- sizeof(struct trace_block_t)) / sizeof(hist_entry_t)) ;

#define BREAK_OPCODE 0xcc
#define NOP_OPCODE 0x90

typedef uint8_t hist_entry_t;

struct trace_block_t;

struct trace_block_header_t
{
	struct trace_block_t *next;
	size_t hist_size;
};

// Block that has the information about execution history
struct trace_block_t
{
	struct trace_block_header_t hdr;
	hist_entry_t hist[0];
};

struct trace_context_t
{
	struct trace_block_t *master_tb;
	struct trace_block_t *current_tb;
	size_t offset;
} trace_ctx;

struct patch_entry_t
{
	void *addr;
	uint8_t patch;
};

// Information about patched locations and how to restore them.
struct patch_info_t
{
	struct patch_entry_t *entry;
	size_t size;
} patch_info;

struct process_t
{
	int pid;
	int status;
};

struct process_t create_process(const char *path, char *const argv[])
{
	struct process_t proc;

	proc.pid = fork();
	proc.status = 0;

	if (proc.pid < 0) {
		fprintf(stderr, "Failed to fork %s\n", path);
		return proc;
	}

	if (proc.pid == 0) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);

		ptrace(PTRACE_TRACEME);
		personality(ADDR_NO_RANDOMIZE);

		execv(path, argv);
		fprintf(stderr, "Failed to execve %s\n", path);
		exit(1);
	}

	return proc;
}

static void dump_hist()
{
	printf("\nTrace history dump:\n");
	for (struct trace_block_t *tb = trace_ctx.master_tb; tb != NULL; tb = tb->hdr.next) {

		bool last_tb = tb->hdr.next == NULL;
		size_t sample_count = last_tb ? trace_ctx.offset : tb->hdr.hist_size;

		for (size_t off = 0; off < sample_count; ++off) {

			size_t sampleno = (size_t) tb->hist[off];

			if (sampleno >= patch_info.size) {
				fprintf(stderr, "Internal error: sample number outside of patch list range (%lu:%lu)\n", off, sampleno);
				continue;
			}

			printf("%p\n", patch_info.entry[sampleno].addr);
		}
	}
}

static void append_trace_block()
{
	struct trace_block_t *new_block = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (new_block == MAP_FAILED) {
		perror("Failed to append new trace block");
		dump_hist();
		exit(1);
	}

	memset(new_block, 0, BLOCK_SIZE);

	new_block->hdr.hist_size = CALC_HIST_SIZE_IN_BLOCK(BLOCK_SIZE);
	trace_ctx.current_tb->hdr.next = new_block;
	trace_ctx.current_tb = new_block;
	trace_ctx.offset = 0;
}

static void trace_hit_fix_exec(uint64_t ip, struct process_t proc, struct patch_entry_t pentry)
{
	uint64_t ins;
	struct user_regs_struct regs;

	// Patch back the old instruction
	ins = ptrace(PTRACE_PEEKTEXT, proc.pid, ip, NULL);
	ins &= (~0xFF);
	ins |= pentry.patch;
	ptrace(PTRACE_POKETEXT, proc.pid, ip, ins);

	// Do a step backwards
	ptrace(PTRACE_GETREGS, proc.pid, NULL, &regs);
	--regs.rip;
	ptrace(PTRACE_SETREGS, proc.pid, NULL, &regs);

	// Execute previously patched instruction
	ptrace(PTRACE_SINGLESTEP, proc.pid, NULL, NULL);
	waitpid(proc.pid, NULL, 0);

	// Patch back int3 so we can receive this trap later, again
	// We have to read the contents of memory again becuase last instruction
	// might have changed It's contents.
	ins = ptrace(PTRACE_PEEKTEXT, proc.pid, ip, NULL);
	ins &= (~0xFF);
	ins |= BREAK_OPCODE;
	ptrace(PTRACE_POKETEXT, proc.pid, ip, ins);
}

static void trace_hit(uint64_t ip, struct process_t proc)
{
	size_t sampleno;

	if (trace_ctx.offset >= trace_ctx.current_tb->hdr.hist_size)
		append_trace_block();

	for (size_t i = 0; i < patch_info.size; ++i) {
		if ((void*) ip == patch_info.entry[i].addr) {

			trace_ctx.current_tb->hist[trace_ctx.offset] = i;
			++trace_ctx.offset;

			trace_hit_fix_exec(ip, proc, patch_info.entry[i]);

			return;
		}
	}
}

static void apply_patches(struct process_t proc)
{
	uint64_t ins;

	for (size_t i = 0; i < patch_info.size; ++i) {
		ins = ptrace(PTRACE_PEEKTEXT, proc.pid, patch_info.entry[i].addr, NULL);

		// Save opcode that will be patched
		patch_info.entry[i].patch = ins & 0xFF;

		// Patch instruction with int3
		ins &= (~0xFF);
		ins |= BREAK_OPCODE;

		ptrace(PTRACE_POKETEXT, proc.pid, patch_info.entry[i].addr, ins);
	}
}

static void alloc_patches(char **patches, int patch_count)
{
	uint64_t addr;
	char *endptr;

	patch_info.size = patch_count;
	patch_info.entry = (struct patch_entry_t *) malloc(sizeof(struct patch_entry_t) * patch_info.size);

	if (patch_info.entry == NULL) {
		perror("Failed to allocate memory for patch_info");
		exit(1);
	}

	for(int i = 0; i < patch_count; ++i) {

		addr = strtoull(patches[i], &endptr, 16);

		// If not whole string matched (parsing error)
		if (!(*patches[i] != '\0' && *endptr == '\0')) {
			addr = 0;
		}

		patch_info.entry[i].addr = (void*) addr;
	}
}

static void alloc_hist()
{
	trace_ctx.master_tb = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (trace_ctx.master_tb == MAP_FAILED) {
		perror("Failed to allocate master trace block");
		exit(1);
	}

	memset(trace_ctx.master_tb, 0, BLOCK_SIZE);

	trace_ctx.master_tb->hdr.hist_size = CALC_HIST_SIZE_IN_BLOCK(BLOCK_SIZE);
	trace_ctx.current_tb = trace_ctx.master_tb;
}

static void usage()
{
	printf("Usage: tracer addr0 [addr1 ...[addrN]]\n");
}

/*
 * Pseudo code of how it works:
 * 1. Parse argc, argv for how many patches and where
 * 2. Allocate needed structures for patching and history recording
 * 3. Load target binary into memory.
 * 4. Setup tracing.
 * 5. Apply patches.
 * 6. Process for break events.
 * 7. Output gathered data and exit.
 */
int main(int argc, char **argv)
{
	struct process_t tracee;
	struct user_regs_struct regs;
	uint64_t ins;

	if (argc < 2) {
		usage();
		exit(1);
	}

	alloc_patches(argv+1, argc-1);
	alloc_hist();

	char* tracee_argv[] = {
		"tracee",
		NULL,
	};

	tracee = create_process("./tracee", tracee_argv);
	printf("Created process: %i\n", tracee.pid);

	// Wait for execv
	waitpid(tracee.pid, NULL, 0);

	apply_patches(tracee);

	if (ptrace(PTRACE_CONT, tracee.pid, NULL, NULL) == -1)
		perror("trace2");

	while (1) {
		waitpid(tracee.pid, &tracee.status, 0);

		if (WIFEXITED(tracee.status))
			break;

		ptrace(PTRACE_GETREGS, tracee.pid, NULL, &regs);

		// Make rip point back to int3 instruction
		--regs.rip;

		// TODO: make this read aligned, manual says it should be aligned (depending on the arch).
		//       x86 is probably fine unaligned for now.
		ins = ptrace(PTRACE_PEEKTEXT, tracee.pid, regs.rip, NULL);

		if ((ins & 0xFF) == BREAK_OPCODE) {

			/* Patching int3 with nop */
			//// Patch breakpoint with nop
			//ins &= ~0xFF;
			//ins |= NOP_OPCODE;

			//ptrace(PTRACE_POKETEXT, tracee.pid, regs.rip, ins);

			trace_hit(regs.rip, tracee);
		} else {
			fprintf(stderr, "Unexpected tracee event, ins: %lx, rip: %llx\n", ins, regs.rip);
			getchar();
		}

		if (ptrace(PTRACE_CONT, tracee.pid, NULL, NULL) == -1)
			perror("trace3");
	}

	printf("Process %i exited with %i\n", tracee.pid, tracee.status);
	dump_hist();
	// Let the kernel do the cleaning
}