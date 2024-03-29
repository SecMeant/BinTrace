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
#define BLOCK_HIST_ENTRY_COUNT ((BLOCK_SIZE - sizeof(struct trace_block_header_t)) / sizeof(struct hist_entry_t))
#define CALC_HIST_SIZE_IN_BLOCK(block_size) \
	(((block_size) - sizeof(struct trace_block_t)) / sizeof(struct hist_entry_t)) ;

#define BREAK_OPCODE 0xcc
#define NOP_OPCODE 0x90

#define MAX_HIT_COUNT 0xffffffffffffffff

#define COL_W 25
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;33m"
#define COLOR_CYAN "\033[0;36m"
#define COLOR_RESET "\033[0m"

#define STR_RED(s) COLOR_RED s COLOR_RESET
#define STR_GREEN(s) COLOR_GREEN s COLOR_RESET
#define STR_CYAN(s) COLOR_CYAN s COLOR_RESET
#define STR_COLORED(color, str) COLOR_##color str COLOR_RESET

#define ARRAY_ELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

struct hist_entry_t
{
	uint8_t break_index;
	size_t hit_count;
	struct user_regs_struct regcaps[5];
};

struct program_opts
{
	uint8_t regdump	: 1;
	char **tracee_argv;
	char *tracee_path;
};

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
	struct hist_entry_t hist[0];
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
	const char *path;
	void *base_load_addr;
};

// Global vars here
struct program_opts opts;

static uint64_t proc_maps_parse_begin_range(char *maps_line)
{
	char     *p      = maps_line;
	char     *endptr = NULL;
	uint64_t  addr   = 0;

	while (1) {
		if (*p == '\0')
			return 0;

		if (*p == '-') {
			*p = '\0';
			addr = strtoul(maps_line, &endptr, 16);

			// If not whole string matched (parsing error)
			if (!(*maps_line != '\0' && *endptr == '\0')) {
				addr = 0;
			}

			*p = '-';

			break;
		}

		++p;
	}

	return addr;
}

static void* get_proc_load_address(struct process_t proc)
{
	FILE   *fmaps;
	char    maps_path[32];
	char   *maps_line      = NULL;
	size_t  maps_line_sz   = 0;
	void   *ret            = NULL;

	snprintf(maps_path, sizeof(maps_path), "/proc/%i/maps", proc.pid);

	fmaps = fopen(maps_path, "rb");

	if (!fmaps) {
		fprintf(stderr,
			"Failed to open procs map file. PID: %i, maps: %s\n",
			proc.pid, maps_path);
		exit(1);
	}

	// Parse /proc/pid/maps format and find load address
	// Example line from maps:
	// 55ebb23e0000-55ebb23e2000 r--p 00000000 103:03 6304311                   /usr/bin/cat
	while (getline(&maps_line, &maps_line_sz, fmaps) != -1) {
		if (strstr(maps_line, proc.path) == NULL)
			continue;

		ret = (void*) proc_maps_parse_begin_range(maps_line);
		break;
	}

	free(maps_line);

	return ret;
}

struct process_t create_process(const char *path, char *const argv[])
{
	struct process_t proc;

	proc.path = realpath(path, NULL);
	if (!proc.path) {
		fprintf(stderr, 
			"Failed to obtain realpath of requested binary: %s\n",
			path);
		exit(1);
	}

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

	// Wait for PTRACE_TRACEME and exec so we can set options
	waitpid(proc.pid, NULL, 0);

	if (ptrace(PTRACE_SETOPTIONS, proc.pid, NULL, PTRACE_O_EXITKILL) == -1) {
		perror("Warning: Failed to set option PTRACE_O_EXITKILL. "
			"Tracee will not exit when tracer dies.");
	}

	proc.base_load_addr = get_proc_load_address(proc);

	if (proc.base_load_addr == NULL) {
		fprintf(stderr,
			"Failed to obtain load address of child process: %i\n",
			proc.pid);
		exit(1);
	}

	return proc;
}

static void copy_regs(struct user_regs_struct* dst, struct user_regs_struct* src)
{
	memcpy(dst, src, sizeof(struct user_regs_struct) );
	return;
}

static void dump_hist()
{
	printf("\nTrace history dump:\n");
	for (struct trace_block_t *tb = trace_ctx.master_tb; tb != NULL; tb = tb->hdr.next) {

		bool last_tb = tb->hdr.next == NULL;
		size_t sample_count = last_tb ? trace_ctx.offset : tb->hdr.hist_size;

		for (size_t off = 0; off < sample_count; ++off) {

			size_t sampleno = (size_t) tb->hist[off].break_index;

			if (sampleno >= patch_info.size) {
				fprintf(stderr, "Internal error: sample number outside of patch list range (%lu:%lu)\n", off, sampleno);
				continue;
			}
		
			char tmpstr[50];	
			sprintf(
				tmpstr, 
				"%p: %zu\n", 
				patch_info.entry[sampleno].addr, 
				tb->hist[off].hit_count
			);
			printf( tmpstr );

			if ( opts.regdump )
			{
				for ( size_t i = 0; i < tb->hist[off].hit_count; ++i )
				{
					struct user_regs_struct curr_regcap = tb->hist[off].regcaps[i];

					printf(	"|  Regdump %lu\n"
						"|  |   RAX: 0x%016llx\tRCX: 0x%016llx\tRDX: 0x%016llx\n"
						"|  |   RBX: 0x%016llx\tRSP: 0x%016llx\tRBP: 0x%016llx\n"
						"|  |   RSI: 0x%016llx\tRDI: 0x%016llx\t\n"
						"|  |    R8: 0x%016llx\t R9: 0x%016llx\tR10: 0x%016llx\n"
						"|  |   R11: 0x%016llx\tR12: 0x%016llx\tR13: 0x%016llx\n"
						"|  |   R14: 0x%016llx\tR15: 0x%016llx\t\n\n",
						i + 1,
						curr_regcap.rax,
						curr_regcap.rcx,
						curr_regcap.rdx,
						curr_regcap.rbx,
						curr_regcap.rsp,
						curr_regcap.rbp,
						curr_regcap.rsi,
						curr_regcap.rdi,
						curr_regcap.r8,
						curr_regcap.r9,
						curr_regcap.r10,
						curr_regcap.r11,
						curr_regcap.r12,
						curr_regcap.r13,
						curr_regcap.r14,
						curr_regcap.r15
					);
				}
			}
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

// TODO: name it better lol
static bool try_compress_hit(size_t hit_break_index)
{
	// If this is the beggining of the block we cannot go back and compress
	if (trace_ctx.offset == 0)
		return false;

	// If the break_index of the prebious hit is different then current hit
	// then we cannot compress
	struct hist_entry_t * prev_hit =
		&trace_ctx.current_tb->hist[trace_ctx.offset - 1];

	if ( prev_hit->break_index != hit_break_index)
		return false;

	// If adding to the prev hit counter would overflow we cannot compress
	if (prev_hit->hit_count == MAX_HIT_COUNT)
		return false;

	++prev_hit->hit_count;
	return true;
}

static void trace_hit(struct user_regs_struct curr_regs, struct process_t proc)
{
	uint64_t ip = curr_regs.rip;

	if (trace_ctx.offset >= trace_ctx.current_tb->hdr.hist_size)
		append_trace_block();

	for (size_t i = 0; i < patch_info.size; ++i) {
		if ((void*) ip == patch_info.entry[i].addr) {

			if (try_compress_hit(i) == false)
			{
				trace_ctx.current_tb->hist[trace_ctx.offset].break_index = i;
				++trace_ctx.current_tb->hist[trace_ctx.offset].hit_count;
				++trace_ctx.offset;
			}

			trace_hit_fix_exec(ip, proc, patch_info.entry[i]);
			if ( opts.regdump )
			{
				copy_regs( 
					&trace_ctx.current_tb->hist[trace_ctx.offset-1].regcaps[
						trace_ctx.current_tb->hist[trace_ctx.offset-1].hit_count-1
						],
					&curr_regs);
			}
			return;
		}
	}

	printf("Missing: %p\n", (void*) ip);
}

static void apply_patches(struct process_t proc)
{
	uint64_t ins;

	for (size_t i = 0; i < patch_info.size; ++i) {
		// Process is loaded now, so we "fix" the patches by adding
		// binary load address to all the traced addresses
		if (patch_info.entry[i].addr != 0)
			patch_info.entry[i].addr += (uint64_t) proc.base_load_addr;

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
	printf(
		"Usage: bintrace [..FLAGS] binpath addr0 [addr1 ...[addrN]] [-- tracee_arg1 ...[tracee_argN]]\n"
		" FLAGS:\n"
		"  -r  | Register Dump Mode\n"
		"  -c  | Disable colors\n"
	);
}

static void parse_cmdline(int argc, char **argv)
{
	int i = 1;
	char *patches_argv[argc];
	size_t cur_patch_idx = 0;

	opts.tracee_path = NULL;
	opts.tracee_argv = NULL;

	while (i < argc) {
		if (strcmp(argv[i], "--") == 0) {
			if (i + 1 == argc) {
				usage();
				exit(1);
			}

			// Patch "--" with bin's name of the tracee, this trick will allow us
			// to cheaply create argv for tracee.
			argv[i] = opts.tracee_path;

			opts.tracee_argv = argv + i;
			break;
		} else if (argv[i][0] != '-') {
			if (opts.tracee_path == NULL) {
				opts.tracee_path = argv[i];
			} else {
				patches_argv[cur_patch_idx] = argv[i];
				++cur_patch_idx;
			}
		} else if (strcmp(argv[i], "-r") == 0) {
			opts.regdump = 1;
		} else {
			fprintf(stderr, "Warning: unknown option \"%s\". Ignored.\n", argv[i]);
		}

		++i;
	}

	if (opts.tracee_path == NULL) {
		usage();
		exit(1);
	}

	if (cur_patch_idx == 0) {
		usage();
		exit(1);
	}

	// TODO(holz): Move this outside parse_cmdline (patches_argv has to be moved too then)
	alloc_patches(patches_argv, cur_patch_idx);
}

#define ARR_SUZE

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

	parse_cmdline(argc, argv);

	alloc_hist();

	char* def_tracee_argv[] = {
		opts.tracee_path,
		NULL,
	};

	if (opts.tracee_argv == NULL) {
		opts.tracee_argv = def_tracee_argv;
	}

	tracee = create_process(opts.tracee_path, opts.tracee_argv);
	printf("Created process: %i, loaded at:%p\n", tracee.pid, tracee.base_load_addr);

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

			trace_hit(regs, tracee);
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

