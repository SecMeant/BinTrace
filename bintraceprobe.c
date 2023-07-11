#include <stdio.h>

void bintrace_probe_hit(void)
{
	void *probe_addr = __builtin_extract_return_addr (__builtin_return_address (0));

	printf("Hit probe at %p\n", probe_addr);
}