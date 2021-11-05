#include <stdio.h>

int add(int a, int b);
int sub(int a, int b);

int main(void)
{
	add(1,2);
	add(2,3);
	sub(add(3,4), sub(7,1));

#pragma GCC unroll 0
	for(int i = 0; i < 4096 * 5; ++i) {
		puts("Hello!");
		asm volatile ("nop" ::);
	}

	return 0;
}

int add(int a, int b)
{
	return a+b;
}

int sub(int a, int b)
{
	return a-b;
}