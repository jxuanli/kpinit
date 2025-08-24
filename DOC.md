
### IO helpers
```c

/*
 * Dumps the memory region in the range [addr, addr + len)
 *
 * @addr: start of the memory region to be dumped
 * @len: length of the memory region to be dumped
 */
void hexdump(void *addr, size_t len);

/*
 * Blocks until the user inputs a new line and tries to convert the input to a 64-bit
 * integer.
 *
 * @fmt: the format string to be displayed
 * return: a 64-bit value
 */
u64 input(const char *fmt, ...);

/*
 * Fancy wrappers of printf
 *
 * @fmt: format string
 */
void important(const char *fmt, ...);
void info(const char *fmt, ...);
void warn(const char *fmt, ...);
void error(const char *fmt, ...);

/*
 * Prints `msg` and exits with code 1 if `cond` is false (!= 0)
 *
 * @cond: condition to be checked
 * @msg: failure message
 */
void checkf(int cond, char *msg);

/*
 * Prints `msg` if `cond` is false (!= 0)
 *
 * @cond: condition to be checked
 * @msg: warning message
 */
i32 checkw(int cond, char *msg);

/*
 * Generates a string of sequential de Bruijn sequence chunks
 *
 * @buf: buffer for populating the result if not null. If the buffer is null, a new chunk is malloc'ed
 * @size: the size of the string
 * @return: the pointer to the string
 */
char *cyclic(char *buf, int size);
```
### General exploit helpers
```c
/*
 * Checks if root (uid = 0). If so, it gets a shell; otherwise, it throws an error.
 */
void shell();

/*
 * Registers a segfault handler to get a shell then segfaults
 */
void crash();

/*
 * Pins CPU to core_id
 */
void pin_cpu(int core_id);

/*
 * Performs retspill with given register values
 *  This function is currently only supported on x86-64
 *
 * @regs: the register values to store on the kernel stack
 */
void retspill(struct syscall_regs *regs);

/*
 * Write the #!/bin/sh header and `cmd` to `path` with permission set to 777
 *
 */
int setup_modprobe(char *path, char *cmd);

/*
 * Runs modprobe path
 */
int run_modprobe();

/*
 * Flushes the TLB entries corresponding to the memory region [addr, addr+len)
 *
 * @addr: address to flush
 * @len: size of the memory region to be flushed from the TLB
 */
void flush_tlb(void *addr, long len);
```
