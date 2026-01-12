
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

/*
 * Checks the return value of a system call. If the syscall returned an error,
 * prints it and exits.
 */
#define SYSCHK(x)                                                              \
  ({                                                                           \
    typeof(x) __res = (x);                                                     \
    if (__res == (typeof(x))-1)                                                \
      error("SYSCHK(" #x "): %s", strerror(errno));                            \
    __res;                                                                     \
  })

/*
 * Checks the return value of a system call. If the syscall returned an error,
 * prints the error and continues.
 */
#define SYSWARN(x)                                                             \
  ({                                                                           \
    typeof(x) __res = (x);                                                     \
    if (__res == (typeof(x))-1)                                                \
      warn("SYSCHK(" #x "): %s", strerror(errno));                             \
    __res;                                                                     \
  })
```
### General exploit helpers
```c
/*
 * Checks if root (uid = 0). If so, it gets a shell; otherwise, it throws an error.
 */
void shell();

/*
 * Drops to a shell with only assembly instructions. Only available for x86-64.
 */
__attribute__((naked)) void shell2();

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
 * Writes the #!/bin/sh header and `cmd` to `path` with permission set to 777
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

/*
 * Prevents exploits from running unintentionally when the NO_KPINIT_EXPLOIT
 * variable is set
 */
static void __no_kpinit_exploit(void);

/*
 * Reverses the byte order of a 64-bit number
 *
 * @x: the number whose byte order is to be reversed
 */
#define swab64(x) /*...*/
```
