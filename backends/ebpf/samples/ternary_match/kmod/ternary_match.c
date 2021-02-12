#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/syscalls.h>
#include <asm/unistd.h>

#include <linux/bpf.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Orange Polska S.A");
MODULE_DESCRIPTION("Ternary match implementation for eBPF for research purpose");


#define MAX_LEN_ENTRY 128

/* Obtain sys_call_table from /proc/kallsyms file.
 * Taken from: https://gist.github.com/GoldenOak/a8cd563d671af04a3d387d198aa3ecf8#file-obtain_syscall_table_by_proc-c
 * Modifications: removed memory leak, added missing code.
 *
 * At some point, kernel has some protections against sys_call_table
 * modifications. Function kallsyms_lookup_name() and table itself are no
 * longer exported, so they can't be used. File /proc/kallsyms must read with
 * root privileges to see an address of a given symbol.
 * */
unsigned long * obtain_syscall_table_by_proc(void)
{
    char *file_name                       = "/proc/kallsyms";
    int i                                 = 0;         /* Read Index */
    struct file *proc_ksyms               = NULL;      /* struct file the '/proc/kallsyms' or '/proc/ksyms' */
    char sct_addr_str[MAX_LEN_ENTRY]      = {0};       /* buffer for save sct addr as str */
    char proc_ksyms_entry[MAX_LEN_ENTRY]  = {0};       /* buffer for each line at file */
    unsigned long* res                    = NULL;      /* return value */
    unsigned long tmp                     = 0;
    char *proc_ksyms_entry_ptr            = NULL;
    int read                              = 0;
    mm_segment_t oldfs;

    proc_ksyms = filp_open(file_name, O_RDONLY, 0);
    if(proc_ksyms == NULL)
        goto CLEAN_UP;

    oldfs = get_fs();
	set_fs(KERNEL_DS);
    read = vfs_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));
    set_fs(oldfs);

    while(read == 1)
    {
        if(proc_ksyms_entry[i] == '\n' || i == MAX_LEN_ENTRY)
        {
            if(strstr(proc_ksyms_entry, "sys_call_table") != NULL)
            {
                printk(KERN_INFO "ternary_match: Found sys_call_table, line is: %s", proc_ksyms_entry);

                proc_ksyms_entry_ptr = proc_ksyms_entry;
                strncpy(sct_addr_str, strsep(&proc_ksyms_entry_ptr, " "), MAX_LEN_ENTRY);
                kstrtoul(sct_addr_str, 16, &tmp);
                res = (unsigned long *) tmp;
                goto CLEAN_UP;
            }

            i = -1;
            memset(proc_ksyms_entry, 0, MAX_LEN_ENTRY);
        }
        i++;

        read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));
    }

CLEAN_UP:
    if(proc_ksyms != NULL)
        filp_close(proc_ksyms, 0);

    return res;
}

typedef long (*bpf_syscall_t)(int, union bpf_attr *, unsigned int);
bpf_syscall_t orig_bpf_syscall = NULL;
unsigned long * syscall_table = NULL;

/* Write value to the CR0 register.
 * Kernel API provides write_cr0(), but it has protection against clearing
 * Protection Write (WP) bit in the register. Simplest method to get around
 * is to write own function. See this code for reference:
 * https://elixir.bootlin.com/linux/v5.8.18/source/arch/x86/kernel/cpu/common.c#L363
 * */
void unsafe_write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

/* Replace syscall in the sys_call_table.
 * sys_call_table is in the read-only page, so temporary Write Protection have
 * to be disabled.
 * */
void * replace_syscall(unsigned long * table, uint16_t offset, void * hook)
{
    void * orig_syscall = NULL;
    unsigned long orig_cr0 = 0;

    printk(KERN_INFO "ternary_match: Setting syscall %d to %lx\n", offset, (unsigned long) hook);

    orig_syscall = (void *) table[offset];

    orig_cr0 = read_cr0();
    unsafe_write_cr0(orig_cr0 & (~0x10000)); /* clear Write Protection */

    table[offset] = (unsigned long) hook;

    write_cr0(orig_cr0); /* restore CR0 */

    printk(KERN_INFO "ternary_match: CR0 value %lx", orig_cr0);

    return orig_syscall;
}

/* Wrapper for bpf sys call.
 * It should normally call original bpf sys call, but on it own serve new
 * eBPF map type.
 *
 * For some reason, original sys call can't be called, because this operation
 * cause page fault.
 *      BUG: unable to handle page fault for address: 00000000831e3fb8
 *      #PF: supervisor read access in kernel mode
 *      #PF: error_code(0x0000) - not-present page
 * So, address taken from sys_call_table is valid? Or there are some other
 * required operation to do this?
 * */
asmlinkage long custom_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    if (orig_bpf_syscall == NULL)
    {
        printk(KERN_INFO "ternary_match: Unknown original BPF syscall!\n");
        return -1;
    }

    printk(KERN_INFO "ternary_match: BPF syscall called with cmd=%d\n", cmd);

    return orig_bpf_syscall(cmd, attr, size);
}

static int __init mod_init(void)
{
    syscall_table = obtain_syscall_table_by_proc();
    printk(KERN_INFO "ternary_match: Syscall table address %lx\n", (unsigned long) syscall_table);
    if (syscall_table == NULL)
        return 0;

    orig_bpf_syscall = (bpf_syscall_t) replace_syscall(syscall_table, __NR_bpf, custom_bpf);
    printk(KERN_INFO "ternary_match: Original BPF syscall %lx\n", (unsigned long) orig_bpf_syscall);

    return 0;
}

static void __exit mod_cleanup(void)
{
    printk(KERN_INFO "ternary_match: Cleaning up module.\n");

    replace_syscall(syscall_table, __NR_bpf, orig_bpf_syscall);
}

module_init(mod_init);
module_exit(mod_cleanup);
