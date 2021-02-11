#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Orange Polska S.A");
MODULE_DESCRIPTION("Ternary match (Palmtrie) implementation for eBPF for research purpose");

static int __init mod_init(void)
{
    printk(KERN_INFO "Hello world!\n");
    return 0; // load successful
}

static void __exit mod_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(mod_init);
module_exit(mod_cleanup);
