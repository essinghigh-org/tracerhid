// Intro to Linux Kernel Modules: https://wiki.archlinux.org/title/Kernel_module
// The Linux Kernel Module Programming Guide: https://tldp.org/LDP/lkmpg/2.6/html/index.html
#include <linux/module.h>  // Include header for kernel module macros and functions
#include <linux/kernel.h>  // Include header for kernel core functions like pr_info, pr_err

// Kernel Probes (Kprobes) Docs: https://www.kernel.org/doc/html/latest/trace/kprobes.html
// Intro to Kprobes: https://lwn.net/Articles/132196/
#include <linux/kprobes.h>  // Include header for kprobe functionality (dynamic instrumentation)

#include <linux/version.h>  // Include header for kernel version information

// task_struct and process management: https://www.kernel.org/doc/html/latest/core-api/workqueue.html
// Process descriptor reference: https://linux-kernel-labs.github.io/refs/heads/master/lectures/processes.html
#include <linux/sched.h>   // Include header for task_struct and scheduling related functions

// Module metadata reference: https://tldp.org/LDP/lkmpg/2.6/html/x279.html
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Henry Essinghigh <henry@essinghigh.dev>");
MODULE_DESCRIPTION("Kernel module to hide TracerPid in /proc/*/status for a specific PID");
MODULE_VERSION("1.0");

static struct kprobe kp;  // Declare a static kprobe structure for hooking into kernel functions

// PID namespaces reference: https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
static pid_t target_pid = 0;  // Static variable to hold the target PID to hide TracerPid for (0 means disabled)

// Kernel module parameters reference: https://tldp.org/LDP/lkmpg/2.6/html/x323.html
// Kernel command-line parameters: https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
module_param(target_pid, int, 0644);  // Make target_pid a module parameter that can be set at load time, with permissions 0644
MODULE_PARM_DESC(target_pid, "PID for which to hide TracerPid (0 = disabled)");  // Describe the parameter

// ptrace docs: https://man7.org/linux/man-pages/man2/ptrace.2.html
// How debuggers work (basics): https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1
static unsigned long ptrace_backup;  // Static variable to backup the original ptrace value

// kprobe handlers: https://www.kernel.org/doc/html/latest/trace/kprobes.html#how-does-a-kprobe-work
// Pre-handler function called before the hooked function executes
static int pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task;  // Declare a pointer to task_struct (represents a process)

    // x86-64 calling convention: https://wiki.osdev.org/System_V_ABI
    // pt_regs reference: https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/ptrace.h
    // The function is proc_pid_status(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *task)
    // Learn about /proc filesystem: https://man7.org/linux/man-pages/man5/proc.5.html
    // TracerPid in /proc/[pid]/status: https://www.kernel.org/doc/html/latest/filesystems/proc.html
    // So, regs->di = m, rsi = ns, rdx = pid, rcx = task
    task = (struct task_struct *)regs->cx;  // Cast and assign the task pointer from registers

    // Check if target_pid is set and matches the current task's PID
    if (target_pid && task_pid_nr(task) == target_pid) {
        ptrace_backup = task->ptrace;  // Backup the original ptrace value
        task->ptrace = 0;  // Set ptrace to 0 to hide TracerPid
    }

    return 0;  // Return 0 to allow the hooked function to proceed
}

// Post-handler function called after the hooked function executes
static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct task_struct *task = (struct task_struct *)regs->cx;  // Get the task pointer again

    // Restore the ptrace value if it was modified
    if (target_pid && task_pid_nr(task) == target_pid) {
        task->ptrace = ptrace_backup;  // Restore the original ptrace value
    }
}

// Module init/exit: https://tldp.org/LDP/lkmpg/2.6/html/hello2.html
// __init macro: https://kernelnewbies.org/FAQ/InitExitMacros
// Initialization function called when the module is loaded
static int __init tracerhid_init(void)
{
    kp.symbol_name = "proc_pid_status";  // Set the symbol (function) to hook: proc_pid_status
    kp.pre_handler = pre_handler;  // Assign the pre-handler function
    kp.post_handler = post_handler;  // Assign the post-handler function

    // Try to register the kprobe
    if (register_kprobe(&kp) < 0) {
        pr_err("Failed to register kprobe\n");  // Print error message if registration fails
        return -1;  // Return error code
    }

    pr_info("TracerPid hiding module loaded, target_pid=%d\n", target_pid);  // Print success message with target PID
    return 0;  // Return success
}

// Exit function called when the module is unloaded
static void __exit tracerhid_exit(void)
{
    unregister_kprobe(&kp);  // Unregister the kprobe
    pr_info("TracerPid hiding module unloaded\n");  // Print unload message
}

module_init(tracerhid_init);  // Register the init function to be called on module load
module_exit(tracerhid_exit);  // Register the exit function to be called on module unload