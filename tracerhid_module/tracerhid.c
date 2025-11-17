// Intro to Linux Kernel Modules: https://wiki.archlinux.org/title/Kernel_module
// The Linux Kernel Module Programming Guide: https://tldp.org/LDP/lkmpg/2.6/html/index.html
#include <linux/module.h>    // Include header for kernel module macros and functions
#include <linux/kernel.h>    // Include header for kernel core functions like pr_info, pr_err
#include <linux/minmax.h>    // Include header for max() helper used when sizing kretprobe maxactive
#include <linux/rcupdate.h>  // Include header for synchronize_rcu used during module exit cleanup
#include <linux/smp.h>       // Include header for NR_CPUS helper used for kretprobe concurrency limits
#include <linux/types.h>     // Include header for bool type used in per-instance state tracking

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

#ifndef CONFIG_X86_64
#error "TracerPid hiding module only supports x86_64 architecture"
#endif

// Kretprobe instance-local storage reference: https://www.kernel.org/doc/html/latest/trace/kprobes.html#concepts-kprobes-and-return-probes
struct tracerhid_data {
    struct task_struct *task;      // Remember the task we modified so we can restore ptrace later
    unsigned long saved_ptrace;    // Remember the original ptrace flags for the specific invocation
    bool ptrace_modified;          // Track whether we actually manipulated ptrace for this instance
};

static struct kretprobe krp;  // Declare a static kretprobe structure for hooking into kernel functions with per-call storage

// PID namespaces reference: https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
static pid_t target_pid = 0;  // Static variable to hold the target PID to hide TracerPid for (0 means disabled)

// Kernel module parameters reference: https://tldp.org/LDP/lkmpg/2.6/html/x323.html
// Kernel command-line parameters: https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
module_param(target_pid, int, 0644);  // Make target_pid a module parameter that can be set at load time, with permissions 0644
MODULE_PARM_DESC(target_pid, "PID for which to hide TracerPid (0 = disabled)");  // Describe the parameter

// ptrace docs: https://man7.org/linux/man-pages/man2/ptrace.2.html
// How debuggers work (basics): https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1

// Entry handler function called before the hooked function executes
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tracerhid_data *data;  // Pointer to per-instance storage allocated by kretprobe
    struct task_struct *task;     // Declare a pointer to task_struct (represents a process)

    // x86-64 calling convention: https://wiki.osdev.org/System_V_ABI
    // pt_regs reference: https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/ptrace.h
    // The function is proc_pid_status(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *task)
    // Learn about /proc filesystem: https://man7.org/linux/man-pages/man5/proc.5.html
    // TracerPid in /proc/[pid]/status: https://www.kernel.org/doc/html/latest/filesystems/proc.html
    // So, regs->di = m, rsi = ns, rdx = pid, rcx = task
    task = (struct task_struct *)regs->cx;  // Cast and assign the task pointer from registers (4th argument on x86_64)

    data = (struct tracerhid_data *)ri->data;  // Retrieve the per-instance storage slot provided by kretprobe
    data->task = NULL;                         // Initialise to NULL so the return handler can safely skip if we do nothing
    data->ptrace_modified = false;             // Assume no modification until we actually touch ptrace

    if (!task) {
        return 0;  // Bail out defensively if the ABI assumption fails or the pointer is unexpectedly NULL
    }

    // Check if target_pid is set and matches the current task's PID
    if (target_pid && task_pid_nr(task) == target_pid) {
        get_task_struct(task);  // Take a reference so the task remains valid until the return handler restores ptrace
        task_lock(task);        // Serialize with other task->ptrace users as documented in include/linux/sched/task.h
        data->saved_ptrace = task->ptrace;  // Backup the original ptrace value for this specific invocation
        task->ptrace = 0;                  // Set ptrace to 0 to hide TracerPid just for the duration of proc_pid_status
        task_unlock(task);     // Release the task lock quickly so we do not hold it while proc_pid_status executes
        data->task = task;     // Remember the task pointer for the return handler
        data->ptrace_modified = true;  // Flag that we changed ptrace so the return handler knows to restore
    }

    return 0;  // Return 0 to allow the hooked function to proceed
}

// Return handler function called after the hooked function executes
static int return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tracerhid_data *data;  // Access the per-instance storage initialised in the entry handler

    data = (struct tracerhid_data *)ri->data;  // Retrieve the storage slot filled out during entry

    if (data->ptrace_modified && data->task) {
        task_lock(data->task);                 // Reacquire the task lock to safely restore ptrace flags
        data->task->ptrace = data->saved_ptrace;  // Restore the original ptrace value captured in entry handler
        task_unlock(data->task);               // Release the lock immediately after restoration
        put_task_struct(data->task);           // Drop the reference acquired in the entry handler to avoid leaks
        data->task = NULL;                     // Defensive clear so double-free is impossible even on fault retriers
        data->ptrace_modified = false;         // Reset flag for completeness (slot may be reused by kretprobe core)
    }

    return 0;  // Return 0 to signal successful completion to the kretprobe core
}

// Module init/exit: https://tldp.org/LDP/lkmpg/2.6/html/hello2.html
// __init macro: https://kernelnewbies.org/FAQ/InitExitMacros
// Initialization function called when the module is loaded
static int __init tracerhid_init(void)
{
    krp.kp.symbol_name = "proc_pid_status";  // Set the symbol (function) to hook: proc_pid_status (internal helper, may change between kernel releases)
    krp.entry_handler = entry_handler;        // Assign the entry handler function
    krp.handler = return_handler;             // Assign the return handler function
    krp.data_size = sizeof(struct tracerhid_data);  // Allocate per-instance storage for ptrace bookkeeping
    krp.maxactive = max(2U, (unsigned int)NR_CPUS);  // Allow at least one probe per CPU to avoid dropped instances

    // Try to register the kretprobe
    if (register_kretprobe(&krp) < 0) {
        pr_err("Failed to register kretprobe for proc_pid_status\n");  // Print error message if registration fails
        return -EINVAL;  // Return error code to indicate initialization failure
    }

    pr_info("TracerPid hiding module loaded, target_pid=%d\n", target_pid);  // Print success message with target PID
    return 0;  // Return success
}

// Exit function called when the module is unloaded
static void __exit tracerhid_exit(void)
{
    unregister_kretprobe(&krp);  // Unregister the kretprobe to clean up instrumentation hooks
    synchronize_rcu();           // Ensure no RCU readers (e.g., proc walkers) are still running our handlers
    pr_info("TracerPid hiding module unloaded\n");  // Print unload message
}

module_init(tracerhid_init);  // Register the init function to be called on module load
module_exit(tracerhid_exit);  // Register the exit function to be called on module unload