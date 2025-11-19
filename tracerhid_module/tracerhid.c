// Intro to Linux Kernel Modules: https://wiki.archlinux.org/title/Kernel_module
// The Linux Kernel Module Programming Guide: https://tldp.org/LDP/lkmpg/2.6/html/index.html
#include <linux/module.h>    // For kernel module macros and functions
#include <linux/kernel.h>    // For core functions like pr_info, pr_err
#include <linux/minmax.h>    // For max() when sizing kretprobe maxactive
#include <linux/rcupdate.h>  // For synchronize_rcu used during module exit cleanup
#include <linux/smp.h>       // For NR_CPUS used for kretprobe concurrency limits
#include <linux/types.h>     // For standard types used for bool type in per-instance state tracking
#include <linux/kprobes.h>   // For kretprobe functionality (dynamic instrumentation)
#include <linux/version.h>   // For kernel version information
#include <linux/sched.h>     // For task_struct and task_pid_nr function
#include <linux/mm.h>        // For vm_area_struct
#include <linux/seq_file.h>  // For seq_file struct
#include <linux/dcache.h>    // For dentry and d_name
#include <linux/file.h>      // For file struct

// ==========================================
// MODULE METADATA
// tldp.org/LDP/lkmpg/2.6/html/x279.html
// ==========================================
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Henry Essinghigh");
MODULE_DESCRIPTION("Hide TracerPid and specific libraries from /proc");
MODULE_VERSION("1.1");

// Do not build on non-x86_64 architectures
#ifndef CONFIG_X86_64
#error "Module only supports x86_64 architecture"
#endif

// ==========================================
// CONFIGURATION
// ==========================================

static pid_t target_pid = 0;         // Target PID to hide TracerPid for (0 = disabled)
module_param(target_pid, int, 0644); // Kernel module parameter to specify target PID
MODULE_PARM_DESC(target_pid, "PID to hide artifacts for (0 = disabled)");

static char *maps_path = NULL;        // Substring of library path to hide from /proc/pid/maps
module_param(maps_path, charp, 0644); // Kernel module parameter for library path substring
MODULE_PARM_DESC(maps_path, "Substring of library path to hide from /proc/pid/maps");

// ==========================================
// TRACERPID HIDING
// ==========================================

struct tracerhid_data {
    struct task_struct *task;     // Remember the task we modified so we can restore ptrace later
    unsigned long saved_ptrace;   // Remember the original ptrace flags for the specific invocation
    bool ptrace_modified;         // Track whether we actually manipulated ptrace for this instance
};

static int status_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tracerhid_data *data; // Pointer to per-instance storage allocated by kretprobe
    struct task_struct *task;    // Declare a pointer to task_struct (represents a process)

    // x86-64 calling convention: https://wiki.osdev.org/System_V_ABI
    // The function is proc_pid_status(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *task)
    // So, regs->di = m, rsi = ns, rdx = pid, rcx = task
    task = (struct task_struct *)regs->cx;    // Cast and assign the task pointer from registers (4th argument on x86_64)
    data = (struct tracerhid_data *)ri->data; // Retrieve per-instance storage slot provided by kretprobe
    
    data->task = NULL;             // Initialize to NULL so the return handler can safely skip if we do nothing
    data->ptrace_modified = false; // Assume no modification until we actually touch ptrace

    if (!task) return 0; // Bail out defensively if the ABI assumption fails or the pointer is unexpectedly NULL

    // Check if target_pid is set and matches the current task's PID
    if (target_pid && task_pid_nr(task) == target_pid) {
        get_task_struct(task);             // Take a reference so the task remains valid until the return handler restores ptrace
        task_lock(task);                   // Serialize with other task->ptrace users (see include/linux/sched/task.h)
        data->saved_ptrace = task->ptrace; // Backup the original ptrace value for this specific invocation
        task->ptrace = 0;                  // Set ptrace to 0 to hide TracerPid just for the duration of proc_pid_status
        task_unlock(task);                 // Release the task lock quickly so we do not hold it while proc_pid_status executes
        data->task = task;                 // Remember the task pointer for the return handler
        data->ptrace_modified = true;      // Flag that we changed ptrace so the return handler knows to restore it
    }
    return 0; // Return 0 to allow the hooked function to proceed normally
}

// Return handler function called after the hooked function returns
static int status_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tracerhid_data *data = (struct tracerhid_data *)ri->data; // Access the per-instance storage initialized in the entry handler

    if (data->ptrace_modified && data->task) {
        task_lock(data->task);                   // Reacquire the task lock to safely restore ptrace flags
        data->task->ptrace = data->saved_ptrace; // Restore the original ptrace value captured in the entry handler
        task_unlock(data->task);                 // Release the lock immediately after restoration
        put_task_struct(data->task);             // Drop the reference acquired in the entry handler to avoid leaks
    }
    return 0; // Return 0 to signal successful completion
}

static struct kretprobe kp_status = {
    .kp.symbol_name = "proc_pid_status",        // Set the symbol to hook: proc_pid_status
    .entry_handler = status_entry_handler,      // Assign the entry handler function
    .handler = status_return_handler,           // Assign the return handler function
    .data_size = sizeof(struct tracerhid_data), // Allocate per-instance storage for ptrace bookkeeping
    .maxactive = 32,                            // Allow at least one probe per CPU to avoid dropped instances (set properly in init)
};

// ==========================================
// MAPS HIDING
// ==========================================

struct mapshid_data {
    struct seq_file *m;       // Pointer to seq_file for buffer manipulation in return handler
    size_t entry_count;       // Snapshot of buffer count before show_map_vma writes
    bool should_hide;         // Flag to indicate if this VMA entry should be hidden
};

// Function signature we are hooking:
// int show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
// RDI = m, RSI = vma
static int maps_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mapshid_data *data = (struct mapshid_data *)ri->data;    // Retrieve per-instance storage slot provided by kretprobe
    struct seq_file *m = (struct seq_file *)regs->di;               // Cast and assign the seq_file pointer from registers (1st argument on x86_64)
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->si; // Cast and assign the vm_area_struct pointer from registers (2nd argument on x86_64)
    struct file *f;                                                 // Declare a pointer to file struct for accessing file path
    
    if (!m || !vma || !maps_path) return 0; // Bail out if any required pointers are NULL or maps_path not set
    
    data->m = m;                    // Store the seq_file pointer for the return handler to manipulate
    data->entry_count = m->count;   // Snapshot the current buffer length before show_map_vma writes
    data->should_hide = false;      // Initialize hide flag to false until we confirm a match
    
    // Check if this VMA has a file we want to hide (global hiding for all processes)
    f = vma->vm_file;                                         // Get the file associated with this VMA (if any)
    if (f && f->f_path.dentry) {                              // Ensure the file and its dentry exist
        const char *filename = f->f_path.dentry->d_name.name; // Extract the filename from the dentry
        
        // If the user provided string (maps_path) contains the filename
        // e.g. maps_path="/opt/hax.so", filename="hax.so" -> MATCH
        // We use strstr for a partial match convenience.
        if (strstr(maps_path, filename) != NULL) { // Check if maps_path substring matches the filename
            data->should_hide = true;              // Set flag to hide this entry in the return handler
        }
    }

    return 0; // Return 0 to allow the hooked function to proceed normally
}

static int maps_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mapshid_data *data = (struct mapshid_data *)ri->data; // Access the per-instance storage initialized in the entry handler

    if (data->should_hide && data->m) { // Only proceed if the entry handler flagged this for hiding and m is valid
        // Rewind the buffer pointer.
        // The kernel wrote the line, but we tell the seq_file logic
        // that the buffer ends exactly where it started.
        // The next write will overwrite the hidden line.
        data->m->count = data->entry_count; // Reset the buffer count to erase the written line
    }

    return 0; // Return 0 to signal successful completion
}

static struct kretprobe kp_maps = {
    .kp.symbol_name = "show_map_vma",         // Set the symbol to hook: show_map_vma
    .entry_handler = maps_entry_handler,      // Assign the entry handler function
    .handler = maps_return_handler,           // Assign the return handler function
    .data_size = sizeof(struct mapshid_data), // Allocate per-instance storage for maps hiding bookkeeping
    .maxactive = 20                           // Allow at least one probe per CPU to avoid dropped instances (set properly in init)
};

// ==========================================
// MODULE INIT / EXIT
// ==========================================

static int __init tracerhid_init(void)
{
    int ret; // Return value for probe registration calls

    // 1. Register TracerPid hider
    kp_status.maxactive = max(20U, (unsigned int)NR_CPUS * 2); // Set maxactive to ensure sufficient concurrency for TracerPid probe
    ret = register_kretprobe(&kp_status);                      // Register the kretprobe for proc_pid_status
    if (ret < 0) {
        pr_err("Failed to register proc_pid_status probe: %d\n", ret);
        return ret;
    }
    pr_info("TracerPid hider loaded for PID %d\n", target_pid); // Log successful loading of TracerPid hider

    // 2. Register Maps hider
    kp_maps.maxactive = max(20U, (unsigned int)NR_CPUS * 2); // Set maxactive to ensure sufficient concurrency for maps probe
    ret = register_kretprobe(&kp_maps);                      // Register the kretprobe for show_map_vma
    if (ret < 0) {
        pr_err("Failed to register show_map_vma probe: %d\n", ret);
        unregister_kretprobe(&kp_status); // Cleanup first probe if second fails
        synchronize_rcu();                // Ensure all RCU callbacks complete before returning
        return ret;
    }
    
    if (maps_path)
        pr_info("Maps hider loaded checking for: %s\n", maps_path); // Log successful loading of maps hider

    return 0;
}

static void __exit tracerhid_exit(void)
{
    unregister_kretprobe(&kp_status); // Unregister the proc_pid_status probe
    unregister_kretprobe(&kp_maps);   // Unregister the show_map_vma probe
    synchronize_rcu();                // Ensure all RCU callbacks complete before module unload
    pr_info("Tracerhid unloaded\n");  // Log module unload completion
}

module_init(tracerhid_init); // Register the module initialization function
module_exit(tracerhid_exit); // Register the module exit function