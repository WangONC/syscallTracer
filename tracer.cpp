#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <getopt.h>

#include <asm/ptrace.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <elf.h>

#include <signal.h>
#include <errno.h>
#include <cerrno>

#define MAX_SYSCALLS 10
#define MAX_MODULES 4096
#define MAX_PATH 256
#define MAX_THREADS 1024
#define MAX_BACKTRACE_DEPTH 16


pid_t g_child_pid = 0;

volatile sig_atomic_t g_running = 1;

struct module_info{
    char name[MAX_PATH];
    unsigned long long start_addr;
    unsigned long long end_addr;
    unsigned long long offset;
};

struct thread_info {
    pid_t tid;
    int syscall_enter;
};

struct {
    int syscalls[MAX_SYSCALLS]; // List of syscalls to hook
    int syscall_count; // Number of syscalls
    pid_t pid;
    char process_name[MAX_PATH]; // Mount by process name
    char exec_command[MAX_PATH]; // Launch a specific application
    int show_absolute; // Show absolute addresses
    int show_relative; // Show relative addresses
    int show_backtrace; // Show call stack
    int verbose; // Verbose output
    struct module_info modules[MAX_MODULES]; // Modules of the pid
    int module_count;
} config;

struct syscall_entry {
    long number;
    const char *name;
} syscall_names[] = {
    {0, "io_setup"},
    {1, "io_destroy"},
    {2, "io_submit"},
    {3, "io_cancel"},
    {4, "io_getevents"},
    {5, "setxattr"},
    {6, "lsetxattr"},
    {7, "fsetxattr"},
    {8, "getxattr"},
    {9, "lgetxattr"},
    {10, "fgetxattr"},
    {11, "listxattr"},
    {12, "llistxattr"},
    {13, "flistxattr"},
    {14, "removexattr"},
    {15, "lremovexattr"},
    {16, "fremovexattr"},
    {17, "getcwd"},
    {18, "lookup_dcookie"},
    {19, "eventfd2"},
    {20, "epoll_create1"},
    {21, "epoll_ctl"},
    {22, "epoll_pwait"},
    {23, "dup"},
    {24, "dup3"},
    {25, "fcntl"},
    {26, "inotify_init1"},
    {27, "inotify_add_watch"},
    {28, "inotify_rm_watch"},
    {29, "ioctl"},
    {30, "ioprio_set"},
    {31, "ioprio_get"},
    {32, "flock"},
    {33, "mknodat"},
    {34, "mkdirat"},
    {35, "unlinkat"},
    {36, "symlinkat"},
    {37, "linkat"},
    {38, "renameat"},
    {39, "umount2"},
    {40, "mount"},
    {41, "pivot_root"},
    {42, "nfsservctl"},
    {43, "statfs"},
    {44, "fstatfs"},
    {45, "truncate"},
    {46, "ftruncate"},
    {47, "fallocate"},
    {48, "faccessat"},
    {49, "chdir"},
    {50, "fchdir"},
    {51, "chroot"},
    {52, "fchmod"},
    {53, "fchmodat"},
    {54, "fchownat"},
    {55, "fchown"},
    {56, "openat"},
    {57, "close"},
    {58, "vhangup"},
    {59, "pipe2"},
    {60, "quotactl"},
    {61, "getdents64"},
    {62, "lseek"},
    {63, "read"},
    {64, "write"},
    {65, "readv"},
    {66, "writev"},
    {67, "pread64"},
    {68, "pwrite64"},
    {69, "preadv"},
    {70, "pwritev"},
    {71, "sendfile"},
    {72, "pselect6"},
    {73, "ppoll"},
    {74, "signalfd4"},
    {75, "vmsplice"},
    {76, "splice"},
    {77, "tee"},
    {78, "readlinkat"},
    {79, "newfstatat"},
    {80, "fstat"},
    {81, "sync"},
    {82, "fsync"},
    {83, "fdatasync"},
    {84, "sync_file_range"},
    {85, "timerfd_create"},
    {86, "timerfd_settime"},
    {87, "timerfd_gettime"},
    {88, "utimensat"},
    {89, "acct"},
    {90, "capget"},
    {91, "capset"},
    {92, "personality"},
    {93, "exit"},
    {94, "exit_group"},
    {95, "waitid"},
    {96, "set_tid_address"},
    {97, "unshare"},
    {98, "futex"},
    {99, "set_robust_list"},
    {100, "get_robust_list"},
    {101, "nanosleep"},
    {102, "getitimer"},
    {103, "setitimer"},
    {104, "kexec_load"},
    {105, "init_module"},
    {106, "delete_module"},
    {107, "timer_create"},
    {108, "timer_gettime"},
    {109, "timer_getoverrun"},
    {110, "timer_settime"},
    {111, "timer_delete"},
    {112, "clock_settime"},
    {113, "clock_gettime"},
    {114, "clock_getres"},
    {115, "clock_nanosleep"},
    {116, "syslog"},
    {117, "ptrace"},
    {118, "sched_setparam"},
    {119, "sched_setscheduler"},
    {120, "sched_getscheduler"},
    {121, "sched_getparam"},
    {122, "sched_setaffinity"},
    {123, "sched_getaffinity"},
    {124, "sched_yield"},
    {125, "sched_get_priority_max"},
    {126, "sched_get_priority_min"},
    {127, "sched_rr_get_interval"},
    {128, "restart_syscall"},
    {129, "kill"},
    {130, "tkill"},
    {131, "tgkill"},
    {132, "sigaltstack"},
    {133, "rt_sigsuspend"},
    {134, "rt_sigaction"},
    {135, "rt_sigprocmask"},
    {136, "rt_sigpending"},
    {137, "rt_sigtimedwait"},
    {138, "rt_sigqueueinfo"},
    {139, "rt_sigreturn"},
    {140, "setpriority"},
    {141, "getpriority"},
    {142, "reboot"},
    {143, "setregid"},
    {144, "setgid"},
    {145, "setreuid"},
    {146, "setuid"},
    {147, "setresuid"},
    {148, "getresuid"},
    {149, "setresgid"},
    {150, "getresgid"},
    {151, "setfsuid"},
    {152, "setfsgid"},
    {153, "times"},
    {154, "setpgid"},
    {155, "getpgid"},
    {156, "getsid"},
    {157, "setsid"},
    {158, "getgroups"},
    {159, "setgroups"},
    {160, "uname"},
    {161, "sethostname"},
    {162, "setdomainname"},
    {163, "getrlimit"},
    {164, "setrlimit"},
    {165, "getrusage"},
    {166, "umask"},
    {167, "prctl"},
    {168, "getcpu"},
    {169, "gettimeofday"},
    {170, "settimeofday"},
    {171, "adjtimex"},
    {172, "getpid"},
    {173, "getppid"},
    {174, "getuid"},
    {175, "geteuid"},
    {176, "getgid"},
    {177, "getegid"},
    {178, "gettid"},
    {179, "sysinfo"},
    {180, "mq_open"},
    {181, "mq_unlink"},
    {182, "mq_timedsend"},
    {183, "mq_timedreceive"},
    {184, "mq_notify"},
    {185, "mq_getsetattr"},
    {186, "msgget"},
    {187, "msgctl"},
    {188, "msgrcv"},
    {189, "msgsnd"},
    {190, "semget"},
    {191, "semctl"},
    {192, "semtimedop"},
    {193, "semop"},
    {194, "shmget"},
    {195, "shmctl"},
    {196, "shmat"},
    {197, "shmdt"},
    {198, "socket"},
    {199, "socketpair"},
    {200, "bind"},
    {201, "listen"},
    {202, "accept"},
    {203, "connect"},
    {204, "getsockname"},
    {205, "getpeername"},
    {206, "sendto"},
    {207, "recvfrom"},
    {208, "setsockopt"},
    {209, "getsockopt"},
    {210, "shutdown"},
    {211, "sendmsg"},
    {212, "recvmsg"},
    {213, "readahead"},
    {214, "brk"},
    {215, "munmap"},
    {216, "mremap"},
    {217, "add_key"},
    {218, "request_key"},
    {219, "keyctl"},
    {220, "clone"},
    {221, "execve"},
    {222, "mmap"},
    {223, "fadvise64"},
    {224, "swapon"},
    {225, "swapoff"},
    {226, "mprotect"},
    {227, "msync"},
    {228, "mlock"},
    {229, "munlock"},
    {230, "mlockall"},
    {231, "munlockall"},
    {232, "mincore"},
    {233, "madvise"},
    {234, "remap_file_pages"},
    {235, "mbind"},
    {236, "get_mempolicy"},
    {237, "set_mempolicy"},
    {238, "migrate_pages"},
    {239, "move_pages"},
    {240, "rt_tgsigqueueinfo"},
    {241, "perf_event_open"},
    {242, "accept4"},
    {243, "recvmmsg"},
    {244, "not implemented"},
    {245, "not implemented"},
    {246, "not implemented"},
    {247, "not implemented"},
    {248, "not implemented"},
    {249, "not implemented"},
    {250, "not implemented"},
    {251, "not implemented"},
    {252, "not implemented"},
    {253, "not implemented"},
    {254, "not implemented"},
    {255, "not implemented"},
    {256, "not implemented"},
    {257, "not implemented"},
    {258, "not implemented"},
    {259, "not implemented"},
    {260, "wait4"},
    {261, "prlimit64"},
    {262, "fanotify_init"},
    {263, "fanotify_mark"},
    {264, "name_to_handle_at"},
    {265, "open_by_handle_at"},
    {266, "clock_adjtime"},
    {267, "syncfs"},
    {268, "setns"},
    {269, "sendmmsg"},
    {270, "process_vm_readv"},
    {271, "process_vm_writev"},
    {272, "kcmp"},
    {273, "finit_module"},
    {274, "sched_setattr"},
    {275, "sched_getattr"},
    {276, "renameat2"},
    {277, "seccomp"},
    {278, "getrandom"},
    {279, "memfd_create"},
    {280, "bpf"},
    {281, "execveat"},
    {282, "userfaultfd"},
    {283, "membarrier"},
    {284, "mlock2"},
    {285, "copy_file_range"},
    {286, "preadv2"},
    {287, "pwritev2"},
    {288, "pkey_mprotect"},
    {289, "pkey_alloc"},
    {290, "pkey_free"},
    {291, "statx"},
};


struct thread_info threads[MAX_THREADS];
int thread_count = 0;

const char *get_syscall_name(long syscall_number) {
    for (size_t i = 0; i < sizeof(syscall_names)/sizeof(syscall_names[0]); i++) {
        if (syscall_names[i].number == syscall_number) {
            return syscall_names[i].name;
        }
    }
    return "unknown";
}

pid_t get_pid_by_name(const char *process_name) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return -1;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            pid_t pid = atoi(entry->d_name);
            if (pid > 0) {
                char filepath[MAX_PATH];
                snprintf(filepath, sizeof(filepath), "/proc/%d/comm", pid);
                FILE *f = fopen(filepath, "r");
                if (f) {
                    char name[MAX_PATH];
                    if (fgets(name, sizeof(name), f) != NULL) {
                        // Remove newline character
                        name[strcspn(name, "\n")] = 0;
                        if (strcmp(name, process_name) == 0) {
                            fclose(f);
                            closedir(dir);
                            return pid;
                        }
                    }
                    fclose(f);
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

void ptraceAttach(pid_t pid){
    if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1){
        printf("[ERROR] Failed to attach to PID %d: %s\n",pid, strerror(errno));
    }
    int stat=0;
    waitpid(pid, &stat, __WALL);
}

bool ptraceGetRegs(pid_t pid, struct user_pt_regs* regs_addr) {
    struct iovec io;
    io.iov_base = regs_addr;
    io.iov_len = sizeof(struct user_pt_regs);
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io) == -1) {
        if (errno == ESRCH) {  // Process has exited
            return false;
        }
        printf("[ERROR] Get registers error for PID %d: %s\n", pid, strerror(errno));
        return false;
    }
    return true;
}

bool ptraceSetRegs(pid_t pid,struct user_pt_regs*regs_addr){
    struct iovec io;
    io.iov_base = regs_addr;
    io.iov_len = sizeof(struct user_pt_regs);
    if(ptrace(PTRACE_SETREGSET,pid,NT_PRSTATUS,&io)==-1){
        printf("[ERROR] Set registers error for PID %d: %s\n", pid, strerror(errno));
        return false;
    }
    return true;
}
void ptraceDetach(pid_t pid){
    ptrace(PTRACE_DETACH,pid,NULL,NULL);
}

bool read_memory(pid_t pid, unsigned long long addr, void *buf, size_t size) {
    struct iovec local_iov = {
        .iov_base = buf,
        .iov_len = size,
    };
    struct iovec remote_iov = {
        .iov_base = (void *)addr,
        .iov_len = size,
    };

    if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) != size) {
        return false;
    }
    return true;
}


void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = 0;
        printf("\nReceived signal %d. Exiting gracefully...\n", signum);
    }
}

void setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}


void load_module_info(pid_t pid) {
    struct module_info temp_modules[MAX_MODULES];
    int temp_module_count = 0;

    char filepath[MAX_PATH];
    snprintf(filepath, sizeof(filepath), "/proc/%d/maps", pid);
    FILE *f = fopen(filepath, "r");
    if (!f) {
        perror("Failed to open memory maps");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f) && temp_module_count < MAX_MODULES) {
        unsigned long long start, end, offset;
        char permissions[5], path[MAX_PATH] = "";
        if (sscanf(line, "%llx-%llx %4s %llx %*s %*s %s", &start, &end, permissions, &offset, path) >= 5) {
            if (path[0] == '/') { // Skip anonymous mappings
            // if (true) { // all in maps
                struct module_info *module = &temp_modules[temp_module_count++];
                strncpy(module->name, path, MAX_PATH - 1);
                module->name[MAX_PATH - 1] = '\0';
                module->start_addr = start;
                module->end_addr = end;
                module->offset = offset;
            }
        }
    }
    fclose(f);

    // Compare temp_modules with config.modules to find new modules
    for (int i = 0; i < temp_module_count; i++) {
        int found = 0;
        for (int j = 0; j < config.module_count; j++) {
            if (strcmp(temp_modules[i].name, config.modules[j].name) == 0 &&
                temp_modules[i].start_addr == config.modules[j].start_addr &&
                temp_modules[i].end_addr == config.modules[j].end_addr &&
                temp_modules[i].offset == config.modules[j].offset) {
                found = 1;
                break;
            }
        }
        if (!found) {
            // Add new module
            if (config.module_count < MAX_MODULES) {
                        struct module_info *module =
                            &config.modules[config.module_count++];
                        strncpy(module->name, temp_modules[i].name, MAX_PATH - 1);
                        module->name[MAX_PATH - 1] = '\0';
                        module->start_addr = temp_modules[i].start_addr;
                        module->end_addr = temp_modules[i].end_addr;
                        module->offset = temp_modules[i].offset;
                        if (config.verbose) {
                            printf("New module loaded: %s (0x%llx - 0x%llx) "
                                    "offset 0x%llx\n",
                                    module->name, module->start_addr,
                                    module->end_addr, module->offset);
                        }
                    } else {
                        fprintf(stderr, "Module list full; cannot add more.\n");
                    }
        }
    }
}

void attach_to_thread(pid_t tid) {
    if (thread_count < MAX_THREADS) {
        ptraceAttach(tid);
        threads[thread_count].tid = tid;
        threads[thread_count].syscall_enter = 1;
        thread_count++;
        printf("Attached to thread: %d\n", tid);

        if (ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
                                                     PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) == -1) {
            perror("Failed to set options for thread");
        }

        // After attaching, continue the thread execution
        if (ptrace(PTRACE_SYSCALL, tid, 0, 0) == -1) {
            perror("Failed to continue thread after attaching");
        }
    } else {
        printf("Warning: Max thread limit reached. Cannot attach to thread %d\n", tid);
    }
}

void scan_and_attach_threads(pid_t pid) {
    char task_path[MAX_PATH];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    
    DIR* dir = opendir(task_path);
    if (!dir) {
        perror("Failed to open task directory");
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        pid_t tid = atoi(entry->d_name);
        if (tid != pid) {  // Don't reattach to the main thread
            attach_to_thread(tid);
        }
    }

    closedir(dir);
}

void get_relative_address(unsigned long long addr, char *buf, size_t buf_size) {
    for (int i = 0; i < config.module_count; i++) {
        if (addr >= config.modules[i].start_addr && addr < config.modules[i].end_addr) {
            // Calculate the offset within the file
            unsigned long long file_offset = addr - config.modules[i].start_addr;
            snprintf(buf, buf_size, "Relative address: 0x%llx in %s (file offset: 0x%llx)",
                     file_offset + config.modules[i].offset, config.modules[i].name, config.modules[i].offset);
            return;
        }
    }
    snprintf(buf, buf_size, "Relative address: Not found in any loaded module, possibly in anonymous memory mapping.");
}

void print_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s [options] -- <command>\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p <pid>           Attach to process by PID\n");
    fprintf(stderr, "  -n <process_name>  Attach to process by name\n");
    fprintf(stderr, "  -e <command>       Execute and attach to command\n");
    fprintf(stderr, "  -s <syscall_num>   Specify syscall number to hook (can be used multiple times)\n");
    fprintf(stderr, "  -a                 Show absolute address\n");
    fprintf(stderr, "  -r                 Show relative address\n");
    fprintf(stderr, "  -b                 Show backtrace\n");
    fprintf(stderr, "  -v                 Verbose output\n");
    fprintf(stderr, "  -h                 Show this help message\n");
}

void parse_args(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:s:n:e:arbvh")) != -1) {
        switch (opt) {
            case 'p':
                config.pid = atoi(optarg);
                break;
            case 'n':
                strncpy(config.process_name, optarg, MAX_PATH - 1);
                break;
            case 'e':
                strncpy(config.exec_command, optarg, MAX_PATH - 1);
                break;
            case 's':
                if (config.syscall_count < MAX_SYSCALLS) {
                    config.syscalls[config.syscall_count++] = atoi(optarg);
                } else {
                    fprintf(stderr, "Too many syscalls specified. Max is %d.\n", MAX_SYSCALLS);
                    exit(1);
                }
                break;
            case 'a':
                config.show_absolute = 1;
                break;
            case 'r':
                config.show_relative = 1;
                break;
            case 'b':
                config.show_backtrace = 1;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    // Ensure that either PID, process name, or command is specified, but not more than one
    if ((config.pid == 0 && strlen(config.process_name) == 0 && strlen(config.exec_command) == 0) ||
        (config.pid != 0 && (strlen(config.process_name) > 0 || strlen(config.exec_command) > 0)) ||
        (strlen(config.process_name) > 0 && strlen(config.exec_command) > 0)) {
        fprintf(stderr, "Error: Either PID, process name, or execution command must be specified, but not more than one.\n");
        print_usage(argv[0]);
        exit(1);
    }
}

int is_target_syscall(long syscall) {
    for (int i = 0; i < config.syscall_count; i++) {
        if (syscall == config.syscalls[i]) {
            return 1;
        }
    }
    return 0;
}
void print_backtrace(pid_t pid, unsigned long long fp, unsigned long long sp, unsigned long long pc) {
    unsigned long long current_fp = fp;
    unsigned long long saved_fp, saved_lr;
    char buf[256];

    printf("Backtrace:\n");

    // First print the current PC
    get_relative_address(pc, buf, sizeof(buf));
    printf("  [0] 0x%llx %s\n", pc, buf);

    for (int i = 1; i < MAX_BACKTRACE_DEPTH; i++) {
        if (current_fp == 0 || current_fp % 8 != 0) {
            break;
        }

        // Read the saved FP and LR from [current_fp] and [current_fp + 8]
        if (!read_memory(pid, current_fp, &saved_fp, sizeof(saved_fp))) {
            printf("[ERROR] Failed to read saved FP from stack at 0x%llx\n", current_fp);
            break;
        }
        if (!read_memory(pid, current_fp + 8, &saved_lr, sizeof(saved_lr))) {
            printf("[ERROR] Failed to read saved LR from stack at 0x%llx\n", current_fp + 8);
            break;
        }

        // 8-byte aligned on ARM64
        if (saved_fp % 8 != 0 && saved_lr % 8 != 0) return;

        // Check if saved LR is non-zero
        if (saved_lr == 0) break;
        

        // Print the LR and its relative address
        get_relative_address(saved_lr, buf, sizeof(buf));
        printf("  [%d] 0x%llx %s\n", i, saved_lr, buf);
        
        // Debug: print raw values to understand the issue
        if (config.verbose) {
            printf("    [DEBUG] saved_fp=0x%llx, saved_lr=0x%llx, current_fp=0x%llx\n", 
                   saved_fp, saved_lr, current_fp);
        }

        // Check for infinite loops
        if (saved_fp == current_fp) {
            // printf("[WARN] Saved FP is equal to current FP, stopping to avoid infinite loop\n");
            break;
        }
        if (saved_fp <= current_fp) {
            // printf("[WARN] Saved FP is less than or equal to current FP, invalid stack frame\n");
            break;
        }

        // Move to the previous frame
        current_fp = saved_fp;
    }
}

void handle_syscall(pid_t tid, int entering) {
    struct user_pt_regs regs;
    if(!ptraceGetRegs(tid, &regs)) return; // reason???
    long syscall_number = regs.regs[8];  // x8 register holds the syscall number on ARM64
    
    // Check for potential module loading BEFORE handling syscall
    // This ensures we have the most up-to-date module information
    if (entering && (syscall_number == 222 || syscall_number == 221)) { // arm64 mmap or execve
        load_module_info(config.pid);
    }
    
    if (is_target_syscall(syscall_number) || config.syscall_count == 0) {
        char line[512];
        int offset = 0;
        offset += snprintf(line + offset, sizeof(line) - offset, "Thread %d %s syscall %s(%ld)", tid, entering ? "entering" : "exiting",get_syscall_name(syscall_number) ,syscall_number);
        if (config.show_absolute) {
            offset += snprintf(line + offset, sizeof(line) - offset, " at 0x%llx", (unsigned long long) regs.pc);
        }
        if (config.show_relative) {
            char rel_addr[256];
            get_relative_address((unsigned long long) regs.pc, rel_addr, sizeof(rel_addr));
            offset += snprintf(line + offset, sizeof(line) - offset, " %s", rel_addr);
        }
        if (!entering) {
            offset += snprintf(line + offset, sizeof(line) - offset, " with return 0x%llx", regs.regs[0]);
        }

        printf("%s\n", line);

        // Print backtrace if enabled
        if (config.show_backtrace) {
            print_backtrace(tid, regs.regs[29], regs.sp, regs.pc);  // FP is x29, SP is regs.sp, PC is regs.pc
        }
    }

    // Also check after syscall exit for some operations
    if (!entering && (syscall_number == 222 || syscall_number == 221)) { // arm64 mmap or execve
        load_module_info(config.pid);
    }
}

void initialize_new_process(pid_t new_pid) {
    // Add retry mechanism for initialization
    int retry_count = 0;
    const int max_retries = 10;
    const int retry_delay_us = 100; // 1ms delay between retries
    
    while (retry_count < max_retries) {
        // Check if process exists
        char proc_path[32];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", new_pid);
        if (access(proc_path, F_OK) == -1) {
            usleep(retry_delay_us);
            retry_count++;
            continue;
        }

        // Try to set options
        if (ptrace(PTRACE_SETOPTIONS, new_pid, 0, 
            PTRACE_O_TRACESYSGOOD | 
            PTRACE_O_TRACECLONE |
            PTRACE_O_TRACEFORK |
            PTRACE_O_TRACEVFORK) != -1) {
            
            // Try to continue the process
            if (ptrace(PTRACE_SYSCALL, new_pid, 0, 0) != -1) {
                // Add to thread list only after successful initialization
                if (thread_count < MAX_THREADS) {
                    threads[thread_count].tid = new_pid;
                    threads[thread_count].syscall_enter = 1;
                    thread_count++;
                    return; // Success
                } else {
                    fprintf(stderr, "Thread list full, cannot add thread %d\n", new_pid);
                    return;
                }
            }
        }
        
        usleep(retry_delay_us);
        retry_count++;
    }
    
    fprintf(stderr, "Failed to initialize thread %d after %d retries\n", 
            new_pid, max_retries);
}

void execute_and_trace(char *command) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process: execute the command
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        perror("execl failed");
        exit(1);
    } else if (child_pid > 0) {
        // Parent process: wait for the child to stop and then attach
        g_child_pid = child_pid;
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFSTOPPED(status)) {
            printf("Successfully started and attached to process %d\n", child_pid);
            config.pid = child_pid;
        } else {
            fprintf(stderr, "Failed to start the child process.\n");
            exit(1);
        }
    } else {
        perror("fork failed");
        exit(1);
    }
}


int main(int argc, char *argv[]) {

    memset(&config, 0, sizeof(config));
    parse_args(argc, argv);

    setup_signal_handlers(); // 设置信号处理，优雅退出

    if (strlen(config.exec_command) > 0) {
        // If the command to execute is specified, launch the application and attach it.
        execute_and_trace(config.exec_command);
    } else if (strlen(config.process_name) > 0) {
        // If the process name is specified, find the process ID and attch it.
        config.pid = get_pid_by_name(config.process_name);
        if (config.pid == -1) {
            fprintf(stderr, "Error: Could not find process with name '%s'.\n", config.process_name);
            exit(1);
        }
         ptraceAttach(config.pid);
    } else if (config.pid != 0) {
        // Directly specified pid, perform attach.
        ptraceAttach(config.pid);
    }
    
    // Attach to the main process
    load_module_info(config.pid);

    // Initialize threads array
    threads[0].tid = config.pid;
    threads[0].syscall_enter = 1;
    thread_count = 1;



    scan_and_attach_threads(config.pid);
    // Set options on the main process
    if (ptrace(PTRACE_SETOPTIONS, config.pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) == -1) {
        perror("Failed to set options for main process");
        exit(1);
    }

    // Continue the main process
    if (ptrace(PTRACE_SYSCALL, config.pid, 0, 0) == -1) {
        perror("Failed to continue main process");
        exit(1);
    }

    int status;
    int syscall_enter = 1;  // Flag to track syscall enter/exit
    struct user_pt_regs regs;
    long orig_x8;
    pid_t current_pid;
    while (g_running) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD)
                break;
            perror("waitpid failed");
            break;
        }

        // This could be a new thread that we haven't initialized yet
        struct thread_info *tinfo = NULL;
        for (int i = 0; i < thread_count; i++) {
            if (threads[i].tid == pid) {
                tinfo = &threads[i];
                break;
            }
        }

        if (tinfo == NULL) {
            // Not in our list, should not happen
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            // Safe thread removal
            int idx = -1;
            for (int i = 0; i < thread_count; i++) {
                if (threads[i].tid == pid) {
                    idx = i;
                    break;
                }
            }
            
            if (idx >= 0) {
                // Shift remaining threads
                for (int i = idx; i < thread_count - 1; i++) {
                    threads[i] = threads[i + 1];
                }
                thread_count--;
                printf("Process %d exited\n", pid);
            }
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == (SIGTRAP | 0x80)) {
                // Syscall stop - check for module changes first
                load_module_info(config.pid);
                handle_syscall(pid, tinfo->syscall_enter);
                tinfo->syscall_enter = !tinfo->syscall_enter;
            } else if (sig == SIGTRAP) {
                // Ptrace event
                unsigned long event = (unsigned long)(status >> 16);
                if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
                    // Handle new process/thread
                    unsigned long new_pid;
                    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) == -1) {
                        fprintf(stderr, "PTRACE_GETEVENTMSG failed for parent %d: %s\n", 
                                pid, strerror(errno));
                    } else {
                        // Check if thread already exists in our list
                        for (int i = 0; i < thread_count; i++) {
                            if (threads[i].tid == new_pid) {
                                break; // Already tracking this thread
                            }
                        }
                        printf("New process/thread created: %ld\n", new_pid);
                        // Attach to new_pid
                        initialize_new_process(new_pid);
                    }
                } else {
                    // Other ptrace events
                }
            }
        }

        // Resume the child
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            if (errno != ESRCH) {  // Ignore if thread has exited
                fprintf(stderr, "Failed to resume thread %d: %s\n", 
                    pid, strerror(errno));
            }
        }
    }

    // Detach from all threads
    for (int i = 0; i < thread_count; i++) {
        ptraceDetach(threads[i].tid);
    }
    return 0;
}
