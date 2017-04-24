#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <sys/user.h>
#include <vector>
#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include "debug_info.h"


long log_error(long ret) {
    if (ret == -1) {
        switch (errno) {
            case EIO:
                std::cerr << "PTRACE ERROR: EIO!" << '\n';
            case EPERM:
                std::cerr << "PTRACE ERROR: EPERM!" << '\n';
            case EINVAL:
                std::cerr << "PTRACE ERROR: EINVAL!" << '\n';
            case EFAULT:
                std::cerr << "PTRACE ERROR: EFAULT!" << '\n';
            default:
                std::cerr << "PTRACE ERROR: ESRCH!" << '\n';
        }
    }
    return ret;
}

std::set<unsigned long long> breaks;
/* истина, если текущий брейкпоинт удалили, когда стояли на нем.
 зачем это нужно: чтобы продолжить выполнение, нужно в любом случае
 убрать 0xcc с инструкции, перейти к следующей, и только потом восстановить
 брейк, если !cleared_on_stop
 */
bool cleared_on_stop = false;
bool is_stopped = false;
bool stopped_on_pc_break = false;
unsigned long long cur_pc_break;
bool is_running = false;
int status;
std::map<unsigned long long, long> text;
debug_info *info;

void set_pc_break(pid_t traced, unsigned long long b) {
    if (breaks.find(b) != breaks.end()) {
        printf("Breakpoint at %llx already set\n", b);
        return;
    }
    long instr = log_error(ptrace(PTRACE_PEEKTEXT, traced, (void *) b, NULL));
    printf("Set breakpoint at PC %llx\n", b);
    text[b] = instr;
    log_error(ptrace(PTRACE_POKETEXT, traced, (void *) b, (void *) (0xcc | (instr & 0xffffffffffffff00))));
    if (stopped_on_pc_break && cur_pc_break == b)
        cleared_on_stop = true;
    breaks.insert(b);
}

void remove_pc_break(pid_t traced, unsigned long long b) {
    if (breaks.find(b) == breaks.end()) {
        printf("Breakpoint at %llx is not set\n", b);
        return;
    }
    if (stopped_on_pc_break && cur_pc_break == b) {
        printf("Breakpoint deleted at %llx\n", b);
        cleared_on_stop = true;
        return;
    }
    printf("Breakpoint deleted at PC %llx\n", b);
    log_error(ptrace(PTRACE_POKETEXT, traced, (void *) b, (void *) text[b]));
    breaks.erase(b);
}


bool handle_pc_break(pid_t traced, unsigned long long b) {
    long t = log_error(ptrace(PTRACE_PEEKTEXT, traced, (void *) b, 0));
    if ((t & 0xff) != 0xcc)
        return 0;
    auto res = info->line_by_pc(b);
    printf("stopped at PC %llx, line %llx, file %s\n", b, res.second, res.first.c_str());
    user_regs_struct regs;
    log_error(ptrace(PTRACE_GETREGS, traced, 0, &regs));
    regs.rip--;
    log_error(ptrace(PTRACE_SETREGS, traced, 0, &regs));
    t &= 0xffffffffffffff00;
    t |= (text[b] & 0xff);
    log_error(ptrace(PTRACE_POKETEXT, traced, b, t));
    cur_pc_break = b;
    return 1;
}

void continue_from_break(pid_t traced, unsigned long long b) {
    log_error(ptrace(PTRACE_SINGLESTEP, traced, 0, 0));
    waitpid(traced, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) & SIGTRAP) {
        long instr = log_error(ptrace(PTRACE_PEEKTEXT, traced, b, 0));
        if (!cleared_on_stop) {
            instr &= 0xffffffffffffff00;
            instr |= 0xcc;
        }
        else
            cleared_on_stop = false;
        log_error(ptrace(PTRACE_POKETEXT, traced, b, instr));
        user_regs_struct regs;
        log_error(ptrace(PTRACE_GETREGS, traced, 0, &regs));
        log_error(ptrace(PTRACE_CONT, traced, 0, 0));
        waitpid(traced, &status, 0);
        is_stopped = 0;
    }
}


void trace(pid_t pid)
{

    struct user_regs_struct regs;

    if (is_stopped) {
        is_stopped = false;
        log_error(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        waitpid(pid, &status, 0);
    }
    while (!WIFEXITED(status))
    {
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & SIGTRAP))
        {
            log_error(ptrace(PTRACE_GETREGS, pid, 0, &regs));
            if (regs.orig_rax >= 0 && regs.orig_rax < 512) {
                printf("SYSCALL %3lld at %llx\n", regs.orig_rax, regs.rip);
            }
            stopped_on_pc_break = handle_pc_break(pid, regs.rip - 1);
            if (stopped_on_pc_break) {
                is_stopped = true;
                return;
            }
        }
        log_error(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        waitpid(pid, &status, 0);
    }
    printf("Process %d exited with code %d\n", pid, WEXITSTATUS(status));
    is_running = false;
}

void trace_step(pid_t pid)
{
    struct user_regs_struct regs;
    if (is_stopped) {
        is_stopped = false;
    }
    log_error(ptrace(PTRACE_SYSCALL, pid, 0, 0));
    waitpid(pid, &status, 0);
    log_error(ptrace(PTRACE_GETREGS, pid, 0, &regs));
    printf("SYSCALL %3lld at %llx\n", regs.orig_rax, regs.rip);
}


void print_regs(pid_t pid, char* reg)
{
    struct user_regs_struct regs;
    log_error(ptrace(PTRACE_GETREGS, pid, 0, &regs));
    if (strcmp(reg, "r15") == 0) printf("r15 = %lld\n", regs.r15);
    else if (strcmp(reg, "r14") == 0) printf("r14 = %lld\n", regs.r14);
    else if (strcmp(reg, "r13") == 0) printf("r13 = %lld\n", regs.r13);
    else if (strcmp(reg, "r12") == 0) printf("r12 = %lld\n", regs.r12);
    else if (strcmp(reg, "rbp") == 0) printf("rbp = %lld\n", regs.rbp);
    else if (strcmp(reg, "rbx") == 0) printf("rbx = %lld\n", regs.rbx);
    else if (strcmp(reg, "r11") == 0) printf("r11 = %lld\n", regs.r11);
    else if (strcmp(reg, "r10") == 0) printf("r10 = %lld\n", regs.r10);
    else if (strcmp(reg, "r9") == 0) printf("r9 = %lld\n", regs.r9);
    else if (strcmp(reg, "r8") == 0) printf("r8 = %lld\n", regs.r8);
    else if (strcmp(reg, "rax") == 0) printf("rax = %lld\n", regs.rax);
    else if (strcmp(reg, "rcx") == 0) printf("rcx = %lld\n", regs.rcx);
    else if (strcmp(reg, "rdx") == 0) printf("rdx = %lld\n", regs.rdx);
    else if (strcmp(reg, "rsi") == 0) printf("rsi = %lld\n", regs.rsi);
    else if (strcmp(reg, "rdi") == 0) printf("rdi = %lld\n", regs.rdi);
    else if (strcmp(reg, "orig_rax") == 0) printf("orig_rax = %lld\n", regs.orig_rax);
    else if (strcmp(reg, "rip") == 0) printf("rip = %lld\n", regs.rip);
    else if (strcmp(reg, "cs") == 0) printf("cs = %lld\n", regs.cs);
    else if (strcmp(reg, "eflags") == 0) printf("eflags = %lld\n", regs.eflags);
    else if (strcmp(reg, "rsp") == 0) printf("rsp = %lld\n", regs.rsp);
    else if (strcmp(reg, "ss") == 0) printf("ss = %lld\n", regs.ss);
    else if (strcmp(reg, "fs_base") == 0) printf("fs_base = %lld\n", regs.fs_base);
    else if (strcmp(reg, "gs_base") == 0) printf("gs_base = %lld\n", regs.gs_base);
    else if (strcmp(reg, "ds") == 0) printf("ds = %lld\n", regs.ds);
    else if (strcmp(reg, "es") == 0) printf("es = %lld\n", regs.es);
    else if (strcmp(reg, "fs") == 0) printf("fs = %lld\n", regs.fs);
    else if (strcmp(reg, "gs") == 0) printf("gs = %lld\n", regs.gs);
    else printf("Invalid register\n");

}

void child(char* path)
{
    char* file = strtok(path, "\\");
    char* last;
    while (file) {
        last = file;
        file = strtok(0, "\\");
    }

    log_error(ptrace(PTRACE_TRACEME, 0, 0, 0));
    execl(path, last, NULL);
}

/*
 * каждый системный вызов ловится дважды (возможно это фиксится, а возможно нет, как в gdb)
*/

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <full path to process to be traced>\n", argv[0]);
        return -1;
    }
    try {
        info = new debug_info(std::string(argv[1]));
    }
    catch (const std::invalid_argument& e) {
        printf("%s\n", e.what());
    }
    pid_t traced = fork();
    if (traced)
    {
        waitpid(traced, &status, 0);

        std::string command;
        while (true)
        {
            printf("> ");
            getline(std::cin, command);
            if (command.empty())
                continue;
            char* ptr;
            ptr = strtok(const_cast<char*>(command.c_str()), " ");
            if (strcmp(ptr, "quit") == 0) {
                log_error(ptrace(PTRACE_DETACH, traced, NULL, NULL));
                kill(traced, SIGTERM);
                return 0;
            } else if (strcmp(ptr, "break") == 0) {
                ptr = strtok(NULL, " ");
                if (ptr != NULL) {
                    if (!strcmp(ptr, "-pc")) {
                        ptr = strtok(NULL, " ");
                        set_pc_break(traced, std::stoull(std::string(ptr), nullptr, 16));
                    }
                    else {
                        try {
                            size_t l = std::stoull(std::string(ptr), nullptr);
                            ptr = strtok(NULL, " ");
                            if (ptr != NULL)
                                set_pc_break(traced, info->pc_by_line(std::string(ptr), l));
                            else
                                set_pc_break(traced, info->pc_by_line(l));
                        }
                        catch (std::exception& e) {
                            printf("Invalid number argument for break\n");
                        }
                    }
                } else {
                    printf("Invalid argument for break\n");
                }
            } else if (strcmp(ptr, "breaklist") == 0) {
                for (auto i = breaks.begin(); i != breaks.end(); i++)
                    printf("Breakpoint at %llx\n", *i);
            } else if (strcmp(ptr, "clear") == 0) {
                ptr = strtok(NULL, " ");
                if (ptr != NULL) {
                    if (!strcmp(ptr, "-pc")) {
                        ptr = strtok(NULL, " ");
                        unsigned long long bp = std::stoull(std::string(ptr), nullptr, 16);
                        remove_pc_break(traced, bp);
                    }
                    else {
                        try {
                            size_t l = std::stoull(std::string(ptr), nullptr);
                            ptr = strtok(NULL, " ");
                            if (ptr != NULL)
                                remove_pc_break(traced, info->pc_by_line(std::string(ptr), l));
                            else
                                remove_pc_break(traced, info->pc_by_line(l));
                        }
                        catch (std::exception& e) {
                            printf("Invalid number argument for break\n");
                        }
                    }
                }

            } else if (strcmp(ptr, "run") == 0) {
                if (!is_running) {
                    printf("Process %d is starting\n", traced);
                    is_running = true;
                    trace(traced);
                } else {
                    printf("Process %d has been started already. Use: continue\n", traced);
                }
            } else if (strcmp(ptr, "continue") == 0) {
                if (is_running) {
                    if (stopped_on_pc_break)
                        continue_from_break(traced, cur_pc_break);
                    trace(traced);
                } else {
                    printf("Process %d is not started yet. Use: run\n", traced);
                }
            } else if (strcmp(ptr, "next") == 0) {
                if (!is_running) {
                    is_running = true;
                }
                trace_step(traced);
            } else if (strcmp(ptr, "reg") == 0) {
                if (is_running) {
                    ptr = strtok(NULL, " ");
                    if (ptr != NULL) {
                        print_regs(traced, ptr);
                    } else {
                        printf("Invalid argument for reg. See: help.\n");
                    }
                } else {
                    printf("Process %d is not running. No registers are available.\n", traced);
                }
            } else if (strcmp(ptr, "mem") == 0) {
                //TODO
                //печать памяти на текущий момент
                //Это не понятно. Мехрубон? Рома?
            } else if (strcmp(ptr, "help") == 0) {
                printf("break -pc <PC>                  - Set a breakpoint at PC\n");
                printf("break <line number> [filename]  - Set a breakpoint at line\n");
                printf("breaklist                       - Prints list of set breakpoints\n");
                printf("clear -pc <PC>                  - Delete a breakpoint at PC\n");
                printf("clear <line number> [filename]  - Delete a breakpoint at line\n");
                printf("continue                        - Continues the stopped process\n");
                printf("help                            - Prints this help message\n");
                printf("mem <address>                   - Prints memory at address\n");
                printf("next                            - Do next step\n");
                printf("reg <register>                  - Prints register\n");
                printf("run                             - Start the process\n");
                printf("quit                            - Exit the program\n");
            } else {
                printf("Invalid command. See help.\n");
            }
        }

    }
    else {
        child(argv[1]);
    }

}
