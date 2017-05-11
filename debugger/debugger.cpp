#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <set>

#include "debug_info.h"


void set_breakpoint(pid_t traced, std::stringstream& stream, bool yes);
void remove_breakpoint(pid_t traced, std::stringstream& stream, bool yes);

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
bool is_done = false;


namespace {
    using std::string;
    const string QUIT[] = {"quit", "q", "Q", "exit"};
    const string RUN[] = {"run", "r", "R"};
    const string HELP[] = {"help", "h", "-h"};
    const string BREAK[] = {"break", "b"};
    const string BREAKLIST[] = {"breaklist", "bl"};
    const string CONTINUE[] = {"continue", "cont"};
    const string CLEAR[] = {"cl", "clear"};
    const string NEXT[] = {"next", "n"};
    const string REG[] = {"reg"};
    const string MEM[] = {"mem"};

    template<size_t N>
    const string* end(const string (&arr)[N]) {
        return arr + N;
    }

    template<size_t N>
    bool helper_checker(const string (&arr)[N], const string& instruction) {
        return find(arr, end(arr), instruction) != end(arr);
    }

    bool is_quit(const string& instruction) {
        return helper_checker(QUIT, instruction);
    }
    bool is_run(const string& instruction) {
        return helper_checker(RUN, instruction);
    }
    bool is_help(const string& instruction) {
        return helper_checker(HELP, instruction);
    }
    bool is_break(const string& instruction) {
        return helper_checker(BREAK, instruction);
    }
    bool is_breaklist(const string& instruction) {
        return helper_checker(BREAKLIST, instruction);
    }
    bool is_continue(const string& instruction) {
        return helper_checker(CONTINUE, instruction);
    }
    bool is_clear(const string& instruction) {
        return helper_checker(CLEAR, instruction);
    }
    bool is_next(const string& instruction) {
        return helper_checker(NEXT, instruction);
    }
    bool is_reg(const string& instruction) {
        return helper_checker(REG, instruction);
    }
    bool is_mem(const string& instruction) {
        return helper_checker(MEM, instruction);
    }
}

// if !yes -- do not print info, because break was called by next program, not user
void set_pc_break(pid_t traced, unsigned long long b, bool yes = true) {
    if (breaks.find(b) != breaks.end()) {
        if (yes) printf("Breakpoint at %llx already set\n", b);
        return;
    }
    long instr = log_error(ptrace(PTRACE_PEEKTEXT, traced, (void *) b, NULL));
    if (yes) printf("Set breakpoint at PC %llx\n", b);
    text[b] = instr;
    log_error(ptrace(PTRACE_POKETEXT, traced, (void *) b, (void *) (0xcc | (instr & 0xffffffffffffff00))));
    if (stopped_on_pc_break && cur_pc_break == b)
        cleared_on_stop = true;
    breaks.insert(b);
}

// if !yes -- do not print info, because break was called by next program, not user
void remove_pc_break(pid_t traced, unsigned long long b, bool yes = true) {
    if (breaks.find(b) == breaks.end()) {
        if (yes) printf("Breakpoint at %llx is not set\n", b);
        return;
    }
    if (stopped_on_pc_break && cur_pc_break == b) {
        if (yes) printf("Breakpoint deleted at %llx\n", b);
        cleared_on_stop = true;
        return;
    }
    if (yes) printf("Breakpoint deleted at PC %llx\n", b);
    log_error(ptrace(PTRACE_POKETEXT, traced, (void *) b, (void *) text[b]));
    breaks.erase(b);
}

bool handle_pc_break(pid_t traced, unsigned long long b) {
    long t = log_error(ptrace(PTRACE_PEEKTEXT, traced, (void *) b, 0));
    if ((t & 0xff) != 0xcc)
        return 0;
    auto res = info->line_by_pc(b);
    printf("stopped at PC %llx, line %lld, file %s\n", b, res.second, res.first.c_str());
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
        else {
            cleared_on_stop = false;
            breaks.erase(b);
        }
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
            if (regs.orig_rax < 512) {
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
    is_done = true;
    exit(0);
}

void initialize_next(pid_t traced)
{
    unsigned long long l = info->find_next_line(1);
    while (l != 0)
    {
        std::stringstream str, str2;
        str << l;
        str2 << l;
        set_breakpoint(traced, str, false);
        l = info->find_next_line(l);
    }
}

void uninitialize_next(pid_t traced, std::set<unsigned long long>* next_breaks)
{
    unsigned long long l = info->find_next_line(1);
    while (l != 0)
    {
        if (next_breaks->find(info->pc_by_line(l)) == next_breaks->end())
        {
            std::stringstream str, str2;
            str << l;
            str2 << l;
            remove_breakpoint(traced, str, false);
        }
        l = info->find_next_line(l);
    }
}
void trace_step(pid_t traced)
{
    auto breaks_copy = breaks;
    initialize_next(traced);

    if (stopped_on_pc_break)
        continue_from_break(traced, cur_pc_break);
    trace(traced);

     uninitialize_next(traced, &breaks_copy);
}


void print_regs(pid_t pid, const std::string& reg_name)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    #define magic_with_define(s) if (reg_name == #s) printf(#s" = %lld\n", regs.s)
    magic_with_define(r15);
    else magic_with_define(r14);
    else magic_with_define(r13);
    else magic_with_define(r12);
    else magic_with_define(rbp);
    else magic_with_define(rbx);
    else magic_with_define(r11);
    else magic_with_define(r10);
    else magic_with_define(r9);
    else magic_with_define(r8);
    else magic_with_define(rax);
    else magic_with_define(rcx);
    else magic_with_define(rdx);
    else magic_with_define(rsi);
    else magic_with_define(rdi);
    else magic_with_define(orig_rax);
    else magic_with_define(rip);
    else magic_with_define(cs);
    else magic_with_define(eflags);
    else magic_with_define(rsp);
    else magic_with_define(ss);
    else magic_with_define(fs_base);
    else magic_with_define(gs_base);
    else magic_with_define(ds);
    else magic_with_define(es);
    else magic_with_define(fs);
    else magic_with_define(gs);
    else printf("Invalid register\n");
    #undef magic_with_define
}

void read_child_memory(int pid, unsigned long long address) {
    for (int tries = 0; tries < 5; ++tries) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(address), 0);
        if (errno == 0) {
            std::cout << "mem " << address << ": " << data << "\n";
            return;
        }
    }
    std::cout << "Can't read memory by this address: " << address << ' ' << strerror(errno) << "\n";
}

void child(char* path)
{
    char* file = strtok(path, "\\");
    char* last = file;
    while (file) {
        last = file;
        file = strtok(0, "\\");
    }

    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(path, last, NULL);
}

void print_help() {
    printf("break -pc <PC>                  - Set a breakpoint at PC\n");
    printf("break <line number> [filename]  - Set a breakpoint at line\n");
    printf("breaklist, bl                   - Prints list of set breakpoints\n");
    printf("clear -pc <PC>                  - Delete a breakpoint at PC\n");
    printf("clear <line number> [filename]  - Delete a breakpoint at line\n");
    printf("continue, cont                  - Continues the stopped process\n");
    printf("help, h, -h                     - Prints this help message\n");
    printf("mem <address>                   - Prints memory at address\n");
    printf("next                            - Do next step\n");
    printf("reg <register>                  - Prints register\n");
    printf("run, r, R                       - Start the process\n");
    printf("quit, q, Q, exit                - Exit the program\n");
}

pid_t traced = -1;

void kill_child() {
    if (traced != -1) {
        ptrace(PTRACE_DETACH, traced, NULL, NULL);
        kill(traced, SIGTERM);
    }
    exit(0);
}

void set_signal_handler() {
    if (signal(SIGINT, [](int signo) {
            if(signo == SIGINT) {
                std::cout << "\tquit with signal\n";
                kill_child();
            }
        }
        ) == SIG_ERR) {
        std::cout << "Can't handle signals\n";
        exit(0);
    }
}

void invalid_args(const std::string& com) {
    printf("Invalid argument for %s\n", com.c_str());
}

// if !yes -- do not print info, because break was called by next program, not user
void set_breakpoint(pid_t traced, std::stringstream& stream, bool yes = true) {
    std::string data;
    /*if (stream >> data) {
        if (find(breaks.begin(), breaks.end(), data) == breaks.end()) {
            breaks.push_back(data);
            printf("Breakpoint set at %zu\n", data);
        } else {
            std::cout << "Such breakpoint was set earlier\n";
        }
    } else {
        invalid_args("breaklist");
    }*/
    if (stream >> data) {
        if (!strcmp(data.c_str(), "-pc")) {
            stream >> data;
            set_pc_break(traced, std::stoull(data, nullptr, 16), yes);
        }
        else {
            try {
                size_t l = std::stoull(data, nullptr);
                stream >> data;
                if (!stream.eof())
                    set_pc_break(traced, info->pc_by_line(data, l), yes);
                else
                    set_pc_break(traced, info->pc_by_line(l), yes);
            }
            catch (std::exception&) {
                if (yes) printf("Invalid number argument for break\n");
            }
        }
    } else {
        if (yes) invalid_args("break");
    }

}

// if !yes -- do not print info, because break was called by next program, not user
void remove_breakpoint(pid_t traced, std::stringstream& stream, bool yes = true) {
    std::string data;
    if (stream >> data) {
        if (!strcmp(data.c_str(), "-pc")) {
            stream >> data;
            remove_pc_break(traced, std::stoull(data, nullptr, 16), yes);
        }
        else {
            try {
                size_t l = std::stoull(data, nullptr);
                stream >> data;
                if (!stream.eof())
                    remove_pc_break(traced, info->pc_by_line(data, l), yes);
                else
                    remove_pc_break(traced, info->pc_by_line(l), yes);
            }
            catch (std::exception&) {
                if (yes) printf("Invalid number argument for break\n");
            }
        }
    } else {
        if (yes) invalid_args("break");
    }
}

int get_base(std::string s) {
    if (s.size() >= 2 && s.substr(0, 2) == "0x") {
        return 16;
    }
    return 10;
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <full path to process to be traced>\n", argv[0]);
        return -1;
    }
    set_signal_handler();
    try {
        info = new debug_info(std::string(argv[1]));
    }
    catch (const std::invalid_argument& e) {
        printf("%s\n", e.what());
    }
    traced = fork();

    if (traced)
    {
        waitpid(traced, &status, 0);
        std::string command;
        while (!is_done)
        {
            printf("> ");
            getline(std::cin, command);
            std::stringstream stream(command);
            std::string next_command;

            stream >> next_command;
            if (is_quit(next_command)) {
                kill_child();
            } else if (is_break(next_command)) {
                set_breakpoint(traced, stream);
            } else if (is_breaklist(next_command)) {
                for (size_t breakpoint : breaks)
                    printf("Breakpoint at %lx\n", breakpoint);
            } else if (is_clear(next_command)) {
                /*stream >> data;
                auto p = std::find(breaks.begin(), breaks.end(), data);
                if (p == breaks.end()) {
                    invalid_args(next_command);
                } else {
                    breaks.erase(p);
                    printf("Breakpoint deleted at %zu\n", data);
                }*/
                remove_breakpoint(traced, stream);
            } else if (is_run(next_command)) {
                if (!is_running) {
                    printf("Process %d is starting\n", traced);
                    is_running = true;
                    trace(traced);
                } else {
                    printf("Process %d has been started already. Use: continue\n", traced);
                }
            } else if (is_continue(next_command)) {
                if (is_running) {
                    if (stopped_on_pc_break)
                        continue_from_break(traced, cur_pc_break);
                    trace(traced);
                } else {
                    printf("Process %d is not started yet. Use: run\n", traced);
                }
            } else if (is_next(next_command)) {
                is_running = true;
                trace_step(traced);
            } else if (is_reg(next_command)) {
                if (is_running) {
                    std::string reg_name;
                    if (stream >> reg_name && !reg_name.empty()) {
                        print_regs(traced, reg_name);
                    } else {
                        invalid_args(next_command);
                    }
                } else {
                    printf("Process %d is not running. No registers are available.\n", traced);
                }
            } else if (is_mem(next_command)) {
                std::string var;
                stream >> var;
                /*long long v;
                if (var.length() >= 2 && var.substr(0, 2) == "0x")
                    v = std::stoull(var, nullptr, 16);
                else
                    v = std::stoull(var, nullptr);
                read_child_memory(traced, v);*/
                read_child_memory(traced, std::stoull(var, nullptr, get_base(var)));
            } else if (is_help(next_command)) {
                print_help();
            } else {
                printf("Invalid command. See help.\n");
            }
        }

    }
    else {
        child(argv[1]);
    }

}
