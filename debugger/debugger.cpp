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

std::vector<long long> breaks;
bool is_stopped = false;
bool is_running = false;
int status;


/*
 * Эта часть нужна для подмены системных вызовов в ребенке, но я пока справился без нее
 *
char code[] = {(char)0xcd, (char)0x80, (char)0xcc, (char)0};
char backup[4];
const int long_size = sizeof(long long);
void getdata(pid_t child, long long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
        long long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

void putdata(pid_t child, long long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
        long long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
    }
}
 *
*/

void trace(pid_t pid)
{
    /*
     * Simple prints all SYSCALLS of attached process
     *
    while (!WIFEXITED(status))
    {
        struct user_regs_struct state;

        if (WIFSTOPPED(status) && (WSTOPSIG(status) & SIGTRAP))
        {
            ptrace(PTRACE_GETREGS, pid, 0, &state);
            printf("SYSCALL %lld at %llx\n", state.orig_rax, state.rip);


            if (state.orig_rax == 1)
            {
                char* text = (char*) state.rsi;
                ptrace(PTRACE_POKEDATA, pid, (void*) (text), 0x77207449);
                ptrace(PTRACE_POKEDATA, pid, (void*) (text + 4), 0x736b726f);
                ptrace(PTRACE_POKEDATA, pid, (void*) (text + 8), 0x00000a21);
            }
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
     *
    */

    struct user_regs_struct regs;

    if (is_stopped) {
        /*is_stopped = false;
        putdata(pid, regs.rip, backup, 3);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);*/
        is_stopped = false;
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
    }

    while (!WIFEXITED(status))
    {
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & SIGTRAP))
        {
            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            printf("SYSCALL %lld at %llx\n", regs.orig_rax, regs.rip);

            auto p = std::find(breaks.begin(), breaks.end(), regs.orig_rax);
            if (p != breaks.end()) {
                /*getdata(pid, regs.rip, backup, 3);
                putdata(pid, regs.rip, code, 3);
                ptrace(PTRACE_CONT, pid, NULL, NULL);
                waitpid(pid, &status, 0);*/
                printf("Process stopped by SYSCALL %lld at %llx\n", regs.orig_rax, regs.rip);
                is_stopped = true;
                return;
            }
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
    printf("Process %d exited with code %d\n", pid, WEXITSTATUS(status));
    is_running = false;
}

void trace_step(pid_t pid)
{
    struct user_regs_struct regs;

    /*if (is_stopped) {
        is_stopped = false;
        putdata(pid, regs.rip, backup, 3);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }*/
    if (is_stopped) {
        is_stopped = false;
    }
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    printf("SYSCALL %lld at %llx\n", regs.orig_rax, regs.rip);
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

void child(char* path)
{
    char* file = strtok(path, "\\");
    char* last;
    while (file) {
        last = file;
        file = strtok(0, "\\");
    }

    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(path, last, NULL);
}

/*
 * Сейчас программа работает, но брейки устанавливаются по системным вызовам.
 * Видимо это не совсем то, что хочется.
 * Надо как-то перейти к командам или строкам.
 * Также, каждый системный вызов ловится дважды (возможно это фиксится, а возможно нет, как в gdb)
*/

long long atoll(const std::string& data) {
    return atoll(data.c_str());
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <full path to process to be traced>\n", argv[0]);
        return -1;
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
            std::stringstream stream(command);
            std::string next_command;
            std::string data;
            stream >> next_command;
            if (next_command == "quit") {
                ptrace(PTRACE_DETACH, traced, NULL, NULL);
                kill(traced, SIGTERM);
                return 0;
            } else if (next_command == "break") {
                stream >> data;
                auto it = find(breaks.begin(), breaks.end(), atoll(data));
                if (it != breaks.end()) {
                    printf("already have such breakpoint\n");
                } else if (data != "") {
                    breaks.push_back(atoll(data));
                    printf("Breakpoint set at %lld\n", atoll(data));
                } else {
                    printf("Invalid argument for break\n");
                }
            } else if (next_command == "breaklist") {
                for (auto i = breaks.begin(); i != breaks.end(); i++)
                    printf("Breakpoint at %lld\n", *i);
            } else if (next_command == "clear") {
                stream >> data;
                auto p = std::find(breaks.begin(), breaks.end(), atoll(data));
                if (p == breaks.end()) {
                    printf("Invalid argument for clear\n");
                } else {
                    breaks.erase(p);
                    printf("Breakpoint deleted at %lld\n", atoll(data));
                }
            } else if (next_command == "run") {
                if (!is_running) {
                    printf("Process %d is starting\n", traced);
                    is_running = true;
                    trace(traced);
                } else {
                    printf("Process %d has been started already. Use: continue\n", traced);
                }
            } else if (next_command == "continue") {
                if (is_running) {
                    trace(traced);
                } else {
                    printf("Process %d is not started yet. Use: run\n", traced);
                }
            } else if (next_command == "next") {
                if (!is_running) {
                    is_running = true;
                }
                trace_step(traced);
            } else if (next_command == "reg") {
                if (is_running) {
                    stream >> data;
                    if (!data.empty()) {
                        print_regs(traced, data);
                    } else {
                        printf("Invalid argument for reg. See: help.\n");
                    }
                } else {
                    printf("Process %d is not running. No registers are available.\n", traced);
                }
            } else if (next_command == "mem") {
                //TODO
                //печать памяти на текущий момент
                //Это не понятно. Мехрубон? Рома?
            } else if (next_command == "help") {
                printf("break <SYSCALL>     - Set a breakpoint at SYSCALL\n");
                printf("breaklist           - Prints list of set breakpoints\n");
                printf("clear <SYSCALL>     - Delete a breakpoint from SYSCALL\n");
                printf("continue            - Continues the stopped process\n");
                printf("help                - Prints this help message\n");
                printf("mem <address>       - Prints memory at address\n");
                printf("next                - Do next step\n");
                printf("reg <register>      - Prints register\n");
                printf("run                 - Start the process\n");
                printf("quit                - Exit the programm\n");
            } else {
                printf("Invalid command. See help.\n");
            }
        }

    }
    else {
        child(argv[1]);
    }

    // g++ -std=c++14 -Wall -Wextra -Werror debugger.cpp -o debugger
    // gcc hello.c -o hello
    // ./debugger <full path to hello>
}

/*
 0x0000000000400546 <+0>:	push   %rbp
   0x0000000000400547 <+1>:	mov    %rsp,%rbp
   0x000000000040054a <+4>:	mov    $0xa,%edi
   0x000000000040054f <+9>:	mov    $0x0,%eax
   0x0000000000400554 <+14>:	callq  0x400440 <sleep@plt>
   0x0000000000400559 <+19>:	mov    $0xe,%edx
   0x000000000040055e <+24>:	mov    $0x400604,%esi
   0x0000000000400563 <+29>:	mov    $0x1,%edi
   0x0000000000400568 <+34>:	mov    $0x0,%eax
   0x000000000040056d <+39>:	callq  0x400410 <write@plt>
   0x0000000000400572 <+44>:	mov    $0x0,%eax
   0x0000000000400577 <+49>:	pop    %rbp
   0x0000000000400578 <+50>:	retq



SYSCALL 219 at 7f4238452f10
SYSCALL 219 at 7f4238452f10
SYSCALL 1 at 7f4238474c00
It works!
SYSCALL 1 at 7f4238474c00
SYSCALL 231 at 7f42384532e9

*/












