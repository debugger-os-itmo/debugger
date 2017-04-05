#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#include <vector>
#include <algorithm>
#include <iostream>

std::vector<long long> breaks;
bool is_stopped = false;
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
                break;
            }
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
}

void trace_step(pid_t pid)
{
    struct user_regs_struct regs;

    /*if (is_stopped) {
        is_stopped = false;
        putdata(pid, regs.rip, backup, 3);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }*/
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    printf("SYSCALL %lld at %llx\n", regs.orig_rax, regs.rip);
}

void print_regs(pid_t pid, char* reg)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
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

    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl(path, last, NULL);
}

/*
 * Сейчас программа работает, но брейки устанавливаются по системным вызовам.
 * Видимо это не совсем то, что хочется.
 * Надо как-то перейти к командам или строкам.
 * Также, каждый системный вызов ловится дважды (возможно это фиксится, а возможно нет, как в gdb)
*/

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
            char* ptr;
            ptr = strtok(const_cast<char*>(command.c_str()), " ");
            if (strcmp(ptr, "quit") == 0) {
                ptrace(PTRACE_DETACH, traced, NULL, NULL);
                kill(traced, SIGTERM);
                return 0;
            } else if (strcmp(ptr, "break") == 0) {
                ptr = strtok(NULL, " ");
                if (ptr != NULL) {
                    breaks.push_back(atoll(ptr));
                    printf("Breakpoint set at %lld\n", atoll(ptr));
                } else {
                    printf("Invalid argument for break\n");
                }
            } else if (strcmp(ptr, "breaklist") == 0) {
                for (auto i = breaks.begin(); i != breaks.end(); i++)
                    printf("Breakpoint at %lld\n", *i);
            } else if (strcmp(ptr, "clear") == 0) {
                ptr = strtok(NULL, " ");
                auto p = std::find(breaks.begin(), breaks.end(), atoll(ptr));
                if (p == breaks.end()) {
                    printf("Invalid argument for clear\n");
                } else {
                    breaks.erase(p);
                    printf("Breakpoint deleted at %lld\n", atoll(ptr));
                }
            } else if (strcmp(ptr, "run") == 0) {
                printf("Process %d is starting\n", traced);
                trace(traced);
            } else if (strcmp(ptr, "continue") == 0) {
                if (is_stopped) {
                    trace(traced);
                } else {
                    printf("Process is not runnig now. Use: run\n");
                }
            } else if (strcmp(ptr, "next") == 0) {
                trace_step(traced);
            } else if (strcmp(ptr, "reg") == 0) {
                ptr = strtok(NULL, " ");
                print_regs(traced, ptr);
            } else if (strcmp(ptr, "mem") == 0) {
                //TODO
                //печать памяти на текущий момент
                //Это не понятно. Мехрубон? Рома?
            } else if (strcmp(ptr, "help") == 0) {
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












