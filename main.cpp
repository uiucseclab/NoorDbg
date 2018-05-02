/******************************************************************/
/*                                                                */
/*             NoorDbg (CS 460 Project) - Noor Michael            */
/*                                                                */
/******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <vector>                               // only purpose of C++ (all style otherwise should be C)
                                                // fail uses (const char *) for compatability

// sizeof(long) == sizeof(long long) == 8
// getting registers as unsigned long longs
// setting registers (long long) as unsigned longs

// defines

#define DWORD_SIZE 4

// type declarations

typedef struct breakpoint_t {
    unsigned long addr;                         // addr of breakpoint
    unsigned long data;                         // original instruction at breakpoint
} breakpoint_t;

typedef struct user_regs_struct regs_t;         // renaming of user_regs_struct

// function declarations

void fail(const char *);                        // prints error and exits
void help();                                    // prints help
void trace();                                   // program loop
int wait_dbg();                                 // runs waitpid (return -1 for exit, o/w signal #)
void add_breakpoint(unsigned long);             // adds breakpoint
void handle_breakpoint();                       // executes when breakpoint is hit
void dump_registers();                          // dumps values of registers in same format as gdb
void set_register(char *, unsigned long);       // sets register value
void print_memory(unsigned long);               // prints 16 DWORDs of memory
void set_memory(unsigned long, unsigned long);  // sets a DWORD of memory at location

// global variables

extern char **environ;
int wstatus;                                    // wait status of tracee
pid_t pid;                                      // pid of tracee
char *line;                                     // user input
std::vector<breakpoint_t> breakpoints;          // vector of breakpoints
breakpoint_t curr_breakpoint = {0, 0};          // breakpoint that was just landed on (addr = 0 means no breakpoint)
regs_t regs;                                    // struct to hold register values

int main(int argc, char *argv[]){

    if(argc == 1){
        printf("Usage: ./dbg <program name> <program arguments>\n\n");
        help();
        exit(EXIT_SUCCESS);
    }

    pid = fork();

    if(pid == -1){      // error
        fail("fork");
    }else if(pid == 0){ // child (tracee)
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) fail("ptrace");
        if(execve(argv[1], argv + 1, environ) == -1) fail("execve");
    }else{              // parent (tracer)
        wait_dbg(); // catch the initial SIGTRAP
        trace();
    }

    return 0;
}

void fail(const char *s){
    perror(s);
    exit(EXIT_FAILURE);
}

void help(){
    printf("COMMANDS\n");
    printf("--------\n");
    printf("help\t\t\t\t -- print help\n");
    printf("run/cont\t\t\t -- run/continue program\n");
    printf("break 0xaddress\t\t\t -- set breakpoint at 0xaddress\n");
    printf("step\t\t\t\t -- step one instruction\n");
    printf("xreg\t\t\t\t -- examine registers\n");
    printf("xmem 0xaddress \t\t\t -- examine memory at 0xaddress \n");
    printf("sreg <reg name> 0xvalue\t\t -- set register value\n");
    printf("smem 0xaddress 0xvalue\t\t -- set memory at 0xaddress\n");
    printf("quit\t\t\t\t -- exit debugger\n");
}

void trace(){

    while(1){

        printf("(DEBUG)> ");

        size_t len = 0;
        ssize_t nread = getline(&line, &len, stdin);
        if(nread == -1) fail("getline");

        char *cmd = strtok(line, " \t\n");

        if(strcmp(cmd, "help") == 0){
            help();
        }else if(strcmp(cmd, "run") == 0 || strcmp(cmd, "cont") == 0){
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            wait_dbg();

            // if breakpoint was hit, add back
            if(curr_breakpoint.addr != 0) add_breakpoint(curr_breakpoint.addr);

            ptrace(PTRACE_CONT, pid, NULL, NULL);

            int s = wait_dbg();
            if(s == 5) handle_breakpoint();
        }else if(strcmp(cmd, "break") == 0){
            char *addr_h = strtok(NULL, " \t\n");

            printf("Breakpoint set at %s\n", addr_h);

            unsigned long addr = strtol(addr_h, NULL, 0);

            add_breakpoint(addr);
        }else if(strcmp(cmd, "step") == 0){
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            wait_dbg();

            curr_breakpoint.addr = 0; // no breakpoint
        }else if(strcmp(cmd, "xreg") == 0){
            dump_registers();          
        }else if(strcmp(cmd, "xmem") == 0){
            char *addr_h = strtok(NULL, " \t\n");

            printf("Examining memory at %s\n\n", addr_h);

            unsigned long addr = strtol(addr_h, NULL, 0);

            print_memory(addr);
        }else if(strcmp(cmd, "sreg") == 0){

            char *reg_name = strtok(NULL, " \t\n");

            char *data_h = strtok(NULL, " \t\n");
            unsigned long data = strtol(data_h, NULL, 0);

            set_register(reg_name, data);
        }else if(strcmp(cmd, "smem") == 0){
            char *addr_h = strtok(NULL, " \t\n");
            char *data_h = strtok(NULL, " \t\n");

            printf("Setting memory at %s to %s\n", addr_h, data_h);

            unsigned long addr = strtol(addr_h, NULL, 0);
            unsigned long data = strtol(data_h, NULL, 0);

            set_memory(addr, data);
        }else if(strcmp(cmd, "quit") == 0){
            if(pid != -1) kill(pid, SIGKILL);

            exit(EXIT_SUCCESS);
        }else{
            printf("Did not recognize command, type <help> to view list of commands.\n");
        }
    }
}

int wait_dbg(){
    // wait(&wstatus);

    if(waitpid(-1, &wstatus, 0) == -1) fail("waitpid");

    int s = -1;

    if(WIFEXITED(wstatus)){
        printf("Child exited with status %d\n", WEXITSTATUS(wstatus));
        pid = -1;
    }else if(WIFSIGNALED(wstatus)){
        s = WTERMSIG(wstatus);
        printf("Child terminated by signal %d (%s)\n", s, strsignal(s));
    }else if(WIFSTOPPED(wstatus)){
        s = WSTOPSIG(wstatus);
        printf("Child stopped by signal %d (%s)\n", s, strsignal(s));
    }else{
        printf("waitpid returned for unknown reason\n");
        exit(EXIT_FAILURE);
    }

    return s;
}

void add_breakpoint(unsigned long addr){
    unsigned long orig_data = ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, NULL);
    unsigned long data = (orig_data & ~0xff) | 0xcc;
    ptrace(PTRACE_POKETEXT, pid, (void *) addr, data);

    breakpoint_t bp = {addr, orig_data};
    breakpoints.push_back(bp);
}

void handle_breakpoint(){

    // get registers

    memset(&regs, 0, sizeof(regs_t));
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    // find which breakpoint

    int curr_index = -1;

    for(int i = 0; i < breakpoints.size(); i++){
        if(breakpoints[i].addr == regs.rip - 1){
            curr_breakpoint = breakpoints[i];
            curr_index = i;
        }
    }

    assert(curr_index != -1); // a breakpoint was hit

    // print breakpoint hit

    printf("Breakpoint hit at 0x%lx\n", curr_breakpoint.addr);

    // restore original data

    ptrace(PTRACE_POKETEXT, pid, (void *) curr_breakpoint.addr, curr_breakpoint.data);

    // fix eip

    // set_register((char *) "rip", curr_breakpoint.addr);

    regs.rip = curr_breakpoint.addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // remove breakpoint from vector

    breakpoints.erase(breakpoints.begin() + curr_index);
}

void dump_registers(){
    // get registers

    memset(&regs, 0, sizeof(regs_t));
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);          
    // print values of registers

    printf("rax \t\t 0x%llx\n", regs.rax);
    printf("rbx \t\t 0x%llx\n", regs.rbx);
    printf("rcx \t\t 0x%llx\n", regs.rcx);
    printf("rdx \t\t 0x%llx\n", regs.rdx);

    printf("rsi \t\t 0x%llx\n", regs.rsi);
    printf("rdi \t\t 0x%llx\n", regs.rdi);
    printf("rbp \t\t 0x%llx\n", regs.rbp);
    printf("rsp \t\t 0x%llx\n", regs.rsp);

    printf("r8 \t\t 0x%llx\n", regs.r8);
    printf("r9 \t\t 0x%llx\n", regs.r9);
    printf("r10 \t\t 0x%llx\n", regs.r10);
    printf("r11 \t\t 0x%llx\n", regs.r11);
    printf("r12 \t\t 0x%llx\n", regs.r12);
    printf("r13 \t\t 0x%llx\n", regs.r13);
    printf("r14 \t\t 0x%llx\n", regs.r14);
    printf("r15 \t\t 0x%llx\n", regs.r15);

    printf("rip \t\t 0x%llx\n", regs.rip);

    printf("eflags \t\t 0x%llx\n", regs.eflags);

    printf("cs \t\t 0x%llx\n", regs.cs);
    printf("ss \t\t 0x%llx\n", regs.ss);
    printf("ds \t\t 0x%llx\n", regs.ds);
    printf("es \t\t 0x%llx\n", regs.es);
    printf("fs \t\t 0x%llx\n", regs.fs);
    printf("gs \t\t 0x%llx\n", regs.gs);
}

void set_register(char *reg_name, unsigned long data){
    memset(&regs, 0, sizeof(regs_t));
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    if(strcmp(reg_name, "rax") == 0){
        regs.rax = data;
    }else if(strcmp(reg_name, "rbx") == 0){
        regs.rbx = data;
    }else if(strcmp(reg_name, "rcx") == 0){
        regs.rcx = data;
    }else if(strcmp(reg_name, "rdx") == 0){
        regs.rdx = data;
    }else if(strcmp(reg_name, "rsi") == 0){
        regs.rsi = data;
    }else if(strcmp(reg_name, "rdi") == 0){
        regs.rdi = data;
    }else if(strcmp(reg_name, "rbp") == 0){
        regs.rbp = data;
    }else if(strcmp(reg_name, "rsp") == 0){
        regs.rsp = data;
    }else if(strcmp(reg_name, "r8") == 0){
        regs.r8 = data;
    }else if(strcmp(reg_name, "r9") == 0){
        regs.r9 = data;
    }else if(strcmp(reg_name, "r10") == 0){
        regs.r10 = data;
    }else if(strcmp(reg_name, "r11") == 0){
        regs.r11 = data;
    }else if(strcmp(reg_name, "r12") == 0){
        regs.r12 = data;
    }else if(strcmp(reg_name, "r13") == 0){
        regs.r13 = data;
    }else if(strcmp(reg_name, "r14") == 0){
        regs.r14 = data;
    }else if(strcmp(reg_name, "r15") == 0){
        regs.r15 = data;
    }else if(strcmp(reg_name, "rip") == 0){
        regs.rip = data;
    }else if(strcmp(reg_name, "eflags") == 0){
        regs.eflags = data;
    }else if(strcmp(reg_name, "cs") == 0){
        regs.cs = data;
    }else if(strcmp(reg_name, "ss") == 0){
        regs.ss = data;
    }else if(strcmp(reg_name, "ds") == 0){
        regs.ds = data;
    }else if(strcmp(reg_name, "es") == 0){
        regs.es = data;
    }else if(strcmp(reg_name, "fs") == 0){
        regs.fs = data;
    }else if(strcmp(reg_name, "gs") == 0){
        regs.gs = data;
    }

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

void print_memory(unsigned long addr){

    for(int i = 0; i < 4; i++){
        printf("%lx: ", addr+i*4*DWORD_SIZE);

        for(int j = 0; j < 4; j++){
            unsigned long orig_data = ptrace(PTRACE_PEEKTEXT, pid, (void *) (addr + i*4*DWORD_SIZE + j*DWORD_SIZE), NULL);
            printf("0x%08lx\t", (orig_data & 0xffffffff));
        }

        printf("\n");
    }
}

void set_memory(unsigned long addr, unsigned long data){

    unsigned long orig_data = ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, NULL);
    data = (orig_data & 0xffffffff00000000 | data);

    ptrace(PTRACE_POKETEXT, pid, (void *) addr, data);
}