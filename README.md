# NoorDbg

NoorDbg is a Debugger for 64-bit Linux. It has the functionality to set breakpoints, and read/write registers and memory.

### Compile and Run

```sh
$ g++ -o dbg main.cpp
$ ./dbg binary
```

### Functionality

  - To print help, type "help".
  - To run or continue the program, type "run" or "cont". They are synonymous. 
  - To set a breakpoint, type "break 0xaddress", where 0xaddress is the address in code you want to set the breakpoint. Addresses can be found easily using a disassembler such as objdump.
  - To step one instruction, type "step".
  - To examine registers, type "xreg".
  - To examine 16 DWORDs at 0xaddress, type "xmem 0xaddress".
  - To set a particular register to a value, type "sreg <reg name> 0xvalue".
  - To set a DWORD in memory, type "smem 0xaddress 0xvalue".
  - To quit the debugger, type "quit".

### Example Binary

In the sample directory, there is a sleeper binary which we will use to demonstrate the functionality of NoorDbg. The sleeper prints "before", then prints "after". We will set a breakpoint between the two print statements and examine the running binary.

```sh
$ g++ -o dbg main.cpp
$ ./dbg sample/sleeper
```

Disassembling the binary in objdump, we get the address 0x40053f as the instruction right before the second print instruction.

```sh
$ objdump -Dslx sample/sleeper | grep main -B 10 -A 25
```

In the debugger we can break at that address.

```sh
> break 0x40053f
```

If we continue the binary, we hit the breakpoint.

```sh
> run
```

We can examine registers. We see that rip points to 0x40053f.

```sh
> xreg
```

We can set register r14 to 0x1. Examining registers once again will show the updated value.

```sh
> sreg r14 0x1
```

The stack (rsp) is at the address 0x7ffdc09424c0. We will examine memory at this location using xmem. This will print out 16 DWORDs. 

```sh
> xmem 0x7ffdc09424c0
```

We can set a DWORD at the top of the stack to a different value using smem.

```sh
> smem 0x7ffdc09424c0 0xabcdabcd
```

Running xmem again, we see the stack has been updated. We can revert the value by setting the memory to the original value.

We can step through the program. Since step only executes one instruction, it will take a large number of steps for the program to finish execution.

```sh
> step
```

To finish executing the program, we continue, then quit.

```sh
> cont
> quit
```
