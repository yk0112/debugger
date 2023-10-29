# debugger

This is a simple ELF files debugger for my study.

### Environment
- OS: Ubuntu, x86_64
- Kernel: 22.04.2 LTS

### Support
- Setting breakpoints by line number
- Step in, Step out, Step over execution
- Displaying registers at breakpoints
- Displaying the value of a variable(partial implementation)

### Not support
- Shared library support

### Example
```
yk0112@yk0112pc:~/debugger/build$ ./debugger ./test3
start debug process: 26186
Unknown SIGTRAP code 0
555555554000
minidbg> break 6:test3.cpp
set break point at address 5555555551c5
minidbg> cont
Hit breakpoint at address 0x5555555551c5
    long a = 1;
    long b = 2;
>   long c = 1 + 2;
    std::cout << c << std::endl; 
  }
  
minidbg> step
    long b = 2;
    long c = 1 + 2;
>   std::cout << c << std::endl; 
  }
  
minidbg> variables
a (0x7fffffffdea8) = 1
b (0x7fffffffdeb0) = 2
c (0x7fffffffdeb8) = 3
```

### Command list
```
`break <line number>:<source file>` - Set a breakpoint on the specified line
`cont`     - Move to next breakpoint
`step`     - If the current line is a function, enter the function(Step in)
`next`     - If the current line is a function, move to the next line without entering the function(Step over)
`finish`   - If the current line is inside a function, continue processing until exiting the function(Step out)
`register` - Display the current register value
`all`      - Display a list of breakpoint addresses
`variables`　- Display a list of current variable values
```

