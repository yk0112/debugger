# debugger

This is a simple ELF files debugger for my study.

reference: https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/

Support
- Setting breakpoints by line number
- Step in, Step out, Step over execution
- Displaying registers at breakpoints
- Displaying the value of a variable(partial implementation)

Not support
- Shared library support

Example
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



