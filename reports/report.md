# 栈溢出攻击实验

## 题目解决思路


### Problem 1: 
- **分析**：关键函数为`func`和`func1`，其中`func1`是我们需要通过修改`func`返回地址来调用的函数（因为在`func1`在反汇编中没有直接调用）。`func`函数中调用`strcpy`函数，将输入内容拷贝到`%rbp - 0x8`，可以成功溢出到`func`函数的返回地址

  ![01](.\assets\01.png)

  `func1`函数直接输出`Yes!I like ICS!`，`func1`的函数地址为`0x0000000000401216`

  ![02](.\assets\02.png)

  结合下面的栈图，可知`problenm1`的`payload`为 `b"A" * 16 + b"\x16\x12\x40\x00\x00\x00\x00\x00"`

  ![03](.\assets\03.png)

- **解决方案**：![04](.\assets\04.png)

- **结果**：![05](.\assets\05.png)

### Problem 2:
- **分析**：关键函数是`func`、`func2`和`pop_rdi`，其中`func2`和`pop_rdi`是我们需要通过修改`func`返回地址来调用的函数(因为`func2`和`pop_rdi`在反汇编中没有直接调用)。`func`函数中调用`memcpy`函数，从输入缓冲区中拷贝`0x38`字节到`%rbp - 0x8`，可以成功溢出到`func`函数的返回地址。

- ![06](.\assets\06.png)

  `func2`函数中`0x0000000000401225`处通过比较`%edi`是否为`0x3f8`来确定是否输出`Yes!I like ICS!`，当调用`func2`时，`%rdi`的值为`0x3f8`才会输出`Yes!I like ICS!`，而本题目又是使用了`Nxenabled`保护类型，栈空间不可执行，所以往栈上写代码是行不通的，只能利用程序本身的代码片段改变`%rdi`的值，显而易见，`pop_rdi`函数的功能就是将栈顶元素赋值给`%rdi`

  ![07](.\assets\07.png)

  ![08](.\assets\08.png)

  上图可以看出，`func2`地址为`0x0000000000401216`，`pop_rdi`地址为`0x00000000004012bb`，结合下面画的栈图，可知`problem2`的`payload`为`b"A" * 8 + b"\xf8\x03\x00\x00\x00\x00\x00\x00" + b"\xbb\x12\x40\x00\x00\x00\x00\x00" + b"\x16\x12\x40\x00\x00\x00\x00\x00"`

  ![09](.\assets\09.png)

- **解决方案**：![10](.\assets\10.png)

- **结果**：![11](.\assets\11.png)

### Problem 3: 
- **分析**：关键函数是`func`和`func1`，其中`func1`需要通过修改`func`返回地址来调用的函数（因为`func1`在反汇编中没有直接调用）。`func`函数中同样调用`memcpy`函数，从输入缓冲区拷贝`0x40`字节到`%rbp - 0x20`，可以成功溢出到`func`函数的返回地址

  ![12](.\assets\12.png)

  `func1`函数中`0x0000000000401225`处通过比较`%edi`是否为`0x72`来确定是否输出`Your lucky number is 114`，当调用`func1`时，`%rdi`的值为`0x72`才会输出`Your lucky number is 114`，而本题目没有使用`Nxenabled`保护类型，栈空间可执行，所以往栈上写代码是可行的。

  ![13](.\assets\13.png)

  新建一个`t.s`，编写如下代码：

  ```asm
  mov $0x72, %rdi		; %rdi赋值
  pushq $0x401216		; 将func1入栈
  ret					; 跳转到func1
  ```

  然后使用`gcc -c t.s`编译，再使用`objdump -d t.o`查看反汇编，如下

  ![14](.\assets\14.png)

  那么现在剩下`%rbp - 0x20`地址的问题了

  ![15](.\assets\15.png)

  使用`gdb`调试，然后查看

  ![16](.\assets\16.png)

  最后的`problem3`的`payload`为`b"\x48\xc7\xc7\x72\x00\x00\x00\x68\x16\x12\x40\x00\xc3" + b"A" * 27 + b"\x30\xdc\xff\xff\xff\x7f\x00\x00" `

- **解决方案**：![17](.\assets\17.png)

- **结果**：![18](.\assets\18.png)

### Problem 4: 
- **分析**：在函数开始时就随机产生一个值，将这个值`CANARY`放到栈上紧挨`%rbp`的上一个位置，当攻击者想通过缓冲区溢出覆盖`%rbp`或者`%rbp`下方的返回地址时，一定会覆盖掉`CANARY`的值；当程序结束时，程序会检查`CANARY`这个值和之前的是否一致，如果不一致，则不会往下运行，从而避免了缓冲区溢出攻击。

  ![19](.\assets\19.png)

  ![20](.\assets\20.png)

  关键函数是`func`，翻译成`C`代码如下

  ```c++
  unsigned __int64 func(unsigned int unYuanshi)
  {
    unsigned int unTmp; 
    unsigned int i; 
  
    unTmp = unYuanshi;
    printf("your money is %u\n", unYuanshi);
    if ( unYuanshi >= 0xFFFFFFFE )
    {
      for ( i = 0; i < 0xFFFFFFFE; ++i )
        --unTmp;
      if ( unTmp == 1 && unYuanshi == -1 )
      {
        func1();
        exit(0);
      }
      puts("No! I will let you fail!");
    }
    else
    {
      puts("your money is not enough!");
    }
  }
  ```

  可以看出，只要输入的`yuanshi`等于`0xFFFFFFFF`(`4294967295`)，就能过关

- **解决方案**：`yuanshi`只要等于`4294967295`即可，其余两个问题答案随意

- **结果**：![21](.\assets\21.png)

## 思考与总结



## 参考资料

[ctf(pwn) canary保护机制讲解 与 解密方法介绍-CSDN博客](https://blog.csdn.net/weixin_45556441/article/details/114339182)
