# pwngolin
写一点可能用得到的pwn小工具


## addr.py
使用`pwnlib.elf`来查找相关地址

内置`write`, `puts`, `system` 的got和plt查找

还有`binsh`, `ret(\xc3)` 地址的直接查找

用法: `python addr.py elf_filename`

example: `python addr.py my_elf_test`

output:

```bash
checksec内容
system_plt = xxx
system_got = xxx
...
ret_addr = xxx

```

另外，还可以设置alias别名来直接使用这个addr.py

```bash
# 在.bashrc中添加(一般是末尾)
alias addr="python /somedir/pwngolin/addr.py"

# 后续只需要输入以下内容便可以使用了
addr elf_filename
```
