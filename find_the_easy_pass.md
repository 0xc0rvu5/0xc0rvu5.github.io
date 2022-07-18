# Find The Easy Pass
## Ghidra
## OllyDbg
```bash

➜  Find_The_Easy_Pass unzip Find\ The\ Easy\ Pass.zip

Password:

hackthebox

➜  wine EasyPass.exe 

Wrong password

sudo apt install ghidra

ghidra &

File -> New Project -> Non-shared project
File -> Import File (file that will be reverse-engineered) -> Select File to Import -> OK -> OK
Double click imported file (or click dragon) -> OK
Go to: Search -> For Strings... -> Search
Filter:

wrong password

Double-click location: 00454200
CodeBrowser -> Right-click 00454200 -> References -> Show References To Address
Double-click location: 00454144
CodeBrowser -> Display Function Graph -> Zoom (scroll) in to bottom half -> Click on FUN_00404628 (parent function of previous function)
Note the reference num:

00454131

sudo apt install ollydbg

ollydbg &

Yes -> File -> Open -> Find EasyPass.exe -> Open
CPU - main thread, module EasyPass:
Locate:

00454131

Right-click -> Breakpoint -> Toggle

Play

Click 'Check Password'

Note the password retrieved:

fortran!

Alternatively

ollydbg -> EasyPass.exe -> right-click - Search for -> All referenced text strings
Text string:

"Wrong Password!"

Right-click -> Toggle breakpoint

Play

Enter password:

check

Password:

fortran!

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621074458.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621074559.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621085331.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621080650.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621080841.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621080949.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621081031.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621081346.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621081844.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621081924.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621082741.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621082833.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621083220.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220621084911.png)

#hacking
