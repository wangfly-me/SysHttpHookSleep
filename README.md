# SysHttpHookSleep
## 代码来源
集合多种方式的ShellcodeLoader，主要代码来自：

https://github.com/mgeeky/ShellcodeFluctuation

https://github.com/TheD1rkMtr/BlockOpenHandle

## 主要功能
Shellcode：异或xor加密+Base64编码+AES加密+Base64编码+字符串反转。<br />
加载方式：URL加密+远程加载+Syswhispers上线。<br />
内存规避：HOOK Sleep函数+内存xor加密+System权限打开句柄。<br />
反虚拟机：注册表+文件+进程+内存。<br />

## 操作步骤
先生成stagerless的raw木马，按顺序分别使用enc.py、AES_Shellcode.exe、rev.py生成b.txt文件，并将其部署在服务器端。

其次将URL使用URL_XOR.exe进行加密，并分成两段填入str1和str2参数中。

最后生成exe，运行上线。

## 免杀效果
由于在项目中已经投入使用一段时间，可能有些已经不免杀，可以尝试VMP加壳，或者修改代码二次开发，来规避杀软。
