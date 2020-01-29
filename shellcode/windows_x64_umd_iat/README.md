# Windows X64 Usermode IAT Hook

## Compile and use

```
cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /c /TC windows_x64_umd_iat.c
ml64 windows_x64_umd_iat.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main "windows_x64_umd_iat.obj"
```

To generate the shellcode for the SMM Rootkit, use the *shellcode64_win.exe* tool from the parent directory
```
shellcode64_win.exe -o windows_x64_umd_iat.exe
```
If you don't want to trust me (you should not!) and run binaries from a random hacker's repo, please download the sources and compile the shellcode-generation tool locally: https://github.com/ufrisk/shellcode64


## Disclaimer

This Windows X64 UMD IAT hooking shellcode is a modified version from Ulf Frisk's [pcileech](https://github.com/ufrisk/pcileech) (Direct Memory Access Attack Software) similar shellcode injection attack.