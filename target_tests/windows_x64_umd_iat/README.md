# Tester program for Windows X64 Usermode IAT Hook

This program is a tester program for the IAT hook shellcode.

It calls `GetCurrentProcessId()` every time enter is pressed inside the console. By default, `GetCurrentProcessId()` is also hooked from the SMM driver. To compile it, you need Visual Studio with C/C++ tools installed. **Compile with Debug & x64**. If you don't compile it with debug option, the rootkit may not find a codecave to write the shellcode! Also run this program as administrator on the target machine!