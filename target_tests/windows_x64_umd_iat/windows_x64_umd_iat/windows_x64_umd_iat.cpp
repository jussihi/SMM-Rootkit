// windows_x64_umd_iat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#ifdef _WIN32
#include <Windows.h>
#define GetProcessID	GetCurrentProcessId
#else
#include <unistd.h>
#define GetProcessID	getpid
#endif


int main()
{
    std::string a;
#ifdef _WIN32
    std::cout << "CreateFileA = " << (void*)CreateFileA << std::endl;
#endif
    while (std::cin >> a)
    {
        std::cout << "Process id is: " << GetProcessID() << std::endl;
    }
}
