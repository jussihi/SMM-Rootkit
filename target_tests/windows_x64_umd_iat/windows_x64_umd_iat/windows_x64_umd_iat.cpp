// windows_x64_umd_iat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <Windows.h>


int main()
{
    std::string a;
    while (std::cin >> a)
    {
        std::cout << "Process id is: " << GetCurrentProcessId() << std::endl;
    }
}