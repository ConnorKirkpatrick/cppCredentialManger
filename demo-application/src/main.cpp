#include <iostream>
#include <vector>
#include <string>

#include "CredentialManager.h"

int main()
{
    std::vector<std::string> msg {"Hello", "C++", "World", "from", "VS Code", "and the C++ extension!"};

    for (const std::string& word : msg)
    {
        std::cout << word << " ";
    }
    std::cout << std::endl;
    CredentialManager::Manager test = CredentialManager::Manager();
}
