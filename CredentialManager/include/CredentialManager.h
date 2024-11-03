#include <vector>
#include <map>
#include <memory>
#include <windows.h>
#include <bcrypt.h>

namespace CredentialManager{
    class Manager{
        public:
            Manager();
            int8_t ready = 0;
        private:
            uint8_t segments = 4;
            std::vector<std::shared_ptr<BYTE>> prkParts;
            std::map<char, char> credentialMemory;
    };
}