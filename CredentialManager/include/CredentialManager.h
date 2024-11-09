#include <array>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>
#include <windows.h>

namespace CredentialManager
{

enum class ErrorCode
{
    SUCCESS,
    NOT_ADMIN,
    INVALID_VALUE,
    GENERAL_ERROR
};

class Manager
{
  public:
    /**
     * @brief The credential manager is used to securely store and handle credentials. The system will automatically
     * setup a Per-Run Key (PRK) in a secure manner that is then used to handle all credentials during the runtime of
     * the manager.
     */
    Manager();
    /**
     * @brief Tear-down of the credential manager object. This needs to destroy the PRK data (if present), and the
     * individual PRK parts stored in memory. In future this will also need to write the encrypted passwords to a
     * persistent file and then destroy the password list.
     */
    ~Manager();

    ErrorCode getStatus();

  private:
    static const uint8_t keySize = 128;
    static const uint8_t segments = 4;
    static const uint8_t IVSize = 32;
    static const uint8_t UUIDSize = 56;
    static const uint16_t rounds = 1000;
    ErrorCode status = ErrorCode::SUCCESS;
    BYTE PRK[keySize];

    std::vector<BYTE *> prkParts;
    std::map<char, char> credentialMemory;

    CredentialManager::ErrorCode generatePRK();
    CredentialManager::ErrorCode constructPRK();
    CredentialManager::ErrorCode destroyPRK();
    void destroyPRKParts();
};
} // namespace CredentialManager
