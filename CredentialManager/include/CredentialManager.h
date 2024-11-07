#include <map>
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
    ~Manager();
    ErrorCode ready = ErrorCode::SUCCESS;

  private:
    BYTE PRK[128];
    uint8_t segments = 4;
    std::vector<BYTE *> prkParts;
    std::map<char, char> credentialMemory;

    CredentialManager::ErrorCode generatePRK();
    CredentialManager::ErrorCode constructPRK();
    CredentialManager::ErrorCode destroyPRK();
    void destroyPRKParts();
};
} // namespace CredentialManager
