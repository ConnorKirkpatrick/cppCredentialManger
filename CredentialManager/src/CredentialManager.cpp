#include "CredentialManager.h"

#include <WinBase.h>
#include <bcrypt.h>
#include <memory.h>
#include <minwindef.h>
#include <winnt.h>

#include "ntstatus.h"
#include <cstring>
#include <malloc.h>
#include <memoryapi.h>

CHAR wide2Narrow(WCHAR w);

CredentialManager::Manager::Manager() : status(generatePRK())
{
}

CredentialManager::Manager::~Manager()
{
    // delete each reference to the PRK
    destroyPRK();
    destroyPRKParts();
}
CredentialManager::ErrorCode CredentialManager::Manager::getStatus()
{
    return status;
};

CHAR wide2Narrow(WCHAR w)
{
    return CHAR(w);
}

CredentialManager::ErrorCode CredentialManager::Manager::generatePRK()
{
    BYTE IV[IVSize];
    BCRYPT_ALG_HANDLE randomProvider = nullptr;
    BCRYPT_ALG_HANDLE derivationProvider = nullptr;

    // Generate the IV
    NTSTATUS cryptoStatus = BCryptOpenAlgorithmProvider(&randomProvider, BCRYPT_RNG_ALGORITHM, nullptr, NULL);
    // BCRYPT_PROV_DISPATCH);
    if (cryptoStatus != STATUS_SUCCESS)
    {
        return ErrorCode::NOT_ADMIN;
    }
    cryptoStatus = BCryptGenRandom(randomProvider, IV, IVSize, 0);
    if (cryptoStatus != STATUS_SUCCESS)
    {
        return ErrorCode::INVALID_VALUE;
    };
    cryptoStatus = BCryptCloseAlgorithmProvider(randomProvider, NULL);
    if (cryptoStatus != STATUS_SUCCESS)
    {
        return ErrorCode::INVALID_VALUE;
    }
    // Grab the hardware ID
    HW_PROFILE_INFO hwID;
    if (!GetCurrentHwProfile(&hwID))
    {
        return ErrorCode::GENERAL_ERROR;
    }
    WCHAR *GUID = hwID.szHwProfileGuid;
    unsigned char UUID[UUIDSize]{};
    // windows GUID is only 54 bytes
    for (int i = 0; i < UUIDSize; i++)
    {
        UUID[i] = wide2Narrow(GUID[i]);
    }

    // combine the IV and UUID (IVSize + UUIDSize)
    unsigned char UUIV[IVSize + UUIDSize];
    memcpy(UUIV, IV, IVSize);
    memcpy(UUIV + IVSize, UUID, UUIDSize);
    SecureZeroMemory(&IV, IVSize);
    cryptoStatus =
        BCryptOpenAlgorithmProvider(&derivationProvider, BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    // BCRYPT_PROV_DISPATCH);
    if (cryptoStatus != STATUS_SUCCESS)
    {
        return ErrorCode::NOT_ADMIN;
    }
    // derive PRK from the combined IV and HWID
    // pass in the salt, salt length, iterations, keyOut, size of keyOut, flags
    cryptoStatus = BCryptDeriveKeyPBKDF2(derivationProvider, nullptr, NULL, static_cast<PUCHAR>(UUIV), sizeof(UUIV),
                                         rounds, PRK, keySize, 0);
    if (cryptoStatus != STATUS_SUCCESS)
    {
        return ErrorCode::GENERAL_ERROR;
    }
    cryptoStatus = BCryptCloseAlgorithmProvider(derivationProvider, NULL);
    if (cryptoStatus != STATUS_SUCCESS)
    {
        return ErrorCode::INVALID_VALUE;
    }
    // Destroy the cryptographic data used to create the PRK
    SecureZeroMemory(&UUIV, IVSize + UUIDSize);

    //// For how ever many segments the user has chosen, store these into the
    /// parts + vector
    prkParts.resize(segments);
    for (int i = 0; i < segments; i++)
    {
        BYTE *PRK_SEG = (BYTE *)malloc(sizeof(BYTE) * (keySize / segments));
        if (PRK_SEG == nullptr)
        {
            destroyPRK();
            destroyPRKParts();
            return ErrorCode::GENERAL_ERROR;
        }
        VirtualLock(PRK_SEG, keySize / segments);
        // BYTE PRK_SEG[keySize / 4];
        memcpy(PRK_SEG, PRK + (keySize / segments) * i, keySize / segments);
        prkParts[i] = PRK_SEG;
    }
    // Destroy the plain PRK in memory
    destroyPRK();
    return ErrorCode::SUCCESS;
}

CredentialManager::ErrorCode CredentialManager::Manager::constructPRK()
{
    for (int i = 0; i < segments; i++)
    {
        BYTE PRK_SEG[keySize / 4];
        memcpy_s(&PRK_SEG, keySize / segments, &PRK + ((keySize / segments) * i), keySize / segments);
        SecureZeroMemory(&PRK_SEG, keySize / segments);
    }
    return ErrorCode::SUCCESS;
}

CredentialManager::ErrorCode CredentialManager::Manager::destroyPRK()
{
    SecureZeroMemory(&PRK, keySize);
    return ErrorCode::SUCCESS;
}

void CredentialManager::Manager::destroyPRKParts()
{
    if (prkParts.size() < 1)
    {
        return;
    }
    for (int i = 0; i < segments; i++)
    {
        SecureZeroMemory(prkParts.at(i), (keySize / segments));
        free(prkParts.at(i));
    }
}
