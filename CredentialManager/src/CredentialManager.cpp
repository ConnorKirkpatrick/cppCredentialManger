#include "CredentialManager.h"
#include "ntstatus.h"
#include <bcrypt.h>
#include <memory.h>
#include <minwindef.h>
#include <WinBase.h>
#include <winnt.h>

CHAR wide2Narrow(WCHAR w);


CredentialManager::Manager::Manager() { generatePRK(); }

CredentialManager::Manager::~Manager(){
    // delete each reference to the PRK
  for (int i = 0; i < segments; i++) {
      SecureZeroMemory(prkParts.at(i), (128 / segments));
  }
};

CHAR wide2Narrow(WCHAR w) {
    return CHAR(w);
}

CredentialManager::ErrorCode CredentialManager::Manager::generatePRK() {
  BYTE IV[32];
  BCRYPT_ALG_HANDLE randomProvider;
  BCRYPT_ALG_HANDLE derivationProvider;

  // Generate the IV
  NTSTATUS cryptoStatus = BCryptOpenAlgorithmProvider(
      &randomProvider, BCRYPT_RNG_ALGORITHM, NULL, NULL);
  // BCRYPT_PROV_DISPATCH);
  if (cryptoStatus != STATUS_SUCCESS) {
    return ErrorCode::NOT_ADMIN;
  }
  cryptoStatus = BCryptGenRandom(randomProvider, IV, 32, 0);
  if (cryptoStatus != STATUS_SUCCESS) {
    return ErrorCode::INVALID_VALUE;
  };
  cryptoStatus = BCryptCloseAlgorithmProvider(randomProvider, NULL);
  if (cryptoStatus != STATUS_SUCCESS) {
    return ErrorCode::INVALID_VALUE;
  }

  // Grab the hardware ID
  HW_PROFILE_INFO hwID;
  if (!GetCurrentHwProfile(&hwID)) {
    return ErrorCode::GENERAL_ERROR;
  }
  WCHAR *GUID = hwID.szHwProfileGuid;
  char UUID[56]; // windows GUID is only 54 bytes
  for (int i = 0; i < 56; i++) {
    UUID[i] = wide2Narrow(GUID[i]);
  }
  SecureZeroMemory(&GUID, 56);

  // generate the PRK
  cryptoStatus =
      BCryptOpenAlgorithmProvider(&derivationProvider, BCRYPT_SHA512_ALGORITHM,
                                  NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  // BCRYPT_PROV_DISPATCH);
  if (cryptoStatus != STATUS_SUCCESS) {
    return ErrorCode::NOT_ADMIN;
  }
  // derive PRK from the combined IV and HWID
  // pass in the salt, salt length, iterations, keyOut, size of keyOut, flags
  cryptoStatus = BCryptDeriveKeyPBKDF2(derivationProvider, NULL, NULL,
                                       reinterpret_cast<unsigned char *>(UUID),
                                       sizeof(UUID), 1000, PRK, 128, 0);
  if (cryptoStatus != STATUS_SUCCESS) {
    return ErrorCode::GENERAL_ERROR;
  }
  cryptoStatus = BCryptCloseAlgorithmProvider(derivationProvider, NULL);
  if (cryptoStatus != STATUS_SUCCESS) {
    return ErrorCode::INVALID_VALUE;
  }
  // Destroy the cryptographic data used to create the PRK
  SecureZeroMemory(&IV, 32);
  SecureZeroMemory(&UUID, 56);

  // For how ever many segments the user has chosen, store these into the parts
  // vector
  for (int i = 0; i < segments; i++) {
    BYTE PRK_SEG[128 / 4];
    memcpy_s(&PRK_SEG, 128 / segments, PRK + (128 / segments) * i,
             128 / segments);
    prkParts.push_back(PRK_SEG);
  }
  // Destroy the plain PRK in memory
  destroyPRK();
  return ErrorCode::SUCCESS;
}

CredentialManager::ErrorCode CredentialManager::Manager::constructPRK() {
  for (int i = 0; i < segments; i++) {
    BYTE PRK_SEG[128 / 4];
    memcpy_s(&PRK + (128 / segments) * i, 128 / segments, &PRK_SEG[0],
             128 / segments);
  }
  return ErrorCode::SUCCESS;
}

CredentialManager::ErrorCode CredentialManager::Manager::destroyPRK() {
  SecureZeroMemory(&PRK, 128);
  return ErrorCode::SUCCESS;
}