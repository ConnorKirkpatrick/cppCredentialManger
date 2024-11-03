#include "CredentialManager.h"
#include "ntstatus.h"
#include <bcrypt.h>

CHAR wide2Narrow(WCHAR w);

CredentialManager::Manager::Manager(){
    BYTE IV[32];
    BCRYPT_ALG_HANDLE randomProvider;
    BCRYPT_ALG_HANDLE derivationProvider;

    // Generate the IV
    NTSTATUS cryptoStatus = BCryptOpenAlgorithmProvider(
        &randomProvider,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        NULL);
        //BCRYPT_PROV_DISPATCH);
    if(cryptoStatus != STATUS_SUCCESS){
        ready = -1;
        return;
    }
    cryptoStatus = BCryptGenRandom
    (
        randomProvider,
        IV,
        32,
        0);
    if(cryptoStatus != STATUS_SUCCESS){
        ready = -2;
        return;
    };
    cryptoStatus = BCryptCloseAlgorithmProvider(randomProvider, NULL);
    if (cryptoStatus != STATUS_SUCCESS) {
        ready = -3;
        return;
    }


    // Grab the hardware ID
    HW_PROFILE_INFO hwID;
    if(!GetCurrentHwProfile(&hwID)){
        ready = -4;
        return;
    }
    WCHAR* x = hwID.szHwProfileGuid;
    char UUID[56]; // windows GUID is only 54 bytes
    for (int i = 0; i < 56; i++) {
        UUID[i] = wide2Narrow(x[i]);
    }
    SecureZeroMemory(&x, 56);
    

    // generate the PRK
    BYTE PRK[128];
    cryptoStatus = BCryptOpenAlgorithmProvider(
        &derivationProvider,
        BCRYPT_SHA512_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
        //BCRYPT_PROV_DISPATCH);
    if(cryptoStatus != STATUS_SUCCESS){
        ready = -5;
        return;
    }
    // derive PRK from the combined IV and HWID
    // pass in the salt, salt length, iterations, keyOut, size of keyOut, flags
    cryptoStatus =  BCryptDeriveKeyPBKDF2(
        derivationProvider,
        NULL,
        NULL,
        reinterpret_cast<unsigned char *>(UUID),
        sizeof(UUID),
        1000,
        PRK,
        128,
        0
    );
    if (cryptoStatus != STATUS_SUCCESS) {
        ready = -6;
        return;
    }
    cryptoStatus = BCryptCloseAlgorithmProvider(derivationProvider, NULL);
    if (cryptoStatus != STATUS_SUCCESS) {
        ready = -7;
        return;
    }
    SecureZeroMemory(&IV, 32);
    SecureZeroMemory(&UUID, 56);

    /*for (int i = 0; i < segments; i++) {
        for (int j = 0; j < 128 / segments; j++) {
            prkParts.at(i)->
        }
    }*/
    SecureZeroMemory(&PRK, 128);
};

CHAR wide2Narrow(WCHAR w) {
    return CHAR(w);
}