/*
 * rsa.cpp
 *
 *  Created on: Dec 11, 2023
 *      Author: dell
 */
#include "rsa.h"
#include <string.h>

// Function to generate RSA key pair
RSA* generate_key()
{
    RSA* keypair = NULL;
    BIGNUM* bne = NULL;
    int ret = 0;

    bne = BN_new();
    ret = BN_set_word(bne, RSA_F4);

    keypair = RSA_new();
    ret = RSA_generate_key_ex(keypair, KEY_LENGTH, bne, NULL);
    return keypair;
}

// Function to create RSA public key
RSA* create_publicKey(RSA* keypair) {
    RSA* rsa = NULL;
    BIO* bio = NULL;
    bio = BIO_new_file("publicKey.txt", "w+");
    PEM_write_bio_RSAPublicKey(bio, keypair);
    BIO_reset(bio);
    PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);
    return rsa;
}

// Function to create RSA private key
RSA* create_privateKey(RSA* keypair) {
    RSA* rsa = NULL;
    BIO* bio = NULL;
    bio = BIO_new_file("privateKey.txt", "w+");
    PEM_write_bio_RSAPrivateKey(bio, keypair, NULL, NULL, 0, NULL, NULL);
    BIO_reset(bio);
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    return rsa;
}

// Function to encrypt a message using RSA public key
int rsaEncrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    
    int result = RSA_public_encrypt(flen, from, to, key, padding);
    return result;
}

int rsaDecrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {

    int result = RSA_private_decrypt(flen, from, to, key, padding);
    return result;
}

// Function to sign a message using RSA private key and SHA-512
std::string rsaSign(RSA* privateKey, const std::string& message) {
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), digest);
    std::vector<unsigned char> signature(RSA_size(privateKey));

    unsigned int sigLen;
    if (RSA_sign(NID_sha512, digest, SHA512_DIGEST_LENGTH, signature.data(), &sigLen, privateKey) != 1) {
        // Handle error
        std::cerr << "Error signing message" << std::endl;
        return "";
    }
    return std::string(signature.begin(), signature.begin() + sigLen);
}


bool rsaVerify(RSA* publicKey, const char* message, const char* signature, size_t messageLength, size_t signatureLength) {
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)message, messageLength, digest);

    return RSA_verify(NID_sha512, digest, SHA512_DIGEST_LENGTH,
                    (const unsigned char*) signature, signatureLength, publicKey) == 1;
}
//
//int rsaTest() {
//    // Generate RSA key pair
//    RSA* keypair = generate_key();
//    RSA* publicKey = create_publicKey(keypair);
//    RSA* privateKey = create_privateKey(keypair);
//
//    // Example usage
//    std::string originalMessage = "Hello, RSA!";
//
//    // Encrypt and decrypt
//    std::string encryptedMessage = rsaEncrypt(publicKey, originalMessage);
//    std::string decryptedMessage = rsaDecrypt(privateKey, encryptedMessage);
//
//    // Sign and verify
//    std::string signature = rsaSign(privateKey, originalMessage);
//    bool isVerified = rsaVerify(publicKey, originalMessage, signature);
//
//    // Output results
//    std::cout << "Original Message: " << originalMessage << std::endl;
//    std::cout << "Encrypted Message: " << encryptedMessage << std::endl;
//    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;
//    std::cout << "Signature: " << signature << std::endl;
//    std::cout << "Verification Result: " << (isVerified ? "Success" : "Failure") << std::endl;
//
//    // Clean up
//    RSA_free(keypair);
//    RSA_free(publicKey);
//    RSA_free(privateKey);
//
//    return 0;
//}
