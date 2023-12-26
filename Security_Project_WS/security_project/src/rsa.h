/*
 * rsa.h
 *
 *  Created on: Dec 11, 2023
 *      Author: dell
 */

#ifndef SRC_RSA_H_
#define SRC_RSA_H_

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <vector>
#include <string>
#include <fstream>
#define KEY_LENGTH       2048


RSA* generate_key();
RSA* create_publicKey(RSA* keypair);
RSA* create_privateKey(RSA* keypair);
int rsaEncrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding);
int rsaDecrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding);
std::string rsaSign(RSA* privateKey, const std::string& message);
bool rsaVerify(RSA* publicKey, const char* message, const char* signature, size_t messageLength, size_t signatureLength);
int rsaTest();
#endif /* SRC_RSA_H_ */
