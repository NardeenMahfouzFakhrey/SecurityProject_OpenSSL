/*
 * aes.h
 *
 *  Created on: Dec 13, 2023
 *      Author: dell
 */

#ifndef SRC_AES_H_
#define SRC_AES_H_


#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <cstring>

int aesTest();
int AES_Encrypt(unsigned char* text, int text_len, unsigned char* key, unsigned char* cipher);
int AES_Decrypt(unsigned char* cipher, int cipher_len, unsigned char* key, unsigned char* text);

#endif /* SRC_AES_H_ */
