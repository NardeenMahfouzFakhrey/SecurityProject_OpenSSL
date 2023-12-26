/*
 * main.cpp
 *
 *  Created on: Dec 13, 2023
 *      Author: dell
 */

#include "aes.h"
#include "rsa.h"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>


using namespace std;

typedef enum { TEXT = '1', BINARY = '2' } FileType;

typedef enum {
  AES_EN = '1',
  AES_DEC,
  RSA_ENCRYPT,
  RSA_DECRYPT,
  RSA_SIGN_VERIFY,
  AES_EN_RSA_SIGN,
  AES_DEC_RSA_VERIFY,
  EXIT
} AlgoType;

int encryptSign(unsigned char *key, unsigned char *plainText, RSA *privateKey,
                unsigned char *cipher);
int decryptVerify(unsigned char *key, unsigned char *cipherText, RSA *publicKey,
                  bool *isVerified, int cipher_len, unsigned char *plaintext);
unsigned char *key = (unsigned char *)"0123456789abcdef";

#include <fstream>
#include <iostream>

int main() {
  //	aesTest();
  char algorithmType;
  string filePath;
  bool flag = 1;
  int encrypt_length;
  RSA *keypair = generate_key();
  RSA *publicKey = create_publicKey(keypair);
  RSA *privateKey = create_privateKey(keypair);
  while (flag) {

    cout << "Select The Algorithm Type:" << endl;
    cout << "1] AES Encryption " << endl;
    cout << "2] AES Decryption " << endl;
    cout << "3] RSA Encryption " << endl;
    cout << "4] RSA Decryption " << endl;
    cout << "5] RSA Sign and Verify" << endl;
    cout << "6] AES Encryption With Sign " << endl;
    cout << "7] AES Decryption With Verify" << endl;
    cout << "8] Exit" << endl;
    cin >> algorithmType;

    if (algorithmType > EXIT || algorithmType < AES_EN) {
      cout << "Invalid option try again" << endl << endl;
    }
    char *content;
    unsigned char *text;
    int text_len;
    const char *filename;
    std::streampos fileSize;
    std::ofstream outputFile;

    if (algorithmType != EXIT) {
      cout << "Enter the file path:" << endl;

      cin.ignore();
      getline(cin, filePath);

      std::ifstream file(
          filesystem::path(filePath).lexically_normal().u8string(),
          std::ios::binary);

      if (!file.is_open()) {
        std::cerr << "Error opening file.\n";
        return 0;
      }

      file.seekg(0, std::ios::end);
      fileSize = file.tellg();
      file.seekg(0, std::ios::beg);

      // Allocate memory for the char array
      content = new char[fileSize];
      // Read the content into the char array
      file.read(content, fileSize);

      text_len = 0;
      //	int cipher_len = 0;
    }
    switch (algorithmType) {

    case AES_EN:

    {
      text = (unsigned char *)content;
      text_len = strlen((const char *)text);

      unsigned char *cipher =
          new unsigned char[((text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE)];
      int cipher_len = (text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
      AES_Encrypt(text, text_len, key, cipher);

      cout << endl;

      filename = "AES_CipherText.bin";
      outputFile = std::ofstream(filename, std::ios::binary);

      if (outputFile) {
        outputFile.write((const char *)cipher, cipher_len);
        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }
      free(cipher);
    } break;

    case AES_DEC: {

      text = (unsigned char *)content;

      text_len = fileSize;
      int cipher_len = fileSize;
      unsigned char *plaintext =
          new unsigned char[(cipher_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE];

      int plaintext_len = AES_Decrypt(text, cipher_len, key, plaintext);

      filename = "AES_plainText.txt";
      outputFile = std::ofstream(filename);

      if (outputFile) {

        outputFile.write((const char *)plaintext, plaintext_len);

        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }

      free(plaintext);
    } break;
    case RSA_ENCRYPT: {
      text = (unsigned char *)content;
      text_len = strlen((const char *)text);
      unsigned char *encrypted_msg = (unsigned char *)malloc(RSA_size(publicKey));
       encrypt_length = rsaEncrypt(text_len, text, encrypted_msg, publicKey,
                                      RSA_PKCS1_OAEP_PADDING);
      if (encrypt_length == -1) {
        cout << "An error occurred in public_encrypt() method" << endl;
      }

      filename = "RSA_cipherText.bin";
      outputFile = std::ofstream(filename);
      if (outputFile) {

        outputFile.write((const char*)encrypted_msg, encrypt_length);

        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }

    } break;
    case RSA_DECRYPT: {
      text = (unsigned char *)content;
	  text_len = strlen((const char *)text);
      unsigned char *decrypted_msg =  (unsigned char *)malloc(encrypt_length);
	  int decrypt_length = rsaDecrypt(encrypt_length,(unsigned char *) text, (unsigned char *)decrypted_msg, privateKey, RSA_PKCS1_OAEP_PADDING);
    if(decrypt_length == -1) {
        cout<<"An error occurred in private_decrypt() method"<<endl;
		}
      filename = "RSA_plainText.txt";
      outputFile = std::ofstream(filename);
      if (outputFile) {

        outputFile.write((const char*)decrypted_msg, decrypt_length);

        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }
    } break;
    case RSA_SIGN_VERIFY: {
      text = (unsigned char *)content;
      text_len = strlen((const char *)text);
      // Sign and verify
      std::string signature = rsaSign(privateKey, (char *)text);
      cout << "RSA Signing Successfully" << endl;
      filename = "RSA_SIGNATURE.bin";
      outputFile = std::ofstream(filename, std::ios::binary);
      if (outputFile) {

        outputFile.write(signature.c_str(), signature.length());
        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }
      bool isVerified =
          rsaVerify(publicKey, (const char *)text, signature.c_str(), text_len,
                    signature.length());
      std::cout << "RSA Verification Result: "
                << (isVerified ? "Success" : "Failure") << std::endl;
      // clean up
    } break;

    case AES_EN_RSA_SIGN: {
      text = (unsigned char *)content;
      text_len = strlen((const char *)text);

      unsigned char *cipher =
          new unsigned char[((text_len + 256) / AES_BLOCK_SIZE + 1) *
                            AES_BLOCK_SIZE];

      int cipher_len =
          encryptSign(key, (unsigned char *)content, privateKey, cipher);
      filename = "AES__RSA.bin";
      outputFile = std::ofstream(filename, std::ios::binary);

      if (outputFile) {

        outputFile.write((const char *)cipher, cipher_len);
        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }
      break;
    }
    case AES_DEC_RSA_VERIFY: {
      text = (unsigned char *)content;
      text_len = fileSize;
      int cipher_len = fileSize;
      unsigned char *plaintext =
          new unsigned char[(cipher_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE];
      bool isVerified = false;
      int plaintext_len = decryptVerify(key, text, publicKey, &isVerified,
                                        cipher_len, plaintext);
      std::cout << "Verification Result: "
                << (isVerified ? "Success" : "Failure") << std::endl;

      filename = "AES_RSA_VERIFICATION.txt";
      outputFile = std::ofstream(filename, std::ios::binary);

      if (outputFile) {

        outputFile.write((const char *)plaintext, plaintext_len - 257);
        std::cout << "File was created: " << filename << std::endl;
      } else {
        std::cerr << "Error creating the file: " << filename << std::endl;
      }

    } break;
    case EXIT:
      flag = 0;
      break;
      //	default:
      //
      //		break;
    }

    // free(cipherText);
    free(content);
	//free(text);
  }
  RSA_free(keypair);
  RSA_free(publicKey);
  RSA_free(privateKey);
  return 0;
}

int encryptSign(unsigned char *key, unsigned char *plainText, RSA *privateKey,
                unsigned char *cipher) {
  std::string signature = rsaSign(privateKey, (char *)plainText);
  signature = (char *)plainText + signature;
  int cipher_len = AES_Encrypt((unsigned char *)signature.c_str(),
                               signature.length() + 1, key, cipher);
  return cipher_len;
}

int decryptVerify(unsigned char *key, unsigned char *cipherText, RSA *publicKey,
                  bool *isVerified, int cipher_len, unsigned char *plaintext) {

  int plaintext_len = AES_Decrypt(cipherText, cipher_len, key, plaintext);

  char sig[256];
  for (int i = plaintext_len - 257, j = 0; i < plaintext_len - 1; i++, j++) {
    sig[j] = plaintext[i];
  }

  char *msg = new char[plaintext_len - 256];
  for (int i = 0; i < plaintext_len - 257; i++) {
    msg[i] = plaintext[i];
  }

  std::string signature = ((std::string)((char *)(sig)));
  std::string originalMessage = ((std::string)((char *)(msg)));

  *isVerified = rsaVerify(publicKey, msg, sig, plaintext_len - 257, 256);

  delete msg;
  return plaintext_len;
}
