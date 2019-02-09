#pragma once

int RC4_Encrypt(unsigned char *Plaintext, int plaintext_len,
	unsigned char *Ciphertext, unsigned char *key, unsigned char *iv);

int RC4_Decrypt(unsigned char *Ciphertext, int ciphertext_len,
	unsigned char *Plaintext, unsigned char *key, unsigned char *iv);

void digest_message_SHA(char *text, int text_len, char *password);

bool EncryptBlock(void *pStartAddr, unsigned long nLength, unsigned long FA, int select);

bool DecryptBlock(void *pStartAddr, unsigned long nLength, unsigned long FA, int select);