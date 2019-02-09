#include "stdafx.h"
#include "工具.h"

//typedef int(*encryptFunc)(unsigned char*, int, unsigned char*, unsigned char*, unsigned char*);

// Decryt 消息处理程序
void handleErrors() {

	MessageBoxA(NULL, "ERROR！", "Lruipeng", MB_OKCANCEL);
	exit(0);
}

int RC4_Encrypt(unsigned char *Plaintext, int plaintext_len,
	unsigned char *Ciphertext, unsigned char *key, unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, iv))
		handleErrors();
	//EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, Ciphertext, &len, Plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */

	if (1 != EVP_EncryptFinal_ex(ctx, Ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;

}

int RC4_Decrypt(unsigned char *Ciphertext, int ciphertext_len,
	unsigned char *Plaintext, unsigned char *key, unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	//EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(ctx, Plaintext, &len, Ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */

	if (1 != EVP_DecryptFinal_ex(ctx, Plaintext + len, &len))
		handleErrors();
	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

void digest_message_SHA(char *text, int text_len, char *password) {

	EVP_MD_CTX *mdctx;
	unsigned char * digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()));
	unsigned int digest_len = 0;
	if ((mdctx = EVP_MD_CTX_create()) == NULL)
		EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))
		handleErrors();

	if (1 != EVP_DigestUpdate(mdctx, text, text_len))
		handleErrors();
	if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);

	int num = 0;
	char H[3] = { '0' };
	int j = 0;
	CString st;
	for (int i = 0; i < digest_len; i++)
	{
		num = digest[i];
		itoa(num, H, 16);
		if (H[1] == '\0')
		{
			H[1] = H[0];
			H[0] = '0';

		}
		st = st + H[0] + H[1];
	}

	USES_CONVERSION;

	char *p = T2A(st.GetBuffer(0));
	st.ReleaseBuffer();
	memcpy(password, p, 32);
}




/*
* 生成加密用的密钥和初始向量
* 使用地址FA的摘要值作为密钥
* 使用大小size的摘要值作为初始向量
*/
void Creatk(int FA, char *key, char *iv, int size)
{
	char fa[64] = { 'W' };
	char S[64] = { 'S' };

	itoa((int)FA, fa, 2);
	itoa(size, S, 2);

	char temp_key[128] = { '\0' };
	digest_message_SHA(fa, 64, temp_key);

	char temp_iv[128] = { '\0' };
	digest_message_SHA(S, 64, temp_iv);

	for (int i = 0; i < 32; i++)
	{
		key[i] = temp_key[i];
	}
	for (int i = 0; i < 16; i++)
	{
		iv[i] = temp_iv[i];
	}

}

bool EncryptBlock(void *pStartAddr, unsigned long nLength, unsigned long FA, int select)
{
	if (!pStartAddr || nLength <= 0)
		return false;
	unsigned char* plaintxt = NULL;
	unsigned char* ciphertxt = NULL;
	unsigned char Key[32];
	unsigned char IV[16];
	plaintxt = new unsigned char[nLength];
	ciphertxt = new unsigned char[nLength];
	unsigned char *p = (unsigned char *)pStartAddr;
	
	for (int i = 0; i < nLength - 6; i++)
	{

		plaintxt[i] = p[i];
	}

	if (select != 0)
	{
		unsigned long tem_k;
		unsigned long size;
		get(&tem_k, &size, select);
		Creatk(tem_k, (char *)Key, (char *)IV, size);

	}
	else
	{
		Creatk(FA, (char *)Key, (char *)IV, nLength);
	}


	int cipher_len = RC4_Encrypt(plaintxt, nLength - 6, ciphertxt, Key, IV);

	//写入密文
	for (int i = 0; i < cipher_len; i++)
	{

		*p = ciphertxt[i];
		printf("%c", *p);
		*p++;


	}
	return true;
}

bool DecryptBlock(void *pStartAddr, unsigned long nLength, unsigned long FA, int select)
{
	if (!pStartAddr || nLength <= 0)
		return false;

	unsigned char* plaintxt = NULL;
	unsigned char* ciphertxt = NULL;
	unsigned char Key[32];
	unsigned char IV[16];
	plaintxt = new unsigned char[nLength];
	ciphertxt = new unsigned char[nLength];
	unsigned char *p = (unsigned char *)pStartAddr;
	
	for (int i = 0; i < nLength - 6; i++)
	{
		ciphertxt[i] = p[i];
	}



	if (select != 0)
	{
		unsigned long tem_k;
		unsigned long size;
		get(&tem_k, &size, select);
		Creatk(tem_k, (char *)Key, (char *)IV, size);

	}
	else
	{
		Creatk(FA, (char *)Key, (char *)IV, nLength);
	}


	int plain_len = RC4_Decrypt(ciphertxt, nLength - 6, plaintxt, Key, IV);

	//写入密文
	for (int i = 0; i < plain_len; i++)
	{
		*p = plaintxt[i];
		//printf("%c", *p);
		*p++;

	}

	return true;
}
