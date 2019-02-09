#include <stdlib.h>
#include <stdio.h>
#include "工具.h"
#include "加密.h"
#include "SMC.h"

#pragma code_seg(".Lrp")

int P[16] = { 5,2,3,9,12,14,29 ,21,22,23,24,11,13,7,6,31};
/*
* 获取CPU序列号
*/
void Getx(unsigned int *x, unsigned int *y)
{
	unsigned int ed, ea;
	_asm {
		mov eax, 0x1 //ID号后32位
		cpuid
		mov ea, eax
		mov eax, 0x3 //ID号前32位
		mov ed, edx

	}
	*x = ea;
	*y = ed;

}

void xor(char *XOR, char *name, char *ID, int len)
{
	for (int i = 0; i < 16; i++)
	{
		XOR[i] = name[i] ^ ID[i];

		XOR[i] = (XOR[i] + name[i]) % 256;

	}
}



void Shift(char *st, int st_len)
{
	for (int i = st_len - 1; i > 0; i--)
	{
		st[i] = st[i - 1];
	}
	st[0] = '0';
}

/*
* 生成特征码ID
* x和y分别是CPU 序列号的高低32位
*/
void change(int x, int y, char *ID)
{
	char Q[9] = { '\0' };
	char H[9] = { '\0' };
	itoa(x, Q, 16);
	itoa(y, H, 16);

	for (int i = 0; i < 9; i++)   //Q移位
	{
		if (Q[i] == '\0')
		{
			for (int j = 0; j < 9 - i; j++)
			{
				Shift(Q, 9);
			}
		}

		if (H[i] == '\0')
		{
			for (int j = 0; j < 9 - i; j++)
			{
				Shift(H, 9);
			}
		}
	}

	for (int i = 0; i < 16; i++)
	{
		if (i < 8)
		{
			ID[i] = Q[i];
		}
		else
		{
			ID[i] = H[i - 8];
		}
	}
}


/*
* 根据用户名和CPU序列号生成与用户名对应密码
*/
bool Getpass_(char *Name, int len, char *password)
{

	unsigned int ed, ea;

	char pass[1024] = { '\0' };

	Getx(&ea, &ed);
	char ID[16] = { '\0' };


	change(ea, ed, ID);



	char name[16] = { 'F' };           ///将用户名控制为16位
	int name_len = len;

	if (name_len > 16)
	{
		return false;
	}
	if (name_len <= 16)
	{
		for (int i = 0; i < 16; i++)
		{
			if (i < name_len)
				name[i] = Name[i];
			else
				name[i] = 'L';
		}
	}
	else
	{
		for (int i = 0; i < 16; i++)
		{
			name[i] = Name[i];
		}

	}
	//TRACE("name:%s", name);
	//TRACE("ID:%s", ID);
	char XOR[16] = { '\0' };
	//用户名和ID异或
	xor (XOR, name, ID, 16);



	digest_message_SHA(XOR, 16, pass); //获取密码的哈希值

	for (int i = 0; i < 16; i++)
	{
		int t = P[i];
		password[i] = pass[t];
	}

	return true;
}

bool Getpass(char *Name, int len, char *password)
{
	bool bFlag = false;
	FuncInfo fi = { NULL,NULL,0 };
	getFuncInfo(".Lrp", Getpass_, Getpass, &fi);
	DecryptBlock(fi.VaAddr, fi.size, 0, 1);
	bFlag = Getpass_(Name, len, password);
	EncryptBlock(fi.VaAddr, fi.size, 0, 1);
	return bFlag;
}

void get_(unsigned long *tem_k, unsigned long *tem_i, int seclet)
{
	switch (seclet)
	{
	case 1:
		*tem_k = 2016;
		*tem_i = 513;
		break;
	case 2:
		*tem_k = 2016;
		*tem_i = 513;
		break;
	case 3:
		*tem_k = 2016;
		*tem_i = 513;
		break;
	default:
		*tem_k = 123;
		*tem_i = 123;
		break;
	}
}

void get(unsigned long *tem_k, unsigned long *tem_i, unsigned long seclet)
{
	unsigned long k = 20161120;
	FuncInfo fi = { NULL,NULL,0 };
	getFuncInfo(".Lrp",get_, get, &fi);
	DecryptBlock(fi.VaAddr, fi.size, k, 0);
	get_(tem_k, tem_i, seclet);
	EncryptBlock(fi.VaAddr, fi.size, k, 0);
}

#pragma code_seg()
#pragma comment(linker, "/SECTION:.Lrp,ERW")
