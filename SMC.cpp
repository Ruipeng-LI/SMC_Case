#include "stdafx.h"
#include "SMC.h"
#include "����.h"
#include "����.h"
#include "��½.h"

#include <Windows.h>

#pragma comment(linker, "/SECTION:.text,ERW")

int FindCodeTag(void *pStartAddr, unsigned long *pTagLoc, unsigned long lTagValue, int nSerachLength)
{
	int nPos = -1;
	int i = 0;
	unsigned char *pAddr = (unsigned char *)pStartAddr;

	while (i < nSerachLength)
	{
		if ((*pAddr == 0xC7) && ((*(pAddr + 1)) == 0x05))
		{
			unsigned long *Loc = (unsigned long *)((unsigned char*)pAddr + 2);
			if (*Loc == (unsigned long)pTagLoc)
			{
				unsigned long *Val = (unsigned long *)((unsigned char*)pAddr + 6);
				if (*Val == lTagValue)
				{
					nPos = i;
					break;
				}
			}
		}

		pAddr++;
		i++;
	}

	return nPos;
}

int VAtoFileOffset(void *pModuleBase, void *pVA)
{
	IMAGE_DOS_HEADER *pDosHead;
	IMAGE_FILE_HEADER *pPEHead;
	IMAGE_SECTION_HEADER *pSection;

	if (::IsBadReadPtr(pModuleBase, sizeof(IMAGE_DOS_HEADER)) || ::IsBadReadPtr(pVA, 4))
		return -1;

	unsigned char *pszModuleBase = (unsigned char *)pModuleBase;
	pDosHead = (IMAGE_DOS_HEADER *)pszModuleBase;
	//����DOSͷ����DOS stub���룬��λ��PE��־λ��
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE\0\0"
		return -1;

	unsigned char *pszVA = (unsigned char *)pVA;
	int nFileOffset = -1;

	//��λ��PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	//����PE header��Option Header����λ��Section��λ��
	pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER) + nSizeofOptionHeader);
	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(".text", (const char*)pSection[i].Name, 5)) //�Ƚ϶�����
		{
			//�����ļ�ƫ���� = �����ڴ������ַ - (������ڴ������ַ - ����ε��ļ�ƫ��)
			nFileOffset = pszVA - (pszModuleBase + pSection[i].VirtualAddress - pSection[i].PointerToRawData);
			break;
		}
	}

	return nFileOffset;
}

/*******GetSMCCode()******
���ã���ȡҪSMC���Զ���εĵ�ַ�ʹ�С(δ����)
��ڲ�����1.ӳ�����ַ��2.�Զ��������3.�Զ���ε�ָ�룻4.�Զ���εĴ�С
���ڲ������ɹ���true��ʧ�ܣ�false
*/
bool GetSMCCode(void *pModuleBase, const char *lpszSection, void** ppPos, LPDWORD lpSize)
{
	IMAGE_DOS_HEADER *pDosHead;
	PIMAGE_NT_HEADERS  pNtH = NULL;
	IMAGE_FILE_HEADER *pPEHead;
	IMAGE_SECTION_HEADER *pSection;

	*ppPos = NULL;
	*lpSize = 0;

	if (::IsBadReadPtr(pModuleBase, sizeof(IMAGE_DOS_HEADER)) || ::IsBadReadPtr(lpszSection, 8))
		return false;

	if (strlen(lpszSection) >= 16)
		return false;

	char szSecName[16];
	memset(szSecName, 0, 16);
	strncpy(szSecName, lpszSection, IMAGE_SIZEOF_SHORT_NAME);

	unsigned char *pszModuleBase = (unsigned char *)pModuleBase;
	pDosHead = (IMAGE_DOS_HEADER *)pszModuleBase;
	//����DOSͷ����DOS stub���룬��λ��PE��־λ��
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE\0\0"
		return false;

	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDosHead + pDosHead->e_lfanew);
	//��λ��PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	bool bFind = false;
	//����PE header��Option Header����λ��Section��λ��,3�ַ���
	//pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER) + nSizeofOptionHeader);
	pSection = IMAGE_FIRST_SECTION(pNtH);// IMAGE_FIRST_SECTION��

	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(szSecName, (const char*)pSection[i].Name, IMAGE_SIZEOF_SHORT_NAME)) //�Ƚ϶�����
		{
			*ppPos = (void *)(pszModuleBase + pSection[i].VirtualAddress);//����ʵ�����ַ
			//*lpSize = pSection[i].SizeOfRawData;//���δ�С
			*lpSize = pSection[i].Misc.VirtualSize;
			//*lpSize = pSection[i].Misc.VirtualSize;//���δ�С
			bFind = true;
			break;
		}
	}

	return bFind;
}

bool GetSectionPoints(void *ImageBase, const char *lpszSection, void** sRVA, void** sFA, LPDWORD size)
{
	PIMAGE_DOS_HEADER  pDH = NULL;//ָ��IMAGE_DOS�ṹ��ָ��
	PIMAGE_NT_HEADERS  pNtH = NULL;//ָ��IMAGE_NT�ṹ��ָ��
	PIMAGE_FILE_HEADER pFH = NULL;;//ָ��IMAGE_FILE�ṹ��ָ��
	PIMAGE_OPTIONAL_HEADER pOH = NULL;//ָ��IMAGE_OPTIONALE�ṹ��ָ��
	PIMAGE_SECTION_HEADER pSH = NULL;//ָ��IMAGE_SECTION_TABLE�ṹ��ָ��first

	char szSecName[16];
	memset(szSecName, 0, 16);
	strncpy(szSecName, lpszSection, IMAGE_SIZEOF_SHORT_NAME);

	//IMAGE_DOS Header�ṹָ��
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	//IMAGE_NT Header�ṹָ��
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	//IMAGE_File Header�ṹָ��
	pFH = &pNtH->FileHeader;
	//IMAGE_Optional Header�ṹָ��
	pOH = &pNtH->OptionalHeader;

	//IMAGE_SECTION_TABLE�ṹ��ָ��
	pSH = IMAGE_FIRST_SECTION(pNtH);// IMAGE_FIRST_SECTION��

	bool bFind = false;
	//����PE header��Option Header����λ��Section��λ��,3�ַ���

	for (int i = 0; i < pFH->NumberOfSections; i++)
	{
		if (!strncmp(szSecName, (const char*)pSH[i].Name, IMAGE_SIZEOF_SHORT_NAME)) //�Ƚ϶�����
		{
			*sRVA = (void*)pSH[i].VirtualAddress;
			*sFA = (void*)pSH[i].PointerToRawData;
			*size = pSH[i].Misc.VirtualSize;
			bFind = true;
			break;
		}
		//pSH++;
	}

	return bFind;
}


void* getFuncAddr(void* pFunc)
{
	int i = 0;
	char* pFuncAddr = (char*)pFunc;
	if (*((unsigned char*)pFuncAddr) == 0xE9)
	{
		pFuncAddr++;
		i = *((int*)pFuncAddr);
		pFuncAddr = pFuncAddr + i + 4;
		return pFuncAddr;
	}
	return pFunc;
}

bool getFuncInfo(char* sName, void* startFunc, void* endFunc,FuncInfo* fi)
{
	void* fVA = 0;
	void* fFA = 0;
	void* sRVA = 0;
	void* sFA = 0;
	int funcSize = 0;
	DWORD Sectionsize = 0;
	bool flag = false;
	HMODULE ImageBase = GetModuleHandle(NULL);

	fVA = (void*)getFuncAddr(startFunc);
	funcSize = (DWORD)getFuncAddr(endFunc) - (DWORD)fVA;                    //���Լ��㺯�������С
	flag = GetSectionPoints((void*)ImageBase,sName, &sRVA, &sFA, &Sectionsize);           
	if (!flag)
	{
		exit(-1);
	}
	//�����ļ�ƫ���� = �����ڴ������ַ - (������ڴ������ַ - ����ε��ļ�ƫ��)
	fFA = (unsigned char*)(DWORD)fVA - ((DWORD)ImageBase + (DWORD)sRVA - (DWORD)sFA);
	fi->VaAddr = fVA;
	fi->RvaAddr = (unsigned char*)(DWORD)fVA - (DWORD)ImageBase;
	fi->FaAddr = fFA;
	fi->size = funcSize;
	return flag;
}


char* join(char* baseName, char* filename)
{
	int s_len = strlen(baseName) + strlen(filename) + 2;
	char* s = (char*)malloc(sizeof(char)*s_len);
	strcpy(s, baseName);
	strcat(s, "\\");
	strcat(s, filename);
	return s;
}

char* getBaseName(char* absName)
{
	const char ch = '\\';
	char* ret = NULL;
	int ret_len = 0;
	int s_len = 0;
	ret = strrchr(absName, ch);
	ret_len = strlen(ret);
	s_len = strlen(absName) - ret_len;
	char* s = (char*)malloc(sizeof(char)*s_len + 1);
	strncpy(s, absName, s_len);
	s[s_len] = '\0';
	//printf("s:%s\n", s);
	return s;
}


bool CreateCopyEXE(char* fname, MappingFile* fctx)
{
	HANDLE hFile = NULL;     // �ļ����
	HANDLE hMapping = NULL;  // ӳ���ļ����
	LPVOID ImageBase = NULL; // ӳ���ַ
	FILE* fin = NULL;
	FILE* fout = NULL;
	char* newFileName = NULL;
	char* baseName = NULL;
	unsigned char buffer[1024];
	FuncInfo fi = { NULL,NULL,0 };

	baseName = getBaseName(fname);
	newFileName = join(baseName, "SMC_PROJECT_ENC.exe");
	fin = fopen(fname, "rb");
	fout = fopen(newFileName, "wb");
	if (fin == NULL || fout == NULL)
	{
		return FALSE;
	}
	while (!feof(fin))
	{
		int num = fread(buffer, 1, 1024, fin);
		fwrite(buffer, 1, num, fout);
	}
	fclose(fin);
	fclose(fout);

	//LPCWSTR LFilename = (LPCWSTR)newFileName;
	hFile = CreateFile(newFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile)
	{
		MessageBox(NULL, "���ļ�����", NULL, MB_OK);
		return FALSE;
	}
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!hMapping)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	ImageBase = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
	if (!ImageBase)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return FALSE;
	}
	fctx->hFile = hFile;
	fctx->hMapping = hMapping;
	fctx->ImageBase = ImageBase;
	//UnmapViewOfFile(ImageBase);
	//CloseHandle(hMapping);
	//CloseHandle(hFile);
	return TRUE;
}

void CreateCopyEXEEnd() {}

void preEncryptBlock(MappingFile* fctx)
{
	unsigned char* fa = NULL;

	
	FuncInfo fi = { NULL,NULL,0 };


	/*Block 3 Func get_�������� */
	unsigned long k = 20161120;
	getFuncInfo(".Lrp", get_, get, &fi);
	EncryptBlock(fi.VaAddr, fi.size, k, 0);  //���ڴ��н��н��ܣ���ΪҪʹ������Ҫ�Ƚ��ܡ�������ʼ�����ܹ���


	/*Block 3 Func Getpass_�����ĳ�ʼ���� */
	getFuncInfo(".Lrp", Getpass_, Getpass, &fi);
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)fi.FaAddr;
	EncryptBlock(fa, fi.size, 0, 1);

	/*Block 2 Func  �Ե�¼������Ա������ʼ�����ܣ����ǵ�¼��ť�ĺ������� */
	void* addr1 = NULL;
	void* addr2 = NULL;
	getClassFuncAddr(&addr1, &Encyt::OnBnClickedButton1_);
	getClassFuncAddr(&addr2, &Encyt::OnBnClickedButton1);
	getFuncInfo(".text", addr1, addr2, &fi);
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)fi.FaAddr;

	//char temp[50] = { 0 };
	//sprintf(temp, "FA:%p\nVA:%p\nSize:%p", fi.FaAddr, fi.VaAddr, fi.size);
	//MessageBoxA(NULL, temp, "Lruipeng", MB_OKCANCEL);

	EncryptBlock(fa, fi.size, 0, 2);

	/*Block 1 Func _get��ʼ������ */
	k = 20161120;
	getFuncInfo(".Lrp", get_, get, &fi);
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)fi.FaAddr;
	EncryptBlock(fa, fi.size, k, 0);


	/*Block 3 Section */
	HMODULE ImageBase = GetModuleHandle(NULL);
	void* sRva = NULL;
	void* sFA = NULL;
	DWORD size = 0;
	char* sName = { ".Lrp" };
	bool bFind = false;
	bFind = GetSectionPoints(ImageBase, sName, &sRva, &sFA, &size);
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)sFA;
	EncryptBlock(fa, size, (DWORD)sRva+(DWORD)ImageBase, 0);
}

void preEncryptBlockEnd()
{
	int answer = 0;
	int whatIs = true;
	if (whatIs)
	{
		answer = 42;
	}
}

void clearFunc(MappingFile* fctx)
{
	unsigned char* fa = NULL;
	unsigned char fill = 0xc3;
	FuncInfo fi = { NULL,NULL,0 };

	getFuncInfo(".text", preEncryptBlock, preEncryptBlockEnd, &fi);
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)fi.FaAddr;
	memcpy(fa, &fill, 1);
	fa++;
	fill = 0xcc;
	memcpy(fa, &fill, fi.size);

	getFuncInfo(".text", CreateCopyEXE, CreateCopyEXEEnd, &fi);
	fill = 0xc3;
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)fi.FaAddr;
	memcpy(fa, &fill, 1);
	fa++;
	fill = 0xcc;
	memcpy(fa, &fill, fi.size);

	getFuncInfo(".text", clearFunc, clearFunc, &fi);
	fa = (unsigned char*)(DWORD)fctx->ImageBase + (DWORD)fi.FaAddr;
	fill = 0xc3;
	memcpy(fa, &fill, 1);

	if (fctx->ImageBase)
	{
		UnmapViewOfFile(fctx->ImageBase);
	}
	if (fctx->hMapping)
	{
		CloseHandle(fctx->hMapping);
	}
	if (fctx->hFile)
	{
		CloseHandle(fctx->hFile);
	}
}