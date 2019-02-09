#pragma once
#include <Windows.h>

typedef struct FuncInfo
{
	void* RvaAddr;
	void* VaAddr;
	void* FaAddr;
	DWORD size;
}FuncInfo;


typedef struct Map
{
	HANDLE hFile;     // �ļ����
	HANDLE hMapping;  // ӳ���ļ����
	LPVOID ImageBase; // ӳ���ַ
}MappingFile, pMappingFile;

int  FindCodeTag(void *pStartAddr, unsigned long *pTagLoc,
	unsigned long lTagValue, int nSerachLength);

int VAtoFileOffset(void *pModuleBase, void *pVA);

bool GetSMCCode(void *pModuleBase, const char *lpszSection, void** ppPos, LPDWORD lpSize);

bool getFuncInfo(char* sName, void* startFunc, void* endFunc, FuncInfo* fi);

bool CreateCopyEXE(char* fname, MappingFile* fctx);

void CreateCopyEXEEnd();

void preEncryptBlock(MappingFile* fctx);

void preEncryptBlockEnd();

void clearFunc(MappingFile* fctx);

