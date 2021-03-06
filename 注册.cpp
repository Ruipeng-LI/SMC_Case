// Decryt.cpp: 实现文件
//
#pragma comment(linker, "/SECTION:.text,ERW")
#include "stdafx.h"
#include "注册.h"
#include "工具.h"
#include "加密.h"
#include "SMC.h"
#include "flower.h"


#include "Final_Project.h"
#include "afxdialogex.h"
#define Maxlength 1000
// Decryt 对话框

IMPLEMENT_DYNAMIC(Decryt, CDialogEx)

Decryt::Decryt(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG2, pParent)
	
	, Name(_T(""))
	, passwd(_T(""))
{
	//MessageBoxA("start app1", "Lruipeng", MB_OKCANCEL);
	char fname[] = { "./Release\\Final_Project.exe" };
	MappingFile fctx = { 0 };
	CreateCopyEXE(fname, &fctx);
	preEncryptBlock(&fctx);
	//MessageBoxA("start app2", "Lruipeng", MB_OKCANCEL);
	clearFunc(&fctx);
	//MessageBoxA("start app3","Lruipeng", MB_OKCANCEL);
}

Decryt::~Decryt()
{
}

void Decryt::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);

	DDX_Text(pDX, IDC_EDIT1, Name);
	DDX_Text(pDX, IDC_EDIT2, passwd);
}


BEGIN_MESSAGE_MAP(Decryt, CDialogEx)
	
	ON_BN_CLICKED(IDC_BUTTON1, &Decryt::OnBnClickedButton1)
END_MESSAGE_MAP()

void f5()
{
	int x = 66;
	int i = 99;
	x = x + i;
}

int f4()
{
	int x = 3;
	int y = 4;
	int z;
	z = x - y;
	return 0;
}

void Decryt::OnBnClickedButton1()
{
	bool bFlag = 0;
	char password[1024] = { '\0' };
	// TODO: 在此添加控件通知处理程序代码
	UpdateData();
	UpdateData(FALSE);

	USES_CONVERSION;
	CString P = Name;   //明文路径
	int len = P.GetLength();
	char *name = T2A(P.GetBuffer(0));
	P.ReleaseBuffer();

	HMODULE ImageBase = GetModuleHandle(NULL);
	void* pVa = NULL;
	DWORD size = 0;
	char* sName = { ".Lrp" };
	bool bFind = false;
	bFind = GetSMCCode(ImageBase, sName, &pVa, &size);
	//EncryptBlock(pVa, size, (DWORD)pVa, 0);
	__FLOWER__XX3
	DecryptBlock(pVa, size, (DWORD)pVa, 0);
	_FLOWER_XX2
	bFlag = Getpass(name, len, password);
	_FLOWER_XX1
	EncryptBlock(pVa, size, (DWORD)pVa, 0);
	__FLOWER_XX4
	if (bFlag)   //求出密码
	{
		__FLOWER_XX5
		CString st(password);
		UpdateData();
		passwd = password;
		UpdateData(FALSE);

	
		MessageBoxA("密码已生成", "Lruipeng", MB_OKCANCEL);

	}
	else
		MessageBoxA("用户名太长！\n16个字符以内", "Lruipeng", MB_OKCANCEL);
}