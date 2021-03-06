// Encyt.cpp: 实现文件
//
#pragma comment(linker, "/SECTION:.text,ERW")
#include "stdafx.h"
#include "登陆.h"
#include "工具.h"
#include "加密.h"
#include "SMC.h"
#include "flower.h"

#include "Final_Project.h"
#include "afxdialogex.h"

#pragma comment(linker, "/SECTION:.text,ERW")

// Encyt 对话框

IMPLEMENT_DYNAMIC(Encyt, CDialogEx)

Encyt::Encyt(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
	
	, User(_T(""))
	, Password(_T(""))
	,number(0)
{
}

Encyt::~Encyt()
{
}

void Encyt::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);

	DDX_Text(pDX, IDC_EDIT1, User);
	DDX_Text(pDX, IDC_EDIT2, Password);
}


BEGIN_MESSAGE_MAP(Encyt, CDialogEx)
	
	ON_BN_CLICKED(IDC_BUTTON1, &Encyt::OnBnClickedButton1)
END_MESSAGE_MAP()



void Encyt::OnBnClickedButton1_()
{
	char password[1024] = { '\0' };
	bool bFlag = 0;
	UpdateData();
	UpdateData(FALSE);
	
	// TODO: 在此添加控件通知处理程序代码
	USES_CONVERSION;
	CString P = User;   //明文路径
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
	_FLOWER_XX0
	DecryptBlock(pVa, size, (DWORD)pVa, 0);
	_FLOWER_XX1
	bFlag = Getpass(name, len, password);
	_FLOWER_XX2
	EncryptBlock(pVa, size, (DWORD)pVa, 0);
	__FLOWER__XX3
	if (!bFlag)   //求出密码
	{
		__FLOWER_XX4
			MessageBoxA("用户名太长！\n16个字符以内", "Lruipeng", MB_OKCANCEL);
		UpdateData();
		User = "";
		UpdateData(FALSE);

	}
	else
	{
	
	
		    __FLOWER_XX5
			CString pass(password);
			__FLOWER_XX6
			if (!CRYPTO_memcmp(pass,Password,pass.GetLength()))
			{
				__FLOWER_XX7
				MessageBoxA( "登录成功", "Liruipeng", MB_OKCANCEL);
				_FLOWER_XX0
				number = 0;
				_FLOWER_XX1
			}
			else
			{
				//_FLOWER_XX2x
				number++;
				if (number >= 3)
				{
					
					MessageBoxA( "信息输入错误超过3次\n程序自动退出", "Liruipeng", MB_OKCANCEL);
					exit(0);
				}
				MessageBoxA("信息输入错误！\n请重新输入", "Liruipeng", MB_OKCANCEL);
				UpdateData();
				User = "";
				Password = "";
				UpdateData(FALSE);
			}	
	}
}


void Encyt::OnBnClickedButton1()
{

	bool bFlag = false;
	void* addr1 = NULL;
	void* addr2 = NULL;
	FuncInfo fi = { NULL,NULL,0 };
	

	//section解密
	HMODULE ImageBase = GetModuleHandle(NULL);
	void* pVa = NULL;
	DWORD size = 0;
	char* sName = { ".Lrp" };
	bool bFind = false;
	bFind = GetSMCCode(ImageBase, sName, &pVa, &size);

	//MessageBoxA("app1", "Lruipeng", MB_OKCANCEL);
	getClassFuncAddr(&addr1, &Encyt::OnBnClickedButton1_);
	getClassFuncAddr(&addr2, &Encyt::OnBnClickedButton1);
	getFuncInfo(".text", addr1, addr2, &fi);

	//char temp[50] = { 0 };
	//sprintf(temp, "FA:%p\nVA:%p\nSize:%p", fi.FaAddr, fi.VaAddr, fi.size);
	//MessageBoxA(temp, "Lruipeng", MB_OKCANCEL);

	//类成员函数解密
	DecryptBlock(pVa, size, (DWORD)pVa, 0);

	DecryptBlock(fi.VaAddr, fi.size, 0, 2);

	EncryptBlock(pVa, size, (DWORD)pVa, 0);

	Encyt::OnBnClickedButton1_();
	// 类成员函数解密
	DecryptBlock(pVa, size, (DWORD)pVa, 0);
	
	EncryptBlock(fi.VaAddr, fi.size, 0, 2);

	EncryptBlock(pVa, size, (DWORD)pVa, 0);

}

void getClassFuncAddr(void** pAddr, ClassFunc funcAddr)
{
	char buf[12];
	sprintf(buf, "%u", funcAddr);
	int d = atoi(buf);
	unsigned char* p = (unsigned char*)d;
	*pAddr = p;
}