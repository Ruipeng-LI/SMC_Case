#pragma once
#include "stdafx.h"

#define Maxlength 1000
// Encyt 对话框

class Encyt : public CDialogEx
{
	DECLARE_DYNAMIC(Encyt)

public:
	Encyt(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~Encyt();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif


public:
	

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg
		void OnBnClickedButton1_();
	void OnBnClickedButton1();
	CString User;
	CString Password;
	int number;
};


typedef void(Encyt::* ClassFunc)();

void getClassFuncAddr(void** pAddr, ClassFunc funcAddr);