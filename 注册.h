#pragma once


// Decryt 对话框
;
class Decryt : public CDialogEx
{
	DECLARE_DYNAMIC(Decryt)

public:
	Decryt(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~Decryt();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG2 };
#endif


protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	
	CString Name;
	CString passwd;
	afx_msg void OnBnClickedButton1();

	
};
