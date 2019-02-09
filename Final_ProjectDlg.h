
// Final_ProjectDlg.h: 头文件
//

#pragma once
#include "注册.h"
#include "登陆.h"

// CFinalProjectDlg 对话框
class CFinalProjectDlg : public CDialogEx
{
// 构造
public:
	CFinalProjectDlg(CWnd* pParent = nullptr);	// 标准构造函数
	

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FINAL_PROJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

private:
	CFont m_Font;
// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnTcnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult);
	DECLARE_MESSAGE_MAP()
public:
	CTabCtrl tile;
	Decryt De;
	Encyt En;
	afx_msg void OnBnClickedButton1();
};
