/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2020 Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


#pragma once

#include "CryptPropertyPage.h"
#include "SecureEdit.h"


// CCreatePropertyPage dialog

class CCreatePropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CCreatePropertyPage)

public:

	CString m_lastDirs[10];
	CString m_lastConfigs[10];
	const int m_numLastDirs = 10;
	const int m_numLastConfigs = 10;

	virtual void DefaultAction();

	// disallow copying
	CCreatePropertyPage(CCreatePropertyPage const&) = delete;
	void operator=(CCreatePropertyPage const&) = delete;

	CCreatePropertyPage();
	virtual ~CCreatePropertyPage();

	void CreateCryptfs();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CREATE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnClickedSelect();
	afx_msg void OnClickedCreate();
	virtual BOOL OnInitDialog();
	afx_msg void OnLbnSelchangeFilenameEncryption();
	afx_msg void OnCbnSelchangePath();
	CSecureEdit m_password;
	CSecureEdit m_password2;
	afx_msg void OnClickedReverse();
	afx_msg void OnClickedSelectConfigPath();
};
