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

#include <windows.h>

#include <string>
#include "openfiles.h"

using namespace std;

class CryptContext;

typedef struct struct_FileHeader {
	unsigned short version;
	unsigned char fileid[FILE_ID_LEN];
} FileHeader;

class KeyDecryptor;

class CryptFile {
public:

	FileHeader m_header;
	LONGLONG m_real_file_size;
	bool m_is_empty;	

	HANDLE m_handle;

	wstring m_path;

	CryptContext *m_con;

	KeyDecryptor *m_pkdc;

	static CryptFile *NewInstance(CryptContext *con);


	void GetKeys(); 

	virtual BOOL Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath, bool bForWrite) = 0;


	virtual BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset) = 0;

	virtual BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo) = 0;

	virtual BOOL SetEndOfFile(LONGLONG offset, BOOL bSet = TRUE) = 0;

	virtual BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length) = 0;

	virtual BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length) = 0;

	BOOL NotImplemented() { SetLastError(ERROR_ACCESS_DENIED); return FALSE; };

	// disallow copying
	CryptFile(CryptFile const&) = delete;
	void operator=(CryptFile const&) = delete;

	CryptFile();
	virtual ~CryptFile();

};

class CryptFileForward:  public CryptFile
{
private:
	shared_ptr<CryptOpenFile> m_openfile;

	bool m_bExclusiveLock;

	void Unlock()
	{
		if (m_openfile) {
			if (m_bExclusiveLock)
				m_openfile->UnlockExclusive();
			else
				m_openfile->UnlockShared();			
		}
	}

	void Lock()
	{
		if (m_openfile) {
			if (m_bExclusiveLock)
				m_openfile->LockExclusive();
			else
				m_openfile->LockShared();
		}
	}

	// toggles mode from shared<=>exclusive
	void ReLock()
	{
		Unlock();
		m_bExclusiveLock = !m_bExclusiveLock;
		Lock();
	}

	bool HaveExclusiveLock() { return m_bExclusiveLock; };

	void GoExclusive()
	{
		if (!HaveExclusiveLock())
			ReLock();
	}

	void GoShared()
	{
		if (HaveExclusiveLock())
			ReLock();
	}

public:


	virtual BOOL Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath, bool /* unused */);

	virtual BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset);

	virtual BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo);

	virtual BOOL SetEndOfFile(LONGLONG offset, BOOL bSet = TRUE);

	virtual BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length);

	virtual BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length);

	// disallow copying
	CryptFileForward(CryptFileForward const&) = delete;
	void operator=(CryptFileForward const&) = delete;

	CryptFileForward();

	virtual ~CryptFileForward();

protected:
	BOOL FlushOutput(LONGLONG& beginblock, BYTE *outputbuf, int& outputbytes); 
	BOOL WriteVersionAndFileId();
	BOOL SetEndOfFileInternal(LARGE_INTEGER& off);


};

class CryptFileReverse:  public CryptFile
{
private:
	BYTE m_block0iv[BLOCK_SIV_LEN];
public:


	virtual BOOL Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath, bool bForWrite);

	virtual BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset);

	virtual BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo)
	{
		return NotImplemented();
	};

	virtual BOOL SetEndOfFile(LONGLONG offset, BOOL bSet = TRUE) { return NotImplemented(); };

	virtual BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length) { return NotImplemented(); };

	virtual BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length) { return NotImplemented(); };

	// disallow copying
	CryptFileReverse(CryptFileReverse const&) = delete;
	void operator=(CryptFileReverse const&) = delete;

	CryptFileReverse();

	virtual ~CryptFileReverse();

};


