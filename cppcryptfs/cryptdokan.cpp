
/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2017 Bailey Brown (github.com/bailey27/cppcryptfs)

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

/* 
	This file is based on the Dokan (actualy Dokany) sample program mirror.c.  
	Below is the copyright notice from that file.

	But a lot of this code is by Bailey Brown.
*/

/*
Dokan : user-mode file system library for Windows

Copyright (C) 2015 - 2016 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

http://dokan-dev.github.io

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


#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <assert.h>

#include "filename/cryptfilename.h"
#include "cryptconfig.h"
#include "cryptcontext.h"
#include "util/fileutil.h"
#include "file/cryptfile.h"
#include "cryptdefs.h"
#include "util/util.h"
#include "cryptdokan.h"
#include "file/iobufferpool.h"


#include <vector>
#include <string>

#include <windows.h>
#include <Shlwapi.h>
#include "dokan/dokan.h"
#include "dokan/fileinfo.h"
#include <malloc.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <stdarg.h>
#include <varargs.h>

#include <unordered_map>

#define UNMOUNT_TIMEOUT 30000
#define MOUNT_TIMEOUT 30000

#define ENABLE_FILE_NAMED_STREAMS_FLAG 1

BOOL g_UseStdErr;
BOOL g_DebugMode; 
BOOL g_HasSeSecurityPrivilege;

struct struct_CryptThreadData {
	DOKAN_OPERATIONS operations;
	DOKAN_OPTIONS options;
	CryptContext con;
	WCHAR mountpoint[4];
};

typedef struct struct_CryptThreadData CryptThreadData;

HANDLE g_DriveThreadHandles[26];
CryptThreadData *g_ThreadDatas[26];




void DbgPrint(LPCWSTR format, ...) {
  if (g_DebugMode) {
    const WCHAR *outputString;
    WCHAR *buffer = NULL;
    size_t length;
    va_list argp;

    va_start(argp, format);
    length = _vscwprintf(format, argp) + 1;
    buffer = (WCHAR*)_malloca(length * sizeof(WCHAR));
    if (buffer) {
      vswprintf_s(buffer, length, format, argp);
      outputString = buffer;
    } else {
      outputString = format;
    }
    if (g_UseStdErr)
      fputws(outputString, stderr);
    else
      OutputDebugStringW(outputString);
    if (buffer)
      _freea(buffer);
    va_end(argp);
  }
}

#define GetContext() ((CryptContext*)EventInfo->DokanFileInfo->DokanOptions->GlobalContext)
#define GetContextFromFileInfo() ((CryptContext*)(DokanFileInfo)->DokanOptions->GlobalContext)

typedef int(WINAPI *PCryptStoreStreamName)(PWIN32_FIND_STREAM_DATA, LPCWSTR encrypted_name,
	std::unordered_map<std::wstring, std::wstring> *pmap);

NTSTATUS DOKAN_CALLBACK
CryptFindStreamsInternal(
	DOKAN_FIND_STREAMS_EVENT *EventInfo, PCryptStoreStreamName StoreStreamName,
	std::unordered_map<std::wstring, std::wstring> *pmap);

static int WINAPI CryptCaseStreamsCallback(PWIN32_FIND_STREAM_DATA pfdata, LPCWSTR encrypted_name,
	std::unordered_map<std::wstring, std::wstring>* pmap)
{
	std::wstring stream_without_type;
	std::wstring type;

	remove_stream_type(pfdata->cStreamName, stream_without_type, type);

	std::wstring uc_stream;

	touppercase(stream_without_type.c_str(), uc_stream);

	pmap->insert(std::make_pair(uc_stream, stream_without_type.c_str()));

	return 0;
}

// The FileNameEnc class has a contstructor that takes the necessary inputs
// for doing the filename encryption.  It saves them for later, at almost zero cost.
// 
// If the encrypted filename is actually needed, then the instance of FileNameEnc
// is passed to one of various functions that take a const WCHAR * for the encrypted path 
// (and possibly an actual_encrypted parameter).  
//
// When the overloaded cast to const WCHAR * is performed, the filename will be encrypted, and
// the actual_encrypted data (if any) will be retrieved.
//
// A note on actual_encrypted:
//
// When creating a new file or directory, if a file or directory with a long name is being created,
// then the actual encrypted name must be written to the special gocryptfs.longname.XXXXX.name file.
// actual_encrypted will contain this data in that case.
//

class FileNameEnc {
private:
	PDOKAN_FILE_INFO m_dokan_file_info;
	std::wstring m_enc_path;
	std::wstring m_correct_case_path;
	std::string *m_actual_encrypted;
	std::wstring m_plain_path;
	CryptContext *m_con;
	bool m_tried;
	bool m_failed;
	bool m_file_existed;  // valid only if case cache is used
	bool m_force_case_cache_notfound;
public:
	LPCWSTR CorrectCasePath()
	{
		if (m_con->IsCaseInsensitive()) {
			Convert();
			return m_correct_case_path.c_str();
		} else {
			return m_plain_path.c_str();
		}
	};

	bool FileExisted() { _ASSERT(m_con->IsCaseInsensitive());  Convert(); return m_file_existed; };

	operator const WCHAR *()
	{
		return Convert();
	};
private:
	const WCHAR *Convert();
	void AssignPlainPath(LPCWSTR plain_path);
public:
	FileNameEnc(PDOKAN_FILE_INFO DokanFileInfo, const WCHAR *fname, std::string *actual_encrypted = NULL, bool ignorecasecache = false);
	virtual ~FileNameEnc();
};

// Due to a bug in the Dokany driver (as of Dokany 1.03), if we set FILE_NAMED_STREAMS in 
// the volume flags (in CryptGetVolumeInformation())
// to announce that we support alternate data streams in files,
// then whenever a path with a stream is sent down to us by File Explorer, there's an extra slash after the filename
// and before the colon (e.g. \foo\boo\foo.txt\:blah:$DATA).
// So here we git rid of that extra slash if necessary.


void FileNameEnc::AssignPlainPath(LPCWSTR plain_path)
{

	m_plain_path = plain_path;

	// The bug mentioned above is now fixed in Dokany.  The fix should be in Dokany 1.04.
	// When Dokany 1.04 comes out, we should verify that the fix is actually there
	// and use the version to determine if we still need to do this or not.
	// But it won't hurt to leave this code in.

	LPCWSTR pColon = wcschr(plain_path, ':');

	if (!pColon)
		return;

	if (pColon == plain_path)
		return;

	if (pColon[-1] != '\\')
		return;

	m_plain_path.erase(pColon - plain_path - 1);

	m_plain_path += pColon;

	DbgPrint(L"converted file with stream path %s -> %s\n", plain_path, m_plain_path.c_str());
}

FileNameEnc::FileNameEnc(PDOKAN_FILE_INFO DokanFileInfo, const WCHAR *fname, std::string *actual_encrypted, bool forceCaseCacheNotFound)
{
	m_dokan_file_info = DokanFileInfo;
	m_con = GetContextFromFileInfo();
	AssignPlainPath(fname);
	m_actual_encrypted = actual_encrypted;
	m_tried = false;
	m_failed = false;
	m_file_existed = false;
	m_force_case_cache_notfound = forceCaseCacheNotFound;
}

FileNameEnc::~FileNameEnc()
{

}

const WCHAR *FileNameEnc::Convert()
{

	if (!m_tried) {

		m_tried = true;

		try {
			if (m_con->GetConfig()->m_reverse) {
				if (rt_is_config_file(m_con, m_plain_path.c_str())) {
					m_enc_path = m_con->GetConfig()->m_basedir + L"\\";
					m_enc_path += REVERSE_CONFIG_NAME;
				} else if (rt_is_virtual_file(m_con, m_plain_path.c_str())) {
					std::wstring dirpath;
					if (!get_file_directory(m_plain_path.c_str(), dirpath))
						throw(-1);
					if (!decrypt_path(m_con, &dirpath[0], m_enc_path))
						throw(-1);
					m_enc_path += L"\\";
					std::wstring filename;
					if (!get_bare_filename(m_plain_path.c_str(), filename))
						throw(-1);
					m_enc_path += filename;
				} else {
					if (!decrypt_path(m_con, m_plain_path.c_str(), m_enc_path)) {
						throw(-1);
					}
				}
			} else {

				LPCWSTR plain_path = m_plain_path.c_str();
				int cache_status = CASE_CACHE_NOTUSED;
				if (m_con->IsCaseInsensitive()) {
					cache_status = m_con->m_case_cache.lookup(m_plain_path.c_str(), m_correct_case_path, m_force_case_cache_notfound);
					if (cache_status == CASE_CACHE_FOUND || cache_status == CASE_CACHE_NOT_FOUND) {
						m_file_existed = cache_status == CASE_CACHE_FOUND;
						plain_path = m_correct_case_path.c_str();
					} else if (cache_status == CASE_CACHE_MISS) {
						if (m_con->m_case_cache.load_dir(m_plain_path.c_str())) {
							cache_status = m_con->m_case_cache.lookup(m_plain_path.c_str(), m_correct_case_path, m_force_case_cache_notfound);
							if (cache_status == CASE_CACHE_FOUND || cache_status == CASE_CACHE_NOT_FOUND) {
								m_file_existed = cache_status == CASE_CACHE_FOUND;
								plain_path = m_correct_case_path.c_str();
							}
						}
					}
					std::wstring stream;
					std::wstring file_without_stream;
					bool have_stream = get_file_stream(plain_path, &file_without_stream, &stream);
					if (have_stream) {
						std::unordered_map<std::wstring, std::wstring> streams_map;
						std::wstring stream_without_type;
						std::wstring type;

						if (!remove_stream_type(stream.c_str(), stream_without_type, type)) {
							throw(-1);
						}

						DOKAN_FIND_STREAMS_EVENT EventInfo;
						memset(&EventInfo, 0, sizeof(EventInfo));
						EventInfo.FileName = (LPWSTR)file_without_stream.c_str();
						EventInfo.DokanFileInfo = m_dokan_file_info;

						if (CryptFindStreamsInternal(&EventInfo,
							CryptCaseStreamsCallback, &streams_map) == 0) {

							std::wstring uc_stream;

							if (!touppercase(stream_without_type.c_str(), uc_stream))
								throw(-1);

							auto it = streams_map.find(uc_stream);

							if (it != streams_map.end()) {
								m_correct_case_path = file_without_stream + it->second + type;
								plain_path = m_correct_case_path.c_str();
								DbgPrint(L"stream found %s -> %s\n", m_plain_path, plain_path);
							} else {
								DbgPrint(L"stream not found %s -> %s\n", m_plain_path, plain_path);
							}
						}
					}
				}
				if (!encrypt_path(m_con, plain_path, m_enc_path, m_actual_encrypted)) {
					throw(-1);
				}
			}
		} catch (...) {
			m_failed = true;
		}
	}

	const WCHAR *rs = !m_failed ? &m_enc_path[0] : NULL;

	if (rs) {
		DbgPrint(L"\tconverted filename %s => %s\n", m_plain_path.c_str(), rs);
	} else {
		DbgPrint(L"\terror converting filename %s\n", m_plain_path.c_str());
	}

	return rs;
}

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {

  if (!g_DebugMode)
		return;

  HANDLE handle;
  UCHAR buffer[1024];
  DWORD returnLength;
  WCHAR accountName[256];
  WCHAR domainName[256];
  DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
  DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
  PTOKEN_USER tokenUser;
  SID_NAME_USE snu;

  handle = DokanOpenRequestorToken(DokanFileInfo);
  if (handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"  DokanOpenRequestorToken failed\n");
    return;
  }

  if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
                           &returnLength)) {
    DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
    CloseHandle(handle);
    return;
  }

  CloseHandle(handle);

  tokenUser = (PTOKEN_USER)buffer;
  if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
                        domainName, &domainLength, &snu)) {
    DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
    return;
  }

  DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

NTSTATUS ToNtStatus(DWORD dwError) {

	// switch is for translating error codes we use that DokanNtStatusFromWin32() does not translate
	switch (dwError) {
	case ERROR_INVALID_DATA:
		return STATUS_DATA_ERROR;
	case ERROR_DATA_CHECKSUM_ERROR:
		return STATUS_CRC_ERROR;
	default:
		return DokanNtStatusFromWin32(dwError);
	}
}

static BOOL AddSeSecurityNamePrivilege() {

	HANDLE token = 0;

	DbgPrint(L"## Attempting to add SE_SECURITY_NAME and SE_RESTORE_NAME privileges to process token ##\n");

	DWORD err;
	LUID securityLuid;
	LUID restoreLuid;
	LUID backupLuid;

	if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &securityLuid)) {

		err = GetLastError();

		if (err != ERROR_SUCCESS) {

			DbgPrint(L"  failed: Unable to lookup SE_SECURITY_NAME value. error = %u\n", err);

			return FALSE;
		}
	}

	if (!LookupPrivilegeValue(0, SE_RESTORE_NAME, &restoreLuid)) {

		err = GetLastError();

		if (err != ERROR_SUCCESS) {

			DbgPrint(L"  failed: Unable to lookup SE_RESTORE_NAME value. error = %u\n", err);

			return FALSE;
		}
	}

	if (!LookupPrivilegeValue(0, SE_BACKUP_NAME, &backupLuid)) {

		err = GetLastError();

		if (err != ERROR_SUCCESS) {

			DbgPrint(L"  failed: Unable to lookup SE_BACKUP_NAME value. error = %u\n", err);

			return FALSE;
		}
	}

	size_t privSize = sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 2);
	PTOKEN_PRIVILEGES privs = (PTOKEN_PRIVILEGES)malloc(privSize);
	PTOKEN_PRIVILEGES oldPrivs = (PTOKEN_PRIVILEGES)malloc(privSize);

	privs->PrivilegeCount = 3;
	privs->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privs->Privileges[0].Luid = securityLuid;
	privs->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privs->Privileges[1].Luid = restoreLuid;
	privs->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	privs->Privileges[2].Luid = backupLuid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {

		err = GetLastError();

		if (err != ERROR_SUCCESS) {

			DbgPrint(L"  failed: Unable obtain process token. error = %u\n", err);

			free(privs);
			free(oldPrivs);

			return FALSE;
		}
	}

	DWORD retSize;

	AdjustTokenPrivileges(token, FALSE, privs, (DWORD)privSize, oldPrivs, &retSize);

	err = GetLastError();

	CloseHandle(token);

	if (err != ERROR_SUCCESS) {

		DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);

		free(privs);
		free(oldPrivs);

		return FALSE;
	}

	BOOL securityPrivPresent = FALSE;
	BOOL restorePrivPresent = FALSE;

	for (unsigned int i = 0; i < oldPrivs->PrivilegeCount && (!securityPrivPresent || !restorePrivPresent); i++) {

		if (oldPrivs->Privileges[i].Luid.HighPart == securityLuid.HighPart
			&& oldPrivs->Privileges[i].Luid.LowPart == securityLuid.LowPart) {

			securityPrivPresent = TRUE;
		}
		else if (oldPrivs->Privileges[i].Luid.HighPart == restoreLuid.HighPart
			&& oldPrivs->Privileges[i].Luid.LowPart == restoreLuid.LowPart) {

			restorePrivPresent = TRUE;
		}
	}

	DbgPrint(securityPrivPresent ? L"  success: SE_SECURITY_NAME privilege already present\n"
		: L"  success: SE_SECURITY_NAME privilege added\n");

	DbgPrint(restorePrivPresent ? L"  success: SE_RESTORE_NAME privilege already present\n"
		: L"  success: SE_RESTORE_NAME privilege added\n");

	free(privs);
	free(oldPrivs);

	return TRUE;
}


#define CryptCheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    DbgPrint(L"\t" L#flag L"\n");                                              \
  }





static NTSTATUS DOKAN_CALLBACK
CryptCreateFile(DOKAN_CREATE_FILE_EVENT *EventInfo) {


  std::string actual_encrypted;
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName, &actual_encrypted);
  HANDLE handle = NULL;
  DWORD fileAttr;
  NTSTATUS status = STATUS_SUCCESS;
  DWORD creationDisposition;
  DWORD fileAttributesAndFlags;
  DWORD error = 0;
  SECURITY_ATTRIBUTES securityAttrib;
  ACCESS_MASK genericDesiredAccess;


  bool is_virtual = rt_is_virtual_file(GetContext(), EventInfo->FileName);

  bool is_reverse_config = rt_is_reverse_config_file(GetContext(), EventInfo->FileName);

  securityAttrib.nLength = sizeof(securityAttrib);
  securityAttrib.lpSecurityDescriptor =
	  EventInfo->SecurityContext.AccessState.SecurityDescriptor;
  securityAttrib.bInheritHandle = FALSE;

  DokanMapKernelToUserCreateFileFlags(
	  EventInfo, &fileAttributesAndFlags,
      &creationDisposition);


  DbgPrint(L"CreateFile : %s\n", EventInfo->FileName);

  PrintUserName(EventInfo->DokanFileInfo);

  // the block of code below was also commented out in the mirror.c sample
  // cppcryptfs modifies the flags after all the CheckFlag() stuff

  /*
  if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
          ShareMode = FILE_SHARE_WRITE;
  else if (ShareMode == 0)
          ShareMode = FILE_SHARE_READ;
  */

  DbgPrint(L"\tShareMode = 0x%x\n", EventInfo->ShareAccess);

  CryptCheckFlag(EventInfo->ShareAccess, FILE_SHARE_READ);
  CryptCheckFlag(EventInfo->ShareAccess, FILE_SHARE_WRITE);
  CryptCheckFlag(EventInfo->ShareAccess, FILE_SHARE_DELETE);

  DbgPrint(L"EventInfo->DesiredAccess = 0x%x\n", EventInfo->DesiredAccess);

  CryptCheckFlag(EventInfo->DesiredAccess, GENERIC_READ);
  CryptCheckFlag(EventInfo->DesiredAccess, GENERIC_WRITE);
  CryptCheckFlag(EventInfo->DesiredAccess, GENERIC_EXECUTE);

  CryptCheckFlag(EventInfo->DesiredAccess, DELETE);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_READ_DATA);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_READ_ATTRIBUTES);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_READ_EA);
  CryptCheckFlag(EventInfo->DesiredAccess, READ_CONTROL);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_WRITE_DATA);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_WRITE_ATTRIBUTES);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_WRITE_EA);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_APPEND_DATA);
  CryptCheckFlag(EventInfo->DesiredAccess, WRITE_DAC);
  CryptCheckFlag(EventInfo->DesiredAccess, WRITE_OWNER);
  CryptCheckFlag(EventInfo->DesiredAccess, SYNCHRONIZE);
  CryptCheckFlag(EventInfo->DesiredAccess, FILE_EXECUTE);
  CryptCheckFlag(EventInfo->DesiredAccess, STANDARD_RIGHTS_READ);
  CryptCheckFlag(EventInfo->DesiredAccess, STANDARD_RIGHTS_WRITE);
  CryptCheckFlag(EventInfo->DesiredAccess, STANDARD_RIGHTS_EXECUTE);

  if (is_reverse_config) {
	  DbgPrint(L"Reverse Mode: failing attempt to open reverse config file %s\n", EventInfo->FileName);
	  return ToNtStatus(ERROR_FILE_NOT_FOUND);
  }

  // When filePath is a directory, needs to change the flag so that the file can
  // be opened.
  fileAttr = is_virtual ? FILE_ATTRIBUTE_NORMAL : GetFileAttributes(filePath);

  BOOL bHasDirAttr = fileAttr != INVALID_FILE_ATTRIBUTES && (fileAttr & FILE_ATTRIBUTE_DIRECTORY);

  // The two blocks below are there because we generally can't write to file 
  // unless we can also read from it.
  if (!(bHasDirAttr || (EventInfo->CreateOptions & FILE_DIRECTORY_FILE)) &&
	  ((EventInfo->DesiredAccess & GENERIC_WRITE) || (EventInfo->DesiredAccess & FILE_WRITE_DATA))) {
	  DbgPrint(L"\tadded FILE_READ_DATA to desired access\n");
	  EventInfo->DesiredAccess |= FILE_READ_DATA;
  }

  genericDesiredAccess = DokanMapStandardToGenericAccess(EventInfo->DesiredAccess);

  if (!(bHasDirAttr || (EventInfo->CreateOptions & FILE_DIRECTORY_FILE)) &&
	  (EventInfo->ShareAccess & FILE_SHARE_WRITE)) {
	  DbgPrint(L"\tadded FILE_SHARE_READ to share access\n");
	  EventInfo->ShareAccess |= FILE_SHARE_READ;
  }

  if (fileAttr != INVALID_FILE_ATTRIBUTES &&
		  (fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
		  !(EventInfo->CreateOptions & FILE_NON_DIRECTORY_FILE)) {
			EventInfo->DokanFileInfo->IsDirectory = TRUE;
		  if (EventInfo->DesiredAccess & DELETE) {
			        // Needed by FindFirstFile to see if directory is empty or not
			  EventInfo->ShareAccess |= FILE_SHARE_READ;
			  
		  }
	}

  DbgPrint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);

  if (fileAttributesAndFlags & FILE_FLAG_NO_BUFFERING) {
	  // we cannot guarantee sector-aligned reads or writes
	  DbgPrint(L"\tremoving FILE_FLAG_NO_BUFFERING\n");
	  fileAttributesAndFlags &= ~FILE_FLAG_NO_BUFFERING;
  }

  if (creationDisposition == CREATE_NEW) {
    DbgPrint(L"\tCREATE_NEW\n");
  } else if (creationDisposition == OPEN_ALWAYS) {
    DbgPrint(L"\tOPEN_ALWAYS\n");
  } else if (creationDisposition == CREATE_ALWAYS) {
    DbgPrint(L"\tCREATE_ALWAYS\n");
  } else if (creationDisposition == OPEN_EXISTING) {
    DbgPrint(L"\tOPEN_EXISTING\n");
  } else if (creationDisposition == TRUNCATE_EXISTING) {
    DbgPrint(L"\tTRUNCATE_EXISTING\n");
  } else {
    DbgPrint(L"\tUNKNOWN creationDisposition!\n");
  }

  if (EventInfo->DokanFileInfo->IsDirectory) {
    // It is a create directory request
    if (creationDisposition == CREATE_NEW) {
      if (!CreateDirectory(filePath, &securityAttrib)) {
        error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);
        status = ToNtStatus(error);
      } else {

		  if (!create_dir_iv(GetContext(), filePath)) {
				error = GetLastError();
				DbgPrint(L"\tcreate dir iv error code = %d\n\n", error);
				status = ToNtStatus(error);
		  }
		  
		  if (actual_encrypted.size() > 0) {
			  if (!write_encrypted_long_name(filePath, actual_encrypted)) {
				  error = GetLastError();
				  DbgPrint(L"\twrite long error code = %d\n\n", error);
				  status = ToNtStatus(error);
				  RemoveDirectory(filePath);
			  }
		  }

		  if (GetContext()->IsCaseInsensitive()) {
			  std::list<std::wstring> files;
			  if (wcscmp(EventInfo->FileName, L"\\")) {
				  files.push_front(L"..");
				  files.push_front(L".");
			  }
			  GetContext()->m_case_cache.store(filePath.CorrectCasePath(), files);
		  }

	  }
    } else if (creationDisposition == OPEN_ALWAYS) {

      if (!CreateDirectory(filePath, &securityAttrib)) {

        error = GetLastError();

        if (error != ERROR_ALREADY_EXISTS) {
          DbgPrint(L"\terror code = %d\n\n", error);
          status = ToNtStatus(error);
        }
      } else {
		 
		  if (!create_dir_iv(GetContext(), filePath)) {
				error = GetLastError();
				DbgPrint(L"\tcreate dir iv error code = %d\n\n", error);
				status = ToNtStatus(error);
		  }
		  
		  if (actual_encrypted.size() > 0) {
			  if (!write_encrypted_long_name(filePath, actual_encrypted)) {
				  error = GetLastError();
				  DbgPrint(L"\twrite long name error code = %d\n\n", error);
				  status = ToNtStatus(error);
				  RemoveDirectory(filePath);
			  }
		  }

		  if (GetContext()->IsCaseInsensitive()) {
			  std::list<std::wstring> files;
			  if (wcscmp(EventInfo->FileName, L"\\")) {
				  files.push_front(L"..");
				  files.push_front(L".");
			  }
			  GetContext()->m_case_cache.store(filePath.CorrectCasePath(), files);
		  }
	  }
    }

    if (status == STATUS_SUCCESS) {
	  //Check first if we're trying to open a file as a directory.
	  if (fileAttr != INVALID_FILE_ATTRIBUTES &&
			!(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
			(EventInfo->CreateOptions & FILE_DIRECTORY_FILE)) {
			return STATUS_NOT_A_DIRECTORY;
	   }

      // FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
		handle =
			CreateFile(filePath, genericDesiredAccess, EventInfo->ShareAccess,
				&securityAttrib, OPEN_EXISTING,

			fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);

      if (handle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);

        status = ToNtStatus(error);
      } else {
		  if (actual_encrypted.size() > 0) {
			  if (!write_encrypted_long_name(filePath, actual_encrypted)) {
				  error = GetLastError();
				  DbgPrint(L"\terror code = %d\n\n", error);
				  status = ToNtStatus(error);
				  RemoveDirectory(filePath);
			  }
		  }
		  EventInfo->DokanFileInfo->Context =
            (ULONG64)handle; // save the file handle in Context
      }
    }
  } else {
	  // It is a create file request
	 
	  if (fileAttr != INVALID_FILE_ATTRIBUTES &&
		  (fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
		  EventInfo->CreateDisposition == FILE_CREATE) {
		  if (GetContext()->IsCaseInsensitive() && handle != INVALID_HANDLE_VALUE && !filePath.FileExisted()) {
			  GetContext()->m_case_cache.store(filePath.CorrectCasePath());
		  }
		  return STATUS_OBJECT_NAME_COLLISION; // File already exist because
											   // GetFileAttributes found it
	  }

	  if (is_virtual) {
		  SetLastError(0);
		  handle = INVALID_HANDLE_VALUE;
	  } else {

		  handle = CreateFile(
			  filePath,
			  genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			  EventInfo->ShareAccess,
			  &securityAttrib, // security attribute
			  creationDisposition,
			  fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
			  NULL);                  // template file handle
	  }
	
	  status = ToNtStatus(GetLastError());

	if (!is_virtual && handle == INVALID_HANDLE_VALUE) {
		  error = GetLastError();
		  DbgPrint(L"\terror code = %d\n\n", error);

		  status = ToNtStatus(error);
    } else {

		if (actual_encrypted.size() > 0) {
			if (!write_encrypted_long_name(filePath, actual_encrypted)) {
				error = GetLastError();
				DbgPrint(L"\twrite long name error code = %d\n\n", error);
				status = ToNtStatus(error);
				RemoveDirectory(filePath);
			}
		}

		EventInfo->DokanFileInfo->Context =
          (ULONG64)handle; // save the file handle in Context

      if (creationDisposition == OPEN_ALWAYS ||
          creationDisposition == CREATE_ALWAYS) {
        error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
          DbgPrint(L"\tOpen an already existing file\n");
		  // Open succeed but we need to inform the driver
		  // that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
		  if (GetContext()->IsCaseInsensitive() && handle != INVALID_HANDLE_VALUE && !filePath.FileExisted()) {
			  GetContext()->m_case_cache.store(filePath.CorrectCasePath());
		  }
		  return STATUS_OBJECT_NAME_COLLISION;
        }
      }
    }
  }
  DbgPrint(L"handle = %I64x", (ULONGLONG)handle);
  DbgPrint(L"\n");
  if (GetContext()->IsCaseInsensitive() && handle != INVALID_HANDLE_VALUE && !filePath.FileExisted()) {
	  GetContext()->m_case_cache.store(filePath.CorrectCasePath());
  }

  return status;
}

static void CheckDeleteOnClose(PDOKAN_FILE_INFO DokanFileInfo, LPCWSTR FileName, FileNameEnc* filePath)
{
	if (DokanFileInfo->DeleteOnClose) {
		DbgPrint(L"\tDeleteOnClose\n");
		if (DokanFileInfo->IsDirectory) {
			DbgPrint(L"  DeleteDirectory ");
			if (!delete_directory(GetContextFromFileInfo(), *filePath)) {
				DbgPrint(L"error code = %d\n\n", GetLastError());
			}
			else {
				if (GetContextFromFileInfo()->IsCaseInsensitive()) {
					if (!GetContextFromFileInfo()->m_case_cache.purge(FileName)) {
						DbgPrint(L"delete failed to purge dir %s\n", FileName);
					}
				}
				DbgPrint(L"success\n\n");
			}
		}
		else {
			DbgPrint(L"  DeleteFile ");
			if (!delete_file(GetContextFromFileInfo(), *filePath)) {
				DbgPrint(L" error code = %d\n\n", GetLastError());
			}
			else {
				if (GetContextFromFileInfo()->IsCaseInsensitive()) {
					if (!GetContextFromFileInfo()->m_case_cache.remove(filePath->CorrectCasePath())) {
						DbgPrint(L"delete failed to remove %s from case cache\n", FileName);
					}
				}
				DbgPrint(L"success\n\n");
			}
		}
	}
}

static void DOKAN_CALLBACK CryptCloseFile(DOKAN_CLOSE_FILE_EVENT *EventInfo) {
   FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);

  if (EventInfo->DokanFileInfo->Context) {
    DbgPrint(L"CloseFile: %s, %x\n", EventInfo->FileName, (DWORD)EventInfo->DokanFileInfo->Context);
    DbgPrint(L"\terror : not cleanuped file\n\n");
	if (EventInfo->DokanFileInfo->Context && (HANDLE)EventInfo->DokanFileInfo->Context != INVALID_HANDLE_VALUE) {
		CloseHandle((HANDLE)EventInfo->DokanFileInfo->Context);
		EventInfo->DokanFileInfo->Context = 0;
		CheckDeleteOnClose(EventInfo->DokanFileInfo, EventInfo->FileName, &filePath);
	}
	
  } else {
    DbgPrint(L"Close (no handle): %s\n\n", EventInfo->FileName);
  }

  
}

static void DOKAN_CALLBACK CryptCleanup(DOKAN_CLEANUP_EVENT *EventInfo) {
	FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
 

	if (EventInfo->DokanFileInfo->Context) {
		DbgPrint(L"Cleanup: %s, %x\n\n", EventInfo->FileName, (DWORD)EventInfo->DokanFileInfo->Context);
		
		CloseHandle((HANDLE)(EventInfo->DokanFileInfo->Context));
		EventInfo->DokanFileInfo->Context = 0;
		CheckDeleteOnClose(EventInfo->DokanFileInfo, EventInfo->FileName, &filePath);
	
	} else {
		DbgPrint(L"Cleanup: %s\n\tinvalid handle\n\n", EventInfo->FileName);
	}

	
}

static NTSTATUS DOKAN_CALLBACK CryptReadFile(DOKAN_READ_FILE_EVENT *EventInfo) {
	FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
	HANDLE handle = (HANDLE)EventInfo->DokanFileInfo->Context;
	BOOL opened = FALSE;
	NTSTATUS ret_status = STATUS_SUCCESS;

	DbgPrint(L"ReadFile : %s, %I64u, paging io = %u\n", EventInfo->FileName, (ULONGLONG)handle, EventInfo->DokanFileInfo->PagingIo);
	DbgPrint(L"ReadFile : attempting to read %u bytes from offset %ld\n", EventInfo->NumberOfBytesToRead, EventInfo->Offset);

	bool is_virtual = rt_is_virtual_file(GetContext(), EventInfo->FileName);

	if (!handle || (!is_virtual && handle == INVALID_HANDLE_VALUE)) {
		DbgPrint(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			DbgPrint(L"\tCreateFile error : %d\n\n", error);
			return ToNtStatus(error);
		}
		opened = TRUE;
	}

	CryptFile *file = CryptFile::NewInstance(GetContext());

	if (rt_is_config_file(GetContext(), EventInfo->FileName)) {
		LARGE_INTEGER l;
		l.QuadPart = EventInfo->Offset;
		if (SetFilePointerEx(handle, l, NULL, FILE_BEGIN)) {
			if (!ReadFile(handle, EventInfo->Buffer, EventInfo->NumberOfBytesToRead, &EventInfo->NumberOfBytesRead, NULL)) {
				ret_status = ToNtStatus(GetLastError());
			}
		} else {
			ret_status = ToNtStatus(GetLastError());
		}
	} else if (is_virtual) {
		if (!read_virtual_file(GetContext(), EventInfo->FileName, (unsigned char *)EventInfo->Buffer, EventInfo->NumberOfBytesToRead, &EventInfo->NumberOfBytesRead, EventInfo->Offset)) {
			DWORD error = GetLastError();
			if (error == 0)
				error = ERROR_ACCESS_DENIED;
			DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
				error, EventInfo->NumberOfBytesToRead, EventInfo->NumberOfBytesRead);
			ret_status = ToNtStatus(error);
		}
	} else if (file->Associate(GetContext(), handle, EventInfo->FileName)) {

		if (!file->Read((BYTE*)EventInfo->Buffer, EventInfo->NumberOfBytesToRead, &EventInfo->NumberOfBytesRead, EventInfo->Offset)) {
			DWORD error = GetLastError();
			DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
				error, EventInfo->NumberOfBytesToRead, EventInfo->NumberOfBytesRead);
			ret_status = ToNtStatus(error);
		}

		DbgPrint(L"file->Read read %u bytes\n", EventInfo->NumberOfBytesRead);

    } else {
		ret_status = STATUS_ACCESS_DENIED;
    }

	delete file;

	if (opened)
		CloseHandle(handle);

    return ret_status;
}

static NTSTATUS DOKAN_CALLBACK CryptWriteFile(DOKAN_WRITE_FILE_EVENT *EventInfo) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  BOOL opened = FALSE;
  NTSTATUS ret_status = STATUS_SUCCESS;



  DbgPrint(L"WriteFile : %s, offset %I64d, length %d - paging io %u\n", EventInfo->FileName, EventInfo->Offset,
	  EventInfo->NumberOfBytesToWrite, EventInfo->DokanFileInfo->PagingIo);

  if (EventInfo->DokanFileInfo->WriteToEndOfFile)
  {
	  if (EventInfo->DokanFileInfo->PagingIo)
	  {
		  DbgPrint(L"paging io to end of file. doing nothing\n");
		  EventInfo->NumberOfBytesWritten = 0;
		  return STATUS_SUCCESS;
	  }
	  
  }

  // reopen the file
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return ToNtStatus(error);
    }
	
    opened = TRUE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());
  if (file->Associate(GetContext(), handle, EventInfo->FileName)) {
	  if (!file->Write((const unsigned char *)EventInfo->Buffer, EventInfo->NumberOfBytesToWrite, &EventInfo->NumberOfBytesWritten, EventInfo->Offset, EventInfo->DokanFileInfo->WriteToEndOfFile, EventInfo->DokanFileInfo->PagingIo)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n",
			  error, EventInfo->NumberOfBytesToWrite, EventInfo->NumberOfBytesWritten);
		  ret_status = ToNtStatus(error);
	  }
	  else {
		  DbgPrint(L"\twrote nbytes = %u\n", EventInfo->NumberOfBytesWritten);
	  }
  } else {
	  ret_status = STATUS_ACCESS_DENIED;
  }

  delete file;

  // close the file when it is reopened
  if (opened)
	  CloseHandle(handle);

  return ret_status;
}

static NTSTATUS DOKAN_CALLBACK
CryptFlushFileBuffers(DOKAN_FLUSH_BUFFERS_EVENT *EventInfo) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle = (HANDLE)EventInfo->DokanFileInfo->Context;


  DbgPrint(L"FlushFileBuffers : %s\n", EventInfo->FileName);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_SUCCESS;
  }

  if (FlushFileBuffers(handle)) {
    return STATUS_SUCCESS;
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"\tflush error code = %d\n", error);
    return ToNtStatus(error);
  }
}

static NTSTATUS DOKAN_CALLBACK CryptGetFileInformation(
	DOKAN_GET_FILE_INFO_EVENT *EventInfo) {
	FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  BOOL opened = FALSE;


  DbgPrint(L"GetFileInfo : %s\n", EventInfo->FileName);

  if (!handle || (handle == INVALID_HANDLE_VALUE && !rt_is_virtual_file(GetContext(), EventInfo->FileName))) {
	  DbgPrint(L"\tinvalid handle, cleanuped?\n");
	  handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
		  OPEN_EXISTING, 0, NULL);
	  if (handle == INVALID_HANDLE_VALUE) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\tCreateFile error : %d\n\n", error);
		  return DokanNtStatusFromWin32(error);
	  }
	  opened = TRUE;
  }


  NTSTATUS status;

  if (get_file_information(GetContext(), filePath, EventInfo->FileName, handle, &EventInfo->FileHandleInfo) != 0) {
	  DWORD error = GetLastError();
	  DbgPrint(L"GetFileInfo failed(%d)\n", error);
	  status = ToNtStatus(error);
  } else {
	  LARGE_INTEGER l;
	  l.LowPart = EventInfo->FileHandleInfo.nFileSizeLow;
	  l.HighPart = EventInfo->FileHandleInfo.nFileSizeHigh;
	  DbgPrint(L"GetFileInformation %s, filesize = %I64d, attr = 0x%08u\n", EventInfo->FileName, l.QuadPart, EventInfo->FileHandleInfo.dwFileAttributes);
	  status = STATUS_SUCCESS;
  }

  if (opened)
	  CloseHandle(handle);

  return status;

}

// use our own callback so rest of the code doesn't need to know about Dokany internals
static int WINAPI crypt_fill_find_data(PWIN32_FIND_DATAW fdata, PWIN32_FIND_DATAW fdata_orig, void * dokan_cb, void * dokan_ctx)
{
	return ((PFillFindData)dokan_cb)((PDOKAN_FIND_FILES_EVENT)dokan_ctx, fdata);
}

static NTSTATUS DOKAN_CALLBACK
CryptFindFiles(DOKAN_FIND_FILES_EVENT *EventInfo) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->PathName);
  size_t fileLen = 0;
  HANDLE hFind = NULL;

  DWORD error;
  long long count = 0;

  DbgPrint(L"FindFiles :%s\n", EventInfo->PathName);



  if (find_files(GetContext(), filePath.CorrectCasePath(), filePath, crypt_fill_find_data, (void *)EventInfo->FillFindData, (void *)EventInfo) != 0) {
	  error = GetLastError();
	  DbgPrint(L"\tFindNextFile error. Error is %u\n\n", error);
	  return ToNtStatus(error);
  }

  return STATUS_SUCCESS;
}

#if 0
static NTSTATUS 
CryptCanDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {


	FileNameEnc filePath(DokanFileInfo, FileName);

	DbgPrint(L"DeleteDirectory %s - %d\n", FileName,
		DokanFileInfo->DeleteOnClose);

	if (!DokanFileInfo->DeleteOnClose) {
		//Dokan notify that the file is requested not to be deleted.
		return STATUS_SUCCESS;
	}


	if (can_delete_directory(filePath)) {
		return STATUS_SUCCESS;
	}
	else {
		DWORD error = GetLastError();
		DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
		return ToNtStatus(error);
	}

}


static NTSTATUS DOKAN_CALLBACK
CryptCanDeleteFile(DOKAN_CAN_DELETE_FILE_EVENT *EventInfo) {
  

  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE	handle = (HANDLE)EventInfo->DokanFileInfo->Context;

  DbgPrint(L"DeleteFile %s - %d\n", EventInfo->FileName, EventInfo->DokanFileInfo->DeleteOnClose);


  if (can_delete_file(filePath)) {

	  DWORD dwAttrib = GetFileAttributes(filePath);

	  if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		  (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		  return STATUS_ACCESS_DENIED;

	  if (handle && handle != INVALID_HANDLE_VALUE) {
		  FILE_DISPOSITION_INFO fdi;
		  fdi.DeleteFile = EventInfo->DokanFileInfo->DeleteOnClose;
		  if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
			  sizeof(FILE_DISPOSITION_INFO)))
			  return DokanNtStatusFromWin32(GetLastError());
	  }

	  return STATUS_SUCCESS;
  } else {
	  DWORD error = GetLastError();
	  if (error == 0)
		  error = ERROR_ACCESS_DENIED;
	  DbgPrint(L"\tDeleteFile error code = %d\n\n", error);
	  return ToNtStatus(error);
  }

  
}

#endif

static NTSTATUS
CryptCanDeleteDirectory(LPCWSTR filePath) {

	

	DbgPrint(L"CanDeleteDirectory %s\n", filePath);

	if (can_delete_directory(filePath))
		return STATUS_SUCCESS;
	else
		return STATUS_DIRECTORY_NOT_EMPTY;
}

static NTSTATUS DOKAN_CALLBACK
CryptCanDeleteFile(DOKAN_CAN_DELETE_FILE_EVENT *EventInfo) {

	FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
	HANDLE	handle = (HANDLE)EventInfo->DokanFileInfo->Context;

	DbgPrint(L"CanDeleteFile %s - %d\n", EventInfo->FileName, EventInfo->DokanFileInfo->DeleteOnClose);


	BY_HANDLE_FILE_INFORMATION fileInfo;

	ZeroMemory(&fileInfo, sizeof(fileInfo));

	if (!GetFileInformationByHandle(handle, &fileInfo))
	{
		return DokanNtStatusFromWin32(GetLastError());
	}

	if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY) {

		return STATUS_CANNOT_DELETE;
	}

	if (EventInfo->DokanFileInfo->IsDirectory) {

		return CryptCanDeleteDirectory(filePath);
	}

	return STATUS_SUCCESS;
}

// see comment in CryptMoveFile() about what the repair stuff is for

static NTSTATUS
CryptMoveFileInternal(DOKAN_MOVE_FILE_EVENT *EventInfo, bool& needRepair, bool repairName) {

  needRepair = false;

  std::string actual_encrypted;
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  FileNameEnc newFilePath(EventInfo->DokanFileInfo, EventInfo->NewFileName, &actual_encrypted, repairName);

  DbgPrint(L"MoveFile %s -> %s\n\n", EventInfo->FileName, EventInfo->NewFileName);

  HANDLE handle;
  DWORD bufferSize;
  BOOL result;
  size_t newFilePathLen;

  PFILE_RENAME_INFO renameInfo = NULL;

  handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
	  DbgPrint(L"\tinvalid handle\n\n");
	  return STATUS_INVALID_HANDLE;
  }

  newFilePathLen = wcslen(newFilePath);

  // the FILE_RENAME_INFO struct has space for one WCHAR for the name at
  // the end, so that
  // accounts for the null terminator

  bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) +
	  newFilePathLen * sizeof(newFilePath[0]));

  renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
  if (!renameInfo) {
	  return STATUS_BUFFER_OVERFLOW;
  }
  ZeroMemory(renameInfo, bufferSize);

  renameInfo->ReplaceIfExists =
	  EventInfo->ReplaceIfExists
	  ? TRUE
	  : FALSE; // some warning about converting BOOL to BOOLEAN
  renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
  renameInfo->FileNameLength =
	  (DWORD)newFilePathLen *
	  sizeof(newFilePath[0]); // they want length in bytes

  wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

  result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo,
	  bufferSize);

  free(renameInfo);

  if (!result) {
	  DWORD error = GetLastError();
	  DbgPrint(L"\tMoveFile failed status = %d, code = %d\n", result, error);
	  return ToNtStatus(error);
  } else {

	  if (GetContext()->IsCaseInsensitive() && !repairName) {

		  if (newFilePath.FileExisted()) {
			  std::wstring existing_file_name;
			  std::wstring new_file_name;

			  if (get_dir_and_file_from_path(newFilePath.CorrectCasePath(), NULL, &existing_file_name) &&
					get_dir_and_file_from_path(EventInfo->NewFileName, NULL, &new_file_name)) {
					if (wcscmp(existing_file_name.c_str(), new_file_name.c_str())) {
						needRepair = true;
					} 
			  } else {
				  DbgPrint(L"movefile get_dir_and_filename failed\n");
			  }
		  }
	  }

	  // clean up any longname
	  if (!delete_file(GetContext(), filePath, true)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\tMoveFile failed code = %d\n", error);
		  return ToNtStatus(error);
	  }

	  if (actual_encrypted.size() > 0) {
		  if (!write_encrypted_long_name(newFilePath, actual_encrypted)) {
			  DWORD error = GetLastError();
			  DbgPrint(L"\tMoveFile failed2 code = %d\n", error);
			  return ToNtStatus(error);
		  }
	  }

	  if (GetContext()->IsCaseInsensitive()) {
		  GetContext()->m_case_cache.remove(filePath.CorrectCasePath());
		  if (!GetContext()->m_case_cache.store(newFilePath.CorrectCasePath())) {
			  DbgPrint(L"move unable to store new filename %s in case cache\n", newFilePath.CorrectCasePath());
		  }
		  if (EventInfo->DokanFileInfo->IsDirectory) {
			  if (!GetContext()->m_case_cache.rename(filePath.CorrectCasePath(), newFilePath.CorrectCasePath())) {
				  DbgPrint(L"move unable to rename directory %s -> %s in case cache\n", filePath.CorrectCasePath(), newFilePath.CorrectCasePath());
			  }
		  }
	  }

      return STATUS_SUCCESS;
  }
}

static int WINAPI StoreRenameStreamCallback(PWIN32_FIND_STREAM_DATA pfdata, LPCWSTR encrypted_name,
	std::unordered_map<std::wstring, std::wstring>* pmap)
{

	pmap->insert(std::make_pair(encrypted_name, pfdata->cStreamName));

	return 0;
}


static NTSTATUS DOKAN_CALLBACK
CryptMoveFile(DOKAN_MOVE_FILE_EVENT *EventInfo) {

	/*
	
	If we are case insensitive, then we need special handling if you have a situation like as follows:

		files boo.txt and foo.txt already exitst, and you do

		move boo.txt FOO.TXT

		In that case, we need to move boo.txt to foo.txt, then rename foo.txt to FOO.TXT

		The second step (the rename) is called "repair" here.
	*/

	bool needRepair = false;

	/* 
		If we are moving a file with an alternate data stream (besides the default "::$DATA" one) 
		to a different directory, then we need to rename the stream(s) (the encrypted name) using
		the new IV for its new dir.

		There is no API for renaming streams, so the rename must be done by copy and delete.

		If the rename_streams_map has more than one (the default) stream, then we know to 
		do this later.

		If we are operating on a (non-default) stream, then we don't need to do any of this.
	*/

	std::unordered_map<std::wstring, std::wstring> rename_streams_map;

	if (!GetContext()->GetConfig()->m_PlaintextNames) {
		std::wstring fromDir, toDir;
		get_file_directory(EventInfo->FileName, fromDir);
		get_file_directory(EventInfo->NewFileName, toDir);
		if (compare_names(GetContext(), fromDir.c_str(), toDir.c_str())) {
			std::wstring stream;
			bool is_stream = false;
			if (get_file_stream(EventInfo->FileName, NULL, &stream)) {
				is_stream = stream.length() > 0 && wcscmp(stream.c_str(), L":") && 
					compare_names(GetContext(), stream.c_str(), L"::$DATA");
			}
			if (!is_stream) {
				DOKAN_FIND_STREAMS_EVENT StreamEventInfo;
				ZeroMemory(&StreamEventInfo, sizeof(StreamEventInfo));
				StreamEventInfo.DokanFileInfo = EventInfo->DokanFileInfo;
				StreamEventInfo.FileName = (LPWSTR)EventInfo->FileName;
				CryptFindStreamsInternal(&StreamEventInfo, StoreRenameStreamCallback, &rename_streams_map);
			}
		}
	}

	NTSTATUS status = CryptMoveFileInternal(EventInfo, needRepair, false);

	if (GetContext()->IsCaseInsensitive() && status == 0 && needRepair) {
		status = CryptMoveFileInternal(EventInfo, needRepair, true);
	}

	if (status == 0) {
		if (rename_streams_map.size() > 1 && status == 0) {
			// rename streams by copying and deleting.  rename doesn't work
			for (auto it : rename_streams_map) {
				if (it.second.length() < 1 || !wcscmp(it.second.c_str(), L":") || 
					!compare_names(GetContext(), it.second.c_str(), L"::$DATA")) {
					DbgPrint(L"movefile skipping default stream %s\n", it.second.c_str());
					continue;
				}

				FileNameEnc newNameWithoutStream(EventInfo->DokanFileInfo, EventInfo->NewFileName);
				std::wstring newEncNameWithOldEncStream = (LPCWSTR)newNameWithoutStream + it.first;
				std::wstring  newNameWithStream = EventInfo->NewFileName + it.second;
				FileNameEnc newEncNameWithNewEncStream(EventInfo->DokanFileInfo, newNameWithStream.c_str());

				HANDLE hStreamSrc = CreateFile(newEncNameWithOldEncStream.c_str(), GENERIC_READ | DELETE, 
							FILE_SHARE_DELETE | FILE_SHARE_READ, NULL, OPEN_EXISTING,
							FILE_FLAG_DELETE_ON_CLOSE, NULL);

				if (hStreamSrc != INVALID_HANDLE_VALUE) {

					HANDLE hStreamDest = CreateFile(newEncNameWithNewEncStream, GENERIC_READ | GENERIC_WRITE, 
						FILE_SHARE_DELETE | FILE_SHARE_READ, NULL, CREATE_NEW,
						0, NULL);

					if (hStreamDest != INVALID_HANDLE_VALUE) {

						CryptFile *src = CryptFile::NewInstance(GetContext());
						CryptFile *dst = CryptFile::NewInstance(GetContext());
				
						// we don't need to pass pt_path to associate in forward mode so it can be null
						// we never get here in reverse mode because it is read-only

						if (src->Associate(GetContext(), hStreamSrc) && 
							dst->Associate(GetContext(), hStreamDest)) {

							const DWORD bufsize = 64 * 1024;

							BYTE *buf = (BYTE*)malloc(bufsize);

							if (buf) {

								LONGLONG offset = 0;
								DWORD nRead;

								while (src->Read(buf, bufsize, &nRead, offset)) {
									if (nRead == 0)
										break;
									DWORD nWritten = 0;
									if (!dst->Write(buf, nRead, &nWritten, offset, FALSE, FALSE))
										break;
									if (nRead != nWritten)
										break;
									offset += nRead;
								}

								free(buf);
							}
						}
						delete src;
						delete dst;
						CloseHandle(hStreamDest);
					}
					CloseHandle(hStreamSrc);
				} else {
					DbgPrint(L"movefile cannot open file to rename stream %s, error = %u\n", newEncNameWithOldEncStream.c_str(), GetLastError());
				}
			}
			SetLastError(0);

		}
	}

	return status;
}

static NTSTATUS DOKAN_CALLBACK CryptLockFile(DOKAN_LOCK_FILE_EVENT *EventInfo) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle;

  DbgPrint(L"LockFile %s\n", EventInfo->FileName);

  handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, EventInfo->FileName)) {

	  if (!file->LockFile(EventInfo->ByteOffset, EventInfo->Length)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\tfailed(%d)\n", error);
		  delete file;
		  return ToNtStatus(error);
	  }
  } else {
	  delete file;
	  return STATUS_ACCESS_DENIED;
  }

  delete file;

  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetEndOfFile(DOKAN_SET_EOF_EVENT *EventInfo) {
	FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle;


  DbgPrint(L"SetEndOfFile %s, %I64d\n", EventInfo->FileName, EventInfo->Length);

  handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, EventInfo->FileName)) {
	  if (!file->SetEndOfFile(EventInfo->Length)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
		  delete file;
		  return ToNtStatus(error);
	  }
  } else {
	  delete file;
	  DbgPrint(L"\tSetEndOfFile unable to associate\n");
	  return STATUS_ACCESS_DENIED;
  }

  delete file;

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetAllocationSize(
	DOKAN_SET_ALLOCATION_SIZE_EVENT *EventInfo) {
	FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle;
  LARGE_INTEGER fileSize;

  DbgPrint(L"SetAllocationSize %s, %I64d\n", EventInfo->FileName, EventInfo->Length);

  handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }


  BY_HANDLE_FILE_INFORMATION finfo;
  DWORD error = 0;
  try {
	  if (get_file_information(GetContext(), filePath, EventInfo->FileName, handle, &finfo) != 0) {
		  throw(-1);
	  }
	  fileSize.LowPart = finfo.nFileSizeLow;
	  fileSize.HighPart = finfo.nFileSizeHigh;
	  if (EventInfo->Length < fileSize.QuadPart) {
		fileSize.QuadPart = EventInfo->Length;
		CryptFile * file = CryptFile::NewInstance(GetContext());
		if (!file->Associate(GetContext(), handle, EventInfo->FileName)) {
			delete file;
			throw(-1);
		}
		if (!file->SetEndOfFile(fileSize.QuadPart)) {
			delete file;
			throw(-1);
		}
		delete file;
	  }
  } catch (...) {
	  error = GetLastError();
	  DbgPrint(L"\terror code = %d\n\n", error);
	  if (!error)
		  error = ERROR_ACCESS_DENIED;
  }

  if (error)
	  return ToNtStatus(error);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetFileBasicInformation(DOKAN_SET_FILE_BASIC_INFO_EVENT *EventInfo) 
{
  
  DbgPrint(L"SetFileBasicInformation %s\n", EventInfo->FileName);

  HANDLE handle = (HANDLE)EventInfo->DokanFileInfo->Context;

  if (!SetFileInformationByHandle(handle,
	  FileBasicInfo,
	  EventInfo->Info,
	  (DWORD)sizeof(FILE_BASIC_INFORMATION))) {

	  DWORD error = GetLastError();

	  DbgPrint(L"\terror code = %d\n\n", error);

	  return DokanNtStatusFromWin32(error);
  }

  DbgPrint(L"\n");
  return STATUS_SUCCESS;
}



static NTSTATUS DOKAN_CALLBACK
CryptUnlockFile(DOKAN_UNLOCK_FILE_EVENT *EventInfo) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE handle;
  

  DbgPrint(L"UnlockFile %s\n", EventInfo->FileName);

  handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, EventInfo->FileName)) {

	  if (!file->UnlockFile(EventInfo->ByteOffset, EventInfo->Length)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\terror code = %d\n\n", error);
		  delete file;
		  return ToNtStatus(error);
	  }
  } else {
	  delete file;
	  return STATUS_ACCESS_DENIED;
  }
  delete file;
  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK CryptGetFileSecurity(
	DOKAN_GET_FILE_SECURITY_EVENT *EventInfo) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);

  BOOLEAN requestingSaclInfo;

  DbgPrint(L"GetFileSecurity %s\n", EventInfo->FileName);

  CryptCheckFlag(EventInfo->SecurityInformation, FILE_SHARE_READ);
  CryptCheckFlag(EventInfo->SecurityInformation, OWNER_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, GROUP_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, DACL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, SACL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, LABEL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, SCOPE_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation,
	  PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, BACKUP_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
  CryptCheckFlag(EventInfo->SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

  requestingSaclInfo = ((EventInfo->SecurityInformation & SACL_SECURITY_INFORMATION) ||
	  (EventInfo->SecurityInformation & BACKUP_SECURITY_INFORMATION));

  if (!g_HasSeSecurityPrivilege) {
	  EventInfo->SecurityInformation &= ~SACL_SECURITY_INFORMATION;
	  EventInfo->SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
  }

  DbgPrint(L"  Opening new handle with READ_CONTROL access\n");

  bool is_virtual = rt_is_virtual_file(GetContext(), EventInfo->FileName);

  std::wstring virt_path;

  if (is_virtual) {
	  if (rt_is_dir_iv_file(GetContext(), EventInfo->FileName)) {
		  if (!get_file_directory(filePath, virt_path)) {
			  return ToNtStatus(ERROR_ACCESS_DENIED);
		  }
	  } else if (rt_is_name_file(GetContext(), EventInfo->FileName)) {
		  
		  std::wstring enc_path;

		  remove_longname_suffix(EventInfo->FileName, enc_path);

		  if (!decrypt_path(GetContext(), &enc_path[0], virt_path))
			  return ToNtStatus(ERROR_ACCESS_DENIED);
	  } else {
		  return ToNtStatus(ERROR_ACCESS_DENIED);
	  }
  }

  HANDLE handle = CreateFile(
	  is_virtual ? &virt_path[0] : filePath,
	  READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege)
		  ? ACCESS_SYSTEM_SECURITY
		  : 0),
	  FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
	  NULL, // security attribute
	  OPEN_EXISTING,
	  FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
	  NULL);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
	  DbgPrint(L"\tinvalid handle\n\n");
	  int error = GetLastError();
	  return DokanNtStatusFromWin32(error);
  }

  if (!GetUserObjectSecurity(handle, &EventInfo->SecurityInformation, EventInfo->SecurityDescriptor,
	  EventInfo->SecurityDescriptorSize, &EventInfo->LengthNeeded)) {
	  int error = GetLastError();
	  if (error == ERROR_INSUFFICIENT_BUFFER) {
		  DbgPrint(L"  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
		  CloseHandle(handle);
		  return STATUS_BUFFER_OVERFLOW;
	  } else {
		  DbgPrint(L"  GetUserObjectSecurity error: %d\n", error);
		  CloseHandle(handle);
		  return DokanNtStatusFromWin32(error);
	  }
  }

  // Ensure the Security Descriptor Length is set
  DWORD securityDescriptorLength =
	  GetSecurityDescriptorLength(EventInfo->SecurityDescriptor);
  DbgPrint(L"  GetUserObjectSecurity return true,  *LengthNeeded = "
	  L"securityDescriptorLength \n");
  EventInfo->LengthNeeded = securityDescriptorLength;

  CloseHandle(handle);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetFileSecurity(
	DOKAN_SET_FILE_SECURITY_EVENT *EventInfo) {
  HANDLE handle;
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);

  DbgPrint(L"SetFileSecurity %s\n", EventInfo->FileName);

  handle = (HANDLE)EventInfo->DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
	  DbgPrint(L"\tinvalid handle\n\n");
	  return STATUS_INVALID_HANDLE;
  }

  if (!SetUserObjectSecurity(handle, &EventInfo->SecurityInformation, EventInfo->SecurityDescriptor)) {
	  int error = GetLastError();
	  DbgPrint(L"  SetUserObjectSecurity error: %d\n", error);
	  return DokanNtStatusFromWin32(error);
  }
  return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK CryptGetVolumeInformation(
	DOKAN_GET_VOLUME_INFO_EVENT *EventInfo) {
  

  DbgPrint(L"GetVolumeInformation\n");

  CryptContext *con = GetContext();

  CryptConfig *config = con->GetConfig();

  WCHAR dl = config->get_base_drive_letter();

  BOOL bGotVI = FALSE;

  DWORD max_component = 255;
  DWORD fs_flags;
  WCHAR fs_name[256];
  fs_name[0] = '\0';

  if (dl) {

	  WCHAR rbuf[4];
	  rbuf[0] = dl;
	  rbuf[1] = ':';
	  rbuf[2] = '\\';
	  rbuf[3] = '\0';

	  bGotVI = GetVolumeInformationW(rbuf, NULL, 0, NULL, &max_component, &fs_flags, fs_name, sizeof(fs_name) / sizeof(fs_name[0]) - 1);
  }
  if (bGotVI) {
	  DbgPrint(L"max component length of underlying file system is %d\n", max_component);
  } else {
	  DbgPrint(L"GetVolumeInformation failed, err = %u\n", GetLastError());
  }

  _ASSERT(max_component == 255);

  size_t maxVolumeNameLengthInBytes = EventInfo->MaxLabelLengthInChars * sizeof(WCHAR);
  size_t volumeNameLengthInBytes = wcslen(&config->m_VolumeName[0]) * sizeof(WCHAR);
  size_t bytesToWrite = min(maxVolumeNameLengthInBytes, volumeNameLengthInBytes);

  memcpy_s(
	  EventInfo->VolumeInfo->VolumeLabel,
	  maxVolumeNameLengthInBytes,
	  &config->m_VolumeName[0],
	  bytesToWrite);

  EventInfo->VolumeInfo->VolumeLabelLength = (ULONG)(bytesToWrite / sizeof(WCHAR));
 

  EventInfo->VolumeInfo->VolumeSerialNumber = con->GetConfig()->m_serial;
#if 0  
  EventInfo->VolumeInfo->MaximumComponentLength = (config->m_PlaintextNames || config->m_LongNames) ? 255 : 160;

  DWORD defFlags = (FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
	  FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
	  FILE_PERSISTENT_ACLS 
#ifdef	ENABLE_FILE_NAMED_STREAMS_FLAG
	  | FILE_NAMED_STREAMS
#endif
	  );

 
   EventInfo->VolumeInfo->FileSystemFlags = defFlags & (bGotVI ? fs_flags : 0xffffffff);

  // File system name could be anything up to 10 characters.
  // But Windows check few feature availability based on file system name.
  // For this, it is recommended to set NTFS or FAT here.
  wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, bGotVI ? fs_name : L"NTFS");
#endif
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptGetVolumeAttributes(DOKAN_GET_VOLUME_ATTRIBUTES_EVENT *EventInfo) {

	LPCWSTR fileSystemName = L"NTFS";
	size_t maxFileSystemNameLengthInBytes = EventInfo->MaxFileSystemNameLengthInChars * sizeof(WCHAR);
	WCHAR volumeRoot[4];
	DWORD fsFlags = 0;
	DWORD MaximumComponentLength = 0;
	WCHAR FileSystemNameBuffer[255];
	DWORD FileSystemNameSize = 255;

	CryptContext *con = GetContext();

	CryptConfig *config = con->GetConfig();

	WCHAR dl = config->get_base_drive_letter();

	EventInfo->Attributes->FileSystemAttributes =
		FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
		FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
		FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;

	EventInfo->Attributes->MaximumComponentNameLength = 255;

	volumeRoot[0] = dl;
	volumeRoot[1] = ':';
	volumeRoot[2] = '\\';
	volumeRoot[3] = '\0';

	ZeroMemory(FileSystemNameBuffer, sizeof(FileSystemNameBuffer));
	if (GetVolumeInformation(volumeRoot, NULL, 0, NULL, &MaximumComponentLength,
		&fsFlags, FileSystemNameBuffer, FileSystemNameSize)) {

		EventInfo->Attributes->MaximumComponentNameLength = MaximumComponentLength;
		EventInfo->Attributes->FileSystemAttributes &= fsFlags;

		DbgPrint(L"GetVolumeInformation: max component length %u\n",
			EventInfo->Attributes->MaximumComponentNameLength);

		fileSystemName = FileSystemNameBuffer;
		DbgPrint(L"GetVolumeInformation: file system name %s\n",
			fileSystemName);

		DbgPrint(L"GetVolumeInformation: got file system flags 0x%08x,"
			L" returning 0x%08x\n", fsFlags, EventInfo->Attributes->FileSystemAttributes);
	}
	else {

		DbgPrint(L"GetVolumeInformation: unable to query underlying fs,"
			L" using defaults.  Last error = %u\n", GetLastError());
	}

	if (!(config->m_PlaintextNames || config->m_LongNames)) {
		EventInfo->Attributes->MaximumComponentNameLength = min(160, EventInfo->Attributes->MaximumComponentNameLength);
	}

	size_t volumeNameLengthInBytes = wcslen(fileSystemName) * sizeof(WCHAR);
	size_t bytesToWrite = min(maxFileSystemNameLengthInBytes, volumeNameLengthInBytes);

	// File system name could be anything up to 10 characters.
	// But Windows check few feature availability based on file system name.
	// For this, it is recommended to set NTFS or FAT here.
	memcpy_s(
		EventInfo->Attributes->FileSystemName,
		maxFileSystemNameLengthInBytes,
		fileSystemName,
		bytesToWrite);

	EventInfo->Attributes->FileSystemNameLength = (ULONG)(bytesToWrite / sizeof(WCHAR));

	return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK CrypGetDiskFreeSpace(DOKAN_GET_DISK_FREE_SPACE_EVENT *EventInfo) {

	CryptContext *con = GetContext();

	CryptConfig *config = con->GetConfig();

	WCHAR dl = config->get_base_drive_letter();

	WCHAR volumeRoot[4];

	volumeRoot[0] = dl;
	volumeRoot[1] = ':';
	volumeRoot[2] = '\\';
	volumeRoot[3] = '\0';

	if (!GetDiskFreeSpaceExW(
		volumeRoot,
		(ULARGE_INTEGER*)&EventInfo->FreeBytesAvailable,
		(ULARGE_INTEGER*)&EventInfo->TotalNumberOfBytes,
		(ULARGE_INTEGER*)&EventInfo->TotalNumberOfFreeBytes))
	{
		int error = GetLastError();
		DbgPrint(L"  GetDiskFreeSpaceExW error: %d\n", error);

		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for CryptFindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;

  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
    _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */



NTSTATUS DOKAN_CALLBACK
CryptFindStreamsInternal(
	DOKAN_FIND_STREAMS_EVENT *EventInfo, PCryptStoreStreamName StoreStreamName,
			std::unordered_map<std::wstring, std::wstring> *pmap) {
  FileNameEnc filePath(EventInfo->DokanFileInfo, EventInfo->FileName);
  HANDLE hFind;
  WIN32_FIND_STREAM_DATA findData;
  DWORD error;
  int count = 0;
  DOKAN_STREAM_FIND_RESULT findResult = DOKAN_STREAM_BUFFER_CONTINUE;


  DbgPrint(L"FindStreams :%s\n", EventInfo->FileName);

  if (rt_is_virtual_file(GetContext(), EventInfo->FileName)) {
	  wcscpy_s(findData.cStreamName, L"::$DATA");
	  if (rt_is_dir_iv_file(GetContext(), EventInfo->FileName)) {

		  findData.StreamSize.QuadPart = DIR_IV_LEN;

	  } else if (rt_is_name_file(GetContext(), EventInfo->FileName)) {
		  BYTE dir_iv[DIR_IV_LEN];

		  if (!derive_path_iv(GetContext(), EventInfo->FileName, dir_iv, TYPE_DIRIV)) {
			  return ToNtStatus(ERROR_PATH_NOT_FOUND);
		  }
		  std::wstring storage, bare_filename;
		  std::string actual_encrypted;
		  if (!get_bare_filename(EventInfo->FileName, bare_filename))
			  return ToNtStatus(ERROR_PATH_NOT_FOUND);
		  const WCHAR *dname = encrypt_filename(GetContext(), dir_iv, bare_filename.c_str(), storage, &actual_encrypted);
		  if (!dname)
			  return ToNtStatus(ERROR_PATH_NOT_FOUND);
		  findData.StreamSize.QuadPart = actual_encrypted.length();
	  } else {
		  return ToNtStatus(ERROR_PATH_NOT_FOUND);
	  }
	  if (EventInfo->FillFindStreamData)
		  EventInfo->FillFindStreamData(EventInfo, &findData);

	  DbgPrint(L"FindStreams on virtual file\n");
	  return STATUS_SUCCESS;;
  }

  std::wstring encrypted_name;

  hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

  if (hFind == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
	return ToNtStatus(error);
  }

  DbgPrint(L"found stream %s\n", findData.cStreamName);

  encrypted_name = findData.cStreamName;
  if (!convert_find_stream_data(GetContext(), EventInfo->FileName, filePath, findData)) {
	  error = GetLastError();
	  DbgPrint(L"\tconvert_find_stream_data returned false. Error is %u\n\n", error);
	  if (error == 0)
		  error = ERROR_ACCESS_DENIED;
	  FindClose(hFind);
	  return ToNtStatus(error);
  }
  DbgPrint(L"Stream %s size = %lld\n", findData.cStreamName, findData.StreamSize.QuadPart);
  if (EventInfo->FillFindStreamData)
	  findResult = EventInfo->FillFindStreamData(EventInfo, &findData);
  if (StoreStreamName && pmap) {
	  StoreStreamName(&findData, encrypted_name.c_str(), pmap);
  }
  count++;

  while (findResult == DOKAN_STREAM_BUFFER_CONTINUE && FindNextStreamW(hFind, &findData) != 0) {
	DbgPrint(L"found stream %s\n", findData.cStreamName);
	encrypted_name = findData.cStreamName;
	if (!convert_find_stream_data(GetContext(), EventInfo->FileName, filePath, findData)) {
		  error = GetLastError();
		  DbgPrint(L"\tconvert_find_stream_data returned false (loop). Error is %u\n\n", error);
		  if (error == 0)
			  error = ERROR_ACCESS_DENIED;
		  FindClose(hFind);
		  return ToNtStatus(error);
	}
	DbgPrint(L"Stream %s size = %lld\n", findData.cStreamName, findData.StreamSize.QuadPart);
	if (EventInfo->FillFindStreamData && EventInfo->DokanFileInfo)
		findResult = EventInfo->FillFindStreamData(EventInfo, &findData);
	if (StoreStreamName && pmap) {
		StoreStreamName(&findData, encrypted_name.c_str(), pmap);
	}
    count++;
  }

  error = GetLastError();
  FindClose(hFind);

  if (findResult == DOKAN_STREAM_BUFFER_FULL) {

	  DbgPrint(L"\tFindStreams returned %d entries in %s with STATUS_BUFFER_OVERFLOW\n\n", count, filePath);

	  // https://msdn.microsoft.com/en-us/library/windows/hardware/ff540364(v=vs.85).aspx
	  return STATUS_BUFFER_OVERFLOW;
  }


  if (error != ERROR_HANDLE_EOF) {
    DbgPrint(L"\tFindNextStreamW error. Error is %u\n\n", error);
    return ToNtStatus(error);
  }

  DbgPrint(L"\tFindStreams returned %d entries in %s\n\n", count, EventInfo->FileName);

  return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
CryptFindStreams(DOKAN_FIND_STREAMS_EVENT *EventInfo) {

	NTSTATUS status = CryptFindStreamsInternal(EventInfo, NULL, NULL);

	DbgPrint(L"CryptFindStreams returning status 0x%08x\n", status);

	return status;
}

static void DOKAN_CALLBACK CryptMounted(DOKAN_MOUNTED_INFO *EventInfo) {
	

	WCHAR dl = 0;
	
	if (EventInfo->DokanOptions->MountPoint) {
		dl = EventInfo->DokanOptions->MountPoint[0];
	}

	if (dl) {
		if (iswlower(dl))
			dl = towupper(dl);
	}
	
	if (dl >= 'A' && dl <= 'Z') {
		CryptContext *con = &g_ThreadDatas[dl - 'A']->con;
		SetEvent(con->m_mountEvent);
		DbgPrint(L"Mounted\n");
	} else {
		DbgPrint(L"Error with mounting\n");
	}
 
   
}

static void DOKAN_CALLBACK CryptUnmounted(DOKAN_UNMOUNTED_INFO *EventInfo) {

  DbgPrint(L"Unmounted\n");

}



static NTSTATUS DOKAN_CALLBACK CryptGetDiskFreeSpace(DOKAN_GET_DISK_FREE_SPACE_EVENT *EventInfo) {

	

	DbgPrint(L"GetDiskFreeSpace\n");

	CryptContext *con = GetContext();
	CryptConfig *config = con->GetConfig();

	if (config->m_basedir.size() > 0) {
		if (GetDiskFreeSpaceExW(&config->m_basedir[0], (PULARGE_INTEGER)&EventInfo->FreeBytesAvailable,
			(PULARGE_INTEGER)&EventInfo->TotalNumberOfBytes, (PULARGE_INTEGER)&EventInfo->TotalNumberOfFreeBytes)) {
			return STATUS_SUCCESS;
		} else {
			DWORD error = GetLastError();
			DbgPrint(L"\tGetDiskFreeSpaceExW error. Error is %u\n\n", error);
			return ToNtStatus(error);
		}
	} else {
		return STATUS_ACCESS_DENIED;
	}
	
}





static DWORD WINAPI CryptThreadProc(
	_In_ LPVOID lpParameter
	
	) 
{
	CryptThreadData *tdata = (CryptThreadData*)lpParameter;

	DokanInit(NULL);

	NTSTATUS status = DokanMain(&tdata->options, &tdata->operations);

	return (DWORD)status;
}


int mount_crypt_fs(WCHAR driveletter, const WCHAR *path, const WCHAR *config_path, const WCHAR *password, std::wstring& mes, bool readonly, bool reverse, int nThreads, int nBufferBlocks, int cachettl, bool caseinsensitve, bool mountmanager, bool mountmanagerwarn) 
{
	mes.clear();

	if (config_path && *config_path == '\0')
		config_path = NULL;

	if (driveletter < 'A' || driveletter > 'Z') {
		mes = L"Invalid drive letter\n";
		return -1;
	}

	if (g_DriveThreadHandles[driveletter - 'A']) {
		mes = L"drive letter already in use\n";
		return -1;
	}

	int retval = 0;
	CryptThreadData *tdata = NULL;
	HANDLE hThread = NULL;

	try {
	
		try {
			tdata = new CryptThreadData;
		} catch (...) {

		}

		if (!tdata) {
			mes = L"Failed to allocate tdata\n";
			throw(-1);
		}

		PDOKAN_OPERATIONS dokanOperations = &tdata->operations;

		init_security_name_privilege();  // make sure AddSecurityNamePrivilege() has been called, whether or not we can get it

		ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
		dokanOperations->ZwCreateFile = CryptCreateFile;
		dokanOperations->Cleanup = CryptCleanup;
		dokanOperations->CloseFile = CryptCloseFile;
		dokanOperations->ReadFile = CryptReadFile;
		dokanOperations->WriteFile = CryptWriteFile;
		dokanOperations->FlushFileBuffers = CryptFlushFileBuffers;
		dokanOperations->GetFileInformation = CryptGetFileInformation;
		dokanOperations->FindFiles = CryptFindFiles;
		dokanOperations->FindFilesWithPattern = NULL;
		dokanOperations->SetFileBasicInformation = CryptSetFileBasicInformation;
		dokanOperations->CanDeleteFile = CryptCanDeleteFile;
		dokanOperations->MoveFileW = CryptMoveFile;
		dokanOperations->SetEndOfFile = CryptSetEndOfFile;
		dokanOperations->SetAllocationSize = CryptSetAllocationSize;
		dokanOperations->LockFile = CryptLockFile;
		dokanOperations->UnlockFile = CryptUnlockFile;
		dokanOperations->GetVolumeFreeSpace = CryptGetDiskFreeSpace;
		dokanOperations->GetVolumeInformationW = CryptGetVolumeInformation;
		dokanOperations->GetVolumeAttributes = CryptGetVolumeAttributes;
		dokanOperations->Mounted = CryptMounted;
		dokanOperations->Unmounted = CryptUnmounted;
		dokanOperations->GetFileSecurityW = CryptGetFileSecurity;
		dokanOperations->SetFileSecurityW = CryptSetFileSecurity;
		dokanOperations->FindStreams = CryptFindStreams;


		CryptContext *con = &tdata->con;

		con->m_bufferblocks = min(256, max(1, nBufferBlocks));

		if (g_IoBufferPool == NULL) {
			g_IoBufferPool = new IoBufferPool(con->m_bufferblocks*CIPHER_BS);
		}

		con->m_dir_iv_cache.SetTTL(cachettl);
		con->m_case_cache.SetTTL(cachettl);

		con->SetCaseSensitive(caseinsensitve);

		CryptConfig *config = con->GetConfig();

		PDOKAN_OPTIONS dokanOptions = &tdata->options;

		ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
		dokanOptions->Version = DOKAN_VERSION;

		dokanOptions->ThreadCount = nThreads; 

#ifdef _DEBUG
		dokanOptions->Timeout = 900000;
		g_DebugMode = 1;
#endif


		config->m_basedir = path;

		// strip any trailing backslashes
		while (config->m_basedir.size() > 0 && config->m_basedir[config->m_basedir.size() - 1] == '\\')
			config->m_basedir.erase(config->m_basedir.size() - 1);

		std::wstring holder = config->m_basedir;

		config->m_basedir = L"\\\\?\\";  // this prefix enables up to 32K long file paths on NTFS

		config->m_basedir += holder;

		config->m_driveletter = (char)driveletter;

		WCHAR *mountpoint = tdata->mountpoint;

		mountpoint[0] = driveletter;
		mountpoint[1] = L':';
		mountpoint[2] = L'\\';
		mountpoint[3] = 0;

		dokanOptions->MountPoint = mountpoint;

		if (!config->read(mes, config_path, reverse)) {
			if (mes.length() < 1)
				mes = L"unable to load config\n";
			throw(-1);
		}

		std::wstring config_error_mes;

		if (!config->check_config(config_error_mes)) {
			mes = &config_error_mes[0];
			throw(-1);
		}

		if (!config->decrypt_key(password)) {
			mes = L"password incorrect\n";
			throw(-1);
		}

		if (config->m_EMENames) {
			try {
				if (!con->InitEme(config->GetMasterKey(), config->m_HKDF)) {
					throw(-1);
				}	
			} catch (...) {
				mes = L"unable to initialize eme context";
				throw(-1);
			}
		}

		if (config->m_AESSIV) {
			try {
				con->m_siv.SetKey(config->GetMasterKey(), 32, config->m_HKDF);
			} catch (...) {
				mes = L"unable to intialize AESSIV context";
				throw(-1);
			}
		} 

		config->init_serial(con);

		WCHAR fs_name[256];

		DWORD fs_flags;

		WCHAR rbuf[4];
		rbuf[0] = config->get_base_drive_letter();
		rbuf[1] = ':';
		rbuf[2] = '\\';
		rbuf[3] = '\0';

		BOOL bGotVI = GetVolumeInformationW(rbuf, NULL, 0, NULL, NULL, &fs_flags, fs_name, sizeof(fs_name) / sizeof(fs_name[0]) - 1);

		if (bGotVI) {

			size_t maxlength = !wcscmp(fs_name, L"NTFS") ? MAX_VOLUME_NAME_LENGTH : MAX_FAT_VOLUME_NAME_LENGTH;

			if (config->m_VolumeName.size() > maxlength)
				config->m_VolumeName.erase(maxlength, std::wstring::npos);

			if (fs_flags & FILE_READ_ONLY_VOLUME)
				dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;

		} else {
			DWORD lasterr = GetLastError();
			DbgPrint(L"GetVolumeInformation failed, lasterr = %u\n", lasterr);
		}

		if (config->m_reverse || readonly) {
			dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
		} else if (mountmanager) {	
			if (mountmanagerwarn && !have_security_name_privilege()) {

				if (!mountmanager_continue_mounting()) {
					mes = L"operation cancelled by user";
					throw(-1);
				}
			}

			if (have_security_name_privilege())
				dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
		}

		dokanOptions->GlobalContext = (ULONG64)con;
		dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

		hThread = CreateThread(NULL, 0, CryptThreadProc, tdata, 0, NULL);

		if (!hThread) {
			mes = L"unable to create thread for drive letter\n";
			throw(-1);
		}

		g_DriveThreadHandles[driveletter - 'A'] = hThread;
		g_ThreadDatas[driveletter - 'A'] = tdata;

		HANDLE handles[2];
		handles[0] = con->m_mountEvent;
		handles[1] = hThread;

		DWORD wait_result = WaitForMultipleObjects(sizeof(handles) / sizeof(handles[0]), handles, FALSE, MOUNT_TIMEOUT);

		if (wait_result != WAIT_OBJECT_0) {
			if (wait_result == (WAIT_OBJECT_0 + 1)) {
				// thread exited without mounting
				mes = L"mount operation failed\n";
			} else if (wait_result == WAIT_TIMEOUT) {
				mes = L"mount operation timed out\n";
				tdata = NULL; // deleting it would probably cause crash
			} else {
				mes = L"error waiting for mount operation\n";
				tdata = NULL; // deleting it would probably cause crash
			}
			throw(-1);
		}

	} catch (...) {
		retval = -1;
	}

	if (retval != 0) {
		if (hThread) {
			CloseHandle(hThread);
		}
		g_DriveThreadHandles[driveletter - 'A'] = NULL;
		if (tdata) {
			delete tdata;
		}
		g_ThreadDatas[driveletter - 'A'] = NULL;
	}

	return retval;
}

BOOL unmount_crypt_fs(WCHAR driveletter, bool wait)
{
	if (driveletter < 'A' || driveletter > 'Z')
		return false;

	BOOL result = DokanUnmount(driveletter);
	if (!result)
		return FALSE;

	if (!g_DriveThreadHandles[driveletter - 'A'])
		return FALSE;

	if (wait) {
		DWORD wait_timeout = UNMOUNT_TIMEOUT;
		DWORD status = WaitForSingleObject(g_DriveThreadHandles[driveletter - 'A'], wait_timeout);

		if (status == WAIT_OBJECT_0) {
			result = TRUE;
			CloseHandle(g_DriveThreadHandles[driveletter - 'A']);
			g_DriveThreadHandles[driveletter - 'A'] = NULL;
			if (g_ThreadDatas[driveletter - 'A']) {
				delete g_ThreadDatas[driveletter - 'A'];
				g_ThreadDatas[driveletter - 'A'] = NULL;
			}
		} else {
			result = FALSE;
		}
	}

	return result;

}



BOOL wait_for_all_unmounted()
{
	HANDLE handles[26];

	DWORD timeout = UNMOUNT_TIMEOUT;

	int count = 0;
	for (int i = 0; i < 26; i++) {
		if (g_DriveThreadHandles[i])
			handles[count++] = g_DriveThreadHandles[i];
	}
	if (!count)
		return TRUE;

	DWORD status = WaitForMultipleObjects(count, handles, TRUE, timeout);

	DWORD first = WAIT_OBJECT_0;
	DWORD last = WAIT_OBJECT_0 + (count - 1);

	if (status >= first && status <= last) {
		for (int i = 0; i < 26; i++) {
			if (g_DriveThreadHandles[i]) {
				CloseHandle(g_DriveThreadHandles[i]);
				g_DriveThreadHandles[i] = NULL;

				if (g_ThreadDatas[i]) {
					delete g_ThreadDatas[i];
					g_ThreadDatas[i] = NULL;
				}
			}
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL write_volume_name_if_changed(WCHAR dl)
{
	CryptThreadData *tdata = g_ThreadDatas[dl - 'A'];

	if (!tdata)
		return FALSE;


	CryptContext *con = &tdata->con;

	if (!con)
		return false;

	std::wstring fs_root;

	fs_root.push_back(dl);
	fs_root.push_back(':');
	fs_root.push_back('\\');
	

	WCHAR volbuf[256];

	if (!GetVolumeInformationW(&fs_root[0], volbuf, sizeof(volbuf) / sizeof(volbuf[0]) - 1, NULL, NULL, NULL, NULL, 0)) {
		DWORD error = GetLastError();
		DbgPrint(L"update volume name error = %u\n", error);
		return FALSE;
	}

	if (con->GetConfig()->m_VolumeName != volbuf) {
		con->GetConfig()->m_VolumeName = volbuf;
		return con->GetConfig()->write_volume_name();
	}

	return TRUE;
}

BOOL have_security_name_privilege()
{
	static BOOL bHaveName = FALSE;
	static BOOL bCheckedName = FALSE;

	if (!bCheckedName) {
		bHaveName = AddSeSecurityNamePrivilege();
		bCheckedName = TRUE;
		g_HasSeSecurityPrivilege = bHaveName;
	}

	return bHaveName;
}

void init_security_name_privilege()
{
	have_security_name_privilege();
}

// use our own callback so rest of the code doesn't need to know about Dokany internals
static int WINAPI crypt_fill_find_data_list(PWIN32_FIND_DATAW fdata, PWIN32_FIND_DATAW fdata_orig, void * dokan_cb, void * dokan_ctx)
{
	std::list<FindDataPair> *findDatas = (std::list<FindDataPair> *)dokan_ctx;

	FindDataPair pair;

	pair.fdata = *fdata;
	pair.fdata_orig = *fdata_orig;

	findDatas->push_back(pair);

	return 0;
}

BOOL list_files(const WCHAR *path, std::list<FindDataPair> &findDatas, std::wstring& err_mes)
{
	err_mes = L""; 

	if (!path) {
		err_mes = L"path is null";
		return FALSE;
	}

	if (wcslen(path) > MAX_PATH - 1) {
		err_mes = L"path is too long";
		return FALSE;
	}

	WCHAR newpath[MAX_PATH + 1];

	if (!PathCanonicalize(newpath, path)) {
		err_mes = L"failed to canonicalize path";
		return FALSE;
	}

	path = newpath;
	
	int dl = *path;

	if (dl < 'A' || dl > 'Z') {
		err_mes = L"invalid drive letter";
		return FALSE;
	}

	if (wcslen(path) < 3) {
		err_mes = L"path is too short";
		return FALSE;
	}

	if (path[1] != ':' || path[2] != '\\') {
		err_mes = L"invalid path";
		return FALSE;
	}

	path += 2;

	CryptThreadData *tdata = g_ThreadDatas[dl - 'A'];

	if (!tdata) {
		err_mes = L"drive not mounted"; 
		return FALSE;
	}

	CryptContext *con = &tdata->con;

	DOKAN_FILE_INFO DokanFileInfo;
	DOKAN_OPTIONS DokanOptions;

	memset(&DokanFileInfo, 0, sizeof(DokanFileInfo));
	memset(&DokanOptions, 0, sizeof(DokanOptions));

	DokanOptions.GlobalContext = (ULONG_PTR)con;

	DokanFileInfo.DokanOptions = &DokanOptions;

	DokanFileInfo.DokanOptions->GlobalContext = (ULONG_PTR)con;

	FileNameEnc filePath(&DokanFileInfo, path);

	if (PathIsDirectory(filePath)) {

		if (find_files(con, filePath.CorrectCasePath(), filePath, crypt_fill_find_data_list, NULL, &findDatas) != 0) {
			err_mes = L"error listing files";
			return FALSE;
		}
	} else if (PathFileExists(filePath)) {

		FindDataPair pair;
		memset(&pair, 0, sizeof(pair));

		wchar_t dl_colon[3]; 

		dl_colon[0] = dl;
		dl_colon[1] = ':';
		dl_colon[2] = '\0';

		std::wstring plain_path;
		
		plain_path += dl_colon;
		plain_path += filePath.CorrectCasePath();

		wcscpy_s(pair.fdata.cFileName, plain_path.c_str());
		wcscpy_s(pair.fdata_orig.cFileName, filePath + (wcslen(filePath) > 4 ? 4 : 0)); // +4 to skip the \\?\
 		
		findDatas.push_back(pair);
	
	} else {

		err_mes = L"path does not exist";
		return FALSE;
	}

	return TRUE;
}
