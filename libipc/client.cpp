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

#include "pch.h"

#include <string>
#include <vector>
#include "client.h"
#include "certutil.h"
#include "../libcppcryptfs/util/LockZeroBuffer.h"
#include "../libcommonutil/commonutil.h"

using namespace std;


static wstring FormatErr(const WCHAR *basemes, DWORD lastErr)
{
	wstring err_str = GetWindowsErrorString(lastErr);
	// eat trailing newline chars
	while (err_str.length() && (err_str.back() == '\n' || err_str.back() == '\r')) {
		err_str.pop_back();
	}
	return wstring(basemes) + L" lastErr = " + to_wstring(lastErr) + L" " + err_str;;
}

int SendArgsToRunningInstance(LPCWSTR args, std::wstring& result, std::wstring& err)
{
	HANDLE hPipe;

	auto args_len = wcslen(args);

	if (args_len < 1)
		return SEND_ARGS_STATUS_SUCCESS;

	static_assert(CMD_PIPE_MAX_ARGS_LEN_USER < CMD_PIPE_MAX_ARGS_LEN, "problem with CMD_PIPE_MAX_ARGS_LEN_USER");

	if (args_len > CMD_PIPE_MAX_ARGS_LEN_USER) {
		err = L"command to long.  max length is " + to_wstring(CMD_PIPE_MAX_ARGS_LEN_USER) + L" characters.";
		return SEND_ARGS_STATUS_ERROR;
	}

	LockZeroBuffer<WCHAR> buf(static_cast<DWORD>(args_len + CMD_PIPE_VERSION_LEN + 1), false);

	if (!buf.IsLocked()) {
		err = L"cannot lock command buffer.";
		return SEND_ARGS_STATUS_ERROR;
	}

	memcpy(buf.m_buf, CMD_PIPE_VERSION_STR, CMD_PIPE_VERSION_LEN * sizeof(WCHAR));

	memcpy(buf.m_buf + CMD_PIPE_VERSION_LEN, args, (args_len + 1) * sizeof(WCHAR));
	
	while (true) {
		hPipe = CreateFile(
			CMD_NAMED_PIPE,   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE,
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

		// break if we have a pipe
		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		// return false if an error other than ERROR_PIPE_BUSY occurs. 
		if (GetLastError() != ERROR_PIPE_BUSY) {
			DWORD lastErr = GetLastError();
			err = FormatErr(L"Unable to open pipe.", lastErr);
			if (lastErr == ERROR_FILE_NOT_FOUND) {
				err += L" Is cppcryptfs running?";
				return SEND_ARGS_STATUS_CANNOT_CONNECT;  // startiing cppcryptfs or retry is worthwhile
			} else if (lastErr == ERROR_ACCESS_DENIED) {
				err += L" Is cppcryptfs running as administrator and you are not?";
				return SEND_ARGS_STATUS_ERROR; // retry not worthwhile
			} else {
				return SEND_ARGS_STATUS_ERROR;
			}
		}

		// All pipe instances are busy, so wait. 
		if (!WaitNamedPipe(CMD_NAMED_PIPE, NMPWAIT_WAIT_FOREVER)) {
			err = L"Named pipe connection wait failed.";
			return SEND_ARGS_STATUS_ERROR;
		}
	}

	ULONG server_process_id;

	if (!GetNamedPipeServerProcessId(hPipe, &server_process_id)) {
		err = L"Unable to get process id of already running cppcryptfs.";
		CloseHandle(hPipe);
		return SEND_ARGS_STATUS_ERROR;
	}

	if (!ValidateNamedPipeConnection(server_process_id)) {
		err = L"Unable to validate signature of already running cppcryptfs.";
		CloseHandle(hPipe);
		return SEND_ARGS_STATUS_ERROR;
	}
	
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	auto fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if (!fSuccess) {
		err = FormatErr(L"Unable to set state of named pipe.", GetLastError());
		CloseHandle(hPipe);
		return SEND_ARGS_STATUS_ERROR;
	}

	// Send a message to the pipe server. 

	auto cbToWrite = buf.m_len*sizeof(buf.m_buf[0]);

	DWORD cbRead = 0;

	result.clear();

	const size_t read_buf_size = CMD_NAMED_PIPE_BUFSIZE; 
	// must be multiple of 2 bytes
	static_assert(read_buf_size % 2 == 0, "TransactNamedPipe read buffer size must multipe of 2 bytes");

	vector<BYTE> read_buf(read_buf_size); 

	// this lamba handles appending data to result
	// it returns SEND_ARGS_STATUS_SUCCESS on success
	// on error it sets err and closes the pipe handle and returns an error value
	auto append_data = [&]() -> int {

		if (!fSuccess && (GetLastError() != ERROR_MORE_DATA)) {
			err = FormatErr(L"TransactNamedPipe failed.", GetLastError());
			result.clear();
			CloseHandle(hPipe);
			return SEND_ARGS_STATUS_ERROR;
		}

		// we expect to read whole WCHARS
		if ((cbRead % sizeof(result[0])) != 0) {
			err = L"malformed response (not integral number of WCHARs) from already running cppcryptfs.";
			result.clear();
			CloseHandle(hPipe);
			return SEND_ARGS_STATUS_ERROR;
		}

		auto chars_read = cbRead / sizeof(result[0]);

		const WCHAR* pRead = reinterpret_cast<WCHAR*>(&read_buf[0]);

		if (fSuccess && (chars_read == 0 || pRead[chars_read - 1] != L'\0')) {
			err = L"malformed response (not null-terminated) from already running cppcryptfs.";
			result.clear();
			CloseHandle(hPipe);
			return SEND_ARGS_STATUS_ERROR;
		}

		result += fSuccess ? pRead : wstring(pRead, chars_read);

		return SEND_ARGS_STATUS_SUCCESS;
	};

	int ret;

	fSuccess = TransactNamedPipe(
		hPipe,                          // pipe handle 
		(LPVOID)buf.m_buf,                   // message 
		static_cast<DWORD>(cbToWrite),  // message length 
		&read_buf[0], 
		static_cast<DWORD>(read_buf.size()),
		&cbRead,                        // bytes written 
		NULL);                          // not overlapped 

	if ((ret = append_data()) != SEND_ARGS_STATUS_SUCCESS)
		return ret;

	while (!fSuccess) {
		// Read from the pipe if there is more data in the message.
		fSuccess = ReadFile(
			hPipe,         // pipe handle 
			&read_buf[0],  // buffer to receive reply 
			static_cast<DWORD>(read_buf.size()),  // size of buffer 
			&cbRead,       // number of bytes read 
			NULL);         // not overlapped 

		if ((ret = append_data()) != SEND_ARGS_STATUS_SUCCESS)
			return ret;
	}

	CloseHandle(hPipe);

	return SEND_ARGS_STATUS_SUCCESS;
}
