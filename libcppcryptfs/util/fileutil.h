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
#include <vector>

using namespace std;

class CryptContext;

bool
get_dir_iv(CryptContext *con, const WCHAR *path, unsigned char *dir_iv);


typedef int(WINAPI *PCryptFillFindData)(PWIN32_FIND_DATAW fdata, PWIN32_FIND_DATAW fdata_orig, void * dokan_cb, void * dokan_ctx);

DWORD
find_files(CryptContext *con, const WCHAR *pt_path, const WCHAR *path, PCryptFillFindData, void * dokan_cb, void * dokan_ctx);

DWORD
get_file_information(CryptContext *con, LPCWSTR FileName, LPCWSTR inputPath, HANDLE handle, LPBY_HANDLE_FILE_INFORMATION pInfo);

bool
create_dir_iv(CryptContext *con, LPCWSTR path); // path is unencrypted

bool
adjust_file_offset_down(LARGE_INTEGER& l);

bool
adjust_file_offset_up(LARGE_INTEGER& l);

bool
adjust_file_size_down(LARGE_INTEGER& l);

bool
adjust_file_size_up(LARGE_INTEGER& l);

bool
adjust_file_offset_up_truncate_zero(LARGE_INTEGER& l);

bool
is_empty_directory(LPCWSTR path, BOOL bMustReallyBeEmpty = FALSE, CryptContext *con = nullptr);

bool
can_delete_directory(LPCWSTR path, BOOL bMustReallyBeEmpty = FALSE, CryptContext *con = nullptr);

bool 
can_delete_file(LPCWSTR path);

bool
delete_directory(CryptContext *con, LPCWSTR path);

bool
delete_file(const CryptContext *con, const WCHAR *filename, bool cleanup_longname_file_only = false);

bool
read_virtual_file(CryptContext *con, LPCWSTR FileName, unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset);

bool
get_dir_and_file_from_path(LPCWSTR path, wstring *dir, wstring *file);

		  // extracts the stream part if any and puts it with the colon in stream,
bool	  // and puts the file name without the stream name in file
get_file_stream(LPCWSTR filename, wstring *file, wstring *stream);

bool  // for handling streams named like ":foo:$DATA".  The ":$DATA" which is the type of stream is not encrypted/decrypted
remove_stream_type(LPCWSTR stream, wstring& stream_without_type, wstring& type);

bool
convert_find_stream_data(CryptContext *con, LPCWSTR pt_path, LPCWSTR path, WIN32_FIND_STREAM_DATA& fdata);

bool
is_suitable_mountpoint(LPCWSTR path);

bool
is_mountpoint_a_dir(LPCWSTR mountpoint);

bool
is_mountpoint_a_drive(LPCWSTR mountpoint);

wstring
prepare_basedir(const wchar_t *path);
