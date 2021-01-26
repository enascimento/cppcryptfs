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
#include <mutex>

#include "util/LockZeroBuffer.h"

#define RANDOM_POOL_SIZE (32*1024)

class RandomBytes {
private:
	mutex m_mutex;
	BYTE* m_randbuf;
	DWORD m_bufpos;

	void lock() { m_mutex.lock(); }
	void unlock() { m_mutex.unlock(); }
public:
	bool GetRandomBytes(unsigned char *buf, DWORD len);
	RandomBytes();
	// disallow copying
	RandomBytes(RandomBytes const&) = delete;
	void operator=(RandomBytes const&) = delete;

	virtual ~RandomBytes();
};

