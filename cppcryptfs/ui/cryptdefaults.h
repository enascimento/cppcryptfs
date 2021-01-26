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

#define PER_FILESYSTEM_THREADS_DEFAULT 0
#define PER_FILESYSTEM_THREADS_RECOMMENDED 0

#define BUFFERBLOCKS_DEFAULT 16
#define BUFFERBLOCKS_RECOMMENDED 16

#define CACHETTL_DEFAULT 10
#define CACHETTL_RECOMMENDED 10

#define CASEINSENSITIVE_DEFAULT 1
#define CASEINSENSITIVE_RECOMMENDED 1

#define MOUNTMANAGER_DEFAULT 0
#define MOUNTMANAGER_RECOMMENDED 0

#define ENABLE_SAVING_PASSWORDS_DEFAULT 0
#define ENABLE_SAVING_PASSWORDS_RECOMMENDED 0

#define NEVER_SAVE_HISTORY_DEFAULT 0
#define NEVER_SAVE_HISTORY_RECOMMENDED 0

#define DELETE_SPURRIOUS_FILES_DEFAULT 0
#define DELETE_SUPRRIOUS_FILES_RECOMMENDED 0

#define OPEN_ON_MOUNTING_DEFAULT 0
#define OPEN_ON_MOUNTING_RECOMMENDED 0

#define ENCRYPT_KEYS_IN_MEMORY_DEFAULT 0
#define ENCRYPT_KEYS_IN_MEMORY_RECOMMENDED 0

#define CACHE_KEYS_IN_MEMORY_DEFAULT 0
#define CACHE_KEYS_IN_MEMORY_RECOMMENDED 0

#define FAST_MOUNTING_DEFAULT 1
#define FAST_MOUNTING_RECOMMENDED 1

// warnings (not really settings)
#define MOUNTMANAGERWARN_DEFAULT 1

