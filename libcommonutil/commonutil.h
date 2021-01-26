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

#include "pch.h"

#include <string>
#include <memory>

using namespace std;

bool GetProductVersionInfo(wstring& strProductName, wstring& strProductVersion,
	wstring& strLegalCopyright, HMODULE hMod = NULL);

wstring GetWindowsErrorString(DWORD dwLastErr);

namespace cppcryptfs
{
	/*
	 * This method takes a function that returns a resource,a function that deletes
	 * the resource and arguments that are to be passed to the function that returns a
	 * resource.
	 *
	 * example usecase of a function:
	 *
	 * auto woof = utility2::unique_rsc( ::fopen,::fclose,"/woof/foo/bar","r" ) ;
	 */
	template<typename Function, typename Deleter, typename ... Arguments>
	auto unique_rsc(Function&& function, Deleter&& deleter, Arguments&& ... args)
	{
		using A = std::remove_pointer_t<std::result_of_t<Function(Arguments &&...)>>;
		using B = std::decay_t<Deleter>;

		return std::unique_ptr<A, B>(function(std::forward<Arguments>(args)...),
			std::forward<Deleter>(deleter));
	}

	/*
	 * This function takes a type,a deleter for the type and optional arguments the
	 * construction of the object of the given type need.
	 *
	 * example:
	 * auto woof = unique_ptr<Foo>(foo_deleter, arg1, arg2, argN);
	 * auto woof = unique_ptr<Foo>(foo_deleter);
	 *
	 * The deleter must be a function that takes a single argument of type "Foo*".
	 *
	 */
	template<typename Type, typename Deleter, typename ...Arguments>
	auto unique_ptr(Deleter&& deleter, Arguments&& ...args)
	{
		auto create_object = [](Arguments&& ...args) {

			if (sizeof ...(args) == 0) {
				return new Type();
			} else {
				return new Type(std::forward<Arguments>(args)...);
			}
		};

		return unique_rsc(std::move(create_object),
			std::forward<Deleter>(deleter),
			std::forward<Arguments>(args)...);
	}

	/*
	 * This function takes a type,a deleter for the type and optional arguments the
	 * construction of the object of the given type need.
	 *
	 * example:
	 * Foo *xxx = new Foo(12,"bar");
	 * auto woof = unique_ptr(xxx, foo_deleter);
	 *
	 * The deleter must be a function that takes a single argument of type "Foo*".
	 *
	 */
	template<typename Type, typename Deleter>
	auto unique_ptr(Type type, Deleter&& deleter)
	{
		return unique_rsc([](auto arg) { return arg; },
			std::forward<Deleter>(deleter),
			type);
	}

	/*
	 * This function takes a function that returns a handle through its first argument and could
	 * take additional arguments.
	 *
	 * The function must return 0 on success.
	 *
	 * example:
	 *
	 * int function(Foo **foo, const char *, int) // function prototype
	 *
	 * auto woof = unique_ptr<Foo>(function, foo_deleter, arg1, arg2, argN);
	 */
	template<typename Type, typename Function, typename Deleter, typename ...Arguments>
	auto unique_ptr(Function&& function, Deleter&& deleter, Arguments&& ...args)
	{
		auto create_object = [](Function&& function, Arguments&& ...args) {
			Type* fl;
			if (function(&fl, std::forward<Arguments>(args)...)) {
				return static_cast<Type*>(nullptr);
			} else {
				return fl;
			}
		};

		return unique_rsc(std::move(create_object),
			std::forward<Deleter>(deleter),
			std::forward<Function>(function),
			std::forward<Arguments>(args)...);
	}
}
