#pragma once
#include <iostream>
#include <ws2tcpip.h> 
#include <Windows.h>
#include <httpserv.h>
#include <atlbase.h>
#include <memory>
#include <set>

#define RETURN_IF_FAILED(result, expr) if(FAILED(result = expr)) {\
		return result; \
	}

enum class JwtValidationType {
	Header = 0,
	Cookie = 1,
	Url = 2
};

enum class JwtCryptoAlgorithm {
	HS256 = 0,
	RS256 = 1
};

extern IHttpServer* g_pHttpServer;
extern HTTP_MODULE_ID g_pModuleId;

namespace std
{
	inline wstring to_wstring(const string& str, UINT codePage = CP_THREAD_ACP)
	{
		int len = ::MultiByteToWideChar(codePage, 0, str.data(), str.size(), NULL, 0);
		if (len == 0)
		{
			return wstring();
		}

		wstring buffer(len, '\0');
		::MultiByteToWideChar(codePage, 0, str.data(), str.size(), &buffer[0], len);
		return buffer;
	}

	template<class _Ty>
	struct insensitive_compare : public binary_function<string, string, bool>
	{
		bool operator()(const _Ty& left, const _Ty& right) const {
			return false;
		}
	};

	template<>
	struct insensitive_compare<string>
	{
		bool operator()(const string& left, const string& right) const {
			return _strcmpi(left.c_str(), right.c_str()) < 0;
		}
	};

	template<>
	struct insensitive_compare<wstring>
	{
		bool operator()(const wstring& left, const wstring& right) const {
			return _wcsicmp(left.c_str(), right.c_str()) < 0;
		}
	};
}