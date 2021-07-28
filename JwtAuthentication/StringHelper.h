#pragma once
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <Windows.h>
#include <cwctype>
#include <cctype>

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

	inline int to_wstring(const string& str, wstring& result, UINT codePage = CP_THREAD_ACP)
	{
		int len = ::MultiByteToWideChar(codePage, 0, str.data(), str.size(), NULL, 0);
		if (len == 0)
		{
			return 0;
		}

		result.resize(len);

		return ::MultiByteToWideChar(codePage, 0, str.data(), str.size(), &result[0], len);
	}

	inline string to_string(LPCWCH pstr, UINT wslen)
	{
		int len = ::WideCharToMultiByte(CP_ACP, 0, pstr, wslen, NULL, 0, NULL, NULL);

		std::string dblstr(len, '\0');
		::WideCharToMultiByte(CP_ACP, 0, pstr, wslen, &dblstr[0], len, NULL, NULL);

		return dblstr;
	}

	inline string to_string(BSTR bstr)
	{
		UINT wslen = ::SysStringLen(bstr);
		return to_string(bstr, wslen);
	}

	inline wstring to_wstring(BSTR bstr)
	{
		UINT wslen = ::SysStringLen(bstr);
		return wstring(bstr, wslen);
	}

	inline BSTR to_bstring(const std::string& str)
	{
		int wslen = ::MultiByteToWideChar(CP_ACP, 0, str.data(), str.length(), NULL, 0);

		BSTR wsdata = ::SysAllocStringLen(NULL, wslen);
		::MultiByteToWideChar(CP_ACP, 0, str.data(), str.length(), wsdata, wslen);

		return wsdata;
	}

	template<typename _Ty>
	struct insensitive_equal_to
	{
		bool operator()(const _Ty& left, const _Ty& right) const {
			return false;
		}
	};

	template<typename _Ty>
	struct insensitive_hash
	{
		size_t operator()(const _Ty& value) const
		{
			return 0;
		}
	};

	template<>
	struct insensitive_equal_to<string>
	{
		bool operator()(const string& left, const string& right) const {
			return _strcmpi(left.c_str(), right.c_str()) == 0;
		}
	};

	template<>
	struct insensitive_hash<string>
	{
		size_t operator()(const string& value) const
		{
			unsigned int hash = 1315423911;

			for (std::size_t i = 0; i < value.length(); i++)
			{
				hash ^= ((hash << 5) + std::toupper(value[i]) + (hash >> 2));
			}

			return (hash & 0x7FFFFFFF);
		}
	};

	template<>
	struct insensitive_equal_to<wstring>
	{
		bool operator()(const wstring& left, const wstring& right) const {
			return _wcsicmp(left.c_str(), right.c_str()) == 0;
		}
	};

	template<>
	struct insensitive_hash<wstring>
	{
		size_t operator()(const wstring& value) const
		{
			unsigned int hash = 1315423911;

			for (std::size_t i = 0; i < value.length(); i++)
			{
				hash ^= ((hash << 5) + std::towupper(value[i]) + (hash >> 2));
			}

			return (hash & 0x7FFFFFFF);
		}
	};

	template<class _Ty>
	using insensitive_unordered_set = unordered_set<_Ty, insensitive_hash<_Ty>, insensitive_equal_to<_Ty>>;

	template<class _Kty, typename _Ty>
	using insensitive_unordered_map = unordered_map<_Kty, _Ty, insensitive_hash<_Kty>, insensitive_equal_to<_Kty>>;
}