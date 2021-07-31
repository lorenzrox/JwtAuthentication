#pragma once
#include "jwt-cpp\jwt.h"
#include <httpserv.h>
#include <iostream>
#include <ws2tcpip.h> 
#include <Windows.h>
#include <atlbase.h>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>


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

enum class JwtAuthenticationAccessType
{
	Allow = 0,
	Deny = 1
};

enum class EventLogType : WORD
{
	Success = EVENTLOG_SUCCESS,
	Error = EVENTLOG_ERROR_TYPE,
	Warning = EVENTLOG_WARNING_TYPE,
	Information = EVENTLOG_INFORMATION_TYPE
};

using jwt_t = jwt::decoded_jwt<jwt::picojson_traits>;

extern IHttpServer* g_pHttpServer;
extern HTTP_MODULE_ID g_pModuleId;