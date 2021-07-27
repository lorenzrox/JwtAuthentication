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