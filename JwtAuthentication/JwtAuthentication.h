#pragma once
#include <iostream>
#include <ws2tcpip.h> 
#include <Windows.h>
#include <httpserv.h>
#include <atlbase.h>

#define RETURN_IF_FAILED(result, expr) if(FAILED(result = expr)) {\
		return result; \
	}

enum class JwtValidationType {
	Header = 0,
	Cookie = 1,
	Url = 2
};

struct JWT_AUTHENTICATION_CONFIGURATION {
	bool enabled;
	JwtValidationType validationType;
	std::string key;
};

extern IHttpServer* g_pHttpServer;
extern JWT_AUTHENTICATION_CONFIGURATION g_configuration;