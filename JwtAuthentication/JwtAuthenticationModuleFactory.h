#pragma once
#include "JwtAuthentication.h"

class JwtAuthenticationModuleFactory : public IHttpModuleFactory
{
public:
	virtual HRESULT GetHttpModule(_Out_ CHttpModule** ppModule, _In_ IModuleAllocator* pAllocator);
	virtual void Terminate();
};