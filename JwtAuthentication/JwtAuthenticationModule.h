#pragma once
#include "JwtAuthentication.h"
#include "JwtClaimsUser.h"

class JwtAuthenticationModule : public CHttpModule
{
public:
	JwtAuthenticationModule();
	~JwtAuthenticationModule();

	HRESULT Initialize();

	virtual REQUEST_NOTIFICATION_STATUS OnBeginRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider);
	virtual REQUEST_NOTIFICATION_STATUS OnAuthenticateRequest(_In_ IHttpContext* pHttpContext, _In_ IAuthenticationProvider* pProvider);

private:
	HRESULT CreateUser(_In_ IHttpContext* pHttpContext, _Out_ std::unique_ptr<JwtClaimsUser>& result);

	HANDLE m_eventLog;
};

