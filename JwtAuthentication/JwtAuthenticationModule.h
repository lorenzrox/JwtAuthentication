#pragma once
#include "JwtAuthentication.h"
#include "JwtClaimsUser.h"
#include "StringHelper.h"


class JwtModuleConfiguration;

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
	bool ValidateJwtTokenPolicies(JwtModuleConfiguration* pConfiguration, const std::string& userName, const std::insensitive_unordered_set<std::string>& roles);
	bool ValidateJwtTokenSignature(JwtModuleConfiguration* pConfiguration, const jwt_t& jwtToken);
	void WriteEventLog(EventLogType type, LPCSTR pMessage, HRESULT hr = S_OK);

	HANDLE m_eventLog;
};

