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
	virtual REQUEST_NOTIFICATION_STATUS OnAuthorizeRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider);

private:
	HRESULT HandleRequest(_In_ IHttpContext* pHttpContext);
	HRESULT AuthenticateUser(_In_ IHttpContext* pHttpContext, IAuthenticationProvider* pProvider);
	HRESULT AuthorizeUser(_In_ IHttpContext* pHttpContext);
	HRESULT MapGrantHeaders(JwtModuleConfiguration* pConfiguration, IHttpRequest* pHttpRequest, const jwt_t& jwtToken);
	bool ValidateTokenPolicies(JwtModuleConfiguration* pConfiguration, const std::string& userName, const std::insensitive_unordered_set<std::string>& roles);
	bool ValidateTokenSignature(JwtModuleConfiguration* pConfiguration, const jwt_t& jwtToken);
	void WriteEventLog(EventLogType type, LPCSTR pMessage, HRESULT hr = S_OK);

	HANDLE m_eventLog;
};

