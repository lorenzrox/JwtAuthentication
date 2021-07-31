
#include "JwtAuthenticationModule.h"
#include "JwtAuthenticationModuleFactory.h"
#include "JwtModuleConfiguration.h"


std::string UrlDecode(PCWSTR pStart, PCWSTR pEnd)
{
	WCHAR a, b;
	size_t offset = 0;
	std::string result(MB_CUR_MAX * (pEnd - pStart), '\0');

	PCWSTR pCurrent = pStart;
	while (pCurrent < pEnd)
	{
		if (*pCurrent == L'%' && (pCurrent + 2 < pEnd) && (a = pCurrent[1]) && (b = pCurrent[2]) && isxdigit(a) && isxdigit(b))
		{
			if (a >= L'a')
			{
				a -= (L'a' - L'A');
			}

			if (a >= L'A')
			{
				a -= (L'A' - 10);
			}
			else
			{
				a -= L'0';
			}

			if (b >= L'a')
			{
				b -= (L'a' - L'A');
			}

			if (b >= L'A')
			{
				b -= (L'A' - 10);
			}
			else
			{
				b -= L'0';
			}

			int len;
			if (wctomb_s(&len, &result[offset], result.size(), 16 * a + b) == 0)
			{
				offset += len;
			}

			pCurrent += 3;
		}
		else if (*pCurrent == L'+')
		{
			result[offset++] = ' ';
			pCurrent++;
		}
		else
		{
			int len;
			if (wctomb_s(&len, &result[offset], result.size(), *pCurrent++) == 0)
			{
				offset += len;
			}
		}
	}

	result.resize(offset);
	return result;
}

std::string UrlDecode(PCSTR pStart, PCSTR pEnd)
{
	char a, b;
	size_t offset = 0;
	std::string result(pEnd - pStart, '\0');

	PCSTR pCurrent = pStart;
	while (pCurrent < pEnd)
	{
		if (*pCurrent == L'%' && (pCurrent + 2 < pEnd) && (a = pCurrent[1]) && (b = pCurrent[2]) && isxdigit(a) && isxdigit(b))
		{
			if (a >= L'a')
			{
				a -= (L'a' - L'A');
			}

			if (a >= L'A')
			{
				a -= (L'A' - 10);
			}
			else
			{
				a -= L'0';
			}

			if (b >= L'a')
			{
				b -= (L'a' - L'A');
			}

			if (b >= L'A')
			{
				b -= (L'A' - 10);
			}
			else
			{
				b -= L'0';
			}

			result[offset++] = 16 * a + b;
			pCurrent += 3;
		}
		else if (*pCurrent == L'+')
		{
			result[offset++] = ' ';
			pCurrent++;
		}
		else
		{
			result[offset++] = *pCurrent++;
		}
	}

	result.resize(offset);
	return result;
}

HRESULT GetHeaderJwtToken(IHttpRequest* httpRequest, JwtModuleConfiguration* pConfiguration, std::string& jwt)
{
	USHORT length;
	PCSTR pHeaderValue;

	auto& path = pConfiguration->GetPath();
	if (path.empty())
	{
		pHeaderValue = httpRequest->GetHeader(HttpHeaderAuthorization, &length);
	}
	else
	{
		pHeaderValue = httpRequest->GetHeader(path.data(), &length);
	}

	if (length == 0)
	{
		return S_FALSE;
	}

	if (_strnicmp(pHeaderValue, "Bearer ", 7) == 0)
	{
		jwt = std::string(pHeaderValue + 7, length - 7);
	}
	else
	{
		jwt = std::string(pHeaderValue, length);
	}

	return S_OK;
}

HRESULT GetCookieJwtToken(IHttpRequest* httpRequest, JwtModuleConfiguration* pConfiguration, std::string& jwt)
{
	USHORT length;
	PCSTR pCookie = httpRequest->GetHeader(HttpHeaderCookie, &length);
	if (length == 0)
	{
		return S_FALSE;
	}

	std::string  path = pConfiguration->GetPath();
	if (path.empty())
	{
		static const std::string& DefaultCookieName = "access_token";
		path = DefaultCookieName;
	}

	PCSTR pCookieEnd = pCookie + length;

	while (pCookie < pCookieEnd)
	{
		PCSTR pParamEnd = strchr(pCookie, ';');
		if (pParamEnd == NULL)
		{
			pParamEnd = pCookieEnd;
		}

		if (_strnicmp(path.data(), pCookie, path.size()) == 0)
		{
			pCookie += path.size();

			if (pCookie < pParamEnd && *pCookie == L'=')
			{
				jwt = UrlDecode(++pCookie, pParamEnd);
				return S_OK;
			}
		}

		pCookie = pParamEnd + 1;

		while (*pCookie == ' ')
		{
			pCookie++;
		}
	}

	return S_FALSE;
}

HRESULT GetUrlJwtToken(IHttpRequest* httpRequest, const JwtModuleConfiguration* pConfiguration, std::string& jwt)
{
	auto path = std::to_wstring(pConfiguration->GetPath());
	if (path.empty())
	{
		static const std::wstring& DefaultUrlParameter = L"access_token";
		path = DefaultUrlParameter;
	}

	auto rawRequest = httpRequest->GetRawHttpRequest();
	if (rawRequest->CookedUrl.pQueryString)
	{
		PCWSTR pParamStart = rawRequest->CookedUrl.pQueryString + 1;
		PCWSTR pQueryEnd = rawRequest->CookedUrl.pQueryString + rawRequest->CookedUrl.QueryStringLength / sizeof(WCHAR);

		while (pParamStart < pQueryEnd)
		{
			PCWSTR pParamEnd = wcschr(pParamStart, L'&');
			if (pParamEnd == NULL)
			{
				pParamEnd = pQueryEnd;
			}

			if (_wcsnicmp(path.data(), pParamStart, path.size()) == 0)
			{
				pParamStart += path.size();

				if (pParamStart < pParamEnd && *pParamStart == L'=')
				{
					jwt = UrlDecode(++pParamStart, pParamEnd);
					return S_OK;
				}
			}

			pParamStart = pParamEnd + 1;
		}
	}

	return S_FALSE;
}

bool CheckAlgorithm(const std::string& algorithm, JwtModuleConfiguration* pConfiguration)
{
	if (algorithm == "HS256") {
		return pConfiguration->GetAlgorithm() == JwtCryptoAlgorithm::HS256;
	}

	if (algorithm == "RS256") {
		return pConfiguration->GetAlgorithm() == JwtCryptoAlgorithm::RS256;
	}

	return false;
}

inline REQUEST_NOTIFICATION_STATUS Error(_In_ IHttpContext* pHttpContext, IHttpEventProvider* pProvider, HRESULT hr)
{
	pHttpContext->GetResponse()->SetStatus(500, "Server Error", 0, hr);
	pHttpContext->SetRequestHandled();

	return RQ_NOTIFICATION_FINISH_REQUEST;
}

inline void GetJwtTokenRoles(JwtModuleConfiguration* pConfiguration, const jwt_t& jwtToken, std::insensitive_unordered_set<std::string>& roles)
{
	auto& roleGrant = pConfiguration->GetRoleGrant();
	if (!roleGrant.empty() && jwtToken.has_payload_claim(roleGrant))
	{
		auto claim = jwtToken.get_payload_claim(roleGrant);
		if (claim.get_type() == jwt::json::type::array)
		{
			for (const auto& value : claim.as_array())
			{
				if (value.is<std::string>())
				{
					roles.insert(value.get<std::string>());
				}
			}
		}
		else
		{
			roles.insert(claim.as_string());
		}
	}
}

inline void GetJwtTokenUser(JwtModuleConfiguration* pConfiguration, const jwt_t& jwtToken, std::string& userName)
{
	auto& nameGrant = pConfiguration->GetNameGrant();
	if (!nameGrant.empty() && jwtToken.has_payload_claim(nameGrant))
	{
		userName = jwtToken.get_payload_claim(nameGrant).as_string();
	}
}


JwtAuthenticationModule::JwtAuthenticationModule() :
	m_eventLog(NULL)
{
}

JwtAuthenticationModule::~JwtAuthenticationModule()
{
	if (m_eventLog != NULL)
	{
		DeregisterEventSource(m_eventLog);
		m_eventLog = NULL;
	}
}

HRESULT JwtAuthenticationModule::Initialize()
{
	if ((m_eventLog = RegisterEventSource(NULL, L"IIS_JWT_AUTH")) == NULL)
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	return S_OK;
}

bool JwtAuthenticationModule::ValidateTokenSignature(JwtModuleConfiguration* pConfiguration, const jwt_t& jwtToken)
{
	if (jwtToken.has_expires_at())
	{
		//Check token expiration
		auto expiration = jwtToken.get_expires_at();
		if (expiration < std::chrono::system_clock::now())
		{
			WriteEventLog(EventLogType::Warning, "JWT token expired");
			return false;
		}
	}

	auto& key = pConfiguration->GetKey();
	if (!jwtToken.has_algorithm())
	{
		return key.empty();
	}

	if (key.empty())
	{
		return true;
	}

	const auto& algoritm = jwtToken.get_algorithm();
	if (!CheckAlgorithm(algoritm, pConfiguration))
	{
		WriteEventLog(EventLogType::Warning, "JWT token signature algorithm not supported");
		return false;
	}

	std::error_code error;

	switch (pConfiguration->GetAlgorithm())
	{
	case JwtCryptoAlgorithm::RS256:
		jwt::verify().allow_algorithm(jwt::crypto::algorithm::rs256(key)).verify(jwtToken, error);
		break;
	default:
		jwt::verify().allow_algorithm(jwt::crypto::algorithm::hs256(key)).verify(jwtToken, error);
		break;
	}

	if (error)
	{
		WriteEventLog(EventLogType::Warning, "JWT token signature verification failed");
		return false;
	}

	return true;
}

bool JwtAuthenticationModule::ValidateTokenPolicies(JwtModuleConfiguration* pConfiguration, const std::string& userName, const std::insensitive_unordered_set<std::string>& roles)
{
	auto& policies = pConfiguration->GetPolicies();
	if (policies.empty())
	{
		return true;
	}

	HRESULT hr;
	bool result;
	for (auto& policy : policies)
	{
		RETURN_IF_FAILED(hr, policy->Check(userName, roles, &result));

		if (result)
		{
			return true;
		}
	}

	WriteEventLog(EventLogType::Warning, "No authorization policy matched");
	return false;
}

void JwtAuthenticationModule::WriteEventLog(EventLogType type, LPCSTR pMessage, HRESULT hr)
{
	if (SUCCEEDED(hr))
	{
		::ReportEventA(m_eventLog, static_cast<WORD>(type), 0, 1, NULL, 1, 0, &pMessage, NULL);
	}
	else
	{
		CHAR buffer[4096] = "";
		LPCSTR strings[2] = { pMessage, buffer };

		::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), buffer, _countof(buffer), nullptr);
		::ReportEventA(m_eventLog, static_cast<WORD>(type), 0, 0, NULL, 2, sizeof(hr), strings, &hr);
	}
}

HRESULT JwtAuthenticationModule::MapGrantHeaders(JwtModuleConfiguration* pConfiguration, IHttpRequest* pHttpRequest, const jwt_t& jwtToken)
{
	HRESULT hr;

	for (auto& entry : pConfiguration->GetGrantMappings())
	{
		if (jwtToken.has_payload_claim(entry.first))
		{
			auto grantValue = jwtToken.get_payload_claim(entry.first).as_string();
			RETURN_IF_FAILED(hr, pHttpRequest->SetHeader(entry.second.Header.data(),
				grantValue.data(), grantValue.size(), entry.second.Replace));
		}
	}

	return S_OK;
}

HRESULT JwtAuthenticationModule::HandleRequest(_In_ IHttpContext* pHttpContext)
{
	HRESULT hr;
	JwtModuleConfiguration* pConfiguration;
	RETURN_IF_FAILED(hr, JwtModuleConfiguration::EnsureConfiguration(pHttpContext->GetApplication(), &pConfiguration));

	if (!pConfiguration->IsEnabled())
	{
		return S_OK;
	}

	IHttpRequest* httpRequest = pHttpContext->GetRequest();
	if (_strnicmp("OPTIONS", httpRequest->GetHttpMethod(), 8) == 0)
	{
		WriteEventLog(EventLogType::Information, "Skipped authentication for OPTIONS request");
		return S_OK;
	}

	std::string jwt;
	switch (pConfiguration->GetValidationType())
	{
	case JwtValidationType::Cookie:
		RETURN_IF_FAILED(hr, GetCookieJwtToken(httpRequest, pConfiguration, jwt));
		break;
	case JwtValidationType::Url:
		RETURN_IF_FAILED(hr, GetUrlJwtToken(httpRequest, pConfiguration, jwt));
		break;
	default:
		RETURN_IF_FAILED(hr, GetHeaderJwtToken(httpRequest, pConfiguration, jwt));
		break;
	}

	if (jwt.empty())
	{
		WriteEventLog(EventLogType::Warning, "JWT token not found");
	}
	else
	{
		try
		{
			auto jwtToken = jwt::decode(jwt);
			if (!ValidateTokenSignature(pConfiguration, jwtToken))
			{
				return S_FALSE;
			}

			std::string userName;
			GetJwtTokenUser(pConfiguration, jwtToken, userName);

			std::insensitive_unordered_set<std::string> roles;
			GetJwtTokenRoles(pConfiguration, jwtToken, roles);

			if (!ValidateTokenPolicies(pConfiguration, userName, roles))
			{
				return S_FALSE;
			}

			RETURN_IF_FAILED(hr, MapGrantHeaders(pConfiguration, httpRequest, jwtToken));

			return S_OK;
		}
		catch (const std::exception& ex)
		{
			WriteEventLog(EventLogType::Error, ex.what());
			return E_FAIL;
		}
	}

	return S_FALSE;
}

HRESULT JwtAuthenticationModule::AuthenticateUser(_In_ IHttpContext* pHttpContext, IAuthenticationProvider* pProvider)
{
	HRESULT hr;
	JwtModuleConfiguration* pConfiguration;
	RETURN_IF_FAILED(hr, JwtModuleConfiguration::EnsureConfiguration(pHttpContext->GetApplication(), &pConfiguration));

	if (!pConfiguration->IsEnabled())
	{
		return S_OK;
	}

	IHttpRequest* httpRequest = pHttpContext->GetRequest();
	if (_strnicmp("OPTIONS", httpRequest->GetHttpMethod(), 8) == 0)
	{
		WriteEventLog(EventLogType::Information, "Skipped authentication for OPTIONS request");
		return S_OK;
	}

	std::string jwt;
	switch (pConfiguration->GetValidationType())
	{
	case JwtValidationType::Cookie:
		RETURN_IF_FAILED(hr, GetCookieJwtToken(httpRequest, pConfiguration, jwt));
		break;
	case JwtValidationType::Url:
		RETURN_IF_FAILED(hr, GetUrlJwtToken(httpRequest, pConfiguration, jwt));
		break;
	default:
		RETURN_IF_FAILED(hr, GetHeaderJwtToken(httpRequest, pConfiguration, jwt));
		break;
	}

	if (jwt.empty())
	{
		WriteEventLog(EventLogType::Warning, "JWT token not found");
	}
	else
	{
		try
		{
			auto jwtToken = jwt::decode(jwt);
			if (!ValidateTokenSignature(pConfiguration, jwtToken))
			{
				return S_FALSE;
			}

			std::set<std::wstring> roles;
			std::wstring userName;

			auto& nameGrant = pConfiguration->GetNameGrant();
			if (!nameGrant.empty() && jwtToken.has_payload_claim(nameGrant))
			{
				userName = std::to_wstring(jwtToken.get_payload_claim(nameGrant).as_string());
			}

			auto& roleGrant = pConfiguration->GetRoleGrant();
			if (!roleGrant.empty() && jwtToken.has_payload_claim(roleGrant))
			{
				auto claim = jwtToken.get_payload_claim(roleGrant);
				if (claim.get_type() == jwt::json::type::array)
				{
					for (const auto& value : claim.as_array())
					{
						roles.insert(std::to_wstring(value.get<std::string>()));
					}
				}
				else
				{
					roles.insert(std::to_wstring(claim.as_string()));
				}
			}

			auto user = std::make_unique<JwtClaimsUser>(std::move(userName), std::move(roles));
			if (user == NULL)
			{
				return E_OUTOFMEMORY;
			}

			RETURN_IF_FAILED(hr, MapGrantHeaders(pConfiguration, httpRequest, jwtToken));

			pProvider->SetUser(user.release());
			return S_OK;
		}
		catch (const std::exception& ex)
		{
			WriteEventLog(EventLogType::Error, ex.what());
			return E_FAIL;
		}
	}

	return S_FALSE;
}

HRESULT JwtAuthenticationModule::AuthorizeUser(_In_ IHttpContext* pHttpContext)
{
	HRESULT hr;
	JwtModuleConfiguration* pConfiguration;
	RETURN_IF_FAILED(hr, JwtModuleConfiguration::EnsureConfiguration(pHttpContext->GetApplication(), &pConfiguration));

	if (!pConfiguration->IsEnabled())
	{
		return S_OK;
	}

	IHttpRequest* httpRequest = pHttpContext->GetRequest();
	if (_strnicmp("OPTIONS", httpRequest->GetHttpMethod(), 8) == 0)
	{
		WriteEventLog(EventLogType::Information, "Skipped authrization for OPTIONS request");
		return S_OK;
	}

	auto& policies = pConfiguration->GetPolicies();
	if (policies.empty())
	{
		return S_OK;
	}

	bool result;
	for (auto& policy : policies)
	{
		RETURN_IF_FAILED(hr, policy->Check(pHttpContext, &result));

		if (result)
		{
			return S_OK;
		}
	}

	WriteEventLog(EventLogType::Warning, "No authorization policy matched");
	return S_FALSE;
}

REQUEST_NOTIFICATION_STATUS JwtAuthenticationModule::OnBeginRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	HRESULT hr = HandleRequest(pHttpContext);
	if (FAILED(hr))
	{
		WriteEventLog(EventLogType::Error, "An error occurred handling the request", hr);

		return Error(pHttpContext, pProvider, hr);
	}
	else if (hr == S_FALSE)
	{
		pHttpContext->GetResponse()->SetStatus(401, "Invalid JWT token");
		pHttpContext->SetRequestHandled();

		return RQ_NOTIFICATION_FINISH_REQUEST;
	}

	return RQ_NOTIFICATION_CONTINUE;
}

REQUEST_NOTIFICATION_STATUS JwtAuthenticationModule::OnAuthenticateRequest(_In_ IHttpContext* pHttpContext, _In_ IAuthenticationProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	HRESULT hr = AuthenticateUser(pHttpContext, pProvider);
	if (FAILED(hr))
	{
		WriteEventLog(EventLogType::Error, "An error occurred handling the request", hr);

		return Error(pHttpContext, pProvider, hr);
	}
	else if (hr == S_FALSE) {
		pHttpContext->GetResponse()->SetStatus(401, "Invalid JWT token");
		pHttpContext->SetRequestHandled();

		return RQ_NOTIFICATION_FINISH_REQUEST;
	}


	return RQ_NOTIFICATION_CONTINUE;
}

REQUEST_NOTIFICATION_STATUS JwtAuthenticationModule::OnAuthorizeRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	HRESULT hr = AuthorizeUser(pHttpContext);
	if (FAILED(hr))
	{
		WriteEventLog(EventLogType::Error, "An error occurred handling the request", hr);

		return Error(pHttpContext, pProvider, hr);
	}
	else if (hr == S_FALSE) {
		pHttpContext->GetResponse()->SetStatus(401, "Unauthorized");
		pHttpContext->SetRequestHandled();

		return RQ_NOTIFICATION_FINISH_REQUEST;
	}

	return RQ_NOTIFICATION_CONTINUE;
}