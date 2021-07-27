#include "jwt-cpp\jwt.h"
#include "JwtAuthenticationModule.h"
#include "JwtAuthenticationModuleFactory.h"
#include "JwtModuleConfiguration.h"
#include "StringHelper.h"

using jwt_t = jwt::decoded_jwt<jwt::picojson_traits>;

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

bool ValidateJwtToken(JwtModuleConfiguration* pConfiguration, const jwt_t& jwtToken)
{
	if (jwtToken.has_expires_at())
	{
		//Check token expiration
		auto expiration = jwtToken.get_expires_at();
		if (expiration < std::chrono::system_clock::now())
		{
			return false;
		}
	}

	if (!jwtToken.has_algorithm())
	{
		return true;
	}

	auto& key = pConfiguration->GetKey();
	if (key.empty())
	{
		return true;
	}

	if (!CheckAlgorithm(jwtToken.get_algorithm(), pConfiguration))
	{
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

	return static_cast<bool>(error);
}

inline REQUEST_NOTIFICATION_STATUS Error(_In_ IHttpContext* pHttpContext, IHttpEventProvider* pProvider, HRESULT hr)
{
	pHttpContext->GetResponse()->SetStatus(500, "Server Error", 0, hr);
	pHttpContext->SetRequestHandled();

	return RQ_NOTIFICATION_FINISH_REQUEST;
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
	if ((m_eventLog = RegisterEventSource(NULL, L"JWT_AUTH")) == NULL)
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	return S_OK;
}

HRESULT JwtAuthenticationModule::CreateUser(_In_ IHttpContext* pHttpContext, _Out_ std::unique_ptr<JwtClaimsUser>& result)
{
	HRESULT hr;
	JwtModuleConfiguration* pConfiguration;

	RETURN_IF_FAILED(hr, JwtModuleConfiguration::EnsureConfiguration(pHttpContext->GetApplication(), &pConfiguration));

	if (!pConfiguration->IsEnabled())
	{
		return S_OK;
	}

	std::string jwt;
	IHttpRequest* httpRequest = pHttpContext->GetRequest();

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

	if (!jwt.empty())
	{
		try
		{
			auto jwtToken = jwt::decode(jwt);
			if (ValidateJwtToken(pConfiguration, jwtToken))
			{
				std::set<std::string, std::insensitive_compare<std::string>> roles;
				std::string userName;

				auto& nameGrant = pConfiguration->GetNameGrant();
				if (!nameGrant.empty() && jwtToken.has_payload_claim(nameGrant))
				{
					userName = jwtToken.get_payload_claim(nameGrant).as_string();
				}

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

				//Check for required roles
				for (auto& role : pConfiguration->GetRequiredRoles())
				{
					if (roles.find(role) == roles.end())
					{
						return S_FALSE;
					}
				}

				if (!userName.empty())
				{
					RETURN_IF_FAILED(hr, pHttpContext->GetResponse()->SetHeader("X-USERID", userName.data(), userName.size(), TRUE));
				}

				/*std::set<std::wstring> roles;
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

				/*if ((result = std::make_unique<JwtClaimsUser>(std::move(userName), std::move(roles))) == NULL)
				{
					return E_OUTOFMEMORY;
				}*/

				return S_OK;
			}
		}
		catch (const std::exception& ex)
		{
			return E_FAIL;
		}
	}

	return S_FALSE;
}

REQUEST_NOTIFICATION_STATUS JwtAuthenticationModule::OnBeginRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	std::unique_ptr<JwtClaimsUser> user;
	HRESULT hr = CreateUser(pHttpContext, user);

	if (FAILED(hr))
	{
		return Error(pHttpContext, pProvider, hr);
	}
	else if (hr == S_FALSE) {
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

	std::unique_ptr<JwtClaimsUser> user;
	HRESULT hr = CreateUser(pHttpContext, user);

	if (FAILED(hr))
	{
		return Error(pHttpContext, pProvider, hr);
	}
	else if (hr == S_FALSE) {
		pHttpContext->GetResponse()->SetStatus(401, "Invalid JWT token");
		pHttpContext->SetRequestHandled();

		return RQ_NOTIFICATION_FINISH_REQUEST;
	}

	pProvider->SetUser(user.release());
	return RQ_NOTIFICATION_CONTINUE;
}