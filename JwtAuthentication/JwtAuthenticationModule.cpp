#include "jwt-cpp\jwt.h"
#include "JwtAuthenticationModule.h"
#include "JwtAuthenticationModuleFactory.h"
#include "JwtModuleConfiguration.h"

using jwt_t = jwt::decoded_jwt<jwt::picojson_traits>;

HRESULT GetHeaderJwtToken(IHttpRequest* httpRequest, JwtModuleConfiguration* pConfiguration, std::string& jwt)
{
	USHORT length;
	PCSTR headerValue;

	auto& path = pConfiguration->GetPath();
	if (path.empty())
	{
		headerValue = httpRequest->GetHeader(HttpHeaderAuthorization, &length);
	}
	else
	{
		headerValue = httpRequest->GetHeader(path.data(), &length);
	}

	if (!headerValue)
	{
		return S_FALSE;
	}

	if (_strnicmp(headerValue, "Bearer ", 7) == 0)
	{
		jwt = std::string(headerValue + 7, length - 7);
	}
	else
	{
		jwt = std::string(headerValue, length);
	}

	return S_OK;
}

HRESULT GetCookieJwtToken(IHttpRequest* httpRequest, JwtModuleConfiguration* pConfiguration, std::string& jwt)
{
	return S_OK;
}

HRESULT GetUrlJwtToken(IHttpRequest* httpRequest, const JwtModuleConfiguration* pConfiguration, std::string& jwt)
{
	auto rawRequest = httpRequest->GetRawHttpRequest();
	UNREFERENCED_PARAMETER(rawRequest);
	return S_OK;
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

REQUEST_NOTIFICATION_STATUS Error(_In_ IHttpContext* pHttpContext, HRESULT hr)
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

	UNREFERENCED_PARAMETER(pProvider);

	std::unique_ptr<JwtClaimsUser> user;
	HRESULT hr = CreateUser(pHttpContext, user);

	if (FAILED(hr))
	{
		return Error(pHttpContext, hr);
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
		return Error(pHttpContext, hr);
	}
	else if (hr == S_FALSE) {
		pHttpContext->GetResponse()->SetStatus(401, "Invalid JWT token");
		pHttpContext->SetRequestHandled();

		return RQ_NOTIFICATION_FINISH_REQUEST;
	}

	pProvider->SetUser(user.release());
	return RQ_NOTIFICATION_CONTINUE;
}