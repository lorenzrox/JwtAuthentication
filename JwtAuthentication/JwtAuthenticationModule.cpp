#include "jwt-cpp/jwt-cpp/jwt.h"
#include "JwtAuthenticationModule.h"
#include "JwtAuthenticationModuleFactory.h"

using jwt_t = jwt::decoded_jwt<jwt::picojson_traits>;

HRESULT GetConfiguration(_In_ IHttpContext* pHttpContext, _Out_ JWT_AUTHENTICATION_CONFIGURATION* pConfig) {
	HRESULT hr;
	CComPtr<IAppHostElement> configurationElement;
	CComPtr<IAppHostProperty> configurationProperty;

	RETURN_IF_FAILED(hr, g_pHttpServer->GetAdminManager()->GetAdminSection(CComBSTR(L"system.webServer/security/authentication/jwtAuthentication"),
		CComBSTR(pHttpContext->GetApplication()->GetAppConfigPath()), &configurationElement));

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"enabled"), &configurationProperty));
	if (configurationProperty) {
		VARIANT enabled;
		VariantInit(&enabled);

		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&enabled));

		pConfig->enabled = enabled.boolVal;

		RETURN_IF_FAILED(hr, VariantClear(&enabled));
	}
	else {
		pConfig->enabled = false;
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"validationType"), &configurationProperty));

	if (configurationProperty) {
		VARIANT validationType;
		VariantInit(&validationType);

		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&validationType));

		pConfig->validationType = static_cast<JwtValidationType>(validationType.intVal);

		RETURN_IF_FAILED(hr, VariantClear(&validationType));
	}
	else {
		pConfig->validationType = JwtValidationType::Header;
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"path"), &configurationProperty));

	if (configurationProperty) {
		VARIANT path;
		VariantInit(&path);

		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&path));

		if (path.bstrVal) {
			pConfig->path = CW2A(path.bstrVal);
		}
		else {
			pConfig->path.clear();
		}

		RETURN_IF_FAILED(hr, VariantClear(&path));
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"algorithm"), &configurationProperty));

	if (configurationProperty) {
		VARIANT algorithm;
		VariantInit(&algorithm);

		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&algorithm));

		pConfig->algorithm = static_cast<JwtCryptoAlgorithm>(algorithm.intVal);

		RETURN_IF_FAILED(hr, VariantClear(&algorithm));
	}

	return S_OK;
}

HRESULT GetHeaderJwtToken(IHttpRequest* httpRequest, const JWT_AUTHENTICATION_CONFIGURATION* pConfiguration, std::string& jwt) {
	USHORT length;

	PCSTR headerValue;
	if (pConfiguration->path.empty()) {
		headerValue = httpRequest->GetHeader(HttpHeaderAuthorization, &length);
	}
	else {
		headerValue = httpRequest->GetHeader(pConfiguration->path.data(), &length);
	}

	if (!headerValue) {
		return S_FALSE;
	}

	if (_strnicmp(headerValue, "Bearer ", 7) == 0) {
		jwt = std::string(headerValue + 7, length - 7);
	}
	else {
		jwt = std::string(headerValue, length);
	}

	return S_OK;
}

HRESULT GetCookieJwtToken(IHttpRequest* httpRequest, const JWT_AUTHENTICATION_CONFIGURATION* pConfiguration, std::string& jwt) {
	return S_OK;
}

HRESULT GetUrlJwtToken(IHttpRequest* httpRequest, const JWT_AUTHENTICATION_CONFIGURATION* pConfiguration, std::string& jwt) {
	auto rawRequest = httpRequest->GetRawHttpRequest();
	UNREFERENCED_PARAMETER(rawRequest);
	return S_OK;
}

bool VerifyJwtToken(const JWT_AUTHENTICATION_CONFIGURATION* pConfiguration, const jwt_t& jwtToken) {
	if (pConfiguration->key.empty()) {
		return true;
	}

	std::error_code error;

	switch (pConfiguration->algorithm)
	{
	case JwtCryptoAlgorithm::RS256:
		jwt::verify().allow_algorithm(jwt::algorithm::rs256(pConfiguration->key)).verify(jwtToken, error);
		break;
	default:
		jwt::verify().allow_algorithm(jwt::algorithm::hs256(pConfiguration->key)).verify(jwtToken, error);
		break;
	}

	return static_cast<bool>(error);
}

REQUEST_NOTIFICATION_STATUS Error(IHttpResponse* httpResponse, HRESULT hr) {
	httpResponse->SetStatus(500, "Server Error", 0, hr);
	return RQ_NOTIFICATION_FINISH_REQUEST;
}

REQUEST_NOTIFICATION_STATUS JwtAuthenticationModule::OnBeginRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider)
{
	__debugbreak();

	UNREFERENCED_PARAMETER(pProvider);

	HRESULT hr;
	std::string jwt;
	IHttpRequest* httpRequest;
	JWT_AUTHENTICATION_CONFIGURATION configuration = {};
	IHttpResponse* httpResponse = pHttpContext->GetResponse();

	if (!httpResponse) {
		return RQ_NOTIFICATION_CONTINUE;
	}

	if (FAILED(hr = GetConfiguration(pHttpContext, &configuration))) {
		return Error(httpResponse, hr);
	}

	if (!configuration.enabled) {
		return RQ_NOTIFICATION_CONTINUE;
	}

	httpRequest = pHttpContext->GetRequest();

	switch (configuration.validationType)
	{
	case JwtValidationType::Cookie:
		if (FAILED(hr = GetCookieJwtToken(httpRequest, &configuration, jwt))) {
			return Error(httpResponse, hr);
		}
		break;
	case JwtValidationType::Url:
		if (FAILED(hr = GetUrlJwtToken(httpRequest, &configuration, jwt))) {
			return Error(httpResponse, hr);
		}
		break;
	default:
		if (FAILED(hr = GetHeaderJwtToken(httpRequest, &configuration, jwt))) {
			return Error(httpResponse, hr);
		}
		break;
	}

	if (!jwt.empty()) {
		auto jwtToken = jwt::decode(jwt);
		if (VerifyJwtToken(&configuration, jwtToken)) {
			return RQ_NOTIFICATION_CONTINUE;
		}
	}

	httpResponse->SetStatus(401, "Invalid JWT token");
	return RQ_NOTIFICATION_FINISH_REQUEST;
}