#include "JwtModuleConfiguration.h"
#include <wrl\wrappers\corewrappers.h>
#include <Shlwapi.h>
#include <pathcch.h>


bool SubstringTrim(const std::string& value, size_t startIndex, size_t endIndex, std::string& result)
{
	while (startIndex < endIndex)
	{
		if (std::isspace(value[endIndex]))
		{
			endIndex--;
		}
		else
		{
			result = value.substr(startIndex, endIndex - startIndex + 1);
			return true;
		}
	}

	return false;
}

template<class _Hasher, class _Keyeq>
void ParsePolicyDefinition(const std::string& value, std::unordered_set<std::string, _Hasher, _Keyeq>& values)
{
	size_t endIndex;
	size_t startIndex = 0;
	std::string token;

	if (value.empty())
	{
		return;
	}

	while ((endIndex = value.find(',', startIndex)) != std::string::npos)
	{
		if (SubstringTrim(value, startIndex, endIndex - 1, token))
		{
			values.emplace(std::move(value));
		}

		startIndex = endIndex + 1;
	}

	if (SubstringTrim(value, startIndex, value.size() - 1, token))
	{
		values.emplace(std::move(value));
	}
}

HRESULT ReadKeyFile(IAppHostElement* pConfigurationElement, const std::wstring& phyiscalPath, std::string& result)
{
	if (phyiscalPath.size() >= MAX_PATH)
	{
		return E_INVALIDARG;
	}

	HRESULT hr;
	CComPtr<IAppHostProperty> configurationProperty;
	if (FAILED(hr = pConfigurationElement->GetPropertyByName(CComBSTR(L"keySource"), &configurationProperty)))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_INDEX))
		{
			return S_FALSE;
		}

		return hr;
	}

	if (configurationProperty == NULL)
	{
		return S_FALSE;
	}

	CComVariant keySource;
	RETURN_IF_FAILED(hr, configurationProperty->get_Value(&keySource));

	UINT keyFileNameLen = SysStringLen(keySource.bstrVal);
	if (keyFileNameLen == 0)
	{
		return S_FALSE;
	}

	WCHAR keyFileName[MAX_PATH];
	if (PathIsRelative(keySource.bstrVal))
	{
		CopyMemory(keyFileName, phyiscalPath.data(), (phyiscalPath.size() + 1) * sizeof(WCHAR));
		RETURN_IF_FAILED(hr, PathCchCombine(keyFileName, MAX_PATH, keyFileName, keySource.bstrVal));
	}
	else
	{
		CopyMemory(keyFileName, keySource.bstrVal, (keyFileNameLen + 1) * sizeof(WCHAR));
	}

	Microsoft::WRL::Wrappers::FileHandle keyFile(CreateFile(keyFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	if (!keyFile.IsValid())
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	LARGE_INTEGER size;
	if (!GetFileSizeEx(keyFile.Get(), &size)) 
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	std::string buffer(size.QuadPart, '\0');
	if (!ReadFile(keyFile.Get(), reinterpret_cast<BYTE*>(&buffer[0]), size.QuadPart, NULL, NULL))
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	result = std::move(buffer);
	return S_OK;
}

template <typename _Ty>
HRESULT ReadInt(IAppHostElement* pConfigurationElement, const CComBSTR& pKey, _Ty& result)
{
	HRESULT hr;
	CComPtr<IAppHostProperty> configurationProperty;
	if (FAILED(hr = pConfigurationElement->GetPropertyByName(pKey, &configurationProperty)))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_INDEX))
		{
			return S_FALSE;
		}

		return hr;
	}

	if (configurationProperty)
	{
		CComVariant value;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&value));

		result = static_cast<_Ty>(value.intVal);
		return S_OK;
	}

	return S_FALSE;
}

HRESULT ReadBoolean(IAppHostElement* pConfigurationElement, const CComBSTR& pKey, bool& result)
{
	HRESULT hr;
	CComPtr<IAppHostProperty> configurationProperty;
	if (FAILED(hr = pConfigurationElement->GetPropertyByName(pKey, &configurationProperty)))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_INDEX))
		{
			return S_FALSE;
		}

		return hr;
	}

	if (configurationProperty)
	{
		CComVariant value;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&value));

		result = value.boolVal != FALSE;
		return S_OK;
	}

	return S_FALSE;
}

HRESULT ReadString(IAppHostElement* pConfigurationElement, const CComBSTR& pKey, std::string& result)
{
	HRESULT hr;
	CComPtr<IAppHostProperty> configurationProperty;
	if (FAILED(hr = pConfigurationElement->GetPropertyByName(pKey, &configurationProperty)))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_INDEX))
		{
			return S_FALSE;
		}

		return hr;
	}

	if (configurationProperty)
	{
		CComVariant value;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&value));

		UINT len = SysStringLen(value.bstrVal);
		if (len) {
			result = std::to_string(value.bstrVal, len);
			return S_OK;
		}
	}

	return S_FALSE;
}

HRESULT ReadPolicies(IAppHostElementCollection* pPoliciesCollection, std::vector<std::unique_ptr<JwtAuthorizationPolicy>>& policies)
{
	HRESULT hr;
	DWORD policyCount;
	RETURN_IF_FAILED(hr, pPoliciesCollection->get_Count(&policyCount));

	VARIANT vtIndex = { VT_INT , 0 };
	CComBSTR accessTypeProperty = L"accessType";
	CComBSTR usersProperty = L"users";
	CComBSTR rolesProperty = L"roles";
	CComBSTR verbsProperty = L"verbs";
	CComPtr<IAppHostElement> policyElement;

	std::insensitive_unordered_set<std::string> users;
	std::insensitive_unordered_set<std::string> roles;
	std::unordered_set<std::string> verbs;

	while (vtIndex.intVal < policyCount)
	{
		RETURN_IF_FAILED(hr, pPoliciesCollection->get_Item(vtIndex, &policyElement));
		vtIndex.intVal++;

		JwtAuthenticationAccessType accessType = JwtAuthenticationAccessType::Allow;
		RETURN_IF_FAILED(hr, ReadInt(policyElement, accessTypeProperty, accessType));

		std::string usersValue;
		RETURN_IF_FAILED(hr, ReadString(policyElement, usersProperty, usersValue));

		std::string rolesValue;
		RETURN_IF_FAILED(hr, ReadString(policyElement, rolesProperty, rolesValue));

		std::string verbsValue;
		RETURN_IF_FAILED(hr, ReadString(policyElement, verbsProperty, verbsValue));

		ParsePolicyDefinition(usersValue, users);
		ParsePolicyDefinition(rolesValue, roles);
		ParsePolicyDefinition(verbsValue, verbs);

		if (users.empty() && roles.empty() && verbs.empty())
		{
			continue;
		}

		if (accessType == JwtAuthenticationAccessType::Deny)
		{
			//TODO:
		}
		else
		{
			policies.emplace_back(std::make_unique<JwtAuthorizationAllowPolicy>(std::move(users), std::move(roles), std::move(verbs)));
		}
	}

	return S_OK;
}

HRESULT ReadPolicies(IAppHostElement* pConfigurationElement, std::vector<std::unique_ptr<JwtAuthorizationPolicy>>& policies)
{
	HRESULT hr;
	CComPtr<IAppHostElement> policiesElement;
	if (FAILED(hr = pConfigurationElement->GetElementByName(CComBSTR(L"policies"), &policiesElement)))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_INDEX))
		{
			return S_FALSE;
		}

		return hr;
	}

	if (policiesElement)
	{
		CComPtr<IAppHostElementCollection> policiesCollection;
		RETURN_IF_FAILED(hr, policiesElement->get_Collection(&policiesCollection));

		if (policiesCollection)
		{
			RETURN_IF_FAILED(hr, ReadPolicies(policiesCollection, policies));
		}
	}

	return S_FALSE;
}

HRESULT ReadPolicies(IAppHostAdminManager* pAdminManager, const CComBSTR& configurationPath, std::vector<std::unique_ptr<JwtAuthorizationPolicy>>& policies)
{
	HRESULT hr;
	CComPtr<IAppHostElement> authorizationConfigurationElement;
	RETURN_IF_FAILED(hr, pAdminManager->GetAdminSection(CComBSTR(L"system.webServer/security/authorization"), configurationPath, &authorizationConfigurationElement));

	if (authorizationConfigurationElement)
	{
		CComPtr<IAppHostElementCollection> policiesCollection;
		RETURN_IF_FAILED(hr, authorizationConfigurationElement->get_Collection(&policiesCollection));

		if (policiesCollection)
		{
			RETURN_IF_FAILED(hr, ReadPolicies(policiesCollection, policies));
		}
	}

	return S_FALSE;
}

HRESULT ReadGrantHeaderMappings(IAppHostElement* pConfigurationElement, std::insensitive_unordered_map<std::string, const JwtGrantMapping>& mappings)
{
	HRESULT hr;
	CComPtr<IAppHostElement> grantMappingsElement;
	if (FAILED(hr = pConfigurationElement->GetElementByName(CComBSTR(L"grantHeaderMappings"), &grantMappingsElement)))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_INDEX))
		{
			return S_FALSE;
		}

		return hr;
	}

	if (grantMappingsElement)
	{
		CComPtr<IAppHostElementCollection> grantMappingsCollection;
		RETURN_IF_FAILED(hr, grantMappingsElement->get_Collection(&grantMappingsCollection));

		if (grantMappingsCollection)
		{
			DWORD grantMappingCount;
			RETURN_IF_FAILED(hr, grantMappingsCollection->get_Count(&grantMappingCount));

			VARIANT vtIndex = { VT_INT , 0 };
			CComBSTR grantProperty = L"grant";
			CComBSTR headerProperty = L"header";
			CComBSTR replaceProperty = L"replace";
			CComPtr<IAppHostElement> mappingElement;

			while (vtIndex.intVal < grantMappingCount)
			{
				RETURN_IF_FAILED(hr, grantMappingsCollection->get_Item(vtIndex, &mappingElement));
				vtIndex.intVal++;

				std::string grant;
				RETURN_IF_FAILED(hr, ReadString(mappingElement, grantProperty, grant));

				if (grant.empty())
				{
					continue;
				}

				std::string header;
				RETURN_IF_FAILED(hr, ReadString(mappingElement, headerProperty, header));

				if (header.empty())
				{
					continue;
				}

				bool replace = true;
				RETURN_IF_FAILED(hr, ReadBoolean(mappingElement, replaceProperty, replace));

				mappings.emplace(std::move(grant), JwtGrantMapping({ std::move(header), replace }));
			}

			return S_OK;
		}
	}

	return S_FALSE;
}


JwtModuleConfiguration::JwtModuleConfiguration(std::wstring&& phyiscalPath, std::wstring&& configurationPath) :
	m_refCount(1),
	m_phyiscalPath(phyiscalPath),
	m_configurationPath(configurationPath)
{
}

void JwtModuleConfiguration::ReferenceConfiguration() noexcept
{
	InterlockedIncrement(&m_refCount);
}

void JwtModuleConfiguration::DereferenceConfiguration() noexcept
{
	if (InterlockedDecrement(&m_refCount) == 0)
	{
		delete this;
	}
}

bool JwtModuleConfiguration::Applies(const std::wstring& configuration) const noexcept
{
	auto index = m_configurationPath.find(configuration);
	if (index == 0)
	{
		// This checks the case where the config path was
		// MACHINE/WEBROOT/site and your site path is MACHINE/WEBROOT/siteTest
		return m_configurationPath.size() == configuration.size() ||
			m_configurationPath[configuration.size()] == L'/';
	}

	return false;
}

HRESULT JwtModuleConfiguration::Reload()
{
	auto adminManager = g_pHttpServer->GetAdminManager();
	auto configurationPath = CComBSTR(m_configurationPath.size(), m_configurationPath.data());

	HRESULT hr;
	CComPtr<IAppHostElement> jwtConfigurationElement;
	RETURN_IF_FAILED(hr, adminManager->GetAdminSection(CComBSTR(L"system.webServer/security/authentication/jwtAuthentication"), configurationPath, &jwtConfigurationElement));

	m_enabled = false;
	m_validationType = JwtValidationType::Header;
	m_algorithm = JwtCryptoAlgorithm::RS256;
	m_path.clear();
	m_nameGrant.clear();
	m_roleGrant.clear();
	m_key.clear();
	m_policies.clear();
	m_grantMappings.clear();

	RETURN_IF_FAILED(hr, ReadBoolean(jwtConfigurationElement, L"enabled", m_enabled));
	RETURN_IF_FAILED(hr, ReadInt(jwtConfigurationElement, L"validationType", m_validationType));
	RETURN_IF_FAILED(hr, ReadString(jwtConfigurationElement, L"path", m_path));
	RETURN_IF_FAILED(hr, ReadInt(jwtConfigurationElement, L"algorithm", m_algorithm));
	RETURN_IF_FAILED(hr, ReadString(jwtConfigurationElement, L"nameGrant", m_nameGrant));
	RETURN_IF_FAILED(hr, ReadString(jwtConfigurationElement, L"roleGrant", m_roleGrant));
	RETURN_IF_FAILED(hr, ReadPolicies(jwtConfigurationElement, m_policies));
	RETURN_IF_FAILED(hr, ReadPolicies(adminManager, configurationPath, m_policies));
	RETURN_IF_FAILED(hr, ReadGrantHeaderMappings(jwtConfigurationElement, m_grantMappings));

	if (m_algorithm == JwtCryptoAlgorithm::RS256)
	{
		RETURN_IF_FAILED(hr, ReadKeyFile(jwtConfigurationElement, m_phyiscalPath, m_key));

		if (hr == S_OK)
		{
			return S_OK;
		}
	}

	RETURN_IF_FAILED(hr, ReadString(jwtConfigurationElement, L"key", m_key));

	return S_OK;
}

void JwtModuleConfiguration::CleanupStoredContext()
{
	DereferenceConfiguration();
}

HRESULT JwtModuleConfiguration::EnsureConfiguration(_In_ IHttpApplication* pApplication, _Out_ JwtModuleConfiguration** ppConfiguration)
{
	if (pApplication == NULL)
	{
		return E_INVALIDARG;
	}

	if (ppConfiguration == NULL)
	{
		return E_POINTER;
	}

	auto contextContainer = pApplication->GetModuleContextContainer();
	if ((*ppConfiguration = reinterpret_cast<JwtModuleConfiguration*>(contextContainer->GetModuleContext(g_pModuleId))) == NULL)
	{
		auto configuration = std::make_unique<JwtModuleConfiguration>(pApplication->GetApplicationPhysicalPath(), pApplication->GetAppConfigPath());
		if (configuration == NULL)
		{
			return E_OUTOFMEMORY;
		}

		HRESULT hr;
		RETURN_IF_FAILED(hr, configuration->Reload());
		RETURN_IF_FAILED(hr, contextContainer->SetModuleContext(configuration.get(), g_pModuleId));

		*ppConfiguration = configuration.release();
	}

	return S_OK;
}