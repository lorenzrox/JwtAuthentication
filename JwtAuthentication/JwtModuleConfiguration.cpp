#include "JwtModuleConfiguration.h"
#include <wrl\wrappers\corewrappers.h>
#include <Shlwapi.h>
#include <pathcch.h>

struct Variant {
public:
	Variant() {
		VariantInit(&value);
	}

	~Variant() {
		VariantClear(&value);
	}

	Variant(Variant&& other) noexcept
		: value(other.value) {
		VariantInit(&other.value);
	}

	Variant(const Variant& other) {
		VariantCopy(&value, &other.value);
	}

	Variant& operator=(Variant&& other) noexcept {
		VariantClear(&value);

		value = other.value;

		VariantInit(&other.value);
		return *this;
	}

	Variant& operator=(const Variant& other) {
		VariantClear(&value);
		VariantCopy(&value, &other.value);
		return *this;
	}

	inline operator VARIANT& () noexcept {
		return value;
	}

	inline VARIANT* operator&() noexcept {
		VariantClear(&value);
		return &value;
	}

	inline const VARIANT& get() const noexcept {
		return value;
	}

	inline const VARIANT* operator->() const noexcept {
		return &value;
	}

private:
	VARIANT value;
};

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

void ParsePolicyDefinition(const std::string& value, std::insensitive_unordered_set<std::string>& values)
{
	size_t endIndex;
	size_t startIndex = 0;
	std::string token;

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
	RETURN_IF_FAILED(hr, pConfigurationElement->GetPropertyByName(CComBSTR(L"keySource"), &configurationProperty));

	if (configurationProperty == NULL)
	{
		return S_FALSE;
	}

	Variant keySource;
	RETURN_IF_FAILED(hr, configurationProperty->get_Value(&keySource));

	if (!SysStringLen(keySource->bstrVal)) {
		return S_FALSE;
	}

	WCHAR keyFileName[MAX_PATH];
	CopyMemory(keyFileName, phyiscalPath.data(), (phyiscalPath.size() + 1) * sizeof(WCHAR));

	RETURN_IF_FAILED(hr, PathCchCombine(keyFileName, MAX_PATH, keyFileName, keySource->bstrVal));

	Microsoft::WRL::Wrappers::FileHandle keyFile(CreateFile(keyFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	if (!keyFile.IsValid())
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

	LARGE_INTEGER size;
	if (!GetFileSizeEx(keyFile.Get(), &size)) {
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
	RETURN_IF_FAILED(hr, pConfigurationElement->GetPropertyByName(pKey, &configurationProperty));

	if (configurationProperty)
	{
		Variant value;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&value));

		result = static_cast<_Ty>(value->intVal);
		return S_OK;
	}

	return S_FALSE;
}

HRESULT ReadBoolean(IAppHostElement* pConfigurationElement, const CComBSTR& pKey, bool& result)
{
	HRESULT hr;
	CComPtr<IAppHostProperty> configurationProperty;
	RETURN_IF_FAILED(hr, pConfigurationElement->GetPropertyByName(pKey, &configurationProperty));

	if (configurationProperty)
	{
		Variant value;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&value));

		result = value->boolVal != FALSE;
		return S_OK;
	}

	return S_FALSE;
}

HRESULT ReadString(IAppHostElement* pConfigurationElement, const CComBSTR& pKey, std::string& result)
{
	HRESULT hr;
	CComPtr<IAppHostProperty> configurationProperty;
	RETURN_IF_FAILED(hr, pConfigurationElement->GetPropertyByName(pKey, &configurationProperty));

	if (configurationProperty)
	{
		Variant value;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&value));

		UINT len = SysStringLen(value->bstrVal);
		if (len) {
			result = std::to_string(value->bstrVal, len);
			return S_OK;
		}
	}

	return S_FALSE;
}

HRESULT ReadPolicies(IAppHostElement* pConfigurationElement, std::vector<JwtAuthenticationPolicy>& policies)
{
	HRESULT hr;
	CComPtr<IAppHostElement> policiesElement;
	RETURN_IF_FAILED(hr, pConfigurationElement->GetElementByName(CComBSTR(L"policies"), &policiesElement));

	if (policiesElement)
	{
		CComPtr<IAppHostElementCollection> policiesCollection;
		RETURN_IF_FAILED(hr, policiesElement->get_Collection(&policiesCollection));

		if (policiesCollection)
		{
			DWORD policyCount;
			RETURN_IF_FAILED(hr, policiesCollection->get_Count(&policyCount));

			VARIANT vtIndex;
			vtIndex.vt = VT_INT;
			vtIndex.intVal = 0;

			JwtAuthenticationPolicy policy;
			CComBSTR usersProperty = L"users";
			CComBSTR rolesProperty = L"roles";
			CComPtr<IAppHostElement> policyElement;

			while (vtIndex.intVal < policyCount)
			{
				RETURN_IF_FAILED(hr, policiesCollection->get_Item(vtIndex, &policyElement));
				vtIndex.intVal++;

				std::string users;
				RETURN_IF_FAILED(hr, ReadString(policyElement, usersProperty, users));

				std::string roles;
				RETURN_IF_FAILED(hr, ReadString(policyElement, rolesProperty, roles));

				ParsePolicyDefinition(users, policy.Users);
				ParsePolicyDefinition(roles, policy.Roles);

				if (policy.Users.empty() && policy.Roles.empty())
				{
					continue;
				}

				policies.emplace_back(std::move(policy));
			}

			return S_OK;
		}
	}

	return S_FALSE;
}

HRESULT ReadGrantHeaderMappings(IAppHostElement* pConfigurationElement, std::insensitive_unordered_map<std::string, const JwtGrantMapping>& mappings)
{
	HRESULT hr;
	CComPtr<IAppHostElement> grantMappingsElement;
	RETURN_IF_FAILED(hr, pConfigurationElement->GetElementByName(CComBSTR(L"grantHeaderMappings"), &grantMappingsElement));

	if (grantMappingsElement)
	{
		CComPtr<IAppHostElementCollection> grantMappingsCollection;
		RETURN_IF_FAILED(hr, grantMappingsElement->get_Collection(&grantMappingsCollection));

		if (grantMappingsCollection)
		{
			DWORD grantMappingCount;
			RETURN_IF_FAILED(hr, grantMappingsCollection->get_Count(&grantMappingCount));

			VARIANT vtIndex;
			vtIndex.vt = VT_INT;
			vtIndex.intVal = 0;

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

				bool replace = false;
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
	HRESULT hr;
	CComPtr<IAppHostElement> configurationElement;
	RETURN_IF_FAILED(hr, g_pHttpServer->GetAdminManager()->GetAdminSection(CComBSTR(L"system.webServer/security/authentication/jwtAuthentication"),
		CComBSTR(m_configurationPath.size(), m_configurationPath.data()), &configurationElement));

	m_enabled = false;
	m_validationType = JwtValidationType::Header;
	m_algorithm = JwtCryptoAlgorithm::RS256;
	m_path.clear();
	m_nameGrant.clear();
	m_roleGrant.clear();
	m_key.clear();
	m_policies.clear();
	m_grantMappings.clear();

	RETURN_IF_FAILED(hr, ReadBoolean(configurationElement, L"enabled", m_enabled));
	RETURN_IF_FAILED(hr, ReadInt(configurationElement, L"validationType", m_validationType));
	RETURN_IF_FAILED(hr, ReadString(configurationElement, L"path", m_path));
	RETURN_IF_FAILED(hr, ReadInt(configurationElement, L"algorithm", m_algorithm));
	RETURN_IF_FAILED(hr, ReadString(configurationElement, L"nameGrant", m_nameGrant));
	RETURN_IF_FAILED(hr, ReadString(configurationElement, L"roleGrant", m_roleGrant));
	RETURN_IF_FAILED(hr, ReadPolicies(configurationElement, m_policies));
	RETURN_IF_FAILED(hr, ReadGrantHeaderMappings(configurationElement, m_grantMappings));

	if (m_algorithm == JwtCryptoAlgorithm::RS256)
	{
		RETURN_IF_FAILED(hr, ReadKeyFile(configurationElement, m_phyiscalPath, m_key));

		if (hr == S_OK)
		{
			return S_OK;
		}
	}

	RETURN_IF_FAILED(hr, ReadString(configurationElement, L"key", m_key));

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