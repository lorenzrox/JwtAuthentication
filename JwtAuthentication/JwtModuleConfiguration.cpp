#include "JwtModuleConfiguration.h"
#include <wrl\wrappers\corewrappers.h>
#include <Shlwapi.h>

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

HRESULT ReadKeyFile(const std::wstring& physicalPath, _In_ BSTR path, std::string& result)
{
	if (!SysStringLen(path)) {
		return S_FALSE;
	}

	WCHAR keyFileName[MAX_PATH] = L"";
	if (!PathCombineW(keyFileName, physicalPath.data(), path))
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}

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

JwtModuleConfiguration::JwtModuleConfiguration() :
	m_refCount(1)
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

HRESULT JwtModuleConfiguration::Reload(const std::wstring& physicalPath, const std::wstring& configurationPath)
{

	HRESULT hr;
	CComPtr<IAppHostElement> configurationElement;
	CComPtr<IAppHostProperty> configurationProperty;

	RETURN_IF_FAILED(hr, g_pHttpServer->GetAdminManager()->GetAdminSection(CComBSTR(L"system.webServer/security/authentication/jwtAuthentication"),
		CComBSTR(configurationPath.size(), configurationPath.data()), &configurationElement));

	m_enabled = false;
	m_validationType = JwtValidationType::Header;
	m_algorithm = JwtCryptoAlgorithm::RS256;
	m_path.clear();
	m_nameGrant.clear();
	m_roleGrant.clear();
	m_key.clear();
	m_requiredRoles.clear();

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"enabled"), &configurationProperty));
	if (configurationProperty)
	{
		Variant enabled;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&enabled));

		m_enabled = enabled->boolVal != FALSE;
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"validationType"), &configurationProperty));

	if (configurationProperty)
	{
		Variant validationType;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&validationType));

		m_validationType = static_cast<JwtValidationType>(validationType->intVal);
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"path"), &configurationProperty));

	if (configurationProperty)
	{
		Variant path;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&path));

		UINT len = SysStringLen(path->bstrVal);
		if (len) {
			m_path = std::to_string(path->bstrVal, len);
		}
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"algorithm"), &configurationProperty));

	if (configurationProperty)
	{
		Variant algorithm;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&algorithm));

		m_algorithm = static_cast<JwtCryptoAlgorithm>(algorithm->intVal);

		RETURN_IF_FAILED(hr, VariantClear(&algorithm));
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"nameGrant"), &configurationProperty));

	if (configurationProperty)
	{
		Variant nameGrant;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&nameGrant));

		UINT len = SysStringLen(nameGrant->bstrVal);
		if (len) {
			m_nameGrant = std::to_string(nameGrant->bstrVal, len);
		}
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"roleGrant"), &configurationProperty));

	if (configurationProperty)
	{
		Variant roleGrant;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&roleGrant));

		UINT len = SysStringLen(roleGrant->bstrVal);
		if (len) {
			m_roleGrant = std::to_string(roleGrant->bstrVal, len);
		}
	}

	CComPtr<IAppHostElement> requiredRolesElement;
	RETURN_IF_FAILED(hr, configurationElement->GetElementByName(CComBSTR(L"requiredRoles"), &requiredRolesElement));

	if (requiredRolesElement)
	{
		CComPtr<IAppHostElementCollection> requiredRolesCollection;
		RETURN_IF_FAILED(hr, requiredRolesElement->get_Collection(&requiredRolesCollection));

		if (requiredRolesCollection)
		{
			DWORD requiredRolesCount;
			RETURN_IF_FAILED(hr, requiredRolesCollection->get_Count(&requiredRolesCount));

			VARIANT vtIndex;
			vtIndex.vt = VT_INT;
			vtIndex.intVal = 0;

			Variant requiredRole;
			CComBSTR propertyName = L"name";
			CComPtr<IAppHostElement> requiredRoleElement;

			while (vtIndex.intVal < requiredRolesCount)
			{
				RETURN_IF_FAILED(hr, requiredRolesCollection->get_Item(vtIndex, &requiredRoleElement));
				RETURN_IF_FAILED(hr, requiredRoleElement->GetPropertyByName(propertyName, &configurationProperty));

				if (configurationProperty)
				{
					RETURN_IF_FAILED(hr, configurationProperty->get_Value(&requiredRole));

					UINT len = SysStringLen(requiredRole->bstrVal);
					if (len) {
						m_requiredRoles.insert(std::to_string(requiredRole->bstrVal, len));
					}
				}

				vtIndex.intVal++;
			}
		}
	}

	if (m_algorithm == JwtCryptoAlgorithm::RS256)
	{
		RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"keySource"), &configurationProperty));

		if (configurationProperty)
		{
			Variant keySource;
			RETURN_IF_FAILED(hr, configurationProperty->get_Value(&keySource));

			RETURN_IF_FAILED(hr, ReadKeyFile(physicalPath, keySource->bstrVal, m_key));
			if (hr == S_OK)
			{
				return S_OK;
			}
		}
	}

	RETURN_IF_FAILED(hr, configurationElement->GetPropertyByName(CComBSTR(L"key"), &configurationProperty));

	if (configurationProperty)
	{
		Variant key;
		RETURN_IF_FAILED(hr, configurationProperty->get_Value(&key));

		UINT len = SysStringLen(key->bstrVal);
		if (len)
		{
			m_key = std::to_string(key->bstrVal, len);
		}
	}

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
		auto configuration = std::make_unique<JwtModuleConfiguration>();
		if (configuration == NULL)
		{
			return E_OUTOFMEMORY;
		}

		HRESULT hr;
		RETURN_IF_FAILED(hr, configuration->Reload(pApplication->GetApplicationPhysicalPath(), pApplication->GetAppConfigPath()));
		RETURN_IF_FAILED(hr, contextContainer->SetModuleContext(configuration.get(), g_pModuleId));

		*ppConfiguration = configuration.release();
	}

	return S_OK;
}