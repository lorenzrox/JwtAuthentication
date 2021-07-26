#pragma once
#include "JwtAuthentication.h"

class JwtModuleConfiguration : public IHttpStoredContext
{
public:
	virtual void CleanupStoredContext();

	HRESULT Reload(_In_ IHttpApplication* pApplication);

	inline bool IsEnabled() const
	{
		return m_enabled;
	}

	inline JwtValidationType GetValidationType() const
	{
		return m_validationType;
	}

	inline JwtCryptoAlgorithm GetAlgorithm() const
	{
		return m_algorithm;
	}

	inline const std::string& GetNameGrant() const
	{
		return m_nameGrant;
	}

	inline const std::string& GetRoleGrant() const
	{
		return m_roleGrant;
	}

	inline const std::string& GetPath() const
	{
		return m_path;
	}

	inline const std::string& GetKey() const
	{
		return m_key;
	}

	inline const std::set<std::string, std::insensitive_compare<std::string>>& GetRequiredRoles() const
	{
		return m_requiredRoles;
	}

	static HRESULT EnsureConfiguration(_In_ IHttpApplication* pApplication, _Out_ JwtModuleConfiguration** ppConfiguration);

private:
	bool m_enabled;
	JwtValidationType m_validationType;
	JwtCryptoAlgorithm m_algorithm;
	std::string m_path;
	std::string m_key;
	std::string m_nameGrant;
	std::string m_roleGrant;
	std::set<std::string, std::insensitive_compare<std::string>> m_requiredRoles;
};

