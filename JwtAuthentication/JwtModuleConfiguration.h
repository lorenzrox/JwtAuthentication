#pragma once
#include "JwtAuthentication.h"
#include "StringHelper.h"

struct JwtGrantMapping
{
	std::string Header;
	bool Replace;
};

enum class JwtAuthenticationAccessType
{
	Allow = 0,
	Deny = 1
};

struct JwtAuthenticationPolicy
{
	std::insensitive_unordered_set<std::string> Users;
	std::insensitive_unordered_set<std::string> Roles;
	std::unordered_set<std::string> Verbs;
};

class JwtAuthorizationPolicy
{
public:
	JwtAuthorizationPolicy(std::insensitive_unordered_set<std::wstring>&& users,
		std::insensitive_unordered_set<std::wstring>&& roles,
		std::unordered_set<std::string>&& verbs);

	virtual HRESULT Check(_In_ IHttpContext* pContext, _Out_ bool* pResult) = 0;

protected:
	inline const std::insensitive_unordered_set<std::wstring>& GetUsers() const noexcept
	{
		return m_users;
	}

	inline const std::insensitive_unordered_set<std::wstring>& GetRoles() const noexcept
	{
		return m_roles;
	}

	inline const std::unordered_set<std::string>& GetVerbs() const noexcept
	{
		return m_verbs;
	}

private:
	std::insensitive_unordered_set<std::wstring> m_users;
	std::insensitive_unordered_set<std::wstring> m_roles;
	std::unordered_set<std::string> m_verbs;
};

class JwtAuthorizationAllowPolicy : public JwtAuthorizationPolicy
{
	virtual HRESULT Check(_In_ IHttpContext* pContext, _Out_ bool* pResult);
};

class JwtModuleConfiguration : IHttpStoredContext
{
public:
	JwtModuleConfiguration(std::wstring&& phyiscalPath, std::wstring&& configurationPath);
	JwtModuleConfiguration(const JwtModuleConfiguration&) = delete;
	const JwtModuleConfiguration& operator=(const JwtModuleConfiguration&) = delete;

	HRESULT Reload();
	void ReferenceConfiguration() noexcept;
	void DereferenceConfiguration() noexcept;
	bool Applies(const std::wstring& configuration) const noexcept;

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

	inline const std::vector<JwtAuthenticationPolicy>& GetPolicies() const
	{
		return m_policies;
	}

	inline const std::insensitive_unordered_map<std::string, const JwtGrantMapping>& GetGrantMappings() const
	{
		return m_grantMappings;
	}

	static HRESULT EnsureConfiguration(_In_ IHttpApplication* pApplication, _Out_ JwtModuleConfiguration** ppConfiguration);

private:
	virtual void CleanupStoredContext();

	mutable LONG m_refCount;
	bool m_enabled;
	JwtValidationType m_validationType;
	JwtCryptoAlgorithm m_algorithm;
	std::string m_path;
	std::string m_key;
	std::string m_nameGrant;
	std::string m_roleGrant;
	std::wstring m_configurationPath;
	std::wstring m_phyiscalPath;
	std::vector<JwtAuthenticationPolicy> m_policies;
	std::insensitive_unordered_map<std::string, const JwtGrantMapping> m_grantMappings;
};

