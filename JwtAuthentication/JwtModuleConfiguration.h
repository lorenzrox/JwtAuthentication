#pragma once
#include "JwtAuthentication.h"
#include "JwtAuthorizationPolicy.h"
#include "StringHelper.h"

struct JwtGrantMapping
{
	std::string Header;
	bool Replace;
};

class JwtModuleConfiguration : public IHttpStoredContext
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

	inline const std::vector<std::unique_ptr<JwtAuthorizationPolicy>>& GetPolicies() const
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
	std::vector<std::unique_ptr<JwtAuthorizationPolicy>> m_policies;
	std::insensitive_unordered_map<std::string, const JwtGrantMapping> m_grantMappings;
};

class JwtModuleConfigurationPtr
{
public:
	JwtModuleConfigurationPtr() :
		m_ptr(NULL)
	{
	}

	JwtModuleConfigurationPtr(std::wstring&& phyiscalPath, std::wstring&& configurationPath) :
		m_ptr(new JwtModuleConfiguration(std::forward<std::wstring>(phyiscalPath), std::forward<std::wstring>(configurationPath)))
	{
	}

	JwtModuleConfigurationPtr(JwtModuleConfiguration* pConfiguration) :
		m_ptr(pConfiguration)
	{
		if (m_ptr != NULL)
		{
			m_ptr->ReferenceConfiguration();
		}
	}

	~JwtModuleConfigurationPtr()
	{
		if (m_ptr != NULL)
		{
			m_ptr->DereferenceConfiguration();
			m_ptr = NULL;
		}
	}

	JwtModuleConfigurationPtr(JwtModuleConfigurationPtr&& other) noexcept :
		m_ptr(NULL)
	{
		std::swap(m_ptr, other.m_ptr);
	}

	JwtModuleConfigurationPtr(const JwtModuleConfigurationPtr& other) :
		m_ptr(other.m_ptr)
	{
		if (m_ptr != NULL)
		{
			m_ptr->ReferenceConfiguration();
		}
	}

	JwtModuleConfigurationPtr& operator=(JwtModuleConfigurationPtr&& other) noexcept
	{
		std::swap(m_ptr, other.m_ptr);
		return *this;
	}

	JwtModuleConfigurationPtr& operator=(const JwtModuleConfigurationPtr& other)
	{
		if (this != std::addressof(other))
		{
			m_ptr = other.m_ptr;

			if (m_ptr != NULL)
			{
				m_ptr->ReferenceConfiguration();
			}
		}

		return *this;
	}

	inline JwtModuleConfiguration* get() const noexcept
	{
		return m_ptr;
	}


	inline JwtModuleConfiguration* operator->() const noexcept
	{
		return m_ptr;
	}

	explicit operator bool() const noexcept
	{
		return m_ptr != NULL;
	}

	bool operator!() const throw()
	{
		return m_ptr == NULL;
	}

	bool operator<(_In_opt_ JwtModuleConfiguration* ptr) const noexcept
	{
		return m_ptr < ptr;
	}

	bool operator!=(_In_opt_ JwtModuleConfiguration* ptr) const
	{
		return !operator==(ptr);
	}

	bool operator==(_In_opt_ JwtModuleConfiguration* ptr) const noexcept
	{
		return m_ptr == ptr;
	}

private:
	JwtModuleConfiguration* m_ptr;
};
