#pragma once
#include "JwtAuthentication.h"
#include "StringHelper.h"


class JwtAuthorizationPolicy
{
public:
	JwtAuthorizationPolicy(std::insensitive_unordered_set<std::string>&& users,
		std::insensitive_unordered_set<std::string>&& roles,
		std::unordered_set<std::string>&& verbs);

	virtual HRESULT Check(_In_ IHttpContext* pContext, _Out_ bool* pResult) = 0;
	virtual HRESULT Check(_In_ const std::string& userName, _In_ const std::insensitive_unordered_set<std::string>& userRoles, _Out_ bool* pResult) = 0;

protected:
	inline const std::insensitive_unordered_set<std::string>& GetUsers() const noexcept
	{
		return m_users;
	}

	inline const std::insensitive_unordered_set<std::string>& GetRoles() const noexcept
	{
		return m_roles;
	}

	inline const std::unordered_set<std::string>& GetVerbs() const noexcept
	{
		return m_verbs;
	}

private:
	std::insensitive_unordered_set<std::string> m_users;
	std::insensitive_unordered_set<std::string> m_roles;
	std::unordered_set<std::string> m_verbs;
};

class JwtAuthorizationAllowPolicy : public JwtAuthorizationPolicy
{
public:
	JwtAuthorizationAllowPolicy(std::insensitive_unordered_set<std::string>&& users,
		std::insensitive_unordered_set<std::string>&& roles,
		std::unordered_set<std::string>&& verbs) :
		JwtAuthorizationPolicy(std::forward<std::insensitive_unordered_set<std::string>>(users),
			std::forward<std::insensitive_unordered_set<std::string>>(roles),
			std::forward<std::unordered_set<std::string>>(verbs))
	{
	}

	virtual HRESULT Check(_In_ IHttpContext* pContext, _Out_ bool* pResult);
	virtual HRESULT Check(_In_ const std::string& userName, _In_ const std::insensitive_unordered_set<std::string>& userRoles, _Out_ bool* pResult);
};