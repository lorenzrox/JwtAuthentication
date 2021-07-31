#include "JwtAuthorizationPolicy.h"


JwtAuthorizationPolicy::JwtAuthorizationPolicy(
	std::insensitive_unordered_set<std::string>&& users,
	std::insensitive_unordered_set<std::string>&& roles,
	std::unordered_set<std::string>&& verbs) :
	m_users(users),
	m_roles(roles),
	m_verbs(verbs)
{
}


HRESULT JwtAuthorizationAllowPolicy::Check(_In_ IHttpContext* pContext, _Out_ bool* pResult)
{
	auto& verbs = GetVerbs();
	if (!verbs.empty())
	{
		if (verbs.find(pContext->GetRequest()->GetHttpMethod()) == verbs.end())
		{
			return S_FALSE;
		}
	}

	auto user = pContext->GetUser();
	if (user == NULL)
	{
		*pResult = false;
		return S_OK;
	}

	auto& users = GetUsers();
	if (!users.empty())
	{
		auto userName = user->GetUserName();
		if (userName == NULL || users.find(std::to_string(userName)) == users.end())
		{
			*pResult = false;
			return S_OK;
		}
	}

	auto& roles = GetRoles();
	if (!user->SupportsIsInRole())
	{
		*pResult = roles.empty();
		return S_OK;
	}

	HRESULT hr;
	BOOL isInRole;
	for (auto& role : GetRoles())
	{
		RETURN_IF_FAILED(hr, user->IsInRole(std::to_wstring(role).data(), &isInRole));

		if (isInRole == FALSE)
		{
			*pResult = false;
			return S_OK;
		}
	}

	*pResult = true;
	return S_OK;

}

HRESULT JwtAuthorizationAllowPolicy::Check(_In_ const std::string& userName, _In_ const std::insensitive_unordered_set<std::string>& userRoles, _Out_ bool* pResult)
{
	auto& users = GetUsers();
	if (!users.empty())
	{
		if (userName.empty() || users.find(userName) == users.end())
		{
			*pResult = false;
			return S_OK;
		}
	}

	auto& roles = GetRoles();
	if (roles.size() != userRoles.size())
	{
		*pResult = false;
		return S_OK;
	}

	for (auto& role : roles)
	{
		if (userRoles.find(role) == userRoles.end())
		{
			*pResult = false;
			return S_OK;
		}
	}

	*pResult = true;
	return S_OK;

}