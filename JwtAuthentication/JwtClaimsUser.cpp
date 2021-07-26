#include "JwtClaimsUser.h"

JwtClaimsUser::JwtClaimsUser(const std::wstring&& userName, const std::set<std::wstring> roles) :
	m_refCount(1),
	m_userName(userName),
	m_roles(roles)
{
}

PCWSTR JwtClaimsUser::GetRemoteUserName()
{
	if (m_userName.empty())
	{
		return NULL;
	}

	return m_userName.data();
}

PCWSTR JwtClaimsUser::GetUserName()
{
	if (m_userName.empty())
	{
		return NULL;
	}

	return m_userName.data();
}

PCWSTR JwtClaimsUser::GetAuthenticationType()
{
	return L"Bearer";
}

PCWSTR JwtClaimsUser::GetPassword()
{
	return NULL;
}

HANDLE JwtClaimsUser::GetImpersonationToken()
{
	return NULL;
}

HANDLE JwtClaimsUser::GetPrimaryToken()
{
	return NULL;
}

void JwtClaimsUser::ReferenceUser()
{
	InterlockedIncrement(&m_refCount);
}

void JwtClaimsUser::DereferenceUser()
{
	if (InterlockedDecrement(&m_refCount) == 0)
	{
		delete this;
	}
}

BOOL JwtClaimsUser::SupportsIsInRole()
{
	return TRUE;
}

HRESULT JwtClaimsUser::IsInRole(_In_ PCWSTR pszRoleName, _Out_ BOOL* pfInRole)
{
	if (pszRoleName == NULL)
	{
		return E_INVALIDARG;
	}

	*pfInRole = m_roles.find(pszRoleName) != m_roles.end();
	return S_OK;
}

PVOID JwtClaimsUser::GetUserVariable(_In_ PCSTR pszVariableName)
{
	return NULL;
}