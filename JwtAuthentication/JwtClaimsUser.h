#pragma once
#include "JwtAuthentication.h"

class JwtClaimsUser : public IHttpUser
{
public:
	JwtClaimsUser(const std::wstring&& userName, const std::set<std::wstring> roles);

	virtual PCWSTR GetRemoteUserName();
	virtual PCWSTR GetUserName();
	virtual PCWSTR GetAuthenticationType();
	virtual PCWSTR GetPassword();
	virtual HANDLE GetImpersonationToken();
	virtual HANDLE GetPrimaryToken();
	virtual void ReferenceUser();
	virtual void DereferenceUser();
	virtual BOOL SupportsIsInRole();
	virtual HRESULT IsInRole(_In_  PCWSTR  pszRoleName, _Out_ BOOL* pfInRole);
	virtual PVOID GetUserVariable(_In_ PCSTR pszVariableName);

#pragma push_macro("GetUserName")

#undef GetUserName

	inline const std::wstring GetUserName() const noexcept
	{
		return m_userName;
	}

#pragma pop_macro("GetUserName")

	inline const std::set<std::wstring> GetRoles() const noexcept
	{
		return m_roles;
	}

private:
	mutable LONG m_refCount;
	const std::wstring m_userName;
	const std::set<std::wstring> m_roles;
};

