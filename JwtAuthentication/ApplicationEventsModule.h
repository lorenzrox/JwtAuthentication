#pragma once
#include "JwtAuthentication.h"
#include <unordered_map>

class JwtModuleConfiguration;

class ApplicationEntry
{
public:
	ApplicationEntry(_In_ IHttpApplication* pApplication);
	~ApplicationEntry();

	HRESULT Initialize();

	inline JwtModuleConfiguration* GetConfiguration() const noexcept
	{
		return m_configuration;
	}

private:
	JwtModuleConfiguration* m_configuration;
};

class ApplicationEventsModule : public CGlobalModule
{
public:
	ApplicationEventsModule();

	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStart(_In_ IHttpApplicationStartProvider* pProvider);
	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalConfigurationChange(_In_ IGlobalConfigurationChangeProvider* pProvider);
	virtual void Terminate();

private:
	HRESULT EnsureApplicationEntry(_In_ IHttpApplication* pApplication, _Out_ std::shared_ptr<ApplicationEntry>& application);
	HRESULT RemoveApplicationEntry(_In_ LPCWSTR pApplicationId);

	SRWLOCK m_srwLock;
	std::unordered_map<std::wstring, std::shared_ptr<ApplicationEntry>> m_applications;
};

