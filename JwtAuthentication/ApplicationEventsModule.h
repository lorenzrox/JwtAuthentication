#pragma once
#include "JwtAuthentication.h"
#include "JwtModuleConfiguration.h"
#include <unordered_map>


class ApplicationEventsModule : public CGlobalModule
{
public:
	ApplicationEventsModule();

	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStart(_In_ IHttpApplicationStartProvider* pProvider);
	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalConfigurationChange(_In_ IGlobalConfigurationChangeProvider* pProvider);
	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStop(_In_ IHttpApplicationStopProvider* pProvider);
	virtual void Terminate();

private:
	HRESULT EnsureApplicationConfiguration(_In_ IHttpApplication* pApplication);
	HRESULT RemoveApplicationConfiguration(_In_ IHttpApplication* pApplication);

	SRWLOCK m_srwLock;
	std::unordered_map<std::wstring, JwtModuleConfigurationPtr> m_configurations;
};