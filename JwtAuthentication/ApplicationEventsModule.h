#pragma once
#include "JwtAuthentication.h"
#include <unordered_map>

class ApplicationEntry
{
public:
	ApplicationEntry(_In_ IHttpApplication* pApplication);

private:
	IHttpApplication* m_application;
};

class ApplicationEventsModule : public CGlobalModule
{
public:
	ApplicationEventsModule();

	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStart(_In_ IHttpApplicationStartProvider* pProvider);
	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalConfigurationChange(_In_ IGlobalConfigurationChangeProvider* pProvider);
	virtual void Terminate();

private:
	SRWLOCK m_srwLock;
	std::unordered_map<std::wstring, std::unique_ptr<ApplicationEntry>> m_applications;
};

