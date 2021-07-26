#include "ApplicationEventsModule.h"
#include "JwtModuleConfiguration.h"


ApplicationEntry::ApplicationEntry(_In_ IHttpApplication* pApplication) :
	m_application(pApplication)
{
}


ApplicationEventsModule::ApplicationEventsModule()
{
	InitializeSRWLock(&m_srwLock);
}

GLOBAL_NOTIFICATION_STATUS ApplicationEventsModule::OnGlobalApplicationStart(_In_ IHttpApplicationStartProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	JwtModuleConfiguration* pConfiguration;
	if (FAILED(JwtModuleConfiguration::EnsureConfiguration(pProvider->GetApplication(), &pConfiguration)))
	{
		return GL_NOTIFICATION_HANDLED;
	}

	return GL_NOTIFICATION_CONTINUE;
}

GLOBAL_NOTIFICATION_STATUS ApplicationEventsModule::OnGlobalConfigurationChange(_In_ IGlobalConfigurationChangeProvider* pProvider)
{
	PCWSTR pwszChangePath = pProvider->GetChangePath();
	if (pwszChangePath != NULL && _wcsicmp(pwszChangePath, L"MACHINE/WEBROOT/") > 0)
	{
		//TODO: reload configuration
		return GL_NOTIFICATION_CONTINUE;
	}

	return GL_NOTIFICATION_CONTINUE;
}

void ApplicationEventsModule::Terminate()
{
	delete this;
}