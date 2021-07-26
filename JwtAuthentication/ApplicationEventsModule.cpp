#include "ApplicationEventsModule.h"
#include "JwtModuleConfiguration.h"

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

void ApplicationEventsModule::Terminate()
{
	delete this;
}