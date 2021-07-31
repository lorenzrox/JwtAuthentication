#include "ApplicationEventsModule.h"
#include "JwtModuleConfiguration.h"
#include "SWRLock.h"

ApplicationEventsModule::ApplicationEventsModule()
{
	InitializeSRWLock(&m_srwLock);
}

HRESULT ApplicationEventsModule::EnsureApplicationConfiguration(_In_ IHttpApplication* pApplication)
{
	auto applicationId = pApplication->GetApplicationId();

	{
		const auto pair = m_configurations.find(applicationId);
		if (pair != m_configurations.end())
		{
			return S_OK;
		}
	}

	SRWExclusiveLock writeLock(m_srwLock);

	// Check if other thread created the application
	const auto pair = m_configurations.find(applicationId);
	if (pair != m_configurations.end())
	{
		return S_OK;
	}

	auto contextContainer = pApplication->GetModuleContextContainer();
	auto currentConfiguration = reinterpret_cast<JwtModuleConfiguration*>(contextContainer->GetModuleContext(g_pModuleId));
	if (currentConfiguration != NULL)
	{
		m_configurations.emplace(applicationId, currentConfiguration);
		return S_OK;
	}

	JwtModuleConfigurationPtr configuration(pApplication->GetApplicationPhysicalPath(), pApplication->GetAppConfigPath());
	if (configuration == NULL)
	{
		return E_OUTOFMEMORY;
	}

	HRESULT hr;
	RETURN_IF_FAILED(hr, configuration->Reload());
	RETURN_IF_FAILED(hr, contextContainer->SetModuleContext(configuration.get(), g_pModuleId));

	configuration->ReferenceConfiguration();

	m_configurations.emplace(applicationId, std::move(configuration));
	return S_OK;
}

HRESULT ApplicationEventsModule::RemoveApplicationConfiguration(_In_ IHttpApplication* pApplication)
{
	auto applicationId = pApplication->GetApplicationId();

	SRWExclusiveLock lock(m_srwLock);

	if (m_configurations.erase(applicationId) == 0)
	{
		return S_FALSE;
	}

	return S_OK;
}

GLOBAL_NOTIFICATION_STATUS ApplicationEventsModule::OnGlobalApplicationStart(_In_ IHttpApplicationStartProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	auto application = pProvider->GetApplication();

	HRESULT hr;
	if (FAILED(hr = EnsureApplicationConfiguration(application)))
	{
		pProvider->SetErrorStatus(hr);
		return GL_NOTIFICATION_HANDLED;
	}

	return GL_NOTIFICATION_CONTINUE;
}

GLOBAL_NOTIFICATION_STATUS ApplicationEventsModule::OnGlobalApplicationStop(_In_ IHttpApplicationStopProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	auto application = pProvider->GetApplication();

	HRESULT hr;
	if (FAILED(hr = RemoveApplicationConfiguration(application)))
	{
		pProvider->SetErrorStatus(hr);
		return GL_NOTIFICATION_HANDLED;
	}

	return GL_NOTIFICATION_CONTINUE;
}

GLOBAL_NOTIFICATION_STATUS ApplicationEventsModule::OnGlobalConfigurationChange(_In_ IGlobalConfigurationChangeProvider* pProvider)
{
#ifdef DEBUG
	__debugbreak();
#endif

	PCWSTR pwszChangePath = pProvider->GetChangePath();
	if (pwszChangePath != NULL && _wcsicmp(pwszChangePath, L"MACHINE/WEBROOT/") > 0)
	{
		SRWExclusiveLock lock(m_srwLock);

		auto iterator = m_configurations.begin();
		while (iterator != m_configurations.end())
		{
			if (iterator->second->Applies(pwszChangePath))
			{
				HRESULT hr;
				if (FAILED(hr = iterator->second->Reload()))
				{
					//Error
					pProvider->SetErrorStatus(hr);
					return GL_NOTIFICATION_HANDLED;
				}
			}

			iterator++;
		}
	}

	return GL_NOTIFICATION_CONTINUE;
}

void ApplicationEventsModule::Terminate()
{
	delete this;
}