#include "ApplicationEventsModule.h"
#include "JwtModuleConfiguration.h"
#include "SWRLock.h"


ApplicationEntry::ApplicationEntry(_In_ IHttpApplication* pApplication) :
	m_configuration(new JwtModuleConfiguration(pApplication->GetApplicationPhysicalPath(), pApplication->GetAppConfigPath()))
{
}

ApplicationEntry::~ApplicationEntry()
{
	if (m_configuration != NULL)
	{
		m_configuration->DereferenceConfiguration();
		m_configuration = NULL;
	}
}

HRESULT ApplicationEntry::Initialize()
{
	if (m_configuration == NULL)
	{
		return E_OUTOFMEMORY;
	}

	return m_configuration->Reload();
}


ApplicationEventsModule::ApplicationEventsModule()
{
	InitializeSRWLock(&m_srwLock);
}

HRESULT ApplicationEventsModule::EnsureApplicationEntry(_In_ IHttpApplication* pApplication, _Out_ std::shared_ptr<ApplicationEntry>& result)
{
	std::wstring applicationId = pApplication->GetApplicationId();

	{
		const auto pair = m_applications.find(applicationId);
		if (pair != m_applications.end())
		{
			result = pair->second;
			return S_OK;
		}
	}

	SRWExclusiveLock writeLock(m_srwLock);

	// Check if other thread created the application
	const auto pair = m_applications.find(applicationId);
	if (pair != m_applications.end())
	{
		result = pair->second;
		return S_OK;
	}


	auto application = std::make_shared<ApplicationEntry>(pApplication);
	if (application == NULL)
	{
		return E_OUTOFMEMORY;
	}

	HRESULT hr;
	RETURN_IF_FAILED(hr, application->Initialize());

	m_applications.emplace(applicationId, application);

	result = std::move(application);
	return S_OK;
}

HRESULT ApplicationEventsModule::RemoveApplicationEntry(_In_ LPCWSTR pApplicationId)
{
	SRWExclusiveLock lock(m_srwLock);

	if (m_applications.erase(pApplicationId) == 0)
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
	JwtModuleConfiguration* pConfiguration;
	if (FAILED(hr = JwtModuleConfiguration::EnsureConfiguration(application, &pConfiguration)))
	{
		pProvider->SetErrorStatus(hr);
		return GL_NOTIFICATION_HANDLED;
	}

	return GL_NOTIFICATION_CONTINUE;
}

GLOBAL_NOTIFICATION_STATUS ApplicationEventsModule::OnGlobalConfigurationChange(_In_ IGlobalConfigurationChangeProvider* pProvider)
{
	return GL_NOTIFICATION_CONTINUE;

	PCWSTR pwszChangePath = pProvider->GetChangePath();
	if (pwszChangePath != NULL && _wcsicmp(pwszChangePath, L"MACHINE/WEBROOT/") > 0)
	{
		SRWExclusiveLock lock(m_srwLock);

		auto iterator = m_applications.begin();
		while (iterator != m_applications.end())
		{
			auto pConfiguration = iterator->second->GetConfiguration();
			if (pConfiguration != NULL && pConfiguration->Applies(pwszChangePath))
			{
				HRESULT hr;
				if (FAILED(hr = pConfiguration->Reload()))
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