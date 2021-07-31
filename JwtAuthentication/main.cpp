#include "JwtAuthenticationModuleFactory.h"
#include "ApplicationEventsModule.h"

//  Global module context id
HTTP_MODULE_ID g_pModuleId = NULL;
IHttpServer* g_pHttpServer = NULL;

//  The RegisterModule entrypoint implementation.
//  This method is called by the server when the module DLL is 
//  loaded in order to create the module factory,
//  and register for server events.
HRESULT WINAPI RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo* pModuleInfo, IHttpServer* pHttpServer)
{
	if (pModuleInfo == NULL || pHttpServer == NULL)
	{
		return E_INVALIDARG;
	}

	g_pModuleId = pModuleInfo->GetId();
	g_pHttpServer = pHttpServer;

	auto applicationEvents = std::make_unique<ApplicationEventsModule>();
	if (applicationEvents == NULL)
	{
		return E_OUTOFMEMORY;
	}

	auto moduleFactory = std::make_unique<JwtAuthenticationModuleFactory>();
	if (moduleFactory == NULL)
	{
		return E_OUTOFMEMORY;
	}

	HRESULT hr;
	//RETURN_IF_FAILED(hr, pModuleInfo->SetRequestNotifications(moduleFactory.get(), RQ_AUTHENTICATE_REQUEST | RQ_AUTHORIZE_REQUEST, 0));
	RETURN_IF_FAILED(hr, pModuleInfo->SetRequestNotifications(moduleFactory.get(), RQ_BEGIN_REQUEST, 0));
	RETURN_IF_FAILED(hr, pModuleInfo->SetPriorityForRequestNotification(RQ_BEGIN_REQUEST, PRIORITY_ALIAS_HIGH));
	RETURN_IF_FAILED(hr, pModuleInfo->SetGlobalNotifications(applicationEvents.get(), GL_CONFIGURATION_CHANGE | GL_APPLICATION_START | GL_APPLICATION_STOP));

	moduleFactory.release();
	applicationEvents.release();
	return S_OK;
}
