#include "JwtAuthenticationModuleFactory.h"

//  Global module context id
PVOID g_pModuleContext = NULL;
IHttpServer* g_pHttpServer = NULL;

//  The RegisterModule entrypoint implementation.
//  This method is called by the server when the module DLL is 
//  loaded in order to create the module factory,
//  and register for server events.
HRESULT WINAPI RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo* pModuleInfo, IHttpServer* pHttpServer)
{
	__debugbreak();

	HRESULT hr = S_OK;
	JwtAuthenticationModuleFactory* pFactory = NULL;

	if (pModuleInfo == NULL || pHttpServer == NULL)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
		goto Finished;
	}

	g_pModuleContext = pModuleInfo->GetId();
	g_pHttpServer = pHttpServer;

	pFactory = new JwtAuthenticationModuleFactory();
	if (pFactory == NULL)
	{
		hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto Finished;
	}


	if (FAILED(hr = pModuleInfo->SetRequestNotifications(pFactory, RQ_BEGIN_REQUEST, 0)))
	{
		goto Finished;
	}

	if (FAILED(hr = pModuleInfo->SetPriorityForRequestNotification(RQ_BEGIN_REQUEST, PRIORITY_ALIAS_HIGH)))
	{
		goto Finished;
	}

	pFactory = NULL;

Finished:
	if (pFactory != NULL)
	{
		delete pFactory;
		pFactory = NULL;
	}

	return hr;
}
