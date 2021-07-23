#include "JwtAuthenticationModuleFactory.h"
#include "JwtAuthenticationModule.h"


HRESULT JwtAuthenticationModuleFactory::GetHttpModule(_Out_ CHttpModule** ppModule, _In_ IModuleAllocator*)
{
	HRESULT hr = S_OK;
	JwtAuthenticationModule* pModule = NULL;
	 
	if (ppModule == NULL)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
		goto Finished;
	}

	pModule = new JwtAuthenticationModule();
	if (pModule == NULL)
	{
		hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto Finished;
	}

	*ppModule = pModule;
	pModule = NULL;


Finished:
	if (pModule != NULL)
	{
		delete pModule;
		pModule = NULL;
	}

	return hr;
}

void JwtAuthenticationModuleFactory::Terminate()
{
	delete this;
}