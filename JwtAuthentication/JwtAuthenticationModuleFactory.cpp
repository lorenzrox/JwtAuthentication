#include "JwtAuthenticationModuleFactory.h"
#include "JwtAuthenticationModule.h"


HRESULT JwtAuthenticationModuleFactory::GetHttpModule(_Out_ CHttpModule** ppModule, _In_ IModuleAllocator* pAllocator)
{
	UNREFERENCED_PARAMETER(pAllocator);

	if (ppModule == NULL)
	{
		return E_INVALIDARG;
	}

	auto module = std::make_unique<JwtAuthenticationModule>();
	if (module == NULL)
	{
		return E_OUTOFMEMORY;
	}

	HRESULT hr;
	RETURN_IF_FAILED(hr, module->Initialize());

	*ppModule = module.release();
	return S_OK;
}

void JwtAuthenticationModuleFactory::Terminate()
{
	delete this;
}