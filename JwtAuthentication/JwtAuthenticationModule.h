#pragma once
#include "JwtAuthentication.h"

class JwtAuthenticationModule : public CHttpModule
{
	virtual REQUEST_NOTIFICATION_STATUS OnBeginRequest(_In_ IHttpContext* pHttpContext, _In_ IHttpEventProvider* pProvider);
};

