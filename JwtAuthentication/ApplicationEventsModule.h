#pragma once
#include "JwtAuthentication.h"

class ApplicationEventsModule : public CGlobalModule
{
public:
	virtual GLOBAL_NOTIFICATION_STATUS OnGlobalApplicationStart(_In_ IHttpApplicationStartProvider* pProvider);
	virtual void Terminate();
};

