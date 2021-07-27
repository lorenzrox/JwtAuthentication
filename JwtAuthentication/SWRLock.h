#pragma once
#include <synchapi.h>

class SRWExclusiveLock
{
public:
	SRWExclusiveLock(const SRWLOCK& lock) noexcept
		: m_lock(lock)
	{
		AcquireSRWLockExclusive(const_cast<SRWLOCK*>(&m_lock));
	}

	~SRWExclusiveLock()
	{
		ReleaseSRWLockExclusive(const_cast<SRWLOCK*>(&m_lock));
	}

private:
	const SRWLOCK& m_lock;
};

class SRWSharedLock
{
public:
	SRWSharedLock(const SRWLOCK& lock)
		: m_lock(lock)
	{
		AcquireSRWLockShared(const_cast<SRWLOCK*>(&m_lock));
	}

	~SRWSharedLock()
	{
		ReleaseSRWLockShared(const_cast<SRWLOCK*>(&m_lock));
	}

private:
	const SRWLOCK& m_lock;
};