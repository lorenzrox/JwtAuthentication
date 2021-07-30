#pragma once
#include <Windows.h>

struct Variant {
public:
	Variant() {
		VariantInit(&value);
	}

	~Variant() {
		VariantClear(&value);
	}

	Variant(Variant&& other) noexcept
		: value(other.value) {
		VariantInit(&other.value);
	}

	Variant(const Variant& other) {
		VariantCopy(&value, &other.value);
	}

	Variant& operator=(Variant&& other) noexcept {
		VariantClear(&value);

		value = other.value;

		VariantInit(&other.value);
		return *this;
	}

	Variant& operator=(const Variant& other) {
		VariantClear(&value);
		VariantCopy(&value, &other.value);
		return *this;
	}

	inline operator VARIANT& () noexcept {
		return value;
	}

	inline VARIANT* operator&() noexcept {
		VariantClear(&value);
		return &value;
	}

	inline const VARIANT& get() const noexcept {
		return value;
	}

	inline const VARIANT* operator->() const noexcept {
		return &value;
	}

private:
	VARIANT value;
};