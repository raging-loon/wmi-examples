#ifndef INTERFACE_PTR_H_
#define INTERFACE_PTR_H_

#include <WbemIdl.h>
#include <type_traits>

static unsigned int s_instances = 0;

template <class T>
concept interface_has_release = requires(T t) {
	{ t.Release() } -> std::same_as<ULONG>;
};

template <class T> requires interface_has_release<T>
class InterfacePtr
{
public:
	InterfacePtr() : m_ptr{ nullptr } { s_instances++; }
	InterfacePtr(T* other) : m_ptr(other) { s_instances++;}
	
	~InterfacePtr() {
		if(m_ptr) {
			m_ptr->Release();
			m_ptr = nullptr;

		}
		s_instances--;
		if (s_instances == 0)
			CoUninitialize();
	}

    T* Get() { return m_ptr; }
	T** GetAddressOf() { return &m_ptr; }
	
	T* operator->() { return m_ptr; }
	T& operator*() { assert(m_ptr); return *m_ptr; }
	
private:
	T* m_ptr;
};

#endif // INTERFACE_PTR_H_