#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"
#include "Utils/ScopedUnprotect.hpp"

// Based very heavily on a fix for a similar issue in NFS Underground 2
// https://github.com/ThirteenAG/WidescreenFixesPack/pull/1045
// by CrabJournal
namespace AffinityChanges
{
	DWORD_PTR gameThreadAffinity = 0;
	DWORD_PTR otherThreadsAffinity = 0;
	static bool Init()
	{
		DWORD_PTR processAffinity, systemAffinity;
		if (!GetProcessAffinityMask(GetCurrentProcess(), &processAffinity, &systemAffinity))
		{
			return false;
		}

		DWORD_PTR otherCoresAff = (processAffinity - 1) & processAffinity;
		if (otherCoresAff == 0) // Only one core is available for the game
		{
			return false;
		}
		gameThreadAffinity = processAffinity & ~otherCoresAff;
		otherThreadsAffinity = otherCoresAff;

		SetThreadAffinityMask(GetCurrentThread(), gameThreadAffinity);

		return true;
	}

	static BOOL WINAPI SetProcessAffinityMask_Stub(HANDLE /*hProcess*/, DWORD_PTR /*dwProcessAffinityMask*/)
	{
		return TRUE;
	}


	static decltype(::CreateThread)* orgCreateThread;
	static HANDLE WINAPI CreateThread_GameThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
		PVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
	{
		HANDLE hThread = orgCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, lpThreadId);
		if (hThread != nullptr)
		{
			SetThreadAffinityMask(hThread, gameThreadAffinity);
			if ((dwCreationFlags & CREATE_SUSPENDED) == 0) // Resume only if the game didn't pass CREATE_SUSPENDED
			{
				ResumeThread(hThread);
			}
		}
		return hThread;
	}

	static void ReplaceFunction_CreateThread(void** funcPtr)
	{
		DWORD dwProtect;

		auto func = reinterpret_cast<decltype(::CreateThread)**>(funcPtr);

		VirtualProtect(func, sizeof(*func), PAGE_READWRITE, &dwProtect);
		orgCreateThread = std::exchange(*func, &CreateThread_GameThread);
		VirtualProtect(func, sizeof(*func), dwProtect, &dwProtect);
	}

	static bool RedirectImports()
	{
		bool bCreateThreadRedirected = false;

		const DWORD_PTR instance = reinterpret_cast<DWORD_PTR>(GetModuleHandle(nullptr));
		const PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(instance + reinterpret_cast<PIMAGE_DOS_HEADER>(instance)->e_lfanew);

		// Find IAT
		PIMAGE_IMPORT_DESCRIPTOR pImports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(instance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for ( ; pImports->Name != 0; pImports++ )
		{
			if ( _stricmp(reinterpret_cast<const char*>(instance + pImports->Name), "kernel32.dll") == 0 )
			{
				if ( pImports->OriginalFirstThunk != 0 )
				{
					const PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(instance + pImports->OriginalFirstThunk);

					for ( ptrdiff_t j = 0; pThunk[j].u1.AddressOfData != 0; j++ )
					{
						if ( strcmp(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(instance + pThunk[j].u1.AddressOfData)->Name, "CreateThread") == 0 )
						{
							void** pAddress = reinterpret_cast<void**>(instance + pImports->FirstThunk) + j;
							ReplaceFunction_CreateThread(pAddress);
							bCreateThreadRedirected = true;
						}
					}
				}
				else
				{
					void** pFunctions = reinterpret_cast<void**>(instance + pImports->FirstThunk);

					for ( ptrdiff_t j = 0; pFunctions[j] != nullptr; j++ )
					{
						if ( pFunctions[j] == &CreateThread )
						{
							ReplaceFunction_CreateThread(&pFunctions[j]);
							bCreateThreadRedirected = true;
						}
					}
				}
			}
		}
		return bCreateThreadRedirected;
	}
}

namespace StreamThreadAffinity
{
	// StreamThread is an usercall with a parameter in eax
	static void* orgStreamThread;
	__declspec(naked) void StreamThread_Wrap()
	{
		void* eaxParam;
		_asm
		{
			push	ebp
			mov		ebp, esp
			sub		esp, __LOCAL_SIZE
			push	ebx
			push	ecx
			push	edx
			push	esi
			mov		[eaxParam], eax
		}
		SetThreadAffinityMask(GetCurrentThread(), AffinityChanges::gameThreadAffinity);
		_asm
		{
			mov		eax, [eaxParam]
			call	orgStreamThread

			pop		esi
			pop		edx
			pop		ecx
			pop		ebx
			mov		esp, ebp
			pop		ebp
			retn
		}
	}
}


void OnInitializeHook()
{
	using namespace Memory;
	using namespace hook::txn;

	auto Protect = ScopedUnprotect::UnprotectSectionOrFullModule(GetModuleHandle(nullptr), ".text");

	// TODO: Set that up only if SingleProcAffinity isn't 0
	if (AffinityChanges::Init())
	{
		bool bPinnedSpecificThreads = false;
		bool bModifiedImports = false;

		// NFS4: Try to pin only the stream decoding threads (main thread is already pinned)
		// If that fails, pin all game threads as fallback
		try
		{
			using namespace StreamThreadAffinity;

			// Make this pattern long to minimize the risk of false positives
			auto start_stream_thread = get_pattern<void*>("50 31 DB 89 48 54 6A FF B9 01 00 00 00 B8 ? ? ? ? E8 ? ? ? ? 85 C0", 6 + 2 + 5 + 1);

			orgStreamThread = *start_stream_thread;
			*start_stream_thread = StreamThread_Wrap;

			bPinnedSpecificThreads = true;
		}
		TXN_CATCH();

		if (!bPinnedSpecificThreads)
		{
			// As a fallback, pin ALL game threads instead of the ones we care about
			bModifiedImports = AffinityChanges::RedirectImports();
		}

		if (bPinnedSpecificThreads || bModifiedImports)
		{
			// Neuter SetProcessAffinityMask so Modern Patch or other solutions can't override
			// our more fine-grained changes
			Memory::VP::InjectHook(&SetProcessAffinityMask, AffinityChanges::SetProcessAffinityMask_Stub, HookType::Jump);
		}
	}
}
