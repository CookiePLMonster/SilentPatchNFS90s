#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"
#include "Utils/ScopedUnprotect.hpp"

// Macroes for Watcom register wrapper functions
#define WATCOM_PROLOG_0_PARAMS \
					_asm push ebp \
					_asm mov ebp, esp \
					_asm sub esp, __LOCAL_SIZE \
					_asm push ebx \
					_asm push ecx \
					_asm push edx \
					_asm push esi \
					_asm push edi


#define WATCOM_EPILOG_0_PARAMS \
					_asm pop edi \
					_asm pop esi \
					_asm pop edx \
					_asm pop ecx \
					_asm pop ebx \
					_asm mov esp, ebp \
					_asm pop ebp \
					_asm ret

#define WATCOM_PROLOG_1_PARAM \
					void* arg1; \
					WATCOM_PROLOG_0_PARAMS \
					_asm mov [arg1], eax

#define WATCOM_EPILOG_1_PARAM WATCOM_EPILOG_0_PARAMS


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
	// StreamThread_NFS2SE is a Watcom register call without parameters
	static void* orgStreamThread_NFS2SE;
	__declspec(naked) void StreamThread_NFS2SE_Wrap()
	{
		WATCOM_PROLOG_0_PARAMS;
		SetThreadAffinityMask(GetCurrentThread(), AffinityChanges::gameThreadAffinity);
		_asm call orgStreamThread_NFS2SE
		WATCOM_EPILOG_0_PARAMS;
	}

	// StreamThread_NFS4 is a Watcom register call with a parameter in eax
	static void* orgStreamThread_NFS4;
	__declspec(naked) void StreamThread_NFS4_Wrap()
	{
		WATCOM_PROLOG_1_PARAM;
		SetThreadAffinityMask(GetCurrentThread(), AffinityChanges::gameThreadAffinity);
		_asm
		{
			mov		eax, [arg1]
			call	orgStreamThread_NFS4
		}	
		WATCOM_EPILOG_1_PARAM;
	}
}


namespace NFS2SEMovieRaceFix
{
	static HANDLE startupEvent;
	void* orgCreateMutex;
	__declspec(naked) void* CreateMutex_SetUpStartupEvent()
	{
		WATCOM_PROLOG_0_PARAMS;

		startupEvent = CreateEvent(nullptr, FALSE, TRUE, nullptr);
		_asm call orgCreateMutex

		WATCOM_EPILOG_0_PARAMS;
	}

	__declspec(naked) void SignalStartup()
	{
		WATCOM_PROLOG_0_PARAMS;

		SetEvent(startupEvent);

		WATCOM_EPILOG_0_PARAMS;
	}

	__declspec(naked) void WaitForStartup()
	{
		WATCOM_PROLOG_0_PARAMS;

		WaitForSingleObject(startupEvent, INFINITE);
		CloseHandle(startupEvent);

		WATCOM_EPILOG_0_PARAMS;
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

		// NFS2SE: Try to pin only the stream decoding thread (main thread is already pinned)
		// If that fails, pin all game threads as fallback
		if (!bPinnedSpecificThreads) try
		{
			using namespace StreamThreadAffinity;

			// Make this pattern long to minimize the risk of false positives
			auto start_stream_thread = get_pattern<void*>("50 31 D2 B8 ? ? ? ? E8 ? ? ? ? 8B 86 A4 00 00 00", 3 + 1);

			orgStreamThread_NFS2SE = *start_stream_thread;
			*start_stream_thread = StreamThread_NFS2SE_Wrap;

			bPinnedSpecificThreads = true;
		}
		TXN_CATCH();

		// NFS4: Try to pin only the stream decoding threads (main thread is already pinned)
		// If that fails, pin all game threads as fallback
		if (!bPinnedSpecificThreads) try
		{
			using namespace StreamThreadAffinity;

			// Make this pattern long to minimize the risk of false positives
			auto start_stream_thread = get_pattern<void*>("50 31 DB 89 48 54 6A FF B9 01 00 00 00 B8 ? ? ? ? E8 ? ? ? ? 85 C0", 6 + 2 + 5 + 1);

			orgStreamThread_NFS4 = *start_stream_thread;
			*start_stream_thread = StreamThread_NFS4_Wrap;

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


	// NFS2SE: Fix a potential race on starting the movie decoding thread
	try
	{
		using namespace NFS2SEMovieRaceFix;

		auto create_event = get_pattern("89 86 A4 00 00 00 E8 ? ? ? ? 89 86 AC 00 00 00", 6);
		auto wait_on_event = get_pattern("8B 86 A4 00 00 00 E8 ? ? ? ? 89 F0", 6);
		auto signal_event = get_pattern("31 C0 E8 ? ? ? ? BF 01 00 00 00 31 ED", 2);

		InterceptCall(create_event, orgCreateMutex, CreateMutex_SetUpStartupEvent);
		InjectHook(wait_on_event, WaitForStartup);
		InjectHook(signal_event, SignalStartup);
	}
	TXN_CATCH();


	// NFS4: Fix jittery mouse
	try
	{
		auto get_device_data = get_pattern("83 7D F4 00 0F 84 ? ? ? ? 89 1D", 4 + 1);

		// je -> jge
		Patch<uint8_t>(get_device_data, 0x8D);
	}
	TXN_CATCH();
}
