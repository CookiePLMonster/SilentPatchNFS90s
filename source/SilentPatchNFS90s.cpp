#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"
#include "Utils/ScopedUnprotect.hpp"

#include <filesystem>

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


// INI file stuff
bool ShouldEnableAffinityChanges()
{
	// Try Modern Patch INI files - INI file named like the EXE + section name as the EXE's stem
	wchar_t exePath[MAX_PATH];
	GetModuleFileNameW(GetModuleHandle(nullptr), exePath, MAX_PATH);
	std::filesystem::path exeFSPath(exePath);
	const std::wstring section = exeFSPath.stem().wstring();
	const std::wstring iniPath = exeFSPath.replace_extension(L".ini").wstring();

	const UINT singleProcAffinity = GetPrivateProfileIntW(section.c_str(), L"SingleProcAffinity", -1, iniPath.c_str());
	if (singleProcAffinity != -1)
	{
		if (singleProcAffinity != 0)
		{
			// Don't enable our changes if they're specifically requested to be disabled
			const UINT spAffinity = GetPrivateProfileIntW(section.c_str(), L"SilentPatchAffinity", -1, iniPath.c_str());
			return spAffinity != 0;
		}
	}
	return false;
}


// Based very heavily on a fix for a similar issue in NFS Underground 2
// https://github.com/ThirteenAG/WidescreenFixesPack/pull/1045
// by CrabJournal
namespace AffinityChanges
{
	DWORD_PTR gameThreadAffinity = 0;
	DWORD_PTR otherThreadsAffinity = 0;
	static bool Init()
	{
		const HANDLE currentProcess = ::GetCurrentProcess();
		DWORD_PTR processAffinity, systemAffinity;
		if (!::GetProcessAffinityMask(currentProcess, &processAffinity, &systemAffinity))
		{
			return false;
		}

		DWORD_PTR otherCoresAff = (systemAffinity - 1) & systemAffinity;
		if (otherCoresAff == 0) // Only one core is available for the game
		{
			return false;
		}
		gameThreadAffinity = systemAffinity & ~otherCoresAff;
		otherThreadsAffinity = otherCoresAff;

		// NFS2SE Modern Patch overrides affinity before we can prevent it
		::SetProcessAffinityMask(currentProcess, systemAffinity);
		::SetThreadAffinityMask(GetCurrentThread(), gameThreadAffinity);

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


__declspec(naked) void NFS2SE_MouseZeroEax()
{
	_asm
	{
		mov		ebx, ecx
		shl		ebx, 4
		xor		eax, eax
		xor		edx, edx
		ret
	}
}


void OnInitializeHook()
{
	using namespace Memory;
	using namespace hook::txn;

	auto Protect = ScopedUnprotect::UnprotectSectionOrFullModule(GetModuleHandle(nullptr), ".text");

	if (ShouldEnableAffinityChanges() && AffinityChanges::Init())
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
			Memory::VP::InjectHook(&::SetProcessAffinityMask, AffinityChanges::SetProcessAffinityMask_Stub, HookType::Jump);
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


	// NFS2SE: Fix jittery mouse
	try
	{
		auto get_device_data = get_pattern("8B 10 50 FF 52 28 89 C2 85 C0 0F 85", 10 + 1);
		auto zero_eax = get_pattern("89 CB C1 E3 04");

		// jne -> js
		Patch<uint8_t>(get_device_data, 0x88);
		// Add xor eax, eax
		InjectHook(zero_eax, NFS2SE_MouseZeroEax, HookType::Call);
	}
	TXN_CATCH();


	// NFS2SE: Fix button bitmask being used as a button count, making gamepad mappings impossible
	try
	{
		auto inc_bitmask = get_pattern("8B 90 ? ? ? ? D3 E7 09 FA 89 90", 6);

		// shl edi, cl \ or edx, edi -> inc edx \ nop
		Patch(inc_bitmask, {0x42, 0x90, 0x90, 0x90});
	}
	TXN_CATCH();


	// NFS2SE: Prevent the game from panicking when the controller disconnects
	try
	{
		// Simplify the error handling function into just
		// return code >= 0;
		auto on_acquire_error = get_pattern("85 C0 74 16 83 F8 01 74 10 3D 57 00 07 80");

		// not eax
		// shr eax, 31
		// ret
		Patch(on_acquire_error, {0xF7, 0xD0, 0xC1, 0xE8, 0x1F, 0xC3});
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
