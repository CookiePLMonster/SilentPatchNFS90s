#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"
#include "Utils/ScopedUnprotect.hpp"

#define DIRECTINPUT_VERSION 0x500
#include <dinput.h>

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

__declspec(naked) void NFS4_PollZeroEdi()
{
	// if (edi >= 0) edi = 0;
	_asm
	{
		mov		edi, eax
		sar		edi, 31
		and		edi, eax
		test	edi, edi
		ret
	}
}


namespace NFS5EnumDevices
{
	static HRESULT WINAPI EnumDInputDevices(LPDIRECTINPUTA dinput, DWORD /*dwDevType*/, LPDIENUMDEVICESCALLBACKA lpCallback, LPVOID pvRef, DWORD /*dwFlags*/)
	{
		// Instead of enumerating all devices, enumerate only keyboards and joysticks + only attached devices
		// Enumerated mice are ignored by the game so don't bother
		HRESULT hr = dinput->EnumDevices(DIDEVTYPE_KEYBOARD, lpCallback, pvRef, DIEDFL_ATTACHEDONLY);
		if (FAILED(hr))
		{
			return hr;
		}
		hr = dinput->EnumDevices(DIDEVTYPE_JOYSTICK, lpCallback, pvRef, DIEDFL_ATTACHEDONLY);
		if (FAILED(hr))
		{
			return hr;
		}

		return S_OK;
	}
	static const auto pEnumDInputDevices = &EnumDInputDevices;
	static const auto pFakeVMT = reinterpret_cast<uintptr_t>(&pEnumDInputDevices) - 0x10;
	__declspec(naked) void SetPtrToEnumDevices()
	{
		_asm
		{
			mov		[esp+14h-4], esi
			mov		ecx, [pFakeVMT]
			ret
		}
	}
}


namespace TextPasteSupport
{
	static std::string GetClipboardText(HWND hWnd)
	{
		std::string result;

		if (IsClipboardFormatAvailable(CF_TEXT))
		{
			if (OpenClipboard(hWnd))
			{
				HGLOBAL hClipboardText = GetClipboardData(CF_TEXT);
				if (hClipboardText != nullptr)
				{
					LPSTR lpStr = static_cast<LPSTR>(GlobalLock(hClipboardText));
					if (lpStr != nullptr)
					{
						result.assign(lpStr);
						GlobalUnlock(hClipboardText);
					}
				}

				CloseClipboard();
			}
		}

		return result;
	}

	static std::string currentClipboardText;
	static decltype(DefWindowProcA)* orgWndProc;
	LRESULT WINAPI WindowProc_PasteSupport_Delayed(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
	{
		auto sendChar = [=]
			{
				SendMessageA(hWnd, WM_CHAR, currentClipboardText.front(), 1);
				currentClipboardText.erase(currentClipboardText.begin());

				if (currentClipboardText.empty())
				{
					KillTimer(hWnd, reinterpret_cast<UINT_PTR>(&currentClipboardText));
				}
			};

		if (Msg == WM_CHAR)
		{
			if (wParam == 0x16) // Ctrl+V
			{
				currentClipboardText = GetClipboardText(hWnd);
				if (!currentClipboardText.empty())
				{
					SetTimer(hWnd, reinterpret_cast<UINT_PTR>(&currentClipboardText), 35, nullptr);
					sendChar();
				}
				else
				{
					KillTimer(hWnd, reinterpret_cast<UINT_PTR>(&currentClipboardText));
				}
				return 0;
			}
		}
		else if (Msg == WM_TIMER && wParam == reinterpret_cast<UINT_PTR>(&currentClipboardText))
		{
			sendChar();
		}
		return orgWndProc(hWnd, Msg, wParam, lParam);
	}

	// Used only by NFS Porsche
	static bool* gKeyboardBuffer;

	LRESULT WINAPI WindowProc_PasteSupport(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
	{
		if (Msg == WM_CHAR)
		{
			if (wParam == 0x16) // Ctrl+V
			{
				char lastCh = '\0';
				for (char ch : GetClipboardText(hWnd))
				{
					if (std::exchange(lastCh, ch) == ch)
					{
						// Send a "delimiter"
						SendMessageA(hWnd, WM_CHAR, '\x2', 1);
					}
					SendMessageA(hWnd, WM_CHAR, ch, 1);
				}
				return 0;
			}
		}
		// NFS Porsche only
		else if (Msg == WM_KILLFOCUS && gKeyboardBuffer != nullptr)
		{
			memset(gKeyboardBuffer, 0, 128);
		}
		return orgWndProc(hWnd, Msg, wParam, lParam);
	}

	static decltype(RegisterClassA)** pOrgRegisterClassA;
	ATOM WINAPI RegisterClassA_PasteSupport(const WNDCLASSA* lpWndClass)
	{
		orgWndProc = std::exchange(const_cast<WNDCLASSA*>(lpWndClass)->lpfnWndProc, WindowProc_PasteSupport);
		return (*pOrgRegisterClassA)(lpWndClass);
	}
	static auto* pRegisterClassA_PasteSupport = &RegisterClassA_PasteSupport;
}


// I'm pretty sure Verok's thrash drivers used to be open source, but I can't find them anymore...
namespace OGLThrashDriverLeak
{
	static decltype(::free)** pOrgThrashDriverFree;
	static decltype(::free)** pOrgThrashDriverFreeFunc;
	static void ThrashDriverFree(void* data)
	{
		if (*pOrgThrashDriverFreeFunc != nullptr)
		{
			(*pOrgThrashDriverFreeFunc)(data);
		}
		else
		{
			(*pOrgThrashDriverFree)(data);
		}
	}

	static void* pLastUnlockedRect = nullptr;
	static void (__thiscall *orgThrashUnlockWindow_Internal)(void* pThis);
	static void __fastcall ThrashUnlockWindow_Internal_LeakFix(void* pThis)
	{
		orgThrashUnlockWindow_Internal(pThis);

		void* lastRect = std::exchange(pLastUnlockedRect, pThis);
		if (lastRect != nullptr)
		{
			void* pBuffer = *static_cast<void**>(lastRect);
			ThrashDriverFree(pBuffer);
			ThrashDriverFree(lastRect);
		}
	}

	static decltype(LoadLibraryA)** pOrgLoadLibraryA;
	HMODULE WINAPI LoadLibraryA_FixThrashDriver(LPCSTR lpLibFileName)
	{
		HMODULE hThrashDriver = (*pOrgLoadLibraryA)(lpLibFileName);
		if (hThrashDriver != nullptr)
		{
			using namespace Memory::VP;
			using namespace hook::txn;

			try
			{
				auto org_free = make_module_pattern(hThrashDriver, "FF 15 ? ? ? ? 83 C4 04 FF 74 24").get_first<decltype(::free)**>(2);
				auto org_free_func = make_module_pattern(hThrashDriver, "A1 ? ? ? ? 56 85 C0 74 04 FF D0").get_first<decltype(::free)**>(1);
				auto unlockwindow_internal = make_module_pattern(hThrashDriver, "8B 4D 08 E8 ? ? ? ? A1").get_first<void>(3);

				pOrgThrashDriverFree = *org_free;
				pOrgThrashDriverFreeFunc = *org_free_func;
				InterceptCall(unlockwindow_internal, orgThrashUnlockWindow_Internal, ThrashUnlockWindow_Internal_LeakFix);
			}
			TXN_CATCH();
		}
		return hThrashDriver;
	}
	static auto* pLoadLibraryA_FixThrashDriver = &LoadLibraryA_FixThrashDriver;
}

namespace KeybdEventStub
{
	void WINAPI keybd_event_Stub(BYTE /*bVk*/, BYTE /*bScan*/, DWORD /*dwFlags*/, ULONG_PTR /*dwExtraInfo*/)
	{

	}

	static void ReplaceFunction(void** funcPtr)
	{
		DWORD dwProtect;

		auto func = reinterpret_cast<decltype(::keybd_event)**>(funcPtr);

		VirtualProtect(func, sizeof(*func), PAGE_READWRITE, &dwProtect);
		*func = &keybd_event_Stub;
		VirtualProtect(func, sizeof(*func), dwProtect, &dwProtect);
	}

	static void RedirectImports()
	{
		const DWORD_PTR instance = reinterpret_cast<DWORD_PTR>(GetModuleHandle(nullptr));
		const PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(instance + reinterpret_cast<PIMAGE_DOS_HEADER>(instance)->e_lfanew);

		// Find IAT
		PIMAGE_IMPORT_DESCRIPTOR pImports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(instance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for ( ; pImports->Name != 0; pImports++ )
		{
			if ( _stricmp(reinterpret_cast<const char*>(instance + pImports->Name), "user32.dll") == 0 )
			{
				if ( pImports->OriginalFirstThunk != 0 )
				{
					const PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(instance + pImports->OriginalFirstThunk);

					for ( ptrdiff_t j = 0; pThunk[j].u1.AddressOfData != 0; j++ )
					{
						if ( strcmp(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(instance + pThunk[j].u1.AddressOfData)->Name, "keybd_event") == 0 )
						{
							void** pAddress = reinterpret_cast<void**>(instance + pImports->FirstThunk) + j;
							ReplaceFunction(pAddress);
							return;
						}
					}
				}
				else
				{
					void** pFunctions = reinterpret_cast<void**>(instance + pImports->FirstThunk);

					for ( ptrdiff_t j = 0; pFunctions[j] != nullptr; j++ )
					{
						if ( pFunctions[j] == &keybd_event )
						{
							ReplaceFunction(&pFunctions[j]);
							return;
						}
					}
				}
			}
		}
	}
}

void OnInitializeHook()
{
	using namespace Memory;
	using namespace hook::txn;

	auto Protect = ScopedUnprotect::UnprotectSectionOrFullModule(GetModuleHandle(nullptr), ".text");

	// Make games not disable Num Lock/Caps Lock/Scroll Lock
	KeybdEventStub::RedirectImports();

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


	// NFS3: Fix jittery mouse
	try
	{
		auto get_device_data = get_pattern("FF 51 28 85 C0 0F 84 ? ? ? ? 31 D2 8B 4D FC", 5 + 1);

		// je -> jge
		Patch<uint8_t>(get_device_data, 0x8D);
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

	
	// NFS2SE/NFS3: Make IDirectInputDevice::Poll() not treat non-zero success codes as errors
	try
	{
		auto poll = get_pattern("FF 52 64 85 C0 74 ? 3D 1E 00 07 80", 3 + 2);

		// je -> jge
		Patch<uint8_t>(poll, 0x7D);
	}
	TXN_CATCH();


	// NFS4: Make IDirectInputDevice::Poll() not treat non-zero success codes as errors
	try
	{
		auto poll = get_pattern("8B 7D F4 85 FF 74 ? 81 7D F4 1E 00 07 80");

		// 'flatten' edi not to contain positive numbers
		InjectHook(poll, NFS4_PollZeroEdi, HookType::Call);
	}
	TXN_CATCH();


	// NFS2SE/NFS4: Re-enable Alt+F4
	try
	{
		auto wm_keydown = get_pattern("B8 01 00 00 00 5F 5E 5B C2 18 00");

		// xor eax, eax \ nop
		Patch(wm_keydown, {0x31, 0xC0, 0x90, 0x90, 0x90});
	}
	TXN_CATCH();


	// NFS3: Re-enable Alt+F4
	try
	{
		auto wm_keydown = get_pattern("83 E3 01 E8 ? ? ? ? EB ? B8 01 00 00 00 5D 5F 5E 5B C2 18 00", 3 + 5 + 2);

		// xor eax, eax \ nop
		Patch(wm_keydown, {0x31, 0xC0, 0x90, 0x90, 0x90});
	}
	TXN_CATCH();


	// NFS Porsche: Re-enable Alt+F4
	try
	{
		auto wm_keydown = pattern("5F 5E B8 01 00 00 00 5B C2 18 00").count(2);
		wm_keydown.for_each_result([](pattern_match match)
		{
			// xor eax, eax \ nop
			Patch(match.get<void>(2), {0x31, 0xC0, 0x90, 0x90, 0x90});
		});
	}
	TXN_CATCH();


	// NFS Porsche: Fix device enumeration to only enumerate keyboard and joysticks AND only attached devices
	try
	{
		using namespace NFS5EnumDevices;

		auto enum_devices = pattern("56 52 89 74 24 0C 8B 08").get_one();

		Nop(enum_devices.get<void>(2), 1);
		InjectHook(enum_devices.get<void>(3), SetPtrToEnumDevices, HookType::Call);
	}
	TXN_CATCH();


	// NFS2SE: Fix Verok's Modern Patch using splitscreen viewport dimensions for multiplayer
	HMODULE modernPatchModule;
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"nfs2se.p", &modernPatchModule) != FALSE)
	{			
		// Rebuild a "damaged" SetViewports function and apply the 1px splitscreen seam fix in a less invasive way
		try
		{
			auto broken_set_viewports = pattern("E9 ? ? ? ? ? ? ? ? ? 75 6B 68 F0 00 00 00").get_one();

			// Only patch if it's calling into Modern Patch DLL, in case somebody else is also re-routing this function
			uintptr_t reroutedCall;
			ReadCall(broken_set_viewports.get<void>(), reroutedCall);
			HMODULE reroutedCallModule;
			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCTSTR>(reroutedCall), &reroutedCallModule) != FALSE
				&& modernPatchModule == reroutedCallModule)
			{
				// push ebx
				// push ecx
				// push edx
				// cmp [gameMode], 1
				Patch(broken_set_viewports.get<void>(), {0x53, 0x51, 0x52, 0x83, 0x3D});

				// Patch the argument in the stock function instead
				Patch<uint32_t>(broken_set_viewports.get<void>(0x1A + 1), 241);
			}
		}
		TXN_CATCH();

		// Fixup gameMode != 0 into gameMode == 1 in an unknown function inside the Modern Patch
		try
		{
			auto cmp_game_mode = make_module_pattern(modernPatchModule, "83 39 00 74 07 FE C0").get_one();

			// cmp [ecx], 0 \ jz
			// ->
			// cmp [ecx], 1 \ jnz
			Memory::VP::Patch(cmp_game_mode.get<void>(2), {0x1, 0x75});
		}
		TXN_CATCH()
	}


	// NFS2SE: Basic text paste support
	try
	{
		using namespace TextPasteSupport;

		auto wnd_proc = get_pattern<decltype(DefWindowProcA)*>("BA ? ? ? ? 8B 3D ? ? ? ? 31 C9 89 04 24", 1);

		orgWndProc = *std::exchange(*wnd_proc, WindowProc_PasteSupport_Delayed);
	}
	TXN_CATCH();


	// NFS3: Basic text paste support
	try
	{
		using namespace TextPasteSupport;

		auto wnd_proc = get_pattern<decltype(DefWindowProcA)*>("C7 45 ? ? ? ? ? 89 75 CC FF 35", 3);

		orgWndProc = *std::exchange(*wnd_proc, WindowProc_PasteSupport);
	}
	TXN_CATCH();


	// NFS4: Basic text paste support
	try
	{
		using namespace TextPasteSupport;

		auto wnd_proc = get_pattern<decltype(DefWindowProcA)*>("B9 0B 00 00 00 BE ? ? ? ? A1 ? ? ? ? 8B 15 ? ? ? ? 31 FF", 5 + 1);

		orgWndProc = *std::exchange(*wnd_proc, WindowProc_PasteSupport);
	}
	TXN_CATCH();


	// NFS Porsche: Basic text paste support
	try
	{
		// Modern Patch overwrites WndProc and doesn't call back to the original function - so hook RegisterClass instead
		using namespace TextPasteSupport;

		auto register_class = get_pattern<decltype(RegisterClassA)**>("89 44 24 50 FF 15 ? ? ? ? 66 85 C0", 4 + 2);

		pOrgRegisterClassA = std::exchange(*register_class, &pRegisterClassA_PasteSupport);

		// NFS Porsche: Clear the keyboard input buffer on WM_KILLFOCUS
		// Fixes an issue potentially introduced by Modern Patch where the keyboard buffer doesn't get cleared on Alt+Tab
		try
		{
			auto keyboard_buffer = *get_pattern<bool*>("68 ? ? ? ? E8 ? ? ? ? 8B 54 24 28 8B 44 24 20", 1);

			gKeyboardBuffer = keyboard_buffer;
		}
		TXN_CATCH();
	}
	TXN_CATCH();


	// NFS Porsche: Fix a memory leak in Verok's thrash drivers causing crashes in multiplayer
	try
	{
		using namespace OGLThrashDriverLeak;

		auto load_library = get_pattern<decltype(LoadLibraryA)**>("8B 35 ? ? ? ? 83 C4 0C 8D 4C 24 14", 2);

		pOrgLoadLibraryA = std::exchange(*load_library, &pLoadLibraryA_FixThrashDriver);
	}
	TXN_CATCH();
}
