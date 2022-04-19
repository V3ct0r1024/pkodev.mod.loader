#include <Windows.h>
#include <detours.h>

#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <string>

#include "loader.h"

namespace pkodev
{
	// Define some useful types
	typedef int(__cdecl* mainCRTStartup__Ptr)();            // Pointer to mainCRTStartup() function from .exe
	typedef void(__stdcall* RtlExitUserProcess__Ptr)(UINT); // Pointer to RtlExitUserProcess() function from ntdll.dll

	// Destination .exe data
	struct exe_ver
	{
		// ID
		unsigned int id;

		// Name
		std::string name;

		// Linker timestamp
		unsigned int timestamp;

		// Constructor
		exe_ver() :
			id(0),
			name(""),
			timestamp(0)
		{

		}

		// Constructor
		exe_ver(unsigned int id_, const std::string& name_, unsigned int timestamp_) :
			id(id_),
			name(name_),
			timestamp(timestamp_)
		{

		}
	};

	// Some information about a mod
	struct mod
	{
		// Name of a mod
		std::string name;

		// Version of the mod
		std::string version;

		// The mod author
		std::string author;

		// Path to DLL
		std::string path;

		// Enable mod function pointer
		Start__Ptr start;

		// Disable mod function pointer
		Stop__Ptr stop;

		// .dll handle
		HMODULE handle;

		// Constructor
		mod() :
			name(""),
			version(""),
			author(""),
			path(""),
			start(nullptr),
			stop(nullptr),
			handle(NULL)
		{

		}
	};

	namespace global
	{
		// Pointer to mainCRTStartup() function from .exe
		mainCRTStartup__Ptr mainCRTStartup = nullptr;

		// Pointer to RtlExitUserProcess function from ntdll.dll
		RtlExitUserProcess__Ptr RtlExitUserProcess = nullptr;

		// Linker timestamp
		unsigned int TimeDateStamp = 0;

		// List of supported .exe files
		std::vector<exe_ver> exes;

		// List of available mods
		std::vector<mod> mods;
	}
}

// Start mod system
void Start();

// Stop mod system
void Stop();

// Search mod libraries
void SearchLibraries(const std::string& path, std::vector<std::string>& arr);

// Hooked version of mainCRTStartup() function
int __cdecl mainCRTStartup();

// Hooked version of RtlExitUserProcess() function
void __stdcall RtlExitUserProcess(UINT code);


// Dummy function for export to GameServer.exe and Game.exe
__declspec(dllexport) void __cdecl ExportedFunction() {}

// Entry point
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
		// DLL attached to the proccess
        case DLL_PROCESS_ATTACH:

			// Get address of entry point and linker timestamp
			{
				// Pointers to DOS, PE and COFF headers of .exe file
				const PIMAGE_DOS_HEADER pidh = reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleHandle(NULL));
				const PIMAGE_NT_HEADERS pinh = reinterpret_cast<PIMAGE_NT_HEADERS>( (reinterpret_cast<BYTE*>(pidh) + pidh->e_lfanew) );
				const PIMAGE_FILE_HEADER pifh = reinterpret_cast<PIMAGE_FILE_HEADER>(&pinh->FileHeader);

				// Get pointer to mainCRTStartup() function
				pkodev::global::mainCRTStartup = reinterpret_cast<pkodev::mainCRTStartup__Ptr>(
					( pinh->OptionalHeader.AddressOfEntryPoint + pinh->OptionalHeader.ImageBase )
				);

				// Get linker timestamp
				pkodev::global::TimeDateStamp = static_cast<unsigned int>(pifh->TimeDateStamp);
			}

			// Get address of RtlExitUserProcess() function
			{
				// Get handle of module ntdll
				const HMODULE hmodntdll = GetModuleHandleA("ntdll");

				// Check the modult handle
				if (hmodntdll != NULL)
				{
					// Get pointer to RtlExitUserProcess() function
					pkodev::global::RtlExitUserProcess = reinterpret_cast<pkodev::RtlExitUserProcess__Ptr>(
						GetProcAddress(hmodntdll, "RtlExitUserProcess")
					);
				}
			}

			// Enable hooks
			if ( (pkodev::global::mainCRTStartup != nullptr)
				&& (pkodev::global::RtlExitUserProcess != nullptr) )
			{
				DetourRestoreAfterWith();
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(&(PVOID&)pkodev::global::mainCRTStartup, mainCRTStartup);
				DetourAttach(&(PVOID&)pkodev::global::RtlExitUserProcess, RtlExitUserProcess);
				DetourTransactionCommit();
			}

            break;

		// DLL detached from the proccess
        case DLL_PROCESS_DETACH:

			// Disable hooks
			if ( (pkodev::global::mainCRTStartup != nullptr)
				&& (pkodev::global::RtlExitUserProcess != nullptr) )
			{
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourDetach(&(PVOID&)pkodev::global::mainCRTStartup, mainCRTStartup);
				DetourDetach(&(PVOID&)pkodev::global::RtlExitUserProcess, RtlExitUserProcess);
				DetourTransactionCommit();
			}

            break;
    }

    return TRUE;
}

// Hooked version of mainCRTStartup() function
int __cdecl mainCRTStartup()
{
	// Launch mod system
	Start();

	// Call original entry point
	return pkodev::global::mainCRTStartup();
}

// Hooked version of RtlExitUserProcess() function
void __stdcall RtlExitUserProcess(UINT code)
{
	// Stop mod system
	Stop();

	// Call original exit proccess function
	pkodev::global::RtlExitUserProcess(code);
}

// Start mod system
void Start()
{
	// Build supported executables files table
	pkodev::global::exes.clear();
	pkodev::global::exes.push_back( { GAMESERVER_136, "GameServer 1.36",       1204708785 } );
	pkodev::global::exes.push_back( { GAMESERVER_138, "GameServer 1.38",       1225867911 } );
	pkodev::global::exes.push_back( { GAME_13X_0,     "Game.exe 1.3x (ID: 0)", 1222073761 } );
	pkodev::global::exes.push_back( { GAME_13X_1,     "Game.exe 1.3x (ID: 1)", 1243412597 } );
	pkodev::global::exes.push_back( { GAME_13X_2,     "Game.exe 1.3x (ID: 2)", 1252912474 } );
	pkodev::global::exes.push_back( { GAME_13X_3,     "Game.exe 1.3x (ID: 3)", 1244511158 } );
	pkodev::global::exes.push_back( { GAME_13X_4,     "Game.exe 1.3x (ID: 4)", 1585009030 } );
	pkodev::global::exes.push_back( { GAME_13X_5,     "Game.exe 1.3x (ID: 5)", 1207214236 } );
	pkodev::global::exes.push_back( { GATESERVER_138, "GateServer 1.38",       1224838480 } );

	// Write a welcome message
	std::cout << "[pkodev.mod.loader] -----------------------------------------------" << std::endl;
	std::cout << "[pkodev.mod.loader]    PKOdev.NET mod loader ver. 1.0 by V3ct0r    " << std::endl;
	std::cout << "[pkodev.mod.loader] -----------------------------------------------" << std::endl;

	// Search current .exe in list of supported executables
	auto exe = std::find_if(
		pkodev::global::exes.begin(),
		pkodev::global::exes.end(),
		[](const pkodev::exe_ver& exe)
		{
			return ( pkodev::global::TimeDateStamp == exe.timestamp );
		}
	);

	// Check that .exe is supported
	if ( exe == pkodev::global::exes.end() )
	{
		// Unsupported .exe version!
		std::cout << "[pkodev.mod.loader] Unsupported .exe file!" << std::endl << std::endl;
		return;
	}

	// Write .exe version
	std::cout << "[pkodev.mod.loader] Detected .exe file: '" << exe->name << "'." << std::endl;

	// Write a message
	std::cout << "[pkodev.mod.loader] Searching mods in 'mods' directory . . ." << std::endl;

	// Search mods
	std::vector<std::string> arr;  // List of dynamic mod libraries
	SearchLibraries("mods", arr);

	// Load mods . . .
	for (const std::string& path : arr)
	{
		// Load current .dll
		HMODULE dll = LoadLibraryA(path.c_str());

		// Check result
		if (dll == NULL)
		{
			// Failed to load the .dll!
			continue;
		}

		// Import GetModInformation() function
		GetModInfo__Ptr GetModInformation = reinterpret_cast<GetModInfo__Ptr>(
			GetProcAddress(dll, "GetModInformation")
		);

		// Import Start() function
		Start__Ptr Start = reinterpret_cast<Start__Ptr>(
			GetProcAddress(dll, "Start")
		);

		// Import Stop() function
		Stop__Ptr Stop = reinterpret_cast<Stop__Ptr>(
			GetProcAddress(dll, "Stop")
		);

		// Check functions
		if ( (GetModInformation == NULL) || (Start == NULL) || (Stop == NULL) )
		{
			// DLL doesn't have required functions
			FreeLibrary(dll);
			continue;
		}

		// Get mod information
		mod_info info;             // Mod information structure
		GetModInformation(info); 

		// Check .exe version
		if (info.exe_version != exe->id)
		{
			// Unsupported mod version 
			FreeLibrary(dll);
			continue;
		}

		// Search mod in list of loaded mods
		auto it = std::find_if(
			pkodev::global::mods.begin(),
			pkodev::global::mods.end(),
			[&info](const pkodev::mod& mod)
			{
				return ( mod.name == std::string(info.name) );
			}
		);

		// Check that mod is not already loaded
		if ( it != pkodev::global::mods.end() )
		{
			// Mod is already loaded
			FreeLibrary(dll);
			continue;
		}

		// Create mod record
		pkodev::mod mod;
		mod.name    = std::string(info.name);
		mod.version = std::string(info.version);
		mod.author  = std::string(info.author);
		mod.path    = path;
		mod.start   = Start;
		mod.stop    = Stop;
		mod.handle  = dll;

		// Add mod to the list
		pkodev::global::mods.push_back(mod);
	}

	// Print found mods
	if ( pkodev::global::mods.empty() == false )
	{
		// Mods counter
		unsigned int counter = 0;

		// Print number of mods found 
		std::cout << "[pkodev.mod.loader] Done! (" << pkodev::global::mods.size() << ") mods found out: " << std::endl;

		// Print table header
		std::cout << '+' << std::setfill('-') << std::setw(5) << '+'  <<        std::setw(33) << '+'    <<        std::setw(11) << '+'        <<        std::setw(17) << '+'              << std::endl;
		std::cout << '|' << std::setfill(' ') << std::setw(4) << "# " << '|' << std::setw(32) << "Mod " << '|' << std::setw(10) << "Version " << '|' << std::setw(16) << "Author " << '|' << std::endl;
		std::cout << '+' << std::setfill('-') << std::setw(5) << '+'  <<        std::setw(33) << '+'    <<        std::setw(11) << '+'        <<        std::setw(17) << '+'              << std::endl;

		// Print mods
		for (const pkodev::mod& mod : pkodev::global::mods)
		{
			// Print information about the mod
			std::cout << '|' << std::setfill(' ') << std::setw(3) << ++counter << '.' << '|' << std::setw(31) << mod.name << ' ' << '|' << std::setw(9) << mod.version << ' ' << '|' << std::setw(15) << mod.author << ' ' << '|' << std::endl;
		}

		// Print table bottom
		std::cout << '+' << std::setfill('-') << std::setw(5) << '+' << std::setw(33) << '+' << std::setw(11) << '+' << std::setw(17) << '+' << std::endl;
	}
	else
	{
		// Write a message that mods not found
		std::cout << "[pkodev.mod.loader] Mods not found." << std::endl << std::endl;
		return;
	}

	// Write a message that mods are being launched
	std::cout << "[pkodev.mod.loader] Launching mods . . ." << std::endl;

	// Start mods
	for (const pkodev::mod& mod : pkodev::global::mods)
	{
		// Extract directory from path
		auto extract_filepath = [](const std::string& path) -> std::string
		{
			// Looking for last slash
			std::size_t pos = path.find_last_of("/\\");

			// Check that the slash is found
			if (pos != std::string::npos)
			{
				// Extract directory
				return path.substr(0, pos);
			}

			// Could not extract directory
			return path;
		};
		
		// Launch the mod
		if (mod.start != nullptr)
		{
			mod.start( extract_filepath(mod.path).c_str() );
		}
	}

	// Write a message that mods are launched
	std::cout << "[pkodev.mod.loader] All mods launched!" << std::endl << std::endl;
}

// Stop mod loader
void Stop()
{
	// Disable all mods
	for (pkodev::mod& mod : pkodev::global::mods)
	{
		// Disable the mod
		if (mod.stop != nullptr)
		{
			// Call Stop() function from mod .dll
			mod.stop();
		}
		
		// Unload mod .dll
		FreeLibrary(mod.handle);

		// Write a message that mod is unloaded
		std::cout << "[pkodev.mod.loader] " << mod.name << " successfully unloaded!" << std::endl;
	}

	// Clear mods list
	pkodev::global::mods.clear();
}

// Search mod libraries
void SearchLibraries(const std::string& path, std::vector<std::string>& arr)
{
	// Path buffer
	char buf[MAX_PATH]{ 0x00 };

	// Build current path
	sprintf_s(buf, sizeof(buf), "%s\\*", path.c_str());

	// Information about the file that is found
    WIN32_FIND_DATAA FindFileData;

	// Open search handle and start search files
    HANDLE hFind = FindFirstFileA(buf, &FindFileData);


	// Check that function FindFirstFileA() succeeds
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			// Convert char* string to std::string
			std::string file(FindFileData.cFileName);
			
			// Check that file is a directory
			if ( FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
			{
				// Skipping files "." and ".."
				if ( (file == ".") || (file == "..") )
				{
					// Skip file
					continue;
				}
				
				// Build current path
				sprintf_s(buf, sizeof(buf), "%s\\%s", path.c_str(), file.c_str());
				
				// Recursively search files in the directory
				SearchLibraries(buf, arr);
			}
			else
			{
				// Check that file name contains five dots
				if ( std::count(file.begin(), file.end(), '.') != 5 )
				{
					// Skip file
					continue;
				}

				// Make file name lower case
				std::transform(file.begin(), file.end(), file.begin(), ::tolower);

				// Check that name starts from string "pkodev.mod."
				if ( file.find("pkodev.mod.") != 0 )
				{
					// Skip file
					continue;
				}

				// Get file extension
				if ( file.substr( file.find_last_of(".") ) != ".dll" )
				{
					// Skip file
					continue;
				}

				// Build full file path
				sprintf_s(buf, sizeof(buf), "%s\\%s", path.c_str(), file.c_str());

				// Add the file to list
				arr.push_back(buf);
			}
		} 
		while ( FindNextFileA(hFind, &FindFileData) == TRUE );
	}

	// Close search handle
	FindClose(hFind);
}