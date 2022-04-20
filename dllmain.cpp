#include <Windows.h>
#include <detours.h>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <queue>
#include <string>
#include <regex>
#include <algorithm>
#include <cctype>

#include "loader.h"

namespace pkodev
{
	// Define some useful types
	typedef int(__cdecl* mainCRTStartup__Ptr)();            // Pointer to mainCRTStartup() function from .exe
	typedef void(__stdcall* RtlExitUserProcess__Ptr)(UINT); // Pointer to RtlExitUserProcess() function from ntdll.dll

	// Destination executable file (Game.exe/GameServer.exe/GateServer.exe) data
	struct executable_version
	{
		// ID from loader.h file
		unsigned int id;

		// Linker build timestamp
		unsigned int timestamp;

		// Human name
		std::string name;

		// Constructor
		executable_version() :
			id(EXE_UNKNOWN),
			timestamp(0),
			name("EXE_UNKNOWN")
		{

		}

		// Constructor
		executable_version(unsigned int id_, unsigned int timestamp_, const std::string& name_) :
			id(id_),
			timestamp(timestamp_),
			name(name_)
		{

		}
	};

	// pkodev.mod data
	struct pkodev_mod
	{
		// Load priority
		unsigned int priority;

		// Name of the mod
		std::string name;

		// Version of the mod
		std::string version;

		// Author of the mod
		std::string author;

		// Path to the mod DLL
		std::string path;

		// Enable mod function pointer
		Start__Ptr start;

		// Disable mod function pointer
		Stop__Ptr stop;

		// The mod .dll handle
		HMODULE handle;

		// Constructor
		pkodev_mod() :
			priority(UINT32_MAX),
			name(""),
			version(""),
			author(""),
			path(""),
			start(nullptr),
			stop(nullptr),
			handle(nullptr)
		{

		}
	};

	// Regular expression for a mod name
	const std::regex name_regex("^pkodev\\.mod\\.\\w+$", std::regex::icase); // pkodev.mod.<name>

	// Regular expression for a mod library name (.dll)
	const std::regex dll_regex(                                              // pkodev.mod.<name>.<client|server|gate>.<ver>.dll
		"^pkodev\\.mod\\.\\w+\\.(?:client|server|gate)\\.\\w+\\.dll$",
		std::regex::icase
	);

	// Pointer to the mainCRTStartup() function from destination executable file
	mainCRTStartup__Ptr mainCRTStartup = nullptr;

	// Pointer to the RtlExitUserProcess function from ntdll.dll
	RtlExitUserProcess__Ptr RtlExitUserProcess = nullptr;

	// Linker build timestamp
	unsigned int TimeDateStamp = 0;

	// List of available mods
	std::vector<pkodev_mod> mods;
}

// Start the mod loader system
void Start();

// Stop the mod loader system
void Stop();

// Search mod libraries
void SearchLibraries(const std::string& path, std::vector<std::string>& arr);

// Load the list of disabled mods (.disabled)
void LoadDotDisabled(const std::string& path, std::vector<std::string>& disabled);

// Load the mod priority list (.priority)
void LoadDotPriority(const std::string& path, std::queue<std::string>& priority);

// Hooked version of mainCRTStartup() function
int __cdecl mainCRTStartup();

// Hooked version of RtlExitUserProcess() function
void __stdcall RtlExitUserProcess(UINT code);

// Utils: Compare two strings in case-insensitive mod
bool StrCompareI(const std::string& str1, const std::string& str2);


// Dummy function for export to executable file (Game.exe/GameServer.exe/GateServer.exe)
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

			// Get address of entry point and linker build timestamp
			{
				// Pointers to DOS, PE and COFF headers of .exe file
				const PIMAGE_DOS_HEADER pidh = reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleHandle(NULL));
				const PIMAGE_NT_HEADERS pinh = reinterpret_cast<PIMAGE_NT_HEADERS>( (reinterpret_cast<BYTE*>(pidh) + pidh->e_lfanew) );
				const PIMAGE_FILE_HEADER pifh = reinterpret_cast<PIMAGE_FILE_HEADER>(&pinh->FileHeader);

				// Get pointer to mainCRTStartup() function
				pkodev::mainCRTStartup = reinterpret_cast<pkodev::mainCRTStartup__Ptr>(
					( pinh->OptionalHeader.AddressOfEntryPoint + pinh->OptionalHeader.ImageBase )
				);

				// Get linker timestamp
				pkodev::TimeDateStamp = static_cast<unsigned int>(pifh->TimeDateStamp);
			}

			// Get address of RtlExitUserProcess() function
			{
				// Get handle of module ntdll
				const HMODULE hmodntdll = GetModuleHandleA("ntdll");

				// Check the modult handle
				if (hmodntdll != nullptr)
				{
					// Get pointer to RtlExitUserProcess() function
					pkodev::RtlExitUserProcess = reinterpret_cast<pkodev::RtlExitUserProcess__Ptr>(
						GetProcAddress(hmodntdll, "RtlExitUserProcess")
					);
				}
			}

			// Enable hooks
			if ( (pkodev::mainCRTStartup != nullptr) && (pkodev::RtlExitUserProcess != nullptr) )
			{
				DetourRestoreAfterWith();
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(&(PVOID&)pkodev::mainCRTStartup, mainCRTStartup);
				DetourAttach(&(PVOID&)pkodev::RtlExitUserProcess, RtlExitUserProcess);
				DetourTransactionCommit();
			}

            break;

		// DLL detached from the proccess
        case DLL_PROCESS_DETACH:

			// Disable hooks
			if ( (pkodev::mainCRTStartup != nullptr) && (pkodev::RtlExitUserProcess != nullptr) )
			{
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourDetach(&(PVOID&)pkodev::mainCRTStartup, mainCRTStartup);
				DetourDetach(&(PVOID&)pkodev::RtlExitUserProcess, RtlExitUserProcess);
				DetourTransactionCommit();
			}

            break;
    }

    return TRUE;
}

// Hooked version of mainCRTStartup() function
int __cdecl mainCRTStartup()
{
	// Start the mod loader system
	Start();

	// Call original entry point
	return pkodev::mainCRTStartup();
}

// Hooked version of RtlExitUserProcess() function
void __stdcall RtlExitUserProcess(UINT code)
{
	// Stop the mod loader system
	Stop();

	// Call original exit proccess function
	pkodev::RtlExitUserProcess(code);
}

// Start the mod loader system
void Start()
{
	// Supported executables files table
	std::vector<pkodev::executable_version> exes;
	exes.push_back( { GAMESERVER_136, TS_GAMESERVER_136, "GameServer 1.36"        } );
	exes.push_back( { GAMESERVER_138, TS_GAMESERVER_138, "GameServer 1.38"        } );
	exes.push_back( { GAME_13X_0,     TS_GAME_13X_0,     "Game.exe 1.3x (ID: 0)"  } );
	exes.push_back( { GAME_13X_1,     TS_GAME_13X_1,     "Game.exe 1.3x (ID: 1)"  } );
	exes.push_back( { GAME_13X_2,     TS_GAME_13X_2,     "Game.exe 1.3x (ID: 2)"  } );
	exes.push_back( { GAME_13X_3,     TS_GAME_13X_3,     "Game.exe 1.3x (ID: 3)"  } );
	exes.push_back( { GAME_13X_4,     TS_GAME_13X_4,     "Game.exe 1.3x (ID: 4)"  } );
	exes.push_back( { GAME_13X_5,     TS_GAME_13X_5,     "Game.exe 1.3x (ID: 5)"  } );
	exes.push_back( { GATESERVER_138, TS_GATESERVER_138, "GateServer 1.38"        } );

	// Write a welcome message
	std::cout << "[pkodev.mod.loader] -----------------------------------------------" << std::endl;
	std::cout << "[pkodev.mod.loader]    PKOdev.NET mod loader ver. 1.1 by V3ct0r    " << std::endl;
	std::cout << "[pkodev.mod.loader] -----------------------------------------------" << std::endl;

	// Search current executable file in list of supported executables
	auto exe = std::find_if(exes.cbegin(), exes.cend(),
		[](const pkodev::executable_version& exe) -> bool
		{
			return ( pkodev::TimeDateStamp == exe.timestamp );
		}
	);

	// Check that the executable is supported
	if ( exe == exes.cend() )
	{
		// Unsupported executable version!
		std::cout << "[pkodev.mod.loader] Unsupported executable (.exe) file!" << std::endl << std::endl;
		return;
	}

	// Write executable version
	std::cout << "[pkodev.mod.loader] Detected executable (.exe) file: '" << exe->name << "'." << std::endl;

	// Write a message
	std::cout << "[pkodev.mod.loader] Searching mods in 'mods' directory . . ." << std::endl;

	// Search mods
	std::vector<std::string> arr;         // List of dynamic mod libraries
	SearchLibraries("mods", arr);

	// Search disabled mods
	unsigned int disabled_counter = 0;    // Disabled mods counter
	std::vector<std::string> disabled;    // List of disabled mods
	LoadDotDisabled("mods\\.disabled", disabled);

	// Load priority list
	std::queue<std::string> priority;     // Mod load priority list
	LoadDotPriority("mods\\.priority", priority);

	// Load mods . . .
	for (const std::string& path : arr)
	{
		// Load current .dll file
		HMODULE dll = LoadLibraryA(path.c_str());

		// Check result
		if (dll == nullptr)
		{
			// Failed to load the .dll file!
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

		// Check functions pointers
		if ( (GetModInformation == nullptr) || (Start == nullptr) || (Stop == nullptr) )
		{
			// DLL doesn't have required functions
			FreeLibrary(dll);
			continue;
		}

		// Get mod information
		mod_info info;
		GetModInformation(info); 

		// Check .exe version
		if (info.exe_version != exe->id)
		{
			// Unsupported mod version 
			FreeLibrary(dll);
			continue;
		}

		// Get the mod name
		const std::string name(info.name);

		// Search the mod in the disabled mods list
		auto disabled_it = std::find_if(disabled.cbegin(), disabled.cend(),
			[&name](const std::string& name_) -> bool { return StrCompareI(name, name_); }
		);

		// Check that mod is not disabled
		if (disabled_it != disabled.cend())
		{
			// The mod is disabled
			++disabled_counter;
			FreeLibrary(dll);
			continue;
		}

		// Search mod in list of loaded mods
		auto loaded_it = std::find_if(pkodev::mods.cbegin(), pkodev::mods.cend(),
			[&name](const pkodev::pkodev_mod& mod) -> bool { return StrCompareI(mod.name, name); }
		);

		// Check that mod is not already loaded
		if (loaded_it != pkodev::mods.cend())
		{
			// Mod is already loaded
			FreeLibrary(dll);
			continue;
		}

		// Create mod record
		pkodev::pkodev_mod mod;
		mod.name     = name;
		mod.version  = std::string(info.version);
		mod.author   = std::string(info.author);
		mod.path     = path;
		mod.start    = Start;
		mod.stop     = Stop;
		mod.handle   = dll;

		// Add the mod to the list
		pkodev::mods.push_back(mod);
	}

	// Sort and print the list of found and enabled mods
	if (pkodev::mods.empty() == false)
	{
		// Sort mods by load priority
		unsigned int priority_counter = 0;
		if (priority.empty() == false)
		{
			// Get mods priority
			while (priority.empty() == false)
			{
				// Get current mod name
				const std::string& name = priority.front();

				// Search the mod in the list of mods
				auto it = std::find_if(pkodev::mods.begin(), pkodev::mods.end(),
					[&name](const pkodev::pkodev_mod& mod) -> bool
					{
						return StrCompareI(mod.name, name);
					}
				);

				// Check that mod is found
				if (it != pkodev::mods.end())
				{
					// Set mod priority
					it->priority = ++priority_counter;
				}

				// Remove current priority from the queue
				priority.pop();
			}

			// Sort the list of mods
			std::sort(pkodev::mods.begin(), pkodev::mods.end(),
				[](const pkodev::pkodev_mod& a, const pkodev::pkodev_mod& b)
				{
					return (a.priority < b.priority);
				}
			);
		}

		// Mods counter
		unsigned int counter = 0;

		// Print number of mods found 
		std::cout << "[pkodev.mod.loader] Done! (" << pkodev::mods.size() << ") mods found out: " << std::endl;

		// Print table header
		std::cout << '+' << std::setfill('-') << std::setw(5) << '+'  <<        std::setw(33) << '+'    <<        std::setw(11) << '+'        <<        std::setw(17) << '+'              << std::endl;
		std::cout << '|' << std::setfill(' ') << std::setw(4) << "# " << '|' << std::setw(32) << "Mod " << '|' << std::setw(10) << "Version " << '|' << std::setw(16) << "Author " << '|' << std::endl;
		std::cout << '+' << std::setfill('-') << std::setw(5) << '+'  <<        std::setw(33) << '+'    <<        std::setw(11) << '+'        <<        std::setw(17) << '+'              << std::endl;

		// Print mods
		for (const pkodev::pkodev_mod& mod : pkodev::mods)
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
	
	// Write a message with the disabled mods number
	std::cout << "[pkodev.mod.loader] (" << disabled_counter << ") mods are disabled. " << std::endl;

	// Write a message that mods are being started
	std::cout << "[pkodev.mod.loader] Starting mods . . ." << std::endl;

	// Utils: extract directory from path
	auto extract_filepath = [](const std::string& path) -> std::string
	{
		// Looking for last slash
		const std::size_t pos = path.find_last_of("/\\");

		// Check that the slash is found
		if (pos != std::string::npos)
		{
			// Extract directory
			return path.substr(0, pos);
		}

		// Could not extract directory
		return path;
	};

	// Start mods
	std::for_each(pkodev::mods.begin(), pkodev::mods.end(),
		[&](const pkodev::pkodev_mod& mod) -> void
		{
			// Start the mod
			mod.start(extract_filepath(mod.path).c_str());
		}
	);

	// Write a message that mods are loaded
	std::cout << "[pkodev.mod.loader] All mods loaded!" << std::endl << std::endl;
}

// Stop the mod loader system
void Stop()
{
	// Stop mods
	std::for_each(pkodev::mods.rbegin(), pkodev::mods.rend(),
		[](const pkodev::pkodev_mod& mod) -> void
		{
			// Stop the mod
			mod.stop();

			// Unload mod .dll
			FreeLibrary(mod.handle);

			// Write a message that mod is unloaded
			std::cout << "[pkodev.mod.loader] " << mod.name << " successfully unloaded!" << std::endl;
		}
	);

	// Clear mods list
	pkodev::mods.clear();

	// Write a message that mods are unloaded
	std::cout << "[pkodev.mod.loader] All mods unloaded!" << std::endl << std::endl;
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
			const std::string file(FindFileData.cFileName);
			
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
				// Check that the file name matches the pattern
				if (std::regex_match(file, pkodev::dll_regex) == true)
				{
					// Build full file path
					sprintf_s(buf, sizeof(buf), "%s\\%s", path.c_str(), file.c_str());

					// Add the file to list
					arr.push_back(buf);
				}
			}
		} 
		while ( FindNextFileA(hFind, &FindFileData) == TRUE );
	}

	// Close search handle
	FindClose(hFind);
}

// Load the list of disabled mods (.disabled)
void LoadDotDisabled(const std::string& path, std::vector<std::string>& disabled)
{
	// Try to open the .disabled file
	std::ifstream file(path, std::ios::in);

	// Check that file is open
	if (file.is_open() == false)
	{
		// The file not found or cannot be read
		return;
	}

	// Read the file line-by-line
	for (std::string line(""); std::getline(file, line); )
	{
		// Remove the spaces from the line
		line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

		// Check that line is empty
		if (line.empty() == true)
		{
			// Skip the line
			continue;
		}

		// Check that line is commented
		if (line.find("//") == 0)
		{
			// Skip the line
			continue;
		}

		// Check that the file name matches the pattern
		if (std::regex_match(line, pkodev::name_regex) == true)
		{
			// Add the file to list
			disabled.push_back(line);
		}
	}

	// Close the file
	file.close();
}

// Load the mod priority list  (.priority)
void LoadDotPriority(const std::string& path, std::queue<std::string>& priority)
{
	// Try to open the .priority file
	std::ifstream file(path, std::ios::in);

	// Check that file is open
	if (file.is_open() == false)
	{
		// The file not found or cannot be read
		return;
	}

	// Read the file line-by-line
	for (std::string line(""); std::getline(file, line); )
	{
		// Remove the spaces from the line
		line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

		// Check that line is empty
		if (line.empty() == true)
		{
			// Skip the line
			continue;
		}

		// Check that line is commented
		if (line.find("//") == 0)
		{
			// Skip the line
			continue;
		}

		// Check that the file name matches the pattern
		if (std::regex_match(line, pkodev::name_regex) == true)
		{
			// Add the file to list
			priority.push(line);
		}
	}

	// Close the file
	file.close();
}

// Utils: Compare two strings in case-insensitive mod
bool StrCompareI(const std::string& str1, const std::string& str2)
{
	// Compare strings length
	if (str1.length() != str2.length())
	{
		// Strings are not equal
		return false;
	}

	// Compare strings characters
	return std::equal(
		str1.cbegin(), str1.cend(), str2.cbegin(), str2.cend(),
		[](const char& c1, const char& c2) -> bool
		{
			if (c1 == c2)
			{
				return true;
			}

			return ( std::tolower(c1) == std::tolower(c2) );
		}
	);
}