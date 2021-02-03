/**
 * @file wpi.cpp
 * @brief Smol program to determine the mandatory integrity level of a running process from command line.
 * (tested on Windows 10 x64)
 *
 * @author 0xalwayslucky (https://github.com/0xalwayslucky)
 */

#include <iostream>
#include <windows.h>
#include <sddl.h>

#define SID_UNTRUSTED "S-1-16-0"
#define SID_LOW "S-1-16-4096"
#define SID_MEDIUM "S-1-16-8192"
#define SID_HIGH "S-1-16-12288"
#define SID_SYSTEM "S-1-16-16384"
#define SID_INSTALLER "S-1-16-20480"

using namespace std;

/**
 * Function that attempts to print the integrity level of the target process on the command line.
 *
 * @param processId
 */
void printProcessIntegrityLevel(DWORD processId){

    HANDLE hProcess             = nullptr;          // Handle of the target process
    HANDLE hToken               = nullptr;          // Handle of the target processes token
    TOKEN_MANDATORY_LABEL *tml  = nullptr;          // Token integrity information struct
    PSID pSidIntegrityProcess   = nullptr;          // Integrity SID of the target process
    PSID pSidIntegrityToCheck   = nullptr;          // Integrity SID to check against the SID of the target process
    bool success                = false;            // Indicator if the previous operation was successful or not
    DWORD dwSize                = 0;                // Size of the Information loaded from the token

    // Get handle of the process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    // Todo: provide an error message that is more specific ( GetLastError )
    // https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-the-last-error-code
    if(!hProcess){
        cout << "Could not load target process. Please check the submitted Process-Id." << endl
        << "Note: This might be because you are running wpi.exe with a lower integrity level than the process you want to check." << endl;
        goto CleanExit;
    }

    // Get token of the process
    success = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken);
    if(!success){
        cout << "Could not obtain process token." << endl << " Exiting..." << endl;
        goto CleanExit;
    }

    // Allocate the according size for the Information contained in TOKEN_MANDATORY_LABEL struct
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, dwSize, &dwSize);
    tml = (TOKEN_MANDATORY_LABEL *) GlobalAlloc(GPTR, dwSize);

    // Get the TokenIntegriyLevel information
    success = GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize);
    if(!success){
        goto CleanExit;
    }

    // Check the Mandatory Integrity Level of the Process
    pSidIntegrityProcess = tml->Label.Sid;

    success = ConvertStringSidToSid((LPCSTR) SID_UNTRUSTED, &pSidIntegrityToCheck);
    if(success && EqualSid(pSidIntegrityProcess, pSidIntegrityToCheck)){
        cout << "Process runs with integrity level: UNTRUSTED" << endl;
        goto CleanExit;
    }

    success = ConvertStringSidToSid((LPCSTR) SID_LOW, &pSidIntegrityToCheck);
    if(success && EqualSid(pSidIntegrityProcess, pSidIntegrityToCheck)){
        cout << "Process runs with integrity level: LOW" << endl;
        goto CleanExit;
    }

    success = ConvertStringSidToSid((LPCSTR) SID_MEDIUM, &pSidIntegrityToCheck);
    if(success && EqualSid(pSidIntegrityProcess, pSidIntegrityToCheck)){
        cout << "Process runs with integrity level: MEDIUM" << endl;
        goto CleanExit;
    }

    success = ConvertStringSidToSid((LPCSTR) SID_HIGH, &pSidIntegrityToCheck);
    if(success && EqualSid(pSidIntegrityProcess, pSidIntegrityToCheck)){
        cout << "Process runs with integrity level: HIGH" << endl;
        goto CleanExit;
    }

    success = ConvertStringSidToSid((LPCSTR) SID_SYSTEM, &pSidIntegrityToCheck);
    if(success && EqualSid(pSidIntegrityProcess, pSidIntegrityToCheck)){
        cout << "Process runs with integrity level: SYSTEM" << endl;
        goto CleanExit;
    }

    success = ConvertStringSidToSid((LPCSTR) SID_INSTALLER, &pSidIntegrityToCheck);
    if(success && EqualSid(pSidIntegrityProcess, pSidIntegrityToCheck)){
        cout << "Process runs with integrity level: INSTALLER/PROTECTED" << endl;
        goto CleanExit;
    }

    cout << "Could not determine the processes integrity level (this should not happen, plox report it)." << endl;

    // Cleanup mmmmmmmmkay...
    CleanExit:
        if(hProcess != nullptr) CloseHandle(hProcess);
        if(pSidIntegrityToCheck) LocalFree(pSidIntegrityToCheck);
        if(tml) GlobalFree(tml);
        if(hToken != nullptr) CloseHandle(hToken);
}

/**
 *  Program has to be called with one parameter. Else it will exit.
 *
 * @param argc Count of the provided parameters
 * @param argv Provided parameters
 * @return Error code
 */
int main(int argc, char *argv[]) {

    if(argc < 2){
        cout << "wpi.exe <Process-Id>" << endl;
        return 1;
    }

    char *processIdString = argv[1];
    DWORD processId = strtoul(processIdString, nullptr, 0);
    printProcessIntegrityLevel(processId);

    return 0;
}
