/*++
Copyright (c) 1999-2002  Microsoft Corporation
Module Name:
scanUser.c
Abstract:
This file contains the implementation for the main function of the
user application piece of scanner.  This function is responsible for
actually scanning file contents.
Environment:
User mode
--*/

#include <windows.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "scanuk.h"
#include "scanuser.h"
#include <dontuse.h>

//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT       1
#define SCANNER_DEFAULT_THREAD_COUNT        1
#define SCANNER_MAX_THREAD_COUNT            1

UCHAR FoulString[] = "foul";

#pragma comment(lib, "Shlwapi.lib")

//
//  Context passed to worker threads
//

typedef struct _SCANNER_THREAD_CONTEXT {

	HANDLE Port;
	HANDLE Completion;

} SCANNER_THREAD_CONTEXT, * PSCANNER_THREAD_CONTEXT;


VOID
Usage(
	VOID
)
/*++
Routine Description
Prints usage
Arguments
None
Return Value
None
--*/
{

	printf("Connects to the scanner filter and scans buffers \n");
	printf("Usage: scanuser [requests per thread] [number of threads(1-64)]\n");
}

BOOL
ScanBuffer(
	_In_reads_bytes_(BufferSize) PUCHAR Buffer,
	_In_ ULONG BufferSize
)
/*++
Routine Description
Scans the supplied buffer for an instance of FoulString.
Note: Pattern matching algorithm used here is just for illustration purposes,
there are many better algorithms available for real world filters
Arguments
Buffer      -   Pointer to buffer
BufferSize  -   Size of passed in buffer
Return Value
TRUE        -    Found an occurrence of the appropriate FoulString
FALSE       -    Buffer is ok
--*/
{
	PUCHAR p;
	ULONG searchStringLength = sizeof(FoulString) - sizeof(UCHAR);

	for (p = Buffer;
		p <= (Buffer + BufferSize - searchStringLength);
		p++) {

		if (RtlEqualMemory(p, FoulString, searchStringLength)) {

			printf("Found a string\n");

			//
			//  Once we find our search string, we're not interested in seeing
			//  whether it appears again.
			//

			return TRUE;
		}
	}

	return FALSE;
}

LPCWSTR GetPipeName()
{
	return L"\\\\.\\pipe\\webroampipe";
}

#define MaxPipeBufSz 1024 * 4

#define MAXLEN  1024 * 4
wchar_t CurP[MAXLEN];

DWORD
ScannerWorker(
	_In_ PSCANNER_THREAD_CONTEXT Context
)
/*++
Routine Description
This is a worker thread that
Arguments
Context  - This thread context has a pointer to the port handle we use to send/receive messages,
and a completion port handle that was already associated with the comm. port by the caller
Return Value
HRESULT indicating the status of thread exit.
--*/
{
	PSCANNER_NOTIFICATION notification;
	SCANNER_REPLY_MESSAGE replyMessage;
	PSCANNER_MESSAGE message;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr = 0;
	ULONG_PTR key;
	//DWORD numWritten;
	//char data[1024];
	//DWORD numRead = 1;
#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant
	/*typedef BOOL (*IsOKAccess_t)(wchar_t *drvcont);
	HANDLE myDLL = LoadLibrary(L"C:\\Users\\Mostafa\\Documents\\Visual Studio 2015\\Projects\\ClassLibrary1\\x64\\Release\\ClassLibrary1.dll");
	IsOKAccess_t IsOKAccess = (IsOKAccess_t)GetProcAddress(myDLL, "IsOKAccessN");*/
	HANDLE pipe = CreateFile(GetPipeName(), GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (pipe == INVALID_HANDLE_VALUE)
	{
		//system("gui\\WrArServ.exe");
		//Sleep(4000);
		//pipe = CreateFile(GetPipeName(), GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
		exit(1);
	}
	//ConnectNamedPipe(pipe, NULL);
	CloseHandle(pipe);
	WCHAR* chReadBuf = malloc(2*MaxPipeBufSz);
	BOOLEAN bresult = TRUE;
	/*DWORD mode = PIPE_NOWAIT;
	SetNamedPipeHandleState(pipe, &mode, NULL, NULL);*/
	COMMTIMEOUTS timeouts = { 0, //interval timeout. 0 = not used
		0, // read multiplier
		10, // read constant (milliseconds)
		0, // Write multiplier
		0  // Write Constant
	};


	wchar_t* pcont = malloc(MAXLEN * 2);

	SetCommTimeouts(pipe, &timeouts);
	while (TRUE) {

#pragma warning(pop)

		//
		//  Poll for messages from the filter component to scan.
		//

		result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &pOvlp, INFINITE);

		//
		//  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
		//  the one dequeued off the completion queue: this is solely because there are multiple
		//  threads per single port handle. Any of the FilterGetMessage() issued messages can be
		//  completed in random order - and we will just dequeue a random one.
		//

		message = CONTAINING_RECORD(pOvlp, SCANNER_MESSAGE, Ovlp);

		if (!result) {

			//
			//  An error occured.
			//

			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}

		//printf("Received message, size %Id\n", pOvlp->InternalHigh);

		notification = &message->Notification;
		size_t len = 0;


		ZeroMemory(pcont, MAXLEN * 2);
		//OVERLAPPED lpOvr = {0};
//		DWORD bytesAvailable = 0;

		mbstowcs_s(&len, pcont, MAXLEN, (const char*)notification->Contents, sizeof(notification->Contents));
		wchar_t resS[MAXLEN];
		ZeroMemory(resS, MAXLEN);
		wcscpy_s(resS, 1024 * 4, pcont);
		//_putws(pcont);
		//StrStrI(pcont, L"wrMainAntiRansomeware.exe") == NULL && StrStrI(pcont, L"WrArServ.exe") == NULL && StrStrI(pcont, L"WebroamAV.exe") == NULL && 
		if (!(StrStrI(pcont, &CurP[2]) != NULL && StrStr(&StrStrI(pcont, &CurP[2])[1], &CurP[2]) != NULL))// && StrStrI(pcont, L".wrdb") == NULL)
		{
		// && StrStrI(pcont,) == NULL && StrStrI(pcont, L"\\Device\\HarddiskVolume1\\Windows\\") == NULL)
			//			wchar_t str2[20] = { 0 }, str3[20] = { 0 };
						//int i = swprintf_s(resS, 1024*4, L"%S\n", pcont);
#pragma warning(disable:4477)
			int i = swprintf_s(resS + len - 1, 1024 * 4, L"\n$R%lld\n", notification->Reserved);
			
			if (swprintf_s(resS + len - 1 + i, 1024 * 4, L"$P%d\n", notification->ProcessID) <= 0)
			{
				//goto endofComm;
				//exit(1);
			}

			LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\webroampipe");
			
			DWORD cbRead;
			BOOL fResult;
			//printf("%S\n", resS);
			ZeroMemory(chReadBuf, MaxPipeBufSz);
			fResult = CallNamedPipeW(
				lpszPipename,          // pipe name 
				resS,              // message to server 
				MaxPipeBufSz,      // message length 
				chReadBuf,             // buffer to receive reply 
				MaxPipeBufSz,     // size of read buffer 
				&cbRead,               // number of bytes read 
				NMPWAIT_WAIT_FOREVER); // wait;-) 
			//printf("%S\n", chReadBuf);
			bresult = StrStrIW(chReadBuf, L"False") == NULL;
			//bresult = (BOOLEAN)IsOKAccess(resS);
			//	printf("%S\n%d\n%d\n", pcont, notification->Reserved, notification->ProcessID);

			/*if (!WriteFile(pipe, resS, MAXLEN, &numWritten, NULL))
			{
				DWORD error = GetLastError();
				if (error != ERROR_NO_DATA)
					printf("*0x%x\n", error);

				bresult = TRUE;
				//	exit(1);
				goto endofComm;
			}
			else
			{
				if (!FlushFileBuffers(pipe))
				{
					DWORD error = GetLastError();
					if (error != ERROR_NO_DATA)
						printf("**0x%x\n", error);

					bresult = TRUE;
					//exit(1);
					goto endofComm;
				}
				
				ZeroMemory(data, 1024);
				//GetOverlappedResult(pipe, &lpOvr, &numRead, TRUE);

				ReadFile(pipe, data, 1024, &numRead, NULL);
				DWORD lerror = GetLastError();


				if (numRead == 0 && lerror != ERROR_NO_DATA && lerror != ERROR_IO_PENDING && lerror != NOERROR )
				{
					printf("***0x%x\n", lerror);
					bresult = TRUE;
					//exit(1);
					goto endofComm;
				}

				bresult = StrStrIA(data, "False") == NULL;
				printf("%s\n%S\n", data, resS);
			}
			*/
			/*if(!bresult)
			*/
			//	assert(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);
				//_Analysis_assume_(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

			//	result = ScanBuffer(notification->Contents, notification->BytesToScan);
		}
		else
		{
			bresult = TRUE;
		}
	//	puts(bresult?"Y":"N");
	//endofComm:
		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;


		//
		//  Need to invert the boolean -- result is true if found
		//  foul language, in which case SafeToOpen should be set to false.
		//


		replyMessage.Reply.SafeToOpen = bresult;

		//printf("Replying message, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen);

		hr = FilterReplyMessage(Context->Port,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage));

		if (SUCCEEDED(hr)) {

			//printf("Replied message\n");

		}
		else {

			printf("Scanner: Error replying message. Error = 0x%X\n", hr);
			//break;
		}

		memset(&message->Ovlp, 0, sizeof(OVERLAPPED));

		hr = FilterGetMessage(Context->Port,
			&message->MessageHeader,
			FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
			&message->Ovlp);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

			//break;
		}
	}

	if (!SUCCEEDED(hr)) {

		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {

			//
			//  Scanner port disconncted.
			//

			printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");

		}
		else {

			printf("Scanner: Unknown error occured. Error = 0x%X\n", hr);
			exit(1);
		}
	}
	free(pcont);
	free(message);
	//	CloseHandle(pipe);
	return hr;
}


int _cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char* argv[]
)
{
	DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;
	DWORD threadCount = SCANNER_DEFAULT_THREAD_COUNT;
	HANDLE threads[SCANNER_MAX_THREAD_COUNT];
	SCANNER_THREAD_CONTEXT context;
	HANDLE port, completion;
	PSCANNER_MESSAGE msg;
	DWORD threadId;
	HRESULT hr;
	DWORD i, j;

	//
	//  Check how many threads and per thread requests are desired.
	//

	if (argc > 1) {

		requestCount = atoi(argv[1]);

		if (requestCount <= 0) {

			Usage();
			return 1;
		}

		if (argc > 2) {

			threadCount = atoi(argv[2]);
		}

		if (threadCount <= 0 || threadCount > 64) {

			Usage();
			return 1;
		}
	}

	//
	//  Open a commuication channel to the filter
	//

	printf("Scanner: Connecting to the filter ...\n");

	hr = FilterConnectCommunicationPort(ScannerPortName,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hr)) {

		printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		return 2;
	}

	//
	//  Create a completion port to associate with this handle.
	//

	completion = CreateIoCompletionPort(port,
		NULL,
		0,
		threadCount);

	if (completion == NULL) {

		printf("ERROR: Creating completion port: %d\n", GetLastError());
		CloseHandle(port);
		return 3;
	}

	printf("Scanner: Port = 0x%p Completion = 0x%p\n", port, completion);

	context.Port = port;
	context.Completion = completion;
	ZeroMemory(CurP, MAXLEN * sizeof(wchar_t));
	GetCurrentDirectory(MAXLEN, CurP);
	//
	//  Create specified number of threads.
	//

	for (i = 0; i < threadCount; i++) {

		threads[i] = CreateThread(NULL,
			0,
			(LPTHREAD_START_ROUTINE)ScannerWorker,
			&context,
			0,
			&threadId);

		if (threads[i] == NULL) {

			//
			//  Couldn't create thread.
			//

			hr = GetLastError();
			printf("ERROR: Couldn't create thread: %d\n", hr);
			goto main_cleanup;
		}

		for (j = 0; j < requestCount; j++) {

			//
			//  Allocate the message.
			//

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in ScannerWorker")
			msg = malloc(sizeof(SCANNER_MESSAGE));

			if (msg == NULL) {

				hr = ERROR_NOT_ENOUGH_MEMORY;
				goto main_cleanup;
			}

			memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

			//
			//  Request messages from the filter driver.
			//

			hr = FilterGetMessage(port,
				&msg->MessageHeader,
				FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
				&msg->Ovlp);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

				free(msg);
				goto main_cleanup;
			}
		}
	}

	hr = S_OK;

	WaitForMultipleObjectsEx(i, threads, TRUE, INFINITE, FALSE);

main_cleanup:

	printf("Scanner:  All done. Result = 0x%08x\n", hr);

	CloseHandle(port);
	CloseHandle(completion);

	return hr;
}