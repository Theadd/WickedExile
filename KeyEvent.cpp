#include <winsock2.h>
#include <stdio.h>
#include "detours.h"
#include <string>
#include <sstream>
#include "Encryption.hpp"
#include "KeyEvent.hpp"
#pragma comment( lib, "WSOCK32.lib" )

REGHANDLE provider;

static FILE* fLogFile = NULL;
unsigned char shaKey[0x40];
Encryption encryption;
bool isValidKey;
u32 lastInput[16];
bool shouldUseLastInput;
int inLoopCount;
u32 firstLoopInput[16];

#define Terminate(...) do { char *buffer = new char[500]; sprintf_s(buffer, 500, __VA_ARGS__); throw buffer; } while(0)

typedef int (WINAPI *t_send)(SOCKET, char *, int, int);
typedef int (WINAPI *t_recv)(SOCKET, char *, int, int);
typedef int (WINAPI *t_sendto)( SOCKET,const char*,int,int,const struct sockaddr* ,int);
typedef int (WINAPI *t_recvfrom)( SOCKET,const char*,int,int,const struct sockaddr* ,int);
typedef int (WINAPI *t_connect)(SOCKET ,const struct sockaddr* ,int);

t_send o_send;
t_recv o_recv;
t_sendto o_sendto;
t_recvfrom o_recvfrom;
t_connect o_connect;

enum BreakpointType
{
	BreakpointCode = 0,
	BreakpointReadWrite,
	BreakpointWrite
};

enum BreakpointSize
{
	BreakpointByte = 0,
	BreakpointWord,
	BreakpointDword,
	BreakpointQword
};

void logExile(std::string msg)
{
	msg += "\n";
	fprintf(fLogFile, msg.c_str());
	fflush(fLogFile);
}

std::string bufferToHex(const char* input, size_t len)
{
    static const char* const lut = "0123456789ABCDEF";

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
		//if (c == 0) continue;
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

void CreateBreakpoint(CONTEXT* Context, void* Address, enum BreakpointType Type, enum BreakpointSize Size)
{
	DWORD* DrAddresses[] =
	{
		&Context->Dr0,
		&Context->Dr1,
		&Context->Dr2,
		&Context->Dr3
	};

	int i;

	int FirstFree = -1;

	for(i = 0; i < 4; i++)
	{
		if(!(Context->Dr7 & (1 << (i * 2))))
		{
			FirstFree = i;
			break;
		}
	}

	if(FirstFree == -1)
		Terminate("No more free breakpoints in thread %u\n", GetCurrentThreadId());

	*DrAddresses[FirstFree] = (DWORD)Address;

	Context->Dr7 |= (1 << (FirstFree * 2));

	Context->Dr7 &= ~(0xF << (FirstFree * 4 + 16));

	Context->Dr7 |= ((Type & 3) | ((Size & 3) << 2)) << (FirstFree * 4 + 16);
}

void CreateBreakpointInThread(unsigned int ThreadId, void* Address, enum BreakpointType Type, enum BreakpointSize Size)
{
	HANDLE Thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, ThreadId);
	CONTEXT Context; 

	if(!Thread)
		Terminate("CreateBreakpointInThread: Unable to get thread handle from thread %u (%u).\n", ThreadId, GetLastError());

	//if(SuspendThread(Thread) == -1)
	//	Terminate("CreateBreakpointInThread: Unable to suspend thread %u (%u).\n", ThreadId, GetLastError());

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if(!GetThreadContext(Thread, &Context))
		Terminate("CreateBreakpointInThread: Unable to get thread context from thread %u (%u).\n", ThreadId, GetLastError());

	CreateBreakpoint(&Context, Address, Type, Size);

	if(!SetThreadContext(Thread, &Context))
		Terminate("CreateBreakpointInThread: Unable to set thread context to thread %u (%u).\n", ThreadId, GetLastError());

	if(ResumeThread(Thread) == -1)
		Terminate("CreateBreakpointInThread: Unable to resume thread %u (%u).\n", ThreadId, GetLastError());

	CloseHandle(Thread);
}

void *hooked_address;

void (__stdcall *ZwContinue)(CONTEXT* Context, int Unknown);

LONG NTAPI exception_handler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if(ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	if(ExceptionInfo->ExceptionRecord->ExceptionAddress != hooked_address)
		return EXCEPTION_CONTINUE_SEARCH;

	EVENT_DATA_DESCRIPTOR data;

	//unsigned char output[0x40];

	auto context = ExceptionInfo->ContextRecord;

	auto key = *(const unsigned char **)(context->Ebp + 8);

	//sha4((const unsigned char *)key, 0x200, output, false);
	//sha4((const unsigned char *)hooked_address, 0x200, output, false);
	//logExile("Key found from hooked address: " + bufferToHex((char *)output, 64));
	//sha4(*(const unsigned char **)hooked_address, 0x200, output, false);
	//logExile("Key found from hooked address: " + bufferToHex((char *)output, 64));

	sha4((const unsigned char *)key, 0x200, shaKey, false);
	logExile("Key send to ETW: " + bufferToHex((char *)shaKey, 64));
	encryption.Setup((unsigned char *)shaKey);
	isValidKey = true;
	for (int i = 0; i < 16; ++i)
		lastInput[i] = encryption.In.ctx.input[i];
	shouldUseLastInput = false;
	inLoopCount = 0;

	EventDataDescCreate(&data, shaKey, 0x40);

	EventWrite(provider, &PrivateKey, 1, &data);

	// do pop ebp
	context->Ebp = *(DWORD *)context->Esp;
	context->Esp += 4;
	context->Eip++;

	ZwContinue(ExceptionInfo->ContextRecord, 0);

	return EXCEPTION_CONTINUE_SEARCH;
}

extern "C" __declspec(dllexport) DWORD after_injection(HMODULE module, DWORD main_thread)
{
	try
	{
		logExile("init keyeve3nt!");
		if(EventRegister(&PoeKeyProvider, NULL, NULL, &provider))
			throw "Unable to register event provider";

		const unsigned char pattern[] = {0x55, 0x8B, 0xEC, 0x56, 0xFF, 0x75, 0x1C, 0x8B, 0xF1, 0xFF, 0x75, 0x14, 0x8B, 0x4E, 0x04, 0xFF, 0x75, 0x0C, 0x8B, 0x01, 0xFF, 0x75, 0x08, 0xFF, 0x50, 0x34, 0x84, 0xC0, 0x74, 0x2A, 0x8B, 0x46, 0x08, 0x8B, 0x4E, 0x04, 0x57, 0x8B, 0x38, 0x8B, 0x01, 0x6A, 0x01, 0xFF, 0x75, 0x18, 0xFF, 0x75, 0x10, 0xFF, 0x50, 0x1C, 0x03, 0x45, 0x08, 0x8B, 0x4E, 0x08, 0x50, 0xFF, 0x57, 0x34, 0x5F, 0x84, 0xC0, 0x74, 0x05, 0x33, 0xC0, 0x40, 0xEB, 0x02, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x18, 0x00};
		char mask[sizeof(pattern)];
		memset(mask, 0xFF, sizeof(mask));

		char *result = (char *)find_pattern(GetModuleHandle(0), ".text", (char *)pattern, mask, sizeof(pattern));

		ZwContinue = (decltype(ZwContinue))GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwContinue");

		if(!AddVectoredExceptionHandler(1, &exception_handler))
			throw "Unable to register vectored exception handler";

		hooked_address = result + sizeof(pattern) - 4;

		//sha4((const unsigned char *)hooked_address, 0x200, shaKey, false);
		//logExile("Key found: " + bufferToHex((char *)shaKey, 64));
		//sha4(*(const unsigned char **)hooked_address, 0x200, shaKey, false);
		//logExile("Key found2: " + bufferToHex((char *)shaKey, 64));

		CreateBreakpointInThread(main_thread, hooked_address, BreakpointCode, BreakpointByte);
	}
	catch(const char *error)
	{
		MessageBoxA(0, error, "KeyEvent Error", 0);
	}

	return 0;
}

//#####################################################
int WINAPI MyConnect(SOCKET s,const struct sockaddr* name,int namelen)
{
	if(fLogFile) {
		fprintf(fLogFile,"connect(), namelen = %d\n", namelen);
		fflush(fLogFile);
	}
	return o_connect(s,name,namelen);
}

int WINAPI Myrecv(SOCKET s, char* buf, int len, int flags)
{
    int read = o_recv(s, buf, len, flags);
    if(read <= 0)
    {
        //read error/connection closed
        return read;
    }

    //fopen_s(&fLogFile, "C:\\RecvLog.txt", "a+");
    //fwrite(buf,sizeof(char),read,fLogFile);
	//if (++packetCount > 10) {

	if (isValidKey) {
		//get port number
		struct sockaddr_in sin;
		int addrlen = sizeof(sin);
		int local_port = 0;
		if(getsockname(s, (struct sockaddr *)&sin, &addrlen) == 0 &&
		   sin.sin_family == AF_INET &&
		   addrlen == sizeof(sin))
		{
			local_port = ntohs(sin.sin_port);
		}
		std::string str_port;
		std::stringstream out;
		out << local_port;
		str_port = out.str();
		//end of get port number
		/*unsigned char keyCopy[0x40];

		for (int i = 0; i < 64; ++i)
			keyCopy[i] = shaKey[i];

		encryption.Setup((unsigned char *)keyCopy);*/
		//Encryption encryption;
		//encryption.Setup((unsigned char *)shaKey);
		unsigned char *decrypted = encryption.Out.Process((unsigned char *)buf, read);
		logExile("RECV [" + str_port + "] " + bufferToHex((char *)decrypted, read));
	}
	//}
	//fprintf(fLogFile, "\nrecv(%d): %s\n", read, bufferToHex(buf, read));
    //fflush(fLogFile);
    return read;
}


int WINAPI MySend(SOCKET s, char *buf, int len, int flags)
{
	//MessageBox(0,"Send()","Send",0);
	if (isValidKey) {
		//get port number
		struct sockaddr_in sin;
		int addrlen = sizeof(sin);
		int local_port = 0;
		if(getsockname(s, (struct sockaddr *)&sin, &addrlen) == 0 &&
		   sin.sin_family == AF_INET &&
		   addrlen == sizeof(sin))
		{
			local_port = ntohs(sin.sin_port);
		}
		std::string str_port;
		std::stringstream out;
		out << local_port;
		str_port = out.str();
		//end of get port number
		/*unsigned char keyCopy[0x40];

		for (int i = 0; i < 64; ++i)
			keyCopy[i] = shaKey[i];

		encryption.Setup((unsigned char *)keyCopy);*/
		//Encryption encryption;
		//encryption.Setup((unsigned char *)shaKey);
		/*if (!shouldUseLastInput) {
			if (inLoopCount == 1) {
				for (int i = 0; i < 16; ++i) 
				encryption.In.ctx.input[i] = firstLoopInput[i];
			} else {
				for (int i = 0; i < 16; ++i)
					lastInput[i] = encryption.In.ctx.input[i];
			}
		} else {
			for (int i = 0; i < 16; ++i)
				encryption.In.ctx.input[i] = lastInput[i];
		}
		shouldUseLastInput = !shouldUseLastInput;*/
		for (int i = 0; i < 16; ++i)
			lastInput[i] = encryption.In.ctx.input[i];

		logExile("\tSEND Stream: " + bufferToHex((char *)encryption.In.Stream, 64));
		logExile("\tSEND Encrypted: " + bufferToHex((char *)buf, len));
		logExile("\tSEND Input BEFORE DECRYP: " + bufferToHex((char *)encryption.In.getInputAsCharacters(), 64));
		unsigned char *decrypted = encryption.In.Process((unsigned char *)buf, len);
		logExile("\tSEND [" + str_port + "] " + bufferToHex((char *)decrypted, len));
		logExile("\tSEND Input AS CHARACTERS: " + bufferToHex((char *)encryption.In.getInputAsCharacters(), 64));
		if (len < 5) {
			for (int i = 0; i < 16; ++i)
				encryption.In.ctx.input[i] = lastInput[i];

			logExile("\tSEND Input ROLLBACK: " + bufferToHex((char *)encryption.In.getInputAsCharacters(), 64));
		}
		/*if (inLoopCount == 0) {
			for (int i = 0; i < 16; ++i) 
				firstLoopInput[i] = encryption.In.ctx.input[i];
		} //else if (inLoopCount == 2
		++inLoopCount;*/
		
	}
	return o_send(s, buf, len, flags);
}

int WINAPI MyRecvFrom(SOCKET s,const char* buf,int len,int flags,const struct sockaddr* to,int tolen)
{
	//MessageBox(0,"Recvfrom()","Recvfrom",0);
	if(fLogFile) {
		fprintf(fLogFile, "recvfrom(%d)\n", len);
		fflush(fLogFile);
	}
	return o_recvfrom(s, buf, len, flags,to,tolen);
}

int WINAPI MySendTo( SOCKET s,const char* buf,int len,int flags,const struct sockaddr* to,int tolen)
{
	//MessageBox(0,"Sendto()","Sendto",0);
	return o_sendto(s, buf, len, flags,to,tolen);
}

void Starthook()
{
	o_recv = (t_recv)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "recv"), (PBYTE)Myrecv);
	o_send = (t_send)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "send"), (PBYTE)MySend);
	o_sendto = (t_sendto)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "sendto"), (PBYTE)MySendTo);
	o_recvfrom = (t_recvfrom)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "recvfrom"), (PBYTE)MyRecvFrom);
	o_connect = (t_connect)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "connect"), (PBYTE)MyConnect);
}
//########################################################

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			DisableThreadLibraryCalls((HMODULE)hModule);
			// Open Log File for Writing:
			fLogFile = fopen("KeyEvent4.txt","w");
			isValidKey = false;
			Starthook();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}
