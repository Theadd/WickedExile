#include <winsock2.h>
#include <stdio.h>
#include "detours.h"
#include <string>
#include "KeyEvent.hpp"
#include "Encryption.hpp"
#pragma comment( lib, "WSOCK32.lib" )

static FILE* fLogFile = NULL;

void *hooked_address;

void (__stdcall *ZwContinue)(CONTEXT* Context, int Unknown);

unsigned char shaKey[0x40];
Encryption encryption;
unsigned long int packetCount;

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

extern "C" __declspec(dllexport) DWORD after_injection(HMODULE module, DWORD main_thread)
{
	try
	{
		const unsigned char pattern[] = {0x55, 0x8B, 0xEC, 0x56, 0xFF, 0x75, 0x1C, 0x8B, 0xF1, 0xFF, 0x75, 0x14, 0x8B, 0x4E, 0x04, 0xFF, 0x75, 0x0C, 0x8B, 0x01, 0xFF, 0x75, 0x08, 0xFF, 0x50, 0x34, 0x84, 0xC0, 0x74, 0x2A, 0x8B, 0x46, 0x08, 0x8B, 0x4E, 0x04, 0x57, 0x8B, 0x38, 0x8B, 0x01, 0x6A, 0x01, 0xFF, 0x75, 0x18, 0xFF, 0x75, 0x10, 0xFF, 0x50, 0x1C, 0x03, 0x45, 0x08, 0x8B, 0x4E, 0x08, 0x50, 0xFF, 0x57, 0x34, 0x5F, 0x84, 0xC0, 0x74, 0x05, 0x33, 0xC0, 0x40, 0xEB, 0x02, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x18, 0x00};
		char mask[sizeof(pattern)];
		memset(mask, 0xFF, sizeof(mask));

		char *result = (char *)find_pattern(GetModuleHandle(0), ".text", (char *)pattern, mask, sizeof(pattern));

		ZwContinue = (decltype(ZwContinue))GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwContinue");

		hooked_address = result + sizeof(pattern) - 4;

		sha4((const unsigned char *)hooked_address, 0x200, shaKey, false);

		log("Key found: " + bufferToHex((char *)shaKey, 64));

		HANDLE Thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, main_thread);
		ResumeThread(Thread);
		CloseHandle(Thread);
	}
	catch(const char *error)
	{
		log("Error trying to find Path of Exile encryption key, error details: " + std::string(error));
	}

	return 0;
}

/*
std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}*/

void log(std::string msg)
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
    if(read <= 10)
    {
        //read error/connection closed
        return read;
    }

    //fopen_s(&fLogFile, "C:\\RecvLog.txt", "a+");
    //fwrite(buf,sizeof(char),read,fLogFile);
	//if (++packetCount > 10) {
		if (!encryption.isValid())
			encryption.Setup((unsigned char *)shaKey);
		
		log("Decrypting packet");
		std::string decrypted = encryption.In.Process((unsigned char *)buf, read);
		log(bufferToHex(decrypted.c_str(), decrypted.length()));
	//}
	//fprintf(fLogFile, "\nrecv(%d): %s\n", read, bufferToHex(buf, read));
    //fflush(fLogFile);
    return read;
}


int WINAPI MySend(SOCKET s, char *buf, int len, int flags)
{
	//MessageBox(0,"Send()","Send",0);
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
	o_recv = (t_recv)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "recv"), (PBYTE)Myrecv);
	o_send = (t_send)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "send"), (PBYTE)MySend);
	o_sendto = (t_sendto)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "sendto"), (PBYTE)MySendTo);
	o_recvfrom = (t_recvfrom)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "recvfrom"), (PBYTE)MyRecvFrom);
	o_connect = (t_connect)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "connect"), (PBYTE)MyConnect);
}

BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	packetCount = 0;
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			DisableThreadLibraryCalls((HMODULE)hModule);
			// Open Log File for Writing:
			char szLogFile[MAX_PATH];
			GetModuleFileName((HMODULE)hModule, szLogFile, MAX_PATH);
			strcpy(strrchr(szLogFile, (int)'.'), ".txt");
			fLogFile = fopen(szLogFile,"w");
			Starthook();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}
