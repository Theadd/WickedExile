#pragma once
#include <string>
#include "KeyEvent.hpp"
#include "ecrypt.c"

#include "Encryption.hpp"

#if !defined(ARRAY_SIZE)
    #define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#endif

Encryption::Encryption()
{
	_isValid = false;
}

Encryption::Context::Context() {}

void Encryption::Context::SetupKey(unsigned char *Key)
{
	unsigned int *stream = (unsigned int *)Key;
	ctx.input[1] = stream[0];
	ctx.input[2] = stream[1];
	ctx.input[3] = stream[2];
	ctx.input[4] = stream[3];
	ctx.input[11] = stream[4];
	ctx.input[12] = stream[5];
	ctx.input[13] = stream[6];
	ctx.input[14] = stream[7];
	ctx.input[0] = 0x61707865;
	ctx.input[5] = 0x3320646e;
	ctx.input[10] = 0x79622d32;
	ctx.input[15] = 0x6b206574;
}

void Encryption::Context::SetupIV(unsigned char *IV)
{
	unsigned int *stream = (unsigned int *)IV;

	ctx.input[6] = stream[0];
	ctx.input[7] = stream[1];
	ctx.input[8] = 0;
	ctx.input[9] = 0;
}
	
std::string Encryption::Context::Process(unsigned char *Data, int len)
{
	if(Data == NULL)
		return NULL;

	if (len == NULL)
		len = ARRAY_SIZE(Data);
			
	unsigned char *output = new unsigned char[len + 1];
	ECRYPT_decrypt_bytes(&ctx, Data, output, len);
	return std::string((char *)output);
}

void Encryption::Setup(unsigned char *Key)
{
	//var EncryptionKey = Segment(Key as array<byte>, 0, 32) as binary;
	In.SetupKey(Key);
	Out.SetupKey(Key);
	In.SetupIV(Key + 32);	//(Segment(Key as array<byte>, 32, 8) as binary);
	Out.SetupIV(Key + 48);	//(Segment(Key as array<byte>, 48, 8) as binary);
	_isValid = true;
}

bool Encryption::isValid()
{
	return _isValid;
}
