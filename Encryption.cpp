//#include "KeyEvent.hpp"
#include "JuceLibraryCode/JuceHeader.h"
#include "ecrypt.c"
#include "Encryption.hpp"

#if !defined(ARRAY_SIZE)
    #define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#endif


//B11DFE8787EBB0ADF6924DC3A67119D8EAFFAD0F58958DB0E2666C934605DA211828301617F92CCD19C6E62451D1C53D73
//4061C052AFAA3015B40925BC52BC7C

void logEx(String msg)
{
	msg += "\n";
	FILE* exileLog = NULL;
	exileLog = fopen("15.txt","w");
	fprintf(exileLog, msg.toRawUTF8());
	fflush(exileLog);
	fclose(exileLog);
}

void salsa20_process(ECRYPT_ctx *x,const u8 *m,u8 *c,u32 bytes, u8 *output)
{
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output,x->input);
    x->input[8] = PLUSONE(x->input[8]);
    if (!x->input[8]) {
      x->input[9] = PLUSONE(x->input[9]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
	  logEx(String((unsigned int)bytes));
	  
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

Encryption::Encryption()
{
	_isValid = false;
}

Encryption::Context::Context() {}

void Encryption::Context::SetupKey(unsigned char *Key)
{
	//ECRYPT_keysetup(&ctx,Key,128,64);
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
	//ECRYPT_ivsetup(&ctx, IV);
	unsigned int *stream = (unsigned int *)IV;

	ctx.input[6] = stream[0];
	ctx.input[7] = stream[1];
	ctx.input[8] = 0;
	ctx.input[9] = 0;
	
}

unsigned char* Encryption::Context::getInputAsCharacters()
{
	u8 wordtobyte_output[64];
	salsa20_wordtobyte(wordtobyte_output, ctx.input);
	return wordtobyte_output;
}
	
unsigned char* Encryption::Context::Process(unsigned char *Data, int len)
{
	if(Data == NULL)
		return NULL;

	if (len == NULL)
		len = ARRAY_SIZE(Data);
			
	unsigned char *output = new unsigned char[len + 1];
	salsa20_process(&ctx, Data, output, len, Stream);
	//return std::string((char *)output);
	return output;
	/*Array<char> DataArray;
	for (int i = 0; i < len; ++i) {
		DataArray.add(Data[i]);
	}
	Array<char> Result;
	int Bytes = len;
	int Offset = 0;
	while (Bytes > 0) {
		int StreamCount = Stream.size();
		if (StreamCount == 0) {
			//static void salsa20_wordtobyte(u8 output[64],const u32 input[16])
			u8 wordtobyte_output[64];
			salsa20_wordtobyte(wordtobyte_output, ctx.input);
			Stream.clear();
			for (int e = 0; e < 64; ++e)
				Stream.add(wordtobyte_output[e]);

			ctx.input[8] += 1;
			if (ctx.input[8] == 0)
				ctx.input[9] += 1;

			StreamCount = 64;
		}
		int Max = (Bytes > StreamCount) ? StreamCount : Bytes;
		for (int i = 0; i < Max; i += 1)
			Result.add(DataArray[Offset + i] ^ Stream[i]);
		
		Stream.removeLast(Stream.size() - Max);
		Offset += Max;
		Bytes -= Max;
	}
	unsigned char *return_val = new unsigned char[Result.size()];
	for (int i = 0; i < Result.size(); ++i)
		return_val[i] = Result[i];

	return return_val;*/
}
/*
array<byte> Stream = [];
	
binary Process(binary Data)
{
	if(Data == null)
		return null;

	var DataArray = Data as array<byte>;
	array<byte> Result = [];
	int Bytes = Data.ByteLength;
	int Offset = 0;
		
    while(Bytes > 0)
	{
		int StreamCount = Count(Stream);
			
		if(StreamCount == 0)
		{
			Stream = WordToByte(Input);
				
			Input[8] += 1;
				
			if(Input[8] == 0)
				Input[9] += 1;
					
			StreamCount = 64;
		}

		var Max = Bytes > StreamCount ? StreamCount : Bytes;
			
		for (int i = 0; i < Max; i += 1)
			Result += [(DataArray[Offset + i] ^ Stream[i]) as byte];
				
		Stream = Segment(Stream, Max);	//Segment(inicio, longitud);
			
		Offset += Max;
		Bytes -= Max;
	}
		
	return Result as binary;
}*/

void Encryption::Setup(unsigned char *Key)
{
	//var EncryptionKey = Segment(Key as array<byte>, 0, 32) as binary;
	In.SetupKey(Key);
	Out.SetupKey(Key);
	In.SetupIV(&(Key[32]));	//(Key + 32);	//(Segment(Key as array<byte>, 32, 8) as binary);
	Out.SetupIV(&(Key[48]));	//(Key + 48);	//(Segment(Key as array<byte>, 48, 8) as binary);
	_isValid = true;
}

bool Encryption::isValid()
{
	return _isValid;
}

//#########################################################
/*
u8 m[4096];
u8 c[4096];
u8 d[4096];
u8 k[32];
u8 v[8];

main()
{
  MD5_CTX fingerprint;
  ECRYPT_ctx x;
  int i;
  int bytes;
  int loop;

  for (loop = 0;loop < 10;++loop) {
    MD5_Init(&fingerprint);
    for (bytes = 0;bytes <= 4096;++bytes) {
      if (loop & 1)
        ECRYPT_keysetup(&x,k,256,64);
      else
        ECRYPT_keysetup(&x,k,128,64);
      ECRYPT_ivsetup(&x,v);
      ECRYPT_encrypt_bytes(&x,m,c,bytes);
      MD5_Update(&fingerprint,c,bytes);
      ECRYPT_ivsetup(&x,v);
      ECRYPT_decrypt_bytes(&x,c,d,bytes);
      for (i = 0;i < bytes;++i)
        if (d[i] != m[i]) printf("mismatch at position %d/%d\n",i,bytes);
      switch(bytes % 3) {
	case 0: for (i = 0;(i < bytes) && (i < 32);++i) k[i] ^= c[i]; break;
	case 1: for (i = 0;(i < bytes) && (i < 8);++i) v[i] ^= c[i]; break;
	case 2: for (i = 0;i < bytes;++i) m[i] = c[i]; break;
      }
    }
    MD5_Final(k,&fingerprint);
    for (i = 0;i < 32;++i) printf("%02x",k[i]); printf("\n"); fflush(stdout);
  }

  MD5_Init(&fingerprint);
  for (loop = 0;loop < 134217728;++loop) {
    ECRYPT_encrypt_bytes(&x,c,c,4096);
    MD5_Update(&fingerprint,c,4096);
  }
  MD5_Final(k,&fingerprint);
  for (i = 0;i < 16;++i) printf("%02x",k[i]); printf("\n"); fflush(stdout);

  return 0;
}
*/