#include "ecrypt-sync.h"

class Encryption
{
public:
	
	Encryption();

	class Context
	{
	public:

		ECRYPT_ctx ctx;
		//Array< char > Stream;
		u8 Stream[64];

		Context();

		void SetupKey(unsigned char *Key);

		void SetupIV(unsigned char *IV);
	
		unsigned char* Process(unsigned char *Data, int len = NULL);
	
		unsigned char* getInputAsCharacters();
	};

	Context In;
	Context Out;

	void Setup(unsigned char *Key);

	bool isValid();

private:
	friend class Context;
	bool _isValid;
};
