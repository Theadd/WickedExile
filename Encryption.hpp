#include "ecrypt-sync.h"

class Encryption
{
public:
	
	Encryption();

	class Context
	{
	public:

		ECRYPT_ctx ctx;

		Context();

		void SetupKey(unsigned char *Key);

		void SetupIV(unsigned char *IV);
	
		std::string Process(unsigned char *Data, int len = NULL);
	
	};

	Context In;
	Context Out;

	void Setup(unsigned char *Key);

	bool isValid();

private:
	friend class Context;
	bool _isValid;
};
