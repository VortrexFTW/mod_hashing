
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <GalacticInterfaces.h>
#include <GalacticStrongPtr.h>

// Allow weak algorithms (MD5 only)
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

// Crypto++ methods
#include <aes.h>
#include <base64.h>
#include <blowfish.h>
#include <gzip.h>
#include <hex.h>
#include <md5.h>
#include <ripemd.h>
#include <sha.h>
#include <twofish.h>
#include <whrlpool.h>

typedef unsigned char byte;

// The modules internal name (Also used for the namespace name)
MODULE_MAIN("hashing");

SDK::Class g_ConnectionClass;
SDK::Class g_ResultClass;

void ModuleRegister()
{

	SDK::RegisterFunction("encodeBase64", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

        std::string message(szInput);

        std::string encodedBase64;
        CryptoPP::StringSource(szInput, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedBase64)));

		SDK::StringValue Value(encodedBase64.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});

	g_ConnectionClass.RegisterFunction("decodeBase64", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

        std::string message(szInput);

        std::string decodedBase64;
        CryptoPP::StringSource(szInput, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedBase64)));	

		SDK::StringValue Value(decodedBase64.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});
	
	g_ConnectionClass.RegisterFunction("md5", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::Weak::MD5 hash;
		byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});	

	
	g_ConnectionClass.RegisterFunction("sha1", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::SHA1 hash;
		byte digest[CryptoPP::SHA1::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});	
			
	g_ConnectionClass.RegisterFunction("sha224", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::SHA224 hash;
		byte digest[CryptoPP::SHA224::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});	
	
	g_ConnectionClass.RegisterFunction("sha256", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::SHA256 hash;
		byte digest[CryptoPP::SHA256::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});	

	g_ConnectionClass.RegisterFunction("sha384", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::SHA384 hash;
		byte digest[CryptoPP::SHA384::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});	

	g_ConnectionClass.RegisterFunction("sha512", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::SHA512 hash;
		byte digest[CryptoPP::SHA512::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});	

	g_ConnectionClass.RegisterFunction("ripemd128", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::RIPEMD128 hash;
		byte digest[CryptoPP::RIPEMD128::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});		

	g_ConnectionClass.RegisterFunction("ripemd160", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::RIPEMD160 hash;
		byte digest[CryptoPP::RIPEMD160::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});		
	
	g_ConnectionClass.RegisterFunction("ripemd256", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::RIPEMD256 hash;
		byte digest[CryptoPP::RIPEMD256::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});		
	
	g_ConnectionClass.RegisterFunction("ripemd320", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::RIPEMD320 hash;
		byte digest[CryptoPP::RIPEMD320::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});		
	
	g_ConnectionClass.RegisterFunction("whirlpool", [](Galactic3D::Interfaces::INativeState* pState, int32_t argc, void* pUser) {
		SDK_TRY;

		SDK::State State(pState);
		
        const char *szInput = State.CheckString(0);

		std::string message(szInput);

		CryptoPP::Whirlpool hash;
		byte digest[CryptoPP::Whirlpool::DIGESTSIZE];

		hash.CalculateDigest(digest, (byte *)szInput, message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;

		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		SDK::StringValue Value(output.c_str());
		State.Return(Value);
		return true;

		SDK_ENDTRY;
	});		
}

void ModuleUnregister()
{
}
