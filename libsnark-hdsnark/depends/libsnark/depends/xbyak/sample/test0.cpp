#if defined(_MSC_VER) && (_MSC_VER <= 1200)
	#pragma warning(disable:4514)
	#pragma warning(disable:4786)
#endif
#if defined(_MSC_VER) && (_MSC_VER >= 1900)
	#pragma warning(disable:4456)
#endif
#include <stdio.h>
#include <stdlib.h>
#define XBYAK_NO_OP_NAMES
#include "xbyak/xbyak.h"

class Sample : public Xbyak::CodeGenerator {
	void operator=(const Sample&);
public:
	Sample(void *userPtr = 0, size_t size = Xbyak::DEFAULT_MAX_CODE_SIZE) : Xbyak::CodeGenerator(size, userPtr)
	{
		inLocalLabel(); // use local label for multiple instance
#ifdef XBYAK32
		mov(ecx, ptr [esp + 4]); // n
#elif defined(XBYAK64_GCC)
		mov(ecx, edi); // n
#else
		// n = ecx
#endif
		xor_(eax, eax); // sum
		test(ecx, ecx);
		jz(".exit");
		xor_(edx, edx); // i
	L(".lp");
		add(eax, edx);
		inc(edx);

		cmp(edx, ecx);
		jbe(".lp"); // jmp to previous @@
	L(".exit"); // <B>
		ret();
		outLocalLabel(); // end of local label
	}
};

class AddFunc : public Xbyak::CodeGenerator {
	void operator=(const AddFunc&);
public:
	AddFunc(int y)
	{
#ifdef XBYAK32
		mov(eax, ptr [esp + 4]);
		add(eax, y);
#elif defined(XBYAK64_WIN)
		lea(rax, ptr [rcx + y]);
#else
		lea(eax, ptr [edi + y]);
#endif
		ret();
	}
	int (*get() const)(int) { return getCode<int(*)(int)>(); }
};

class CallAtoi : public Xbyak::CodeGenerator {
	void operator=(const CallAtoi&);
public:
	CallAtoi()
	{
#ifdef XBYAK64
#ifdef XBYAK64_WIN
		sub(rsp, 32); // return-address is destroied if 64bit debug mode
#endif
		mov(rax, (size_t)atoi);
		call(rax);
#ifdef XBYAK64_WIN
		add(rsp, 32);
#endif
#else
		mov(eax, ptr [esp + 4]);
		push(eax);
#ifdef XBYAK_VARIADIC_TEMPLATE
		call(atoi);
#else
		call(Xbyak::CastTo<void*>(atoi));
#endif
		add(esp, 4);
#endif
		ret();
	}
	int (*get() const)(const char *) { return getCode<int (*)(const char *)>(); }
};

class JmpAtoi : public Xbyak::CodeGenerator {
	void operator=(const JmpAtoi&);
public:
	JmpAtoi()
	{
		/* already pushed "456" */
#ifdef XBYAK64
		mov(rax, (size_t)atoi);
		jmp(rax);
#else
		jmp(Xbyak::CastTo<void*>(atoi));
#endif
	}
	int (*get() const)(const char *) { return getCode<int (*)(const char *)>(); }
};

struct Reset : public Xbyak::CodeGenerator {
	void init(int n)
	{
		xor_(eax, eax);
		mov(ecx, n);
		test(ecx, ecx);
		jnz("@f");
		ret();
	L("@@");
		for (int i = 0; i < 10 - n; i++) {
			add(eax, ecx);
		}
		sub(ecx, 1);
		jnz("@b");
		ret();
	}
};

void testReset()
{
	puts("testReset");
	Reset code;
	int (*f)(int) = code.getCode<int(*)(int)>();
	for (int i = 0; i < 10; i++) {
		code.init(i);
		int v = f(i);
		printf("%d %d\n", i, v);
		code.reset();
	}
}

int main()
{
	try {
		Sample s;
		printf("Xbyak version=%s\n", s.getVersionString());
#ifdef XBYAK64_GCC
		puts("64bit mode(gcc)");
#elif defined(XBYAK64_WIN)
		puts("64bit mode(win)");
#else
		puts("32bit");
#endif
		int (*func)(int) = s.getCode<int (*)(int)>();
		for (int i = 0; i <= 10; i++) {
			printf("0 + ... + %d = %d\n", i, func(i));
		}
		for (int i = 0; i < 10; i++) {
			AddFunc a(i);
			int (*add)(int) = a.get();
			int y = add(i);
			printf("%d + %d = %d\n", i, i, y);
		}
		CallAtoi c;
		printf("call atoi(\"123\") = %d\n", c.get()("123"));
		JmpAtoi j;
		printf("jmp atoi(\"456\") = %d\n", j.get()("456"));
		{
			// use memory allocated by user
			using namespace Xbyak;
			const size_t codeSize = 1024;
			uint8 buf[codeSize + 16];
			uint8 *p = CodeArray::getAlignedAddress(buf);
			CodeArray::protect(p, codeSize, true);
			Sample s(p, codeSize);
			int (*func)(int) = s.getCode<int (*)(int)>();
			if (Xbyak::CastTo<uint8*>(func) != p) {
				fprintf(stderr, "internal error %p %p\n", p, Xbyak::CastTo<uint8*>(func));
				return 1;
			}
			printf("0 + ... + %d = %d\n", 100, func(100));
			CodeArray::protect(p, codeSize, false);
		}
		puts("OK");
		testReset();
	} catch (std::exception& e) {
		printf("ERR:%s\n", e.what());
	} catch (...) {
		printf("unknown error\n");
	}
}

