#include <Windows.h>
#include <stdio.h>


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE {
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};


DWORD calcHash(char* data) {
	DWORD hash = 0x99;
	for (int i = 0; i < strlen(data); i++) {
		hash += data[i] + (hash << 1);
	}
	return hash;
}

static DWORD calcHashModule(LDR_MODULE* mdll) {
	char name[64];
	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
		name[i] = (char)mdll->dllname.Buffer[i];
		i++;
	}
	name[i] = 0;
	return calcHash((char*)CharLowerA(name));
}

static HMODULE getModule(DWORD myHash) {
	HMODULE module;
	INT_PTR peb = __readgsqword(0x60);
	auto ldr = 0x18;
	auto flink = 0x10;

	auto Mldr = *(INT_PTR*)(peb + ldr);
	auto M1flink = *(INT_PTR*)(Mldr + flink);
	auto Mdl = (LDR_MODULE*)M1flink;
	do {
		Mdl = (LDR_MODULE*)Mdl->e[0].Flink;
		if (Mdl->base != NULL) {

			if (calcHashModule(Mdl) == myHash) { 
				break;
			}
		}
	} while (M1flink != (INT_PTR)Mdl);

	module = (HMODULE)Mdl->base;
	return module;
}

static LPVOID getAPIAddr(HMODULE module, DWORD myHash) {

	PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module + img_dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
		(LPBYTE)module + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD fAddr = (PDWORD)((LPBYTE)module + img_edt->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)module + img_edt->AddressOfNames);
	PWORD  fOrd = (PWORD)((LPBYTE)module + img_edt->AddressOfNameOrdinals);

	for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
		if (calcHash(pFuncName) == myHash) {
			printf("\n[+] Successfully Found! %s\n", pFuncName);
			return (LPVOID)((LPBYTE)module + fAddr[fOrd[i]]);
		}
	}
	return NULL;
}

int main(int argc, char** argv) {
	HMODULE mod = getModule(4097367);	// Hash of ntdll.dll
	LPVOID addr = getAPIAddr(mod, atoi(argv[1]));	// argv[1] : Hash of the NT API
	WORD SSN = (WORD)*(INT_PTR*)((INT_PTR)addr + 0x4);
	printf("[+] SSN at 0x%p : %2x\n", ((INT_PTR)addr + 0x4), SSN);
	WORD syscallIns = (WORD)*(INT_PTR*)((INT_PTR)addr + 0x12);
	printf("[+] syscall instruction [ %2x ]	 at 0x%p\n", syscallIns, ((INT_PTR)addr + 0x12));
	
	return 0;
}
