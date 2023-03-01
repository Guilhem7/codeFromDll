#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

/* Image optional header
typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase; // Not sure of this, I though it was 64 bits...
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;
*/

#define CHUNK_SIZE 4096
#define MAX_CODE_LENGTH 2048
#define RET_INSTR 0xc3

void hexprint(void* toPrint, int l) {
	for (int i = 0; i < l; i++) {
		printf("%02X ", *(unsigned char*)((unsigned long long)toPrint + i)); // Diff between deref and cast
	}
	printf("\n");
}

void printCode(unsigned char* code) {
	printf("unsigned char myFunc[] = {\n\t");
	for (int i = 0; i < MAX_CODE_LENGTH - 1; i++) {
		printf("0x%02X, ", code[i]);
		if ( (i+1) % 4 == 0 && i !=0) {
			printf("\n\t");
		}
		if (code[i + 1] == RET_INSTR) {
			printf("0x%02X\n", code[i+1]);
			break;
		}
	}
	printf("\t};\n");
}

int memem(void * memory, int size, BYTE * pattern, int patternSize) {
	int res = -1;
	for (int i = 0; i < size; i++) {
		if (memcmp( (BYTE *)((unsigned long long)memory + i), pattern, patternSize) == 0) {
			res = i;
			break;
		}
	}
	return res;
}

// Find Word in memory
int memFoundPat(void* memory, int size, WORD pattern) {
	int res = -1;
	for (int i = 0; i < size; i++) {
		if( *(WORD *)((unsigned long long)memory + i) == pattern) {
			res = i;
			break;
		}
	}
	return res;
}


int readFileMem(FILE * fp, char * buf, int offset, int num) {
	if (fseek(fp, offset, SEEK_SET) != 0) {
		return 0;
	}

	if (fread(buf, sizeof(BYTE), num, fp) > 0) {
		return 1;
	}

	return 0;
}

int readFileStr(FILE* fp, char* buf, int offset) {
	if (fseek(fp, offset, SEEK_SET) != 0) {
		return 0;
	}

	if (fgets(buf, 500, fp) != NULL) {
		return 1;
	}

	return 0;
}

void readFileMemUntil(FILE* fp, int offset, char * code) {
	if (fseek(fp, offset, SEEK_SET) != 0) {
		return 0;
	}

	int i = 0;
	BYTE ch;

	while (i < MAX_CODE_LENGTH) {
		ch = (BYTE) fgetc(fp);
		code[i] = ch;

		if (ch == RET_INSTR) {
			break;
		}
		i++;
	}
}

int parseSectionHdrs(FILE * fp, int chunk_addr, BYTE * memHeader, char * sections) {
	PIMAGE_SECTION_HEADER res = malloc(sizeof(IMAGE_SECTION_HEADER));
	int size = sizeof(IMAGE_OPTIONAL_HEADER64);
	int offsetWithRva = -1;

	for(int i=0;i < 10; i++){ // TODO Parse number of sections present
		memcpy(res, ((DWORDLONG)memHeader + size + chunk_addr + (i* sizeof(IMAGE_SECTION_HEADER)) ), sizeof(IMAGE_SECTION_HEADER) );
		if (strcmp(res->Name, sections) == 0) {
			offsetWithRva = res->VirtualAddress - res->PointerToRawData;
			break;
		}
	}
	return offsetWithRva;
}

int main() {
	PIMAGE_OPTIONAL_HEADER64 OptionalHeader = NULL;

	char* target_dll = "C:\\Windows\\System32\\ntdll.dll";
	char* target_func = "NtReadVirtualMemory";
	FILE* fp = NULL;
	
	int chunk_addr = 0;
	void * chunk[CHUNK_SIZE] = {0};
	BYTE code[MAX_CODE_LENGTH] = { 0 };

	IMAGE_DATA_DIRECTORY exportDirectoryAddr;
	IMAGE_EXPORT_DIRECTORY imgExpDir;

	exportDirectoryAddr.VirtualAddress = NULL;
	exportDirectoryAddr.Size = 0;

	fopen_s(&fp, target_dll, "rb");
	if (fp == NULL) {
		printf("Error opening file\n");
		exit(1);		
	}

	if(fread(chunk, sizeof(BYTE), CHUNK_SIZE, fp) > 0) {
		chunk_addr = memFoundPat(chunk, CHUNK_SIZE, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
		if (chunk_addr == -1) {
			printf("Failed..\n");
		}
		else {
			OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((DWORDLONG)chunk + chunk_addr);
			exportDirectoryAddr = OptionalHeader->DataDirectory[0];
		}
		//hexprint( (void *)((DWORDLONG)chunk + chunk_addr), 2);
	}

	int offsetRVA = parseSectionHdrs(fp, chunk_addr, chunk, ".rdata");
	int offsetRVAOfText = parseSectionHdrs(fp, chunk_addr, chunk, ".text");
	if (offsetRVA == -1) {
		printf("[-] WOW such error..\n");
		return 1;
	}
	printf("[+] Found: offset: 0x%X\n", offsetRVA);

	if (exportDirectoryAddr.Size > 0) {
		printf("[+] Size of export directory (%d Mo)\n", exportDirectoryAddr.Size/1024);
		fseek(fp, exportDirectoryAddr.VirtualAddress - offsetRVA, SEEK_SET);
		if (fread(chunk, sizeof(BYTE), CHUNK_SIZE, fp) > 0) {
			memcpy(&imgExpDir, chunk, sizeof(IMAGE_EXPORT_DIRECTORY));
			printf("[+] Number of functions: 0x%X\n", imgExpDir.NumberOfFunctions);
			printf("[+] Functions start at address: 0x%X\n", (imgExpDir.AddressOfFunctions - offsetRVA) );
			void* funcNames = malloc(imgExpDir.NumberOfFunctions);
			char* tempFuncName[500] = { 0 };
			void* tempFuncAddr[4] = { 0 };

			for (int i = 0; i < imgExpDir.NumberOfFunctions; i++) {
				readFileMem(fp, tempFuncAddr, imgExpDir.AddressOfNames - offsetRVA + (4*i) , 4);
				readFileStr(fp, tempFuncName, *(int*)tempFuncAddr - offsetRVA);
			
				if (strcmp(tempFuncName, target_func) == 0) {
					printf("[+] Found function [%s]\n", target_func);
					printf("[+] Address of the function code: 0x%X\n", imgExpDir.AddressOfFunctions - offsetRVA + (4 * i));

					memset(tempFuncName, 0, 8);
					readFileMem(fp, tempFuncName, imgExpDir.AddressOfFunctions - offsetRVA + (4 * i), 4);
					printf("[+] Dumping code of function %s:\n\n", target_func);
					int addrOfFuncCode = (unsigned long)(*tempFuncName);
					
					readFileMemUntil(fp, addrOfFuncCode - offsetRVAOfText, code);

					// Function code recovered: printing in a C manner
					printCode(code);
					break;
				}

				if (i == imgExpDir.NumberOfFunctions - 1) {
					printf("[-] Function not found..\n");
				}
			}
		}
		
	}

	return 0;
}
