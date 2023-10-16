
#include <windows.h>
#include <iostream>
#include "argparse.h"
#include <fstream>

#include <vector>
#include <set>
#include <string>
#include <sstream>


bool GetExportNames(const char* dllPath, std::vector<std::string>& outExportNames)
{
	HANDLE hFile, hFileMap;//文件句柄和内存映射文件句柄
	DWORD fileAttrib = 0;//存储文件属性用，在createfile中用到。
	void* mod_base;//内存映射文件的起始地址，也是模块的起始地址
	typedef PVOID(CALLBACK* PFNEXPORTFUNC)(PIMAGE_NT_HEADERS, PVOID, ULONG, PIMAGE_SECTION_HEADER*);
	//首先取得ImageRvaToVa函数本来只要#include <Dbghelp.h>就可以使用这个函数，但是可能没有这个头文件
	PFNEXPORTFUNC ImageRvaToVax = NULL;
	HMODULE hModule = ::LoadLibraryA("DbgHelp.dll");
	if (hModule != NULL)
	{
		ImageRvaToVax = (PFNEXPORTFUNC)::GetProcAddress(hModule, "ImageRvaToVa");
		if (ImageRvaToVax == NULL)
		{
			::FreeLibrary(hModule);
			return false;
		}
	}
	else
	{
		return false;
	}

	hFile = CreateFileA(dllPath, GENERIC_READ, 0, 0, OPEN_EXISTING, fileAttrib, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		::FreeLibrary(hModule);
		return false;
	}
	hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
	if (hFileMap == NULL)
	{
		CloseHandle(hFile);
		::FreeLibrary(hModule);
		return false;
	}
	mod_base = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (mod_base == NULL)
	{
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		::FreeLibrary(hModule);
		return false;
	}
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)mod_base;
	IMAGE_NT_HEADERS* pNtHeader =
		(IMAGE_NT_HEADERS*)((BYTE*)mod_base + pDosHeader->e_lfanew);//得到NT头首址
	IMAGE_OPTIONAL_HEADER* pOptHeader =
		(IMAGE_OPTIONAL_HEADER*)((BYTE*)mod_base + pDosHeader->e_lfanew + 24);//optional头首址
	IMAGE_EXPORT_DIRECTORY* pExportDesc = (IMAGE_EXPORT_DIRECTORY*)
		ImageRvaToVax(pNtHeader, mod_base, pOptHeader->DataDirectory[0].VirtualAddress, 0);
	if (pExportDesc != NULL)
	{
		//导出表首址。函数名称表首地址每个DWORD代表一个函数名字字符串的地址
		PDWORD nameAddr = (PDWORD)ImageRvaToVax(pNtHeader, mod_base, pExportDesc->AddressOfNames, 0);
		DWORD i = 0;
		DWORD unti = pExportDesc->NumberOfNames;
		for (i = 0; i < unti; i++)
		{
			const char* func_name = (const char*)ImageRvaToVax(pNtHeader, mod_base, (DWORD)nameAddr[i], 0);
			if (func_name)
				outExportNames.push_back(func_name);
		}
	}

	::FreeLibrary(hModule);
	UnmapViewOfFile(mod_base);
	CloseHandle(hFileMap);
	CloseHandle(hFile);

	return true;
}

std::string replace(const char* pszSrc, const char* pszOld, const char* pszNew)
{
	std::string strContent, strTemp;
	strContent.assign(pszSrc);
	std::string::size_type nPos = 0;
	while (true)
	{
		nPos = strContent.find(pszOld, nPos);
		strTemp = strContent.substr(nPos + strlen(pszOld), strContent.length());
		if (nPos == std::string::npos)
		{
			break;
		}
		strContent.replace(nPos, strContent.length(), pszNew);
		strContent.append(strTemp);
		nPos += strlen(pszNew) - strlen(pszOld) + 1; //防止重复替换 避免死循环
	}
	return strContent;
}

using namespace argparse;

int main(int argc, char** argv)
{
	ArgumentParser parser("EasyDLL", "EasyDLL");
	parser.add_argument()
		.names({ "-w", "--wraper" })
		.description("Wraper class name.")
		.required(true);
	parser.add_argument()
		.names({ "-d", "--dll" })
		.description("DLL name or path.")
		.required(true);
	parser.add_argument()
		.names({ "-a", "--alias" })
		.description("Wraper alias name.")
		.required(false);
	parser.add_argument()
		.names({ "-e", "--exclude" })
		.description("Exclude list file path. One export name one line")
		.required(false);
	parser.add_argument()
		.names({ "-o", "--output" })
		.description("Output file path.")
		.required(false);
	parser.enable_help();
	auto err = parser.parse(argc, argv);
	if (err)
	{
		std::cout << err.what() << std::endl;
		parser.print_help();
		return 1;
	}

#define EL << std::endl <<

	std::string wrapperClass = parser.get<std::string>("w");
	std::string dllName = parser.get<std::string>("d");
	std::string aliasName = parser.get<std::string>("a");
	std::string excludeListFile = parser.get<std::string>("e");
	std::string outputFile = parser.get<std::string>("o");

	std::set<std::string> excludeExportNames;
	if (!excludeListFile.empty())
	{
		std::ifstream file(excludeListFile); // 打开文件
		if (file.is_open()) 
		{
			std::string line;
			while (std::getline(file, line)) 
			{ // 逐行读取文件内容
				excludeExportNames.insert(line.c_str());
			}
			file.close(); // 关闭文件
		}
		else 
		{
			std::cout << "无法打开文件:" << excludeListFile << std::endl;
			return 2;
		}		
	}
	
	std::vector<std::string> outExportNames;
	if (!GetExportNames(dllName.c_str(), outExportNames))
	{
		std::cout << "获得导出表失败:" << dllName << std::endl;
		return 3;
	}
		
	std::stringstream ss;
	ss <<
		"#pragma once" EL
		"#ifndef _AFX" EL
		"#include <windows.h>" EL
		"#endif" EL
		"#include <string>" EL
		"#define DEF_PROC(name) decltype(::name)* name" EL
		"#define SET_PROC(hDll, name) this->name = (decltype(::name)*)::GetProcAddress(hDll, #name)" << std::endl;

	bool sysQuot = true;
	std::vector<std::string> dllInc;
	dllInc.push_back("ChakraCore.h");
	dllInc.push_back("Core/CommonTypedefs.h");
	for (size_t i = 0; i < dllInc.size(); i++)
	{
		ss << "#include " << (sysQuot ? "<" : "\"") << dllInc[i] << (sysQuot ? ">" : "\"") << std::endl;
	}

	ss <<
		"class " << wrapperClass EL
		"{" EL
		"private:" EL
		"	static " << wrapperClass << "* s_ins;" EL
		"	HMODULE hDll;" EL
		"" EL
		"	~" << wrapperClass << "()" EL
		"	{" EL
		"		if (hDll)" EL
		"		{" EL
		"			FreeLibrary(hDll);" EL
		"			hDll = NULL;" EL
		"		}" EL
		"	}" EL
		"" EL
		"public:" EL
		"	static " << wrapperClass << "& Ins()" EL
		"	{" EL
		"		if (!s_ins)" EL
		"			s_ins = new " << wrapperClass << ";" EL
		"		return *s_ins;" EL
		"	}" EL
		"" EL
		"	static void Rel()" EL
		"	{" EL
		"		if (s_ins)" EL
		"		{" EL
		"			delete s_ins;" EL
		"			s_ins = NULL;" EL
		"		}" EL
		"	}" EL
		"" EL
		"	static HMODULE LoadLibraryFromCurrentDir(const char* dllName)" EL
		"	{" EL
		"		HMODULE hDll = LoadLibraryA(dllName);" EL
		"		if (!hDll)" EL
		"		{" EL
		"			char selfPath[MAX_PATH];" EL
		"			MEMORY_BASIC_INFORMATION mbi;" EL
		"			HMODULE hModule = ((::VirtualQuery(LoadLibraryFromCurrentDir, &mbi, sizeof(mbi)) != 0) ? " EL
		"				(HMODULE)mbi.AllocationBase : NULL);" EL
		"			::GetModuleFileNameA(hModule, selfPath, MAX_PATH);" EL
		"			std::string moduleDir(selfPath);" EL
		"			size_t idx = moduleDir.find_last_of('\\\\');" EL
		"			moduleDir = moduleDir.substr(0, idx);" EL
		"			std::string modulePath = moduleDir + \"\\\\\" + dllName;" EL
		"			char curDir[MAX_PATH];" EL
		"			::GetCurrentDirectoryA(MAX_PATH, curDir);" EL
		"			::SetCurrentDirectoryA(moduleDir.c_str());" EL
		"			hDll = LoadLibraryA(modulePath.c_str());" EL
		"			::SetCurrentDirectoryA(curDir);" EL
		"		}" EL
		"" EL
		"		if (!hDll)" EL
		"		{" EL
		"			DWORD err = ::GetLastError();" EL
		"			char buf[10];" EL
		"			sprintf_s(buf, \"%u\", err);" EL
		"			::MessageBoxA(NULL, (std::string(\"找不到\") + dllName + \"模块:\" + buf).c_str()," EL
		"				\"找不到模块\", MB_OK | MB_ICONERROR);" EL
		"		}" EL
		"		return hDll;" EL
		"	}" << std::endl;

	dllName = replace(dllName.c_str(), "\\", "\\\\");
	ss <<
		"	" << wrapperClass << "()" EL
		"	{" EL
		"		hDll = LoadLibraryFromCurrentDir(\"" << dllName << "\");" EL
		"		if (!hDll)" EL
		"			return;" << std::endl;

	for (size_t i = 0; i < outExportNames.size(); i++)
	{
		if (excludeExportNames.find(outExportNames[i].c_str()) == excludeExportNames.end())
			ss << "		SET_PROC(hDll, " << outExportNames[i] << ");" << std::endl;
	}

	ss << "	}" << std::endl;

	for (size_t i = 0; i < outExportNames.size(); i++)
	{
		if (excludeExportNames.find(outExportNames[i].c_str()) == excludeExportNames.end())
			ss << "		DEF_PROC(" << outExportNames[i] << ");" << std::endl;
	}

	ss << "};" << std::endl;
	ss <<
		"__declspec(selectany) " << wrapperClass << "* " << wrapperClass << "::s_ins = NULL;" << std::endl;

	if (!aliasName.empty())
	{
		ss << "#define " << aliasName << " " << wrapperClass << "::Ins()";
	}

	std::string sTxt = ss.str();
	if (!outputFile.empty())
	{
		std::ofstream file(outputFile);
		if (file.is_open()) 
		{
			file << sTxt;
			file.close();
			std::cout << "OK" << std::endl;
		}
		else 
		{
			std::cout << "无法打开文件:" << outputFile << std::endl;
			return 4;
		}
	}
	else
	{
		std::cout << sTxt << std::endl;
	}

	return 0;
}