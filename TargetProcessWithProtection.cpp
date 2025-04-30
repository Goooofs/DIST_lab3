#define LOCAL_BLOCKDLLPOLICY
#define STOP_ARG "xakep"

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Функция для создания процесса с политикой защиты от загрузки неподписанных DLL
BOOL CreateProcessWithBlockDllPolicy(IN LPSTR lpProcessPath, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    STARTUPINFOEXA siEx = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T attrListSize = 0;

    if (lpProcessPath == NULL)
        return FALSE;

    // Инициализируем структуру STARTUPINFOEXA
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    // Указываем, что будем использовать расширенные параметры запуска
    siEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // Первый вызов для получения необходимого размера буфера атрибутов
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrListSize);
    if (pAttrList == NULL) {
        return FALSE;
    }

    // Инициализируем список атрибутов
    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrListSize)) {
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // Задаём политику митигации: блокировка загрузки DLL, не подписанных Microsoft
    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(dwPolicy), NULL, NULL)) {
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // Привязываем список атрибутов к структуре запуска
    siEx.lpAttributeList = pAttrList;

    // Запускаем процесс с расширенными атрибутами
    if (!CreateProcessA(
            NULL,
            lpProcessPath,  // командная строка с путем к исполняемому файлу и аргументом защиты
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT,
            NULL,
            NULL,
            &siEx.StartupInfo,
            &pi))
    {
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // Возвращаем информацию о созданном процессе
    *dwProcessId = pi.dwProcessId;
    *hProcess = pi.hProcess;
    *hThread = pi.hThread;

    // Освобождаем ресурсы
    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);

    return TRUE;
}

int main(int argc, char* argv[]) {
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL, hThread = NULL;

    static bool cleared = false;

    // Удаляем лог, если это первичный запуск (без аргумента xakep)
    if (argc == 1 && !cleared) {
        DeleteFileA("protection_log.txt");
        cleared = true;
    }

    FILE* logFile;
    fopen_s(&logFile, "protection_log.txt", "a");
    if (!logFile) return -1;

    #ifdef LOCAL_BLOCKDLLPOLICY
    fprintf(logFile, "[*] Process started. Arg count: %d\n", argc);
    if (argc == 2) {
        fprintf(logFile, "[*] Arg 1: %s\n", argv[1]);
    }

    if (argc == 2 && (strcmp(argv[1], STOP_ARG) == 0)) {
        fprintf(logFile, "[+] Protection is active. Sleeping forever.\n");
        fflush(logFile);
        fclose(logFile);
        WaitForSingleObject((HANDLE)-1, INFINITE);
    } else {
        fprintf(logFile, "[!] Protection is NOT active. Restarting with protection...\n");

        char filename[MAX_PATH * 2] = {0};
        if (!GetModuleFileNameA(NULL, filename, sizeof(filename))) {
            fprintf(logFile, "[!] GetModuleFileNameA failed. Error: %lu\n", GetLastError());
            fclose(logFile);
            return -1;
        }

        size_t bufferSize = strlen(filename) + strlen(STOP_ARG) + 64;
        char* buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (buffer == NULL) {
            fprintf(logFile, "[!] Failed to allocate memory for buffer.\n");
            fclose(logFile);
            return -1;
        }

        sprintf_s(buffer, bufferSize, "%s %s", filename, STOP_ARG);
        fprintf(logFile, "[*] Launching: %s\n", buffer);

        if (!CreateProcessWithBlockDllPolicy(buffer, &dwProcessId, &hProcess, &hThread)) {
            fprintf(logFile, "[!] Failed to launch protected process. Error: %lu\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, buffer);
            fclose(logFile);
            return -1;
        }

        fprintf(logFile, "[+] Protected process started. PID: %lu\n", dwProcessId);
        HeapFree(GetProcessHeap(), 0, buffer);
        fflush(logFile);
        fclose(logFile);
    }
#endif

#ifndef LOCAL_BLOCKDLLPOLICY
    fprintf(logFile, "[*] Starting external protected process...\n");
    if (!CreateProcessWithBlockDllPolicy((LPSTR)"C:\\Windows\\System32\\RuntimeBroker.exe", &dwProcessId, &hProcess, &hThread)) {
        fprintf(logFile, "[!] Failed to start protected process. Error: %lu\n", GetLastError());
        fclose(logFile);
        return -1;
    }
    fprintf(logFile, "[+] Started protected process. PID: %lu\n", dwProcessId);
    fflush(logFile);
    fclose(logFile);
#endif

    return 0;
}