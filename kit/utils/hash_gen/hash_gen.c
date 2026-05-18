// hash_gen.c -- Generator ROR13 хешей для kit/artifact/api_hash.h
//
// Совместим с алгоритмом из api_hash.h:
//   h = 0
//   for byte b in name:
//       h = ROR(h, 13) + b
//
//   Модули: lowercase ASCII (как в BaseDllName, приведённое к нижнему регистру).
//   Функции: case-sensitive ASCII.
//
// Использование:
//   hash_gen [-m] <name> [<name> ...]
//   hash_gen -f file.txt
//
//   -m   режим "module" (lowercase перед хешированием)
//   -f   читать имена из файла (по одному на строку)
//   без аргументов: интерактивный режим (читает stdin)
//
// Примеры:
//   hash_gen LoadLibraryA VirtualAlloc CreateThread
//   hash_gen -m kernel32.dll ntdll.dll user32.dll
//   hash_gen -f api_list.txt
//
// Сборка (MSVC, x64):
//   cl /nologo /O2 /W3 hash_gen.c
//
// Сборка (MSVC, x86):
//   vcvarsall x86 && cl /nologo /O2 /W3 hash_gen.c
//
// Сборка (MinGW / другая x64):
//   gcc -O2 -Wall hash_gen.c -o hash_gen.exe

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef unsigned int u32;

// ROR-13 + add, бит-в-бит идентично api_hash.h::ah_hash_ansi
static u32 ror13_hash(const char *s, int to_lower) {
    u32 h = 0;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (to_lower && c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        h = ((h >> 13) | (h << (32 - 13))) + c;
    }
    return h;
}

// Печать строки #define вида:
//   #define H_<TAG>      0x<HEX>U     // <orig name>
//
// TAG: для функций — сам name; для модулей — name с '.' -> '_' и upper.
static void print_define(const char *name, int is_module) {
    char tag[128];
    size_t i;
    u32 h = ror13_hash(name, is_module);

    if (is_module) {
        for (i = 0; name[i] && i + 1 < sizeof(tag); ++i) {
            char c = name[i];
            if (c == '.' || c == '-') c = '_';
            else if (c >= 'a' && c <= 'z') c = (char)(c - 32);
            tag[i] = c;
        }
        tag[i] = 0;
    } else {
        for (i = 0; name[i] && i + 1 < sizeof(tag); ++i) tag[i] = name[i];
        tag[i] = 0;
    }
    printf("#define H_%-32s 0x%08XU  // %s\n", tag, h, name);
}

static void strip_eol(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' ||
                     s[n-1] == ' '  || s[n-1] == '\t'))
        s[--n] = 0;
}

static int read_file_lines(const char *path, int is_module) {
    FILE *f = fopen(path, "r");
    char buf[512];
    if (!f) {
        fprintf(stderr, "[-] cannot open: %s\n", path);
        return 1;
    }
    while (fgets(buf, sizeof(buf), f)) {
        strip_eol(buf);
        if (buf[0] == 0 || buf[0] == '#' || buf[0] == ';') continue;
        print_define(buf, is_module);
    }
    fclose(f);
    return 0;
}

static int interactive(int is_module) {
    char buf[512];
    fprintf(stderr, "[*] Interactive mode (%s). Enter name per line, EOF to exit.\n",
            is_module ? "module/lowercase" : "function/case-sensitive");
    while (fgets(buf, sizeof(buf), stdin)) {
        strip_eol(buf);
        if (buf[0] == 0) continue;
        print_define(buf, is_module);
    }
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "hash_gen -- ROR13 API hash generator (matches kit/artifact/api_hash.h)\n"
        "\n"
        "Usage:\n"
        "  hash_gen [-m] <name> [<name> ...]    one or more names from CLI\n"
        "  hash_gen [-m] -f <file>              read names from file\n"
        "  hash_gen [-m]                        interactive (stdin)\n"
        "\n"
        "Options:\n"
        "  -m       module mode (lowercase before hashing, e.g. kernel32.dll)\n"
        "  -f FILE  read names from FILE (one per line, # and ; comments)\n"
        "\n"
        "Examples:\n"
        "  hash_gen LoadLibraryA VirtualAlloc\n"
        "  hash_gen -m kernel32.dll ntdll.dll\n"
        "  hash_gen -f apis.txt > new_hashes.h\n");
}

int main(int argc, char **argv) {
    int is_module = 0;
    int i;

    // Парсинг -m в любой позиции (один раз)
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-m") == 0) {
            is_module = 1;
            // Сдвигаем массив, чтобы дальнейший парсинг был чище
            int j;
            for (j = i; j < argc - 1; ++j) argv[j] = argv[j + 1];
            argc--;
            break;
        }
    }

    if (argc < 2) {
        // stdin
        return interactive(is_module);
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "/?") == 0) {
        usage();
        return 0;
    }

    if (strcmp(argv[1], "-f") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[-] -f requires a filename\n");
            usage();
            return 1;
        }
        return read_file_lines(argv[2], is_module);
    }

    // Имена из CLI
    for (i = 1; i < argc; ++i) {
        print_define(argv[i], is_module);
    }
    return 0;
}
