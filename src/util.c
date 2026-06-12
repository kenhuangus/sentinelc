/* util.c - small helpers shared everywhere.
 * C11, Win32 user-mode. Libs: kernel32, advapi32.
 */
#include "sentinelc.h"

#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <wchar.h>

/* ---- severity / signing names ---- */

const char *sev_name(Severity s)
{
    switch (s) {
    case SEV_INFO: return "INFO";
    case SEV_LOW:  return "LOW";
    case SEV_MED:  return "MEDIUM";
    case SEV_HIGH: return "HIGH";
    case SEV_CRIT: return "CRITICAL";
    default:       return "UNKNOWN";
    }
}

const char *sign_name(SignVerdict v)
{
    switch (v) {
    case SIGN_UNKNOWN:   return "UNKNOWN";
    case SIGN_UNSIGNED:  return "UNSIGNED";
    case SIGN_INVALID:   return "INVALID";
    case SIGN_SIGNED:    return "SIGNED";
    case SIGN_SIGNED_MS: return "SIGNED-MS";
    default:             return "UNKNOWN";
    }
}

/* ---- UTF conversions ---- */

/* UTF-16 -> UTF-8 into out (returns bytes written, not counting NUL; 0 on error).
 * Always NUL-terminates out when cap > 0. */
size_t wide_to_utf8(const wchar_t *w, char *out, size_t cap)
{
    if (!out || cap == 0)
        return 0;
    out[0] = '\0';
    if (!w)
        return 0;

    /* Reserve one byte for the terminator. */
    int icap = (cap > (size_t)INT_MAX) ? INT_MAX : (int)cap;
    if (icap <= 1) {
        out[0] = '\0';
        return 0;
    }

    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, icap, NULL, NULL);
    if (n > 0) {
        /* n includes the terminating NUL. */
        out[(size_t)icap - 1] = '\0';
        return (size_t)(n - 1);
    }

    /* Buffer too small (or other error): convert a bounded prefix that fits.
     * WideCharToMultiByte writes nothing on ERROR_INSUFFICIENT_BUFFER, so do
     * it explicitly with WC_NO_BEST_FIT_CHARS off, shrinking the source until
     * the result fits. Keep it simple and bounded: copy a converted prefix. */
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        /* Find the largest source length whose conversion fits in icap-1. */
        int srclen = (int)wcslen(w);
        for (; srclen > 0; --srclen) {
            int need = WideCharToMultiByte(CP_UTF8, 0, w, srclen,
                                           NULL, 0, NULL, NULL);
            if (need > 0 && need <= icap - 1) {
                int got = WideCharToMultiByte(CP_UTF8, 0, w, srclen,
                                              out, icap - 1, NULL, NULL);
                if (got > 0) {
                    out[got] = '\0';
                    return (size_t)got;
                }
                break;
            }
        }
        out[0] = '\0';
        return 0;
    }

    out[0] = '\0';
    return 0;
}

/* UTF-8 -> UTF-16 into out (returns wchars written, not counting NUL; 0 on error).
 * Always NUL-terminates out when cap_wchars > 0. */
size_t utf8_to_wide(const char *s, wchar_t *out, size_t cap_wchars)
{
    if (!out || cap_wchars == 0)
        return 0;
    out[0] = L'\0';
    if (!s)
        return 0;

    int icap = (cap_wchars > (size_t)INT_MAX) ? INT_MAX : (int)cap_wchars;
    if (icap <= 1) {
        out[0] = L'\0';
        return 0;
    }

    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, out, icap);
    if (n > 0) {
        out[(size_t)icap - 1] = L'\0';
        return (size_t)(n - 1);
    }

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        int srclen = (int)strlen(s);
        for (; srclen > 0; --srclen) {
            int need = MultiByteToWideChar(CP_UTF8, 0, s, srclen, NULL, 0);
            if (need > 0 && need <= icap - 1) {
                int got = MultiByteToWideChar(CP_UTF8, 0, s, srclen,
                                              out, icap - 1);
                if (got > 0) {
                    out[got] = L'\0';
                    return (size_t)got;
                }
                break;
            }
        }
        out[0] = L'\0';
        return 0;
    }

    out[0] = L'\0';
    return 0;
}

/* ---- string helpers ---- */

void str_lower(char *s)
{
    if (!s)
        return;
    for (; *s; ++s)
        *s = (char)tolower((unsigned char)*s);
}

bool str_iendswith(const char *s, const char *suffix)
{
    if (!s || !suffix)
        return false;
    size_t ls = strlen(s);
    size_t lf = strlen(suffix);
    if (lf > ls)
        return false;
    const char *p = s + (ls - lf);
    for (size_t i = 0; i < lf; ++i) {
        if (tolower((unsigned char)p[i]) != tolower((unsigned char)suffix[i]))
            return false;
    }
    return true;
}

bool str_icontains(const char *hay, const char *needle)
{
    if (!hay || !needle)
        return false;
    if (needle[0] == '\0')
        return true;
    size_t lh = strlen(hay);
    size_t ln = strlen(needle);
    if (ln > lh)
        return false;
    for (size_t i = 0; i + ln <= lh; ++i) {
        size_t j = 0;
        for (; j < ln; ++j) {
            if (tolower((unsigned char)hay[i + j]) !=
                tolower((unsigned char)needle[j]))
                break;
        }
        if (j == ln)
            return true;
    }
    return false;
}

/* Extract the base name (component after the last '\\' or '/') into out. */
void base_name(const char *path, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!path)
        return;

    const char *base = path;
    for (const char *p = path; *p; ++p) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }

    size_t i = 0;
    for (; base[i] && i + 1 < cap; ++i)
        out[i] = base[i];
    out[i] = '\0';
}

/* ---- privilege / elevation ---- */

bool enable_debug_privilege(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    bool ok = false;
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (AdjustTokenPrivileges(token, FALSE, &tp,
                                  sizeof(tp), NULL, NULL)) {
            /* AdjustTokenPrivileges may "succeed" yet not assign the privilege
             * (ERROR_NOT_ALL_ASSIGNED). Only report true if actually enabled. */
            if (GetLastError() == ERROR_SUCCESS)
                ok = true;
        }
    }

    CloseHandle(token);
    return ok;
}

bool process_is_elevated(void)
{
    /* Primary: check the token's elevation flag. */
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD ret = 0;
        if (GetTokenInformation(token, TokenElevation, &elev,
                                sizeof(elev), &ret) &&
            ret == sizeof(elev)) {
            BOOL elevated = elev.TokenIsElevated ? TRUE : FALSE;
            CloseHandle(token);
            if (elevated)
                return true;
            /* Not elevated by token flag; fall through to group check below
             * in case UAC is disabled and admin membership is the signal. */
        } else {
            CloseHandle(token);
        }
    }

    /* Fallback: is the current token a member of the Administrators alias? */
    PSID admins = NULL;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_auth, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &admins)) {
        BOOL is_member = FALSE;
        if (CheckTokenMembership(NULL, admins, &is_member)) {
            FreeSid(admins);
            return is_member ? true : false;
        }
        FreeSid(admins);
    }

    return false;
}
