/* legacy_app.c — a deliberately REPRESENTATIVE 1990s-shaped Win32 business app.
 *
 * Ground truth for the census. The point is NOT realism for its own sake: it is
 * that I know EXACTLY which Win32 APIs this calls, so the census can be checked
 * against a known import set instead of trusting the lifter's output blindly.
 *
 * The shape mirrors what a 40-year-old line-of-business binary actually does:
 *   - business RULES in pure arithmetic/branching (the dowry — the valuable part)
 *   - persistence via file I/O (OS)
 *   - configuration via registry (OS)
 *   - a bit of UI (OS)
 *   - string munging split between CRT-ish local code and OS calls
 */
#include <windows.h>

/* ---- BUSINESS LOGIC: pure computation, no OS. This is what must be captured. */

static int tier_of_balance(int cents) {
    if (cents >= 1000000) return 3;
    if (cents >=  250000) return 2;
    if (cents >=   50000) return 1;
    return 0;
}

static int discount_bps(int tier, int years_customer, int is_employee) {
    int bps = 0;
    switch (tier) {
        case 3: bps = 1500; break;
        case 2: bps =  900; break;
        case 1: bps =  400; break;
        default: bps = 0;   break;
    }
    if (years_customer > 10) bps += 250;
    else if (years_customer > 5) bps += 100;
    if (is_employee) bps += 500;
    if (bps > 2500) bps = 2500;          /* cap */
    return bps;
}

static int apply_discount(int gross_cents, int bps) {
    long long d = (long long)gross_cents * (long long)bps / 10000LL;
    return (int)((long long)gross_cents - d);
}

static int vat_cents(int net_cents, int reduced_rate) {
    int rate_bps = reduced_rate ? 700 : 1900;
    return (int)(((long long)net_cents * rate_bps + 5000LL) / 10000LL);
}

static int checksum_account(const char *acct) {
    int sum = 0, i = 0, weight = 2;
    while (acct[i] != 0) {
        int c = acct[i];
        if (c >= '0' && c <= '9') {
            int v = (c - '0') * weight;
            if (v > 9) v -= 9;
            sum += v;
            weight = (weight == 2) ? 1 : 2;
        }
        i++;
    }
    return (10 - (sum % 10)) % 10;
}

static int parse_int(const char *s) {
    int v = 0, i = 0, neg = 0;
    if (s[0] == '-') { neg = 1; i = 1; }
    while (s[i] >= '0' && s[i] <= '9') { v = v * 10 + (s[i] - '0'); i++; }
    return neg ? -v : v;
}

static void fmt_cents(int cents, char *out) {
    int i = 0, j, n = cents < 0 ? -cents : cents;
    char tmp[32];
    int frac = n % 100; n /= 100;
    if (n == 0) tmp[i++] = '0';
    while (n > 0) { tmp[i++] = (char)('0' + (n % 10)); n /= 10; }
    j = 0;
    if (cents < 0) out[j++] = '-';
    while (i > 0) out[j++] = tmp[--i];
    out[j++] = '.';
    out[j++] = (char)('0' + frac / 10);
    out[j++] = (char)('0' + frac % 10);
    out[j] = 0;
}

/* ---- OS BOUNDARY: every call below escapes into Windows. */

static int read_config_rate(void) {
    HKEY k; DWORD type = 0, val = 0, cb = sizeof(val);
    int reduced = 0;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\LegacyApp", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "ReducedRate", NULL, &type, (LPBYTE)&val, &cb) == ERROR_SUCCESS)
            reduced = (int)val;
        RegCloseKey(k);
    }
    return reduced;
}

static int write_invoice(const char *path, const char *line) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    WriteFile(h, line, (DWORD)lstrlenA(line), &written, NULL);
    CloseHandle(h);
    return (int)written;
}

static int load_customer_record(const char *path, char *buf, int cap) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD got = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL);
    CloseHandle(h);
    buf[got] = 0;
    return (int)got;
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
    char rec[256], out[256], amount[32];
    int gross, tier, bps, net, vat, total, cd, reduced;

    (void)hi; (void)hp; (void)show;

    if (!load_customer_record("C:\\LEGACY\\CUST.DAT", rec, sizeof(rec)))
        lstrcpyA(rec, "0000123456,750000,7,0");

    gross   = parse_int(rec);
    reduced = read_config_rate();
    tier    = tier_of_balance(gross);
    bps     = discount_bps(tier, parse_int(cmd), 0);
    net     = apply_discount(gross, bps);
    vat     = vat_cents(net, reduced);
    total   = net + vat;
    cd      = checksum_account(rec);

    fmt_cents(total, amount);
    wsprintfA(out, "INVOICE total=%s tier=%d bps=%d cd=%d", amount, tier, bps, cd);

    write_invoice("C:\\LEGACY\\OUT.TXT", out);
    MessageBoxA(NULL, out, "LegacyApp", MB_OK);
    return 0;
}
