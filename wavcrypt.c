#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * File -> WAV encryption format (version 1)
 *
 * The encrypted file is stored in the PCM sample bytes of a normal mono,
 * 16-bit, 44.1 kHz WAV file.  Consequently the WAV is playable by ordinary
 * players (the audio sounds like noise).  The original file name and size are
 * encrypted together with the file data.
 *
 * RIFF chunks:
 *   fmt  : PCM, 1 channel, 44100 Hz, 16 bit
 *   ENCV : 64-byte authenticated parameter block (see below)
 *   data : AES-256-GCM ciphertext bytes, one ciphertext byte per 8-bit
 *          half-sample (i.e. little-endian 16-bit PCM samples).  If the
 *          ciphertext length is odd, one zero byte is appended so that the
 *          PCM data chunk stays aligned to a 16-bit sample.
 *
 * ENCV payload (64 bytes):
 *   0  8  magic "ENCRWAV1"
 *   8  4  PBKDF2 iteration count (little endian)
 *  12 16  PBKDF2 salt
 *  28 12  GCM nonce
 *  40  8  ciphertext length (little endian)
 *  48 16  GCM authentication tag
 * The first 48 bytes are supplied to AES-GCM as additional authenticated data.
 *
 * Encrypted plaintext:
 *   0  8  inner magic "ENCPAY1\0"
 *   8  8  original file size (little endian)
 *  16  2  original file name length (little endian)
 *  18  N  original file name (basename, no NUL)
 *  18+N  original file data
 */

#define PBKDF2_ITERATIONS      600000u
#define PBKDF2_MIN_ITERATIONS  100000u
#define PBKDF2_MAX_ITERATIONS 1000000u

#define SALT_LEN               16
#define NONCE_LEN              12
#define TAG_LEN                16
#define AAD_LEN                48
#define ENCV_PAYLOAD_LEN        64
#define INNER_FIXED_LEN         18
#define MAX_NAME_LEN          4096
#define MAX_PASSWORD_LEN      1024
#define INPUT_CAP             4096
#define IO_CHUNK             65536

#define WAV_SAMPLE_RATE       44100u
#define WAV_CHANNELS             1
#define WAV_BITS                16
#define WAV_BLOCK_ALIGN          2
#define WAV_BYTE_RATE        88200u
#define WAV_HEADER_LEN         116
#define WAV_TAG_OFFSET          92
#define WAV_DATA_OFFSET        116

static const unsigned char ENCV_MAGIC[8] =
    {'E', 'N', 'C', 'R', 'W', 'A', 'V', '1'};
static const unsigned char INNER_MAGIC[8] =
    {'E', 'N', 'C', 'P', 'A', 'Y', '1', 0};

typedef struct {
    uint32_t iterations;
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char aad[AAD_LEN];
    uint64_t cipher_len;
    uint64_t data_offset;
    uint32_t data_size;
} WavInfo;

/* State used by the signal handler to restore the terminal and clean up. */
static struct termios g_saved_termios;
static volatile sig_atomic_t g_termios_saved = 0;
static char *g_temp_path = NULL;
static int g_temp_fd = -1;

static void signal_handler(int sig)
{
    if (g_termios_saved) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
    }
    if (g_temp_fd >= 0) {
        (void)close(g_temp_fd);
    }
    if (g_temp_path != NULL) {
        (void)unlink(g_temp_path);
    }
    _exit(128 + sig);
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    int signals[] = {SIGINT, SIGTERM, SIGHUP};
    size_t i;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    for (i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        if (sigaction(signals[i], &sa, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static void clear_temp_state(void)
{
    g_temp_path = NULL;
    g_temp_fd = -1;
}

static uint16_t rd16le(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32le(const unsigned char *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64le(const unsigned char *p)
{
    return (uint64_t)rd32le(p) | ((uint64_t)rd32le(p + 4) << 32);
}

static void wr16le(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
}

static void wr32le(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static void wr64le(unsigned char *p, uint64_t v)
{
    wr32le(p, (uint32_t)(v & 0xffffffffu));
    wr32le(p + 4, (uint32_t)(v >> 32));
}

/*
 * Read one line from stdin.  A line that does not fit into cap is drained and
 * flagged as truncated.  Returns -1 on EOF/error.
 */
static int read_line_stdin(char *buf, size_t cap, int *truncated)
{
    size_t len;
    int has_newline;

    if (cap == 0 || cap > (size_t)INT_MAX) {
        return -1;
    }
    *truncated = 0;
    if (fgets(buf, (int)cap, stdin) == NULL) {
        return -1;
    }

    len = strlen(buf);
    has_newline = (len > 0 && buf[len - 1] == '\n');
    if (has_newline) {
        buf[--len] = '\0';
        if (len > 0 && buf[len - 1] == '\r') {
            buf[--len] = '\0';
        }
    } else if (!feof(stdin)) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            /* drain the rest of the overlong line */
        }
        *truncated = 1;
    }
    return 0;
}

static int read_secret_line(const char *prompt, char *buf, size_t cap)
{
    int truncated = 0;
    int rc;

    printf("%s", prompt);
    fflush(stdout);

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
        struct termios quiet = g_saved_termios;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0) {
            g_termios_saved = 1;
        }
    }

    rc = read_line_stdin(buf, cap, &truncated);

    if (g_termios_saved) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_saved = 0;
    }
    printf("\n");

    if (rc != 0) {
        fprintf(stderr, "读取输入失败。\n");
        return -1;
    }
    if (truncated) {
        fprintf(stderr, "输入内容过长。\n");
        OPENSSL_cleanse(buf, cap);
        return -1;
    }
    return 0;
}

static void strip_wrapping_quotes(char *s)
{
    size_t n = strlen(s);
    if (n >= 2 &&
        ((s[0] == '"' && s[n - 1] == '"') ||
         (s[0] == '\'' && s[n - 1] == '\''))) {
        memmove(s, s + 1, n - 2);
        s[n - 2] = '\0';
    }
}

static int prompt_path(const char *prompt, char *out, size_t cap)
{
    char line[INPUT_CAP];
    int truncated = 0;

    for (;;) {
        printf("%s", prompt);
        fflush(stdout);
        if (read_line_stdin(line, sizeof(line), &truncated) != 0) {
            fprintf(stderr, "读取输入失败。\n");
            return -1;
        }
        if (truncated) {
            fprintf(stderr, "路径过长，请重新输入。\n");
            continue;
        }
        strip_wrapping_quotes(line);
        if (line[0] == '\0') {
            fprintf(stderr, "路径不能为空。\n");
            continue;
        }
        if (strlen(line) >= cap) {
            fprintf(stderr, "路径过长，请重新输入。\n");
            continue;
        }
        strcpy(out, line);
        return 0;
    }
}

static int prompt_mode(void)
{
    char line[32];
    int truncated = 0;

    for (;;) {
        printf("\n请选择模式：\n");
        printf("  0 - 加密（文件 -> WAV）\n");
        printf("  1 - 解密（WAV -> 文件）\n");
        printf("请输入 0 或 1：");
        fflush(stdout);

        if (read_line_stdin(line, sizeof(line), &truncated) != 0) {
            fprintf(stderr, "\n读取输入失败。\n");
            return -1;
        }
        if (!truncated && strcmp(line, "0") == 0) {
            return 0;
        }
        if (!truncated && strcmp(line, "1") == 0) {
            return 1;
        }
        fprintf(stderr, "输入无效，请输入 0 或 1。\n");
    }
}

static int get_new_password(char *password, size_t cap)
{
    char confirm[MAX_PASSWORD_LEN];

    for (;;) {
        if (read_secret_line("请设置解密密钥（输入时不会显示）：", password, cap) != 0) {
            OPENSSL_cleanse(confirm, sizeof(confirm));
            return -1;
        }
        if (password[0] == '\0') {
            fprintf(stderr, "密钥不能为空。\n");
            continue;
        }
        if (read_secret_line("请再次输入密钥确认：", confirm, sizeof(confirm)) != 0) {
            OPENSSL_cleanse(password, cap);
            OPENSSL_cleanse(confirm, sizeof(confirm));
            return -1;
        }
        if (strcmp(password, confirm) != 0) {
            fprintf(stderr, "两次输入的密钥不一致，请重新设置。\n");
            OPENSSL_cleanse(password, cap);
            OPENSSL_cleanse(confirm, sizeof(confirm));
            continue;
        }
        OPENSSL_cleanse(confirm, sizeof(confirm));
        if (strlen(password) < 8) {
            fprintf(stderr, "提示：密钥少于 8 个字符，安全性较弱。\n");
        }
        return 0;
    }
}

static int get_password(char *password, size_t cap)
{
    for (;;) {
        if (read_secret_line("请输入解密密钥（输入时不会显示）：", password, cap) != 0) {
            return -1;
        }
        if (password[0] == '\0') {
            fprintf(stderr, "密钥不能为空。\n");
            continue;
        }
        return 0;
    }
}

static int write_full(FILE *fp, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;

    while (len > 0) {
        size_t n = fwrite(p, 1, len, fp);
        if (n == 0) {
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
}

static int read_full(FILE *fp, void *data, size_t len)
{
    unsigned char *p = (unsigned char *)data;

    while (len > 0) {
        size_t n = fread(p, 1, len, fp);
        if (n == 0) {
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
}

static int make_temp_file(const char *template_str, char **path_out, FILE **fp_out)
{
    char *path = strdup(template_str);
    int fd;
    FILE *fp;

    if (path == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        return -1;
    }
    fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "无法创建临时文件：%s\n", strerror(errno));
        free(path);
        return -1;
    }

    fp = fdopen(fd, "w+b");
    if (fp == NULL) {
        fprintf(stderr, "无法打开临时文件：%s\n", strerror(errno));
        close(fd);
        unlink(path);
        free(path);
        return -1;
    }

    g_temp_path = path;
    g_temp_fd = fd;
    *path_out = path;
    *fp_out = fp;
    return 0;
}

static char *path_basename_dup(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *base = (slash != NULL) ? slash + 1 : path;
    size_t n = strlen(base);
    char *result;

    if (n == 0) {
        return NULL;
    }
    result = malloc(n + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, base, n + 1);
    return result;
}

static char *path_dir_dup(const char *path)
{
    const char *slash = strrchr(path, '/');
    char *result;
    size_t n;

    if (slash == NULL) {
        return strdup(".");
    }
    if (slash == path) {
        return strdup("/");
    }
    n = (size_t)(slash - path);
    result = malloc(n + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, path, n);
    result[n] = '\0';
    return result;
}

static char *path_join(const char *dir, const char *name)
{
    size_t dl = strlen(dir);
    size_t nl = strlen(name);
    int need_slash = !(dl > 0 && dir[dl - 1] == '/');
    char *result;
    size_t pos;

    if (dl > SIZE_MAX - nl - 2) {
        return NULL;
    }
    result = malloc(dl + nl + (size_t)need_slash + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, dir, dl);
    pos = dl;
    if (need_slash) {
        result[pos++] = '/';
    }
    memcpy(result + pos, name, nl);
    result[pos + nl] = '\0';
    return result;
}

static int paths_same_inode(const char *a, const char *b)
{
    struct stat sa;
    struct stat sb;

    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) {
        return 0;
    }
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static int confirm_overwrite(const char *path)
{
    struct stat st;
    char answer[32];
    int truncated = 0;

    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            return 1;
        }
        fprintf(stderr, "无法检查输出文件 %s：%s\n", path, strerror(errno));
        return 0;
    }

    printf("输出文件已存在：%s\n", path);
    printf("是否覆盖？[y/N]：");
    fflush(stdout);
    if (read_line_stdin(answer, sizeof(answer), &truncated) != 0) {
        fprintf(stderr, "\n读取输入失败。\n");
        return 0;
    }
    if (truncated) {
        return 0;
    }
    return answer[0] == 'y' || answer[0] == 'Y';
}

static void build_encv(unsigned char out[ENCV_PAYLOAD_LEN],
                       const unsigned char salt[SALT_LEN],
                       const unsigned char nonce[NONCE_LEN],
                       uint32_t iterations,
                       uint64_t cipher_len)
{
    memcpy(out, ENCV_MAGIC, sizeof(ENCV_MAGIC));
    wr32le(out + 8, iterations);
    memcpy(out + 12, salt, SALT_LEN);
    memcpy(out + 28, nonce, NONCE_LEN);
    wr64le(out + 40, cipher_len);
    memset(out + 48, 0, TAG_LEN);
}

static int parse_encv(const unsigned char in[ENCV_PAYLOAD_LEN], WavInfo *info)
{
    uint32_t iterations;

    if (memcmp(in, ENCV_MAGIC, sizeof(ENCV_MAGIC)) != 0) {
        fprintf(stderr, "不是本程序生成的加密 WAV（ENCV 标识不匹配）。\n");
        return -1;
    }
    iterations = rd32le(in + 8);
    if (iterations < PBKDF2_MIN_ITERATIONS ||
        iterations > PBKDF2_MAX_ITERATIONS) {
        fprintf(stderr, "WAV 中的 KDF 参数无效。\n");
        return -1;
    }

    info->iterations = iterations;
    memcpy(info->salt, in + 12, SALT_LEN);
    memcpy(info->nonce, in + 28, NONCE_LEN);
    info->cipher_len = rd64le(in + 40);
    memcpy(info->tag, in + 48, TAG_LEN);
    memcpy(info->aad, in, AAD_LEN);
    return 0;
}

static void build_wav_header(unsigned char header[WAV_HEADER_LEN],
                             uint32_t riff_size,
                             uint32_t data_size,
                             const unsigned char encv[ENCV_PAYLOAD_LEN])
{
    memcpy(header + 0, "RIFF", 4);
    wr32le(header + 4, riff_size);
    memcpy(header + 8, "WAVE", 4);

    memcpy(header + 12, "fmt ", 4);
    wr32le(header + 16, 16);
    wr16le(header + 20, 1);                    /* PCM */
    wr16le(header + 22, WAV_CHANNELS);
    wr32le(header + 24, WAV_SAMPLE_RATE);
    wr32le(header + 28, WAV_BYTE_RATE);
    wr16le(header + 32, WAV_BLOCK_ALIGN);
    wr16le(header + 34, WAV_BITS);

    memcpy(header + 36, "ENCV", 4);
    wr32le(header + 40, ENCV_PAYLOAD_LEN);
    memcpy(header + 44, encv, ENCV_PAYLOAD_LEN);

    memcpy(header + 108, "data", 4);
    wr32le(header + 112, data_size);
}

static int derive_key(const char *password,
                      const unsigned char salt[SALT_LEN],
                      uint32_t iterations,
                      unsigned char key[32])
{
    size_t plen = strlen(password);

    if (plen > (size_t)INT_MAX) {
        fprintf(stderr, "密钥过长。\n");
        return -1;
    }
    if (PKCS5_PBKDF2_HMAC(password, (int)plen,
                          salt, SALT_LEN,
                          (int)iterations,
                          EVP_sha256(),
                          32, key) != 1) {
        fprintf(stderr, "PBKDF2 密钥派生失败。\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

static int init_gcm_encrypt(EVP_CIPHER_CTX **ctx_out,
                            const unsigned char key[32],
                            const unsigned char nonce[NONCE_LEN],
                            const unsigned char aad[AAD_LEN])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0;

    if (ctx == NULL) {
        fprintf(stderr, "无法创建 OpenSSL 加密上下文。\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &outlen, aad, AAD_LEN) != 1) {
        fprintf(stderr, "初始化 AES-256-GCM 失败。\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ctx_out = ctx;
    return 0;
}

static int init_gcm_decrypt(EVP_CIPHER_CTX **ctx_out,
                            const unsigned char key[32],
                            const unsigned char nonce[NONCE_LEN],
                            const unsigned char aad[AAD_LEN])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0;

    if (ctx == NULL) {
        fprintf(stderr, "无法创建 OpenSSL 解密上下文。\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &outlen, aad, AAD_LEN) != 1) {
        fprintf(stderr, "初始化 AES-256-GCM 失败。\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ctx_out = ctx;
    return 0;
}

static int parse_encrypted_wav(const char *path, WavInfo *info)
{
    FILE *fp = NULL;
    struct stat st;
    unsigned char riff[12];
    unsigned char chunk[8];
    unsigned char fmt[16];
    unsigned char encv[ENCV_PAYLOAD_LEN];
    uint32_t riff_size;
    uint64_t file_size;
    uint64_t pos;
    int have_fmt = 0;
    int have_encv = 0;
    int have_data = 0;
    off_t end;
    int ret = -1;

    memset(info, 0, sizeof(*info));

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "无法打开 WAV 文件 %s：%s\n", path, strerror(errno));
        goto done;
    }
    if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "输入不是普通文件。\n");
        goto done;
    }
    if (fseeko(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "无法定位 WAV 文件：%s\n", strerror(errno));
        goto done;
    }
    end = ftello(fp);
    if (end < 0) {
        fprintf(stderr, "无法读取 WAV 文件长度：%s\n", strerror(errno));
        goto done;
    }
    file_size = (uint64_t)end;
    if (file_size < 12) {
        fprintf(stderr, "文件太小，不是有效的 WAV。\n");
        goto done;
    }
    if (fseeko(fp, 0, SEEK_SET) != 0 || read_full(fp, riff, sizeof(riff)) != 0) {
        fprintf(stderr, "读取 WAV 头失败。\n");
        goto done;
    }
    if (memcmp(riff, "RIFF", 4) != 0 || memcmp(riff + 8, "WAVE", 4) != 0) {
        fprintf(stderr, "不是 RIFF/WAVE 文件。\n");
        goto done;
    }
    riff_size = rd32le(riff + 4);
    if ((uint64_t)riff_size + 8 > file_size) {
        fprintf(stderr, "WAV 的 RIFF 长度字段无效。\n");
        goto done;
    }

    pos = 12;
    while (pos + 8 <= file_size) {
        uint32_t size;
        uint64_t payload;

        if (fseeko(fp, (off_t)pos, SEEK_SET) != 0 ||
            read_full(fp, chunk, sizeof(chunk)) != 0) {
            fprintf(stderr, "读取 WAV 块失败。\n");
            goto done;
        }
        size = rd32le(chunk + 4);
        payload = pos + 8;
        if (payload + (uint64_t)size > file_size) {
            fprintf(stderr, "WAV 块长度越界，文件已损坏。\n");
            goto done;
        }

        if (memcmp(chunk, "fmt ", 4) == 0) {
            if (have_fmt) {
                fprintf(stderr, "WAV 包含重复的 fmt 块。\n");
                goto done;
            }
            if (size < sizeof(fmt) ||
                fseeko(fp, (off_t)payload, SEEK_SET) != 0 ||
                read_full(fp, fmt, sizeof(fmt)) != 0) {
                fprintf(stderr, "WAV 的 fmt 块无效。\n");
                goto done;
            }
            if (rd16le(fmt + 0) != 1 ||
                rd16le(fmt + 2) != WAV_CHANNELS ||
                rd32le(fmt + 4) != WAV_SAMPLE_RATE ||
                rd32le(fmt + 8) != WAV_BYTE_RATE ||
                rd16le(fmt + 12) != WAV_BLOCK_ALIGN ||
                rd16le(fmt + 14) != WAV_BITS) {
                fprintf(stderr, "WAV 不是本程序使用的 44.1kHz/16-bit/单声道 PCM 格式。\n");
                goto done;
            }
            have_fmt = 1;
        } else if (memcmp(chunk, "ENCV", 4) == 0) {
            if (have_encv) {
                fprintf(stderr, "WAV 包含重复的 ENCV 块。\n");
                goto done;
            }
            if (size != ENCV_PAYLOAD_LEN ||
                fseeko(fp, (off_t)payload, SEEK_SET) != 0 ||
                read_full(fp, encv, sizeof(encv)) != 0 ||
                parse_encv(encv, info) != 0) {
                goto done;
            }
            have_encv = 1;
        } else if (memcmp(chunk, "data", 4) == 0) {
            if (have_data) {
                fprintf(stderr, "WAV 包含重复的 data 块。\n");
                goto done;
            }
            info->data_offset = payload;
            info->data_size = size;
            have_data = 1;
        }

        pos = payload + (uint64_t)size + (uint64_t)(size & 1u);
    }

    if (!have_fmt || !have_encv || !have_data) {
        fprintf(stderr, "WAV 缺少 fmt、ENCV 或 data 块，无法解密。\n");
        goto done;
    }
    if (info->cipher_len == 0 ||
        (uint64_t)info->data_size !=
            info->cipher_len + (info->cipher_len & 1u) ||
        info->data_offset + info->cipher_len > file_size) {
        fprintf(stderr, "WAV 中的密文长度无效。\n");
        goto done;
    }
    if (info->cipher_len < INNER_FIXED_LEN + 1) {
        fprintf(stderr, "WAV 中的密文长度过短。\n");
        goto done;
    }

    ret = 0;

done:
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

static int do_encrypt(const char *in_path, const char *out_path,
                      const char *password)
{
    FILE *in = NULL;
    FILE *out = NULL;
    char *tmp_path = NULL;
    char *tmp_template = NULL;
    char *name = NULL;
    unsigned char *inner = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char key[32];
    unsigned char encv[ENCV_PAYLOAD_LEN];
    unsigned char header[WAV_HEADER_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char inbuf[IO_CHUNK];
    unsigned char outbuf[IO_CHUNK + 32];
    struct stat st;
    off_t end;
    uint64_t file_size;
    uint64_t inner_len;
    uint64_t cipher_len;
    uint64_t riff_size64;
    uint64_t total_written = 0;
    uint64_t data_pad;
    uint64_t data_size64;
    size_t name_len;
    int outlen = 0;
    int ret = -1;

    memset(salt, 0, sizeof(salt));
    memset(nonce, 0, sizeof(nonce));
    memset(key, 0, sizeof(key));
    memset(encv, 0, sizeof(encv));
    memset(tag, 0, sizeof(tag));

    in = fopen(in_path, "rb");
    if (in == NULL) {
        fprintf(stderr, "无法打开输入文件 %s：%s\n", in_path, strerror(errno));
        goto done;
    }
    if (fstat(fileno(in), &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "输入必须是普通文件。\n");
        goto done;
    }
    if (fseeko(in, 0, SEEK_END) != 0) {
        fprintf(stderr, "无法定位输入文件：%s\n", strerror(errno));
        goto done;
    }
    end = ftello(in);
    if (end < 0) {
        fprintf(stderr, "无法读取输入文件长度：%s\n", strerror(errno));
        goto done;
    }
    file_size = (uint64_t)end;
    if (fseeko(in, 0, SEEK_SET) != 0) {
        fprintf(stderr, "无法回到输入文件开头：%s\n", strerror(errno));
        goto done;
    }

    name = path_basename_dup(in_path);
    if (name == NULL) {
        fprintf(stderr, "无法取得输入文件名。\n");
        goto done;
    }
    name_len = strlen(name);
    if (name_len == 0 || name_len > MAX_NAME_LEN) {
        fprintf(stderr, "文件名长度无效（最多 %d 字节）。\n", MAX_NAME_LEN);
        goto done;
    }
    if (name_len > UINT16_MAX) {
        fprintf(stderr, "文件名过长。\n");
        goto done;
    }

    inner_len = (uint64_t)INNER_FIXED_LEN + (uint64_t)name_len;
    if (file_size > UINT64_MAX - inner_len) {
        fprintf(stderr, "输入文件过大。\n");
        goto done;
    }
    cipher_len = inner_len + file_size;
    data_pad = cipher_len & 1u;
    data_size64 = cipher_len + data_pad;
    riff_size64 = 108u + data_size64;
    if (data_size64 > UINT32_MAX || riff_size64 > UINT32_MAX) {
        fprintf(stderr, "输入文件过大：WAV 容器最多只能容纳约 4 GiB 加密数据。\n");
        goto done;
    }

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "生成随机数失败。\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    build_encv(encv, salt, nonce, PBKDF2_ITERATIONS, cipher_len);
    if (derive_key(password, salt, PBKDF2_ITERATIONS, key) != 0) {
        goto done;
    }
    if (init_gcm_encrypt(&ctx, key, nonce, encv) != 0) {
        goto done;
    }

    inner = malloc((size_t)inner_len);
    if (inner == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        goto done;
    }
    memcpy(inner, INNER_MAGIC, sizeof(INNER_MAGIC));
    wr64le(inner + 8, file_size);
    wr16le(inner + 16, (uint16_t)name_len);
    memcpy(inner + INNER_FIXED_LEN, name, name_len);

    tmp_template = malloc(strlen(out_path) + sizeof(".tmp.XXXXXX") + 1);
    if (tmp_template == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        goto done;
    }
    sprintf(tmp_template, "%s.tmp.XXXXXX", out_path);
    if (make_temp_file(tmp_template, &tmp_path, &out) != 0) {
        goto done;
    }

    build_wav_header(header, (uint32_t)riff_size64,
                     (uint32_t)data_size64, encv);
    if (write_full(out, header, sizeof(header)) != 0) {
        fprintf(stderr, "写入 WAV 头失败：%s\n", strerror(errno));
        goto done;
    }

    if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inner, (int)inner_len) != 1 ||
        outlen < 0 ||
        write_full(out, outbuf, (size_t)outlen) != 0) {
        fprintf(stderr, "加密文件头失败。\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    total_written += (uint64_t)outlen;

    for (;;) {
        size_t n = fread(inbuf, 1, sizeof(inbuf), in);
        if (n > 0) {
            if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)n) != 1 ||
                outlen < 0) {
                fprintf(stderr, "加密数据失败。\n");
                ERR_print_errors_fp(stderr);
                goto done;
            }
            if (write_full(out, outbuf, (size_t)outlen) != 0) {
                fprintf(stderr, "写入加密数据失败：%s\n", strerror(errno));
                goto done;
            }
            total_written += (uint64_t)outlen;
        }
        if (n < sizeof(inbuf)) {
            if (ferror(in)) {
                fprintf(stderr, "读取输入文件失败。\n");
                goto done;
            }
            break;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1 || outlen < 0) {
        fprintf(stderr, "完成加密失败。\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    if (outlen > 0) {
        if (write_full(out, outbuf, (size_t)outlen) != 0) {
            fprintf(stderr, "写入加密数据失败：%s\n", strerror(errno));
            goto done;
        }
        total_written += (uint64_t)outlen;
    }
    if (total_written != cipher_len) {
        fprintf(stderr, "内部错误：加密数据长度不一致。\n");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        fprintf(stderr, "获取 GCM 认证标签失败。\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    if (fflush(out) != 0) {
        fprintf(stderr, "刷新输出文件失败：%s\n", strerror(errno));
        goto done;
    }
    if (fseeko(out, WAV_TAG_OFFSET, SEEK_SET) != 0 ||
        write_full(out, tag, sizeof(tag)) != 0) {
        fprintf(stderr, "写入 GCM 认证标签失败：%s\n", strerror(errno));
        goto done;
    }
    if (fseeko(out, 0, SEEK_END) != 0) {
        fprintf(stderr, "定位输出文件失败：%s\n", strerror(errno));
        goto done;
    }
    if (data_pad != 0) {
        unsigned char zero = 0;
        if (write_full(out, &zero, 1) != 0) {
            fprintf(stderr, "写入 WAV 填充字节失败：%s\n", strerror(errno));
            goto done;
        }
    }
    if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
        fprintf(stderr, "同步输出文件失败：%s\n", strerror(errno));
        goto done;
    }
    if (fclose(out) != 0) {
        out = NULL;
        fprintf(stderr, "关闭输出文件失败：%s\n", strerror(errno));
        goto done;
    }
    out = NULL;
    g_temp_fd = -1;

    if (rename(tmp_path, out_path) != 0) {
        fprintf(stderr, "无法生成输出文件 %s：%s\n", out_path, strerror(errno));
        goto done;
    }
    clear_temp_state();
    ret = 0;

done:
    if (out != NULL) {
        fclose(out);
    }
    if (in != NULL) {
        fclose(in);
    }
    if (tmp_path != NULL) {
        if (ret != 0) {
            unlink(tmp_path);
        }
        if (g_temp_path == tmp_path) {
            clear_temp_state();
        }
        free(tmp_path);
    }
    if (tmp_template != NULL) {
        free(tmp_template);
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (inner != NULL) {
        OPENSSL_cleanse(inner, (size_t)inner_len);
        free(inner);
    }
    if (name != NULL) {
        OPENSSL_cleanse(name, strlen(name));
        free(name);
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(inbuf, sizeof(inbuf));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    return ret;
}

static int do_decrypt(const char *wav_path, const char *password)
{
    WavInfo info;
    FILE *wav = NULL;
    FILE *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32];
    unsigned char fixed_ct[INNER_FIXED_LEN];
    unsigned char name_ct[MAX_NAME_LEN];
    unsigned char outbuf[IO_CHUNK + 32];
    unsigned char inbuf[IO_CHUNK];
    char name[MAX_NAME_LEN + 1];
    char *dir = NULL;
    char *out_path = NULL;
    char *tmp_path = NULL;
    char *tmp_template = NULL;
    uint64_t original_size;
    uint64_t header_len;
    uint64_t remaining;
    uint16_t name_len;
    int outlen = 0;
    int auth_failed = 0;
    int ret = -1;

    memset(&info, 0, sizeof(info));
    memset(key, 0, sizeof(key));
    memset(name, 0, sizeof(name));

    if (parse_encrypted_wav(wav_path, &info) != 0) {
        goto done;
    }
    if (derive_key(password, info.salt, info.iterations, key) != 0) {
        goto done;
    }

    wav = fopen(wav_path, "rb");
    if (wav == NULL) {
        fprintf(stderr, "无法打开 WAV 文件 %s：%s\n", wav_path, strerror(errno));
        goto done;
    }
    if (fseeko(wav, (off_t)info.data_offset, SEEK_SET) != 0) {
        fprintf(stderr, "无法定位 WAV 密文：%s\n", strerror(errno));
        goto done;
    }
    if (init_gcm_decrypt(&ctx, key, info.nonce, info.aad) != 0) {
        goto done;
    }

    if (read_full(wav, fixed_ct, sizeof(fixed_ct)) != 0 ||
        EVP_DecryptUpdate(ctx, outbuf, &outlen, fixed_ct,
                          (int)sizeof(fixed_ct)) != 1 ||
        outlen != (int)sizeof(fixed_ct)) {
        fprintf(stderr, "读取加密文件头失败，WAV 已损坏。\n");
        goto done;
    }
    if (memcmp(outbuf, INNER_MAGIC, sizeof(INNER_MAGIC)) != 0) {
        fprintf(stderr, "解密失败：密钥错误，或 WAV 文件已损坏。\n");
        goto done;
    }

    original_size = rd64le(outbuf + 8);
    name_len = rd16le(outbuf + 16);
    header_len = (uint64_t)INNER_FIXED_LEN + (uint64_t)name_len;

    if (name_len == 0 || name_len > MAX_NAME_LEN ||
        info.cipher_len < header_len ||
        original_size != info.cipher_len - header_len) {
        fprintf(stderr, "解密失败：密钥错误，或 WAV 文件已损坏。\n");
        goto done;
    }

    if (read_full(wav, name_ct, name_len) != 0 ||
        EVP_DecryptUpdate(ctx, outbuf, &outlen, name_ct, (int)name_len) != 1 ||
        outlen != (int)name_len) {
        fprintf(stderr, "读取加密文件名失败，WAV 已损坏。\n");
        goto done;
    }
    memcpy(name, outbuf, name_len);
    name[name_len] = '\0';

    if (memchr(name, '\0', name_len) != NULL ||
        strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0 ||
        strchr(name, '/') != NULL) {
        fprintf(stderr, "解密失败：WAV 中的原文件名无效。\n");
        goto done;
    }

    dir = path_dir_dup(wav_path);
    if (dir == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        goto done;
    }
    out_path = path_join(dir, name);
    tmp_template = path_join(dir, ".file2wav-XXXXXX");
    if (out_path == NULL || tmp_template == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        goto done;
    }
    if (make_temp_file(tmp_template, &tmp_path, &out) != 0) {
        goto done;
    }

    remaining = original_size;
    while (remaining > 0) {
        size_t want = (remaining > sizeof(inbuf)) ? sizeof(inbuf) : (size_t)remaining;
        if (read_full(wav, inbuf, want) != 0 ||
            EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)want) != 1 ||
            outlen != (int)want) {
            fprintf(stderr, "解密数据失败，WAV 已损坏。\n");
            goto done;
        }
        if (write_full(out, outbuf, (size_t)outlen) != 0) {
            fprintf(stderr, "写入解密文件失败：%s\n", strerror(errno));
            goto done;
        }
        remaining -= (uint64_t)want;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            TAG_LEN, info.tag) != 1) {
        fprintf(stderr, "设置 GCM 认证标签失败。\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        auth_failed = 1;
        goto done;
    }
    if (outlen != 0) {
        fprintf(stderr, "内部错误：GCM 产生了额外明文。\n");
        goto done;
    }

    if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
        fprintf(stderr, "同步解密文件失败：%s\n", strerror(errno));
        goto done;
    }
    if (fclose(out) != 0) {
        out = NULL;
        fprintf(stderr, "关闭解密文件失败：%s\n", strerror(errno));
        goto done;
    }
    out = NULL;
    g_temp_fd = -1;

    if (paths_same_inode(out_path, wav_path)) {
        fprintf(stderr, "拒绝覆盖输入 WAV 文件本身。\n");
        goto done;
    }
    if (!confirm_overwrite(out_path)) {
        fprintf(stderr, "已取消解密输出。\n");
        goto done;
    }
    if (rename(tmp_path, out_path) != 0) {
        fprintf(stderr, "无法生成输出文件 %s：%s\n", out_path, strerror(errno));
        goto done;
    }
    clear_temp_state();

    printf("解密完成：%s\n", out_path);
    printf("原始文件大小：%llu 字节\n", (unsigned long long)original_size);
    ret = 0;

done:
    if (ret != 0 && auth_failed) {
        fprintf(stderr, "解密失败：密钥错误，或 WAV 文件已被修改/损坏。\n");
    }
    if (out != NULL) {
        fclose(out);
    }
    if (wav != NULL) {
        fclose(wav);
    }
    if (tmp_path != NULL) {
        if (ret != 0) {
            unlink(tmp_path);
        }
        if (g_temp_path == tmp_path) {
            clear_temp_state();
        }
        free(tmp_path);
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    free(dir);
    free(out_path);
    free(tmp_template);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(name, sizeof(name));
    OPENSSL_cleanse(inbuf, sizeof(inbuf));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    return ret;
}

int main(void)
{
    char input[INPUT_CAP];
    char password[MAX_PASSWORD_LEN];
    char *output = NULL;
    int mode;
    int rc = 1;

    memset(password, 0, sizeof(password));

    if (install_signal_handlers() != 0) {
        fprintf(stderr, "无法安装信号处理器：%s\n", strerror(errno));
        return 1;
    }

    printf("============================================\n");
    printf("  文件 <-> 加密 WAV 工具（AES-256-GCM）\n");
    printf("============================================\n");

    mode = prompt_mode();
    if (mode < 0) {
        goto done;
    }

    if (mode == 0) {
        if (prompt_path("请输入要加密的文件路径：", input, sizeof(input)) != 0) {
            goto done;
        }
        if (get_new_password(password, sizeof(password)) != 0) {
            goto done;
        }

        output = malloc(strlen(input) + sizeof(".wav"));
        if (output == NULL) {
            fprintf(stderr, "内存分配失败。\n");
            goto done;
        }
        sprintf(output, "%s.wav", input);

        if (!confirm_overwrite(output)) {
            fprintf(stderr, "已取消加密。\n");
            goto done;
        }
        if (do_encrypt(input, output, password) != 0) {
            goto done;
        }
        printf("加密完成：%s\n", output);
        printf("WAV 格式：PCM 16-bit / 单声道 / 44100 Hz，可直接用播放器播放（内容为噪声）。\n");
        rc = 0;
    } else {
        if (prompt_path("请输入待解密的 WAV 文件路径：", input, sizeof(input)) != 0) {
            goto done;
        }
        if (get_password(password, sizeof(password)) != 0) {
            goto done;
        }
        if (do_decrypt(input, password) != 0) {
            goto done;
        }
        rc = 0;
    }

done:
    OPENSSL_cleanse(password, sizeof(password));
    if (output != NULL) {
        OPENSSL_cleanse(output, strlen(output));
        free(output);
    }
    return rc;
}
