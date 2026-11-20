#ifndef APP_VERSION
#define APP_VERSION "1.0.1"
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jansson.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#define MAX_HEADER_JSON (256 * 1024 * 1024)
#define CHUNK_SIZE (1024 * 1024)
#define INTEGRITY_BLOCK (4 * 1024 * 1024)

static void die(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "far2l-asar: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static char *xstrdup(const char *s) {
    char *p = strdup(s);
    if (!p) die("Out of memory");
    return p;
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("Out of memory");
    return p;
}

/* Проверка и нормализация относительного пути внутри архива */
static char *safe_name(const char *raw, bool allow_empty) {
    size_t len = strlen(raw);
    char *buf = xmalloc(len + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (raw[i] == '\r' || raw[i] == '\n') {
            free(buf);
            die("Unsafe newline in path");
        }
        char c = (raw[i] == '\\') ? '/' : raw[i];
        if (c == '/' && (j == 0 || buf[j - 1] == '/')) continue;
        buf[j++] = c;
    }
    while (j > 0 && buf[j - 1] == '/') j--;
    buf[j] = '\0';

    if (j == 0) {
        if (allow_empty) return buf;
        free(buf);
        die("Unsafe empty archive path");
    }

    char *copy = xstrdup(buf);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, "/", &saveptr); tok; tok = strtok_r(NULL, "/", &saveptr)) {
        if (strcmp(tok, ".") == 0 || strcmp(tok, "..") == 0) {
            free(copy);
            free(buf);
            die("Unsafe archive path traversal: '%s'", raw);
        }
    }
    free(copy);
    return buf;
}

static uint32_t read_u32_le(const uint8_t b[4]) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void write_u32_le(uint8_t b[4], uint32_t v) {
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)((v >> 8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
}

typedef struct {
    char *path;
    FILE *fp;
    uint64_t length;
    uint64_t data_offset;
    json_t *header;
} Archive;

static void validate_tree(json_t *node) {
    json_t *files = json_object_get(node, "files");
    if (!json_is_object(files)) return;
    const char *key;
    json_t *val;
    json_object_foreach(files, key, val) {
        if (!key[0] || strcmp(key, ".") == 0 || strcmp(key, "..") == 0 ||
            strpbrk(key, "/\\\r\n") != NULL || !json_is_object(val)) {
            die("Unsupported ASAR entry name: '%s'", key);
        }
        validate_tree(val);
    }
}

static Archive *archive_open(const char *filename) {
    Archive *ar = xmalloc(sizeof(Archive));
    memset(ar, 0, sizeof(*ar));
    ar->path = realpath(filename, NULL);
    if (!ar->path) ar->path = xstrdup(filename);

    ar->fp = fopen(filename, "rb");
    if (!ar->fp) die("Cannot open '%s': %s", filename, strerror(errno));

    struct stat st;
    if (fstat(fileno(ar->fp), &st) != 0) die("fstat failed: %s", strerror(errno));
    ar->length = (uint64_t)st.st_size;

    uint8_t raw[16];
    if (fread(raw, 1, 16, ar->fp) != 16) die("Truncated ASAR header");

    uint32_t magic = read_u32_le(raw);
    uint32_t header_size = read_u32_le(raw + 4);
    uint32_t payload_size = read_u32_le(raw + 8);
    uint32_t json_size = read_u32_le(raw + 12);

    if (magic != 4 || header_size < 8 || (uint64_t)header_size > ar->length - 8 ||
        payload_size + 4 != header_size || json_size > header_size - 8 ||
        json_size > MAX_HEADER_JSON) {
        die("Invalid ASAR header");
    }

    char *jbuf = xmalloc(json_size + 1);
    if (fread(jbuf, 1, json_size, ar->fp) != json_size) die("Truncated ASAR JSON");
    jbuf[json_size] = '\0';

    json_error_t jerr;
    ar->header = json_loads(jbuf, JSON_REJECT_DUPLICATES, &jerr);
    free(jbuf);
    if (!ar->header) die("JSON parse error: %s", jerr.text);
    if (!json_is_object(json_object_get(ar->header, "files"))) {
        die("ASAR header has no files object");
    }
    validate_tree(ar->header);
    ar->data_offset = 8ULL + header_size;
    return ar;
}

static void archive_close(Archive *ar) {
    if (!ar) return;
    if (ar->fp) fclose(ar->fp);
    if (ar->header) json_decref(ar->header);
    free(ar->path);
    free(ar);
}

static uint64_t node_size(json_t *node) {
    if (json_object_get(node, "files")) return 0;
    json_t *sz = json_object_get(node, "size");
    if (!json_is_integer(sz) || json_integer_value(sz) < 0) {
        die("Invalid ASAR file size");
    }
    return (uint64_t)json_integer_value(sz);
}

/* Разрешение внутренних ссылок (link) с защитой от циклов */
static json_t *archive_resolve(Archive *ar, const char *raw_name, char **out_real, int depth) {
    if (depth > 32) die("Cyclic ASAR link: %s", raw_name);
    char *name = safe_name(raw_name, false);
    json_t *curr = ar->header;
    char *copy = xstrdup(name);
    char *saveptr = NULL;
    char *accum = xstrdup("");

    for (char *tok = strtok_r(copy, "/", &saveptr); tok; tok = strtok_r(NULL, "/", &saveptr)) {
        json_t *files = json_object_get(curr, "files");
        if (!json_is_object(files)) {
            die("Entry not found: %s", name);
        }
        json_t *child = json_object_get(files, tok);
        if (!child) die("Entry not found: %s", name);

        char *next_accum;
        if (asprintf(&next_accum, "%s%s%s", accum, accum[0] ? "/" : "", tok) < 0) die("OOM");
        free(accum);
        accum = next_accum;

        json_t *link = json_object_get(child, "link");
        if (json_is_string(link)) {
            char *target = safe_name(json_string_value(link), false);
            char *rest = strtok_r(NULL, "", &saveptr);
            char *combined;
            if (rest && rest[0]) {
                if (asprintf(&combined, "%s/%s", target, rest) < 0) die("OOM");
            } else {
                combined = xstrdup(target);
            }
            free(target);
            free(accum);
            free(copy);
            free(name);
            json_t *res = archive_resolve(ar, combined, out_real, depth + 1);
            free(combined);
            return res;
        }
        curr = child;
    }

    free(copy);
    free(name);
    if (out_real) *out_real = accum;
    else free(accum);
    return curr;
}

static void list_walk(Archive *ar, const char *virt_prefix, json_t *node, int depth) {
    if (depth > 64) die("Directory nesting too deep");
    json_t *files = json_object_get(node, "files");
    if (!json_is_object(files)) return;

    const char *key;
    json_t *child;
    json_object_foreach(files, key, child) {
        char *vpath;
        if (asprintf(&vpath, "%s%s%s", virt_prefix, virt_prefix[0] ? "/" : "", key) < 0) die("OOM");
        char *real = NULL;
        json_t *target = archive_resolve(ar, vpath, &real, 0);
        bool is_dir = json_is_object(json_object_get(target, "files"));
        char line[1024];
        int n = snprintf(line, sizeof(line), "%c %020" PRIu64 " %s",
                         is_dir ? 'D' : '.', node_size(target), vpath);
        if (n < 0 || n > 510) {
            die("Path exceeds MultiArc listing limit: %s", vpath);
        }
        puts(line);
        if (is_dir) {
            list_walk(ar, vpath, target, depth + 1);
        }
        free(real);
        free(vpath);
    }
}

static void cmd_list(const char *archive_path) {
    Archive *ar = archive_open(archive_path);
    list_walk(ar, "", ar->header, 0);
    archive_close(ar);
}
static void mkdir_p(const char *dir) {
    char *tmp = xstrdup(dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                die("mkdir '%s': %s", tmp, strerror(errno));
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        die("mkdir '%s': %s", tmp, strerror(errno));
    free(tmp);
}

static char *parent_dir(const char *path) {
    char *copy = xstrdup(path);
    char *slash = strrchr(copy, '/');
    if (!slash) { free(copy); return xstrdup("."); }
    if (slash == copy) { copy[1] = '\0'; return copy; }
    *slash = '\0';
    return copy;
}

static const char *basename_ptr(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static char *check_destination(const char *base_cwd, const char *relative) {
    char *rel = safe_name(relative, false);
    char *full;
    if (asprintf(&full, "%s/%s", base_cwd, rel) < 0) die("OOM");

    char *curr = xstrdup(base_cwd);
    char *copy = xstrdup(rel);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, "/", &saveptr); tok; tok = strtok_r(NULL, "/", &saveptr)) {
        char *next;
        if (asprintf(&next, "%s/%s", curr, tok) < 0) die("OOM");
        free(curr);
        curr = next;
        struct stat st;
        if (lstat(curr, &st) == 0 && S_ISLNK(st.st_mode))
            die("Destination is a symlink: %s", curr);
    }
    free(copy);
    free(curr);
    free(rel);
    return full;
}

static void copy_node_data(Archive *ar, const char *real_path, json_t *node, FILE *out) {
    uint64_t remaining = node_size(node);
    FILE *src = ar->fp;
    bool close_src = false;

    if (json_is_true(json_object_get(node, "unpacked"))) {
        char *unpacked_dir, *raw_src;
        if (asprintf(&unpacked_dir, "%s.unpacked", ar->path) < 0) die("OOM");
        char *real_base = realpath(unpacked_dir, NULL);
        if (!real_base) die("Missing unpacked dir: %s", unpacked_dir);
        if (asprintf(&raw_src, "%s/%s", real_base, real_path) < 0) die("OOM");
        char *real_src = realpath(raw_src, NULL);
        if (!real_src) die("Missing unpacked file: %s", raw_src);

        size_t blen = strlen(real_base);
        if (strncmp(real_src, real_base, blen) != 0 ||
            (real_src[blen] != '/' && real_src[blen] != '\0'))
            die("Unpacked file escapes directory: %s", real_path);

        src = fopen(real_src, "rb");
        if (!src) die("Open '%s': %s", real_src, strerror(errno));
        close_src = true;
        free(real_src); free(raw_src); free(real_base); free(unpacked_dir);
    } else {
        json_t *off_val = json_object_get(node, "offset");
        if (!json_is_string(off_val)) die("Invalid offset: %s", real_path);
        const char *off_str = json_string_value(off_val);
        for (const char *p = off_str; *p; p++)
            if (*p < '0' || *p > '9') die("Invalid offset digits: %s", real_path);
        uint64_t pos = ar->data_offset + strtoull(off_str, NULL, 10);
        if (pos + remaining > ar->length) die("File exceeds ASAR: %s", real_path);
        if (fseeko(src, (off_t)pos, SEEK_SET) != 0) die("fseeko: %s", strerror(errno));
    }

    uint8_t *buf = xmalloc(CHUNK_SIZE);
    while (remaining > 0) {
        size_t to_read = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        if (fread(buf, 1, to_read, src) != to_read) die("Truncated file: %s", real_path);
        if (fwrite(buf, 1, to_read, out) != to_read) die("Write error: %s", strerror(errno));
        remaining -= to_read;
    }
    free(buf);
    if (close_src) fclose(src);
}
typedef struct {
    char *target;
    char *real;
    json_t *node;
} ExtractItem;

typedef struct {
    ExtractItem *items;
    size_t count;
    size_t cap;
} ExtractPlan;

static void plan_add(ExtractPlan *plan, char *target, char *real, json_t *node) {
    for (size_t i = 0; i < plan->count; i++) {
        if (strcmp(plan->items[i].target, target) == 0) {
            if (strcmp(plan->items[i].real, real) != 0)
                die("Two selected files have the same destination: %s", target);
            free(target);
            free(real);
            return;
        }
    }
    if (plan->count == plan->cap) {
        plan->cap = plan->cap ? plan->cap * 2 : 64;
        plan->items = realloc(plan->items, plan->cap * sizeof(ExtractItem));
        if (!plan->items) die("OOM");
    }
    plan->items[plan->count++] = (ExtractItem){target, real, node};
}

static void plan_walk(Archive *ar, const char *base_cwd, const char *root,
                      bool flat, const char *virt_name, ExtractPlan *plan, int depth) {
    if (depth > 64) die("Directory nesting too deep");
    char *real = NULL;
    json_t *node = archive_resolve(ar, virt_name, &real, 0);
    bool is_dir = json_is_object(json_object_get(node, "files"));

    const char *relative = virt_name;
    if (root && root[0]) {
        size_t rlen = strlen(root);
        if (strncmp(virt_name, root, rlen) != 0 || virt_name[rlen] != '/')
            die("Selection is outside current archive directory: %s", virt_name);
        relative = virt_name + rlen + 1;
    }

    if (flat) {
        if (!is_dir) {
            char *target = check_destination(base_cwd, basename_ptr(relative));
            plan_add(plan, target, real, node);
        } else {
            free(real);
        }
    } else {
        char *target = check_destination(base_cwd, relative);
        plan_add(plan, target, real, node);
    }

    if (is_dir) {
        json_t *files = json_object_get(node, "files");
        const char *key;
        json_t *child;
        json_object_foreach(files, key, child) {
            char *next_virt;
            if (asprintf(&next_virt, "%s/%s", virt_name, key) < 0) die("OOM");
            plan_walk(ar, base_cwd, root, flat, next_virt, plan, depth + 1);
            free(next_virt);
        }
    }
}

static char **read_response_lines(const char *list_file, size_t *out_count) {
    FILE *fp = fopen(list_file, "rb");
    if (!fp) die("Cannot open response file '%s': %s", list_file, strerror(errno));

    char **lines = NULL;
    size_t count = 0, cap = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    bool first = true;

    while ((nread = getline(&line, &len, fp)) != -1) {
        char *p = line;
        if (first && nread >= 3 &&
            (uint8_t)p[0] == 0xEF && (uint8_t)p[1] == 0xBB && (uint8_t)p[2] == 0xBF) {
            p += 3;
            nread -= 3;
        }
        first = false;
        while (nread > 0 && (p[nread - 1] == '\n' || p[nread - 1] == '\r'))
            p[--nread] = '\0';
        if (nread == 0) continue;

        if (count == cap) {
            cap = cap ? cap * 2 : 32;
            lines = realloc(lines, cap * sizeof(char *));
            if (!lines) die("OOM");
        }
        lines[count++] = xstrdup(p);
    }
    free(line);
    fclose(fp);
    *out_count = count;
    return lines;
}

static void cmd_extract(const char *archive_path, const char *list_file,
                        const char *raw_root, bool flat) {
    Archive *ar = archive_open(archive_path);
    char cwd_buf[PATH_MAX];
    if (!getcwd(cwd_buf, sizeof(cwd_buf))) die("getcwd failed");
    char *base_cwd = realpath(cwd_buf, NULL);
    if (!base_cwd) base_cwd = xstrdup(cwd_buf);

    char *root = safe_name(raw_root, true);
    size_t req_count = 0;
    char **req = read_response_lines(list_file, &req_count);
    ExtractPlan plan = {0};

    for (size_t i = 0; i < req_count; i++) {
        for (char *c = req[i]; *c; c++)
            if (*c == '\\') *c = '/';
        if (strcmp(req[i], "*") == 0 || strcmp(req[i], "*.*") == 0) {
            json_t *root_node = root[0] ? archive_resolve(ar, root, NULL, 0) : ar->header;
            json_t *files = json_object_get(root_node, "files");
            const char *key;
            json_t *val;
            json_object_foreach(files, key, val) {
                char *seed;
                if (root[0]) {
                    if (asprintf(&seed, "%s/%s", root, key) < 0) die("OOM");
                } else {
                    seed = xstrdup(key);
                }
                plan_walk(ar, base_cwd, root, flat, seed, &plan, 0);
                free(seed);
            }
        } else {
            char *seed = safe_name(req[i], false);
            plan_walk(ar, base_cwd, root, flat, seed, &plan, 0);
            free(seed);
        }
        free(req[i]);
    }
    free(req);

    if (plan.count == 0) die("No entries selected");

    for (size_t i = 0; i < plan.count; i++) {
        ExtractItem *it = &plan.items[i];
        if (json_is_object(json_object_get(it->node, "files"))) {
            mkdir_p(it->target);
        } else {
            char *pdir = parent_dir(it->target);
            mkdir_p(pdir);

            char *tmp_tmpl;
            if (asprintf(&tmp_tmpl, "%s/.asar-XXXXXX", pdir) < 0) die("OOM");
            int tfd = mkstemp(tmp_tmpl);
            if (tfd < 0) die("mkstemp failed: %s", strerror(errno));

            FILE *out = fdopen(tfd, "wb");
            if (!out) { close(tfd); unlink(tmp_tmpl); die("fdopen failed"); }
            copy_node_data(ar, it->real, it->node, out);
            mode_t mode = json_is_true(json_object_get(it->node, "executable")) ? 0755 : 0644;
            fchmod(fileno(out), mode);
            fflush(out);
            fsync(fileno(out));
            fclose(out);

            if (rename(tmp_tmpl, it->target) != 0) {
                unlink(tmp_tmpl);
                die("rename to '%s' failed: %s", it->target, strerror(errno));
            }
            free(tmp_tmpl);
            free(pdir);
        }
        free(it->target);
        free(it->real);
    }
    free(plan.items);
    free(root);
    free(base_cwd);
    archive_close(ar);
}
/* Встроенная реализация SHA-256 (FIPS 180-4) без зависимости от OpenSSL */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} Sha256Ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(Sha256Ctx *ctx, const uint8_t data[64]) {
    uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
    for (int i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR32(m[i - 15], 7) ^ ROTR32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = ROTR32(m[i - 2], 17) ^ ROTR32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + sha256_k[i] + m[i];
        uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(Sha256Ctx *ctx, const void *buf, size_t len) {
    const uint8_t *data = (const uint8_t *)buf;
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(Sha256Ctx *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;
    ctx->bitlen += ctx->datalen * 8;
    for (int j = 0; j < 8; ++j)
        ctx->data[56 + j] = (uint8_t)(ctx->bitlen >> ((7 - j) * 8));
    sha256_transform(ctx, ctx->data);
    for (int j = 0; j < 4; ++j) {
        for (int s = 0; s < 8; ++s)
            hash[j + s * 4] = (uint8_t)((ctx->state[s] >> (24 - j * 8)) & 0xff);
    }
}

static void sha256_oneshot(const void *buf, size_t len, uint8_t hash[32]) {
    Sha256Ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, buf, len);
    sha256_final(&ctx, hash);
}

/* Расчёт SHA-256 (цельного и поблочного по 4 МБ) для поля integrity */
static void hex_encode(const uint8_t *digest, unsigned int len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < len; i++) {
        out[i * 2] = hex[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[digest[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static json_t *digest_file_json(const char *filepath, uint64_t *out_size) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) die("Cannot open '%s' for hashing: %s", filepath, strerror(errno));

    Sha256Ctx whole_ctx, blk_ctx;
    sha256_init(&whole_ctx);
    sha256_init(&blk_ctx);

    json_t *blocks = json_array();
    uint8_t *buf = xmalloc(CHUNK_SIZE);
    uint64_t total = 0;
    size_t blk_fill = 0;
    uint8_t md[32];
    char hex_str[65];

    while (true) {
        size_t got = fread(buf, 1, CHUNK_SIZE, fp);
        if (got == 0) {
            if (ferror(fp)) die("Read error hashing '%s': %s", filepath, strerror(errno));
            break;
        }
        total += got;
        sha256_update(&whole_ctx, buf, got);

        size_t off = 0;
        while (off < got) {
            size_t space = INTEGRITY_BLOCK - blk_fill;
            size_t take = (got - off < space) ? (got - off) : space;
            sha256_update(&blk_ctx, buf + off, take);
            blk_fill += take;
            off += take;

            if (blk_fill == INTEGRITY_BLOCK) {
                sha256_final(&blk_ctx, md);
                hex_encode(md, 32, hex_str);
                json_array_append_new(blocks, json_string(hex_str));
                sha256_init(&blk_ctx);
                blk_fill = 0;
            }
        }
    }

    if (blk_fill > 0 || json_array_size(blocks) == 0) {
        sha256_final(&blk_ctx, md);
        hex_encode(md, 32, hex_str);
        json_array_append_new(blocks, json_string(hex_str));
    }

    sha256_final(&whole_ctx, md);
    hex_encode(md, 32, hex_str);

    free(buf);
    fclose(fp);

    *out_size = total;
    json_t *obj = json_object();
    json_object_set_new(obj, "algorithm", json_string("SHA256"));
    json_object_set_new(obj, "hash", json_string(hex_str));
    json_object_set_new(obj, "blockSize", json_integer(INTEGRITY_BLOCK));
    json_object_set_new(obj, "blocks", blocks);
    return obj;
}

/* Рекурсивный сбор файлов для добавления/замены */
typedef struct {
    char *rel_name;
    char *src_path;
    bool is_dir;
    bool executable;
} IncomingItem;

typedef struct {
    IncomingItem *items;
    size_t count;
    size_t cap;
} IncomingList;

static void incoming_add(IncomingList *list, char *rel, char *src, bool is_dir, bool exec) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].rel_name, rel) == 0) {
            if (strcmp(list->items[i].src_path, src) != 0)
                die("Duplicate input destination: %s", rel);
            free(rel);
            free(src);
            return;
        }
    }
    if (list->count == list->cap) {
        list->cap = list->cap ? list->cap * 2 : 64;
        list->items = realloc(list->items, list->cap * sizeof(IncomingItem));
        if (!list->items) die("OOM");
    }
    list->items[list->count++] = (IncomingItem){rel, src, is_dir, exec};
}

static void incoming_visit(IncomingList *list, const char *src_path, const char *rel_name, int depth) {
    if (depth > 64) die("Input directory nesting too deep");
    char *clean_rel = safe_name(rel_name, false);
    if (strpbrk(clean_rel, "\r\n\\") != NULL) die("Unsupported input name: %s", clean_rel);

    struct stat st;
    if (lstat(src_path, &st) != 0) die("Cannot stat '%s': %s", src_path, strerror(errno));
    if (S_ISLNK(st.st_mode)) die("Adding symbolic links is not supported: %s", src_path);

    if (S_ISDIR(st.st_mode)) {
        incoming_add(list, clean_rel, xstrdup(src_path), true, false);
        DIR *d = opendir(src_path);
        if (!d) die("Cannot open directory '%s': %s", src_path, strerror(errno));
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            char *next_src, *next_rel;
            if (asprintf(&next_src, "%s/%s", src_path, ent->d_name) < 0) die("OOM");
            if (asprintf(&next_rel, "%s/%s", clean_rel, ent->d_name) < 0) die("OOM");
            incoming_visit(list, next_src, next_rel, depth + 1);
            free(next_src);
            free(next_rel);
        }
        closedir(d);
    } else if (S_ISREG(st.st_mode)) {
        bool exec = (st.st_mode & 0111) != 0;
        incoming_add(list, clean_rel, xstrdup(src_path), false, exec);
    } else {
        die("Not a regular file or directory: %s", src_path);
    }
}
/* Вспомогательные функции пересборки и блокировки */
static void rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
                char *sub;
                if (asprintf(&sub, "%s/%s", path, ent->d_name) >= 0) {
                    rm_rf(sub);
                    free(sub);
                }
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void copy_dir_recursive(const char *src, const char *dst) {
    mkdir_p(dst);
    DIR *d = opendir(src);
    if (!d) die("Cannot open '%s': %s", src, strerror(errno));
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char *s_sub, *d_sub;
        if (asprintf(&s_sub, "%s/%s", src, ent->d_name) < 0) die("OOM");
        if (asprintf(&d_sub, "%s/%s", dst, ent->d_name) < 0) die("OOM");
        struct stat st;
        if (lstat(s_sub, &st) != 0) die("lstat '%s': %s", s_sub, strerror(errno));
        if (S_ISLNK(st.st_mode)) {
            char link_target[PATH_MAX];
            ssize_t len = readlink(s_sub, link_target, sizeof(link_target) - 1);
            if (len < 0) die("readlink '%s': %s", s_sub, strerror(errno));
            link_target[len] = '\0';
            if (symlink(link_target, d_sub) != 0) die("symlink '%s': %s", d_sub, strerror(errno));
        } else if (S_ISDIR(st.st_mode)) {
            copy_dir_recursive(s_sub, d_sub);
        } else {
            FILE *in = fopen(s_sub, "rb");
            FILE *out = fopen(d_sub, "wb");
            if (!in || !out) die("Copy '%s' -> '%s' failed", s_sub, d_sub);
            uint8_t *buf = xmalloc(CHUNK_SIZE);
            size_t n;
            while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
                if (fwrite(buf, 1, n, out) != n) die("Write error: %s", d_sub);
            }
            free(buf);
            fchmod(fileno(out), st.st_mode & 0777);
            fclose(in);
            fclose(out);
        }
        free(s_sub);
        free(d_sub);
    }
    closedir(d);
}

static int acquire_archive_lock(const char *archive_path) {
    char *dir = NULL;
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    struct stat st;
    if (xdg && xdg[0] == '/' && lstat(xdg, &st) == 0 &&
        S_ISDIR(st.st_mode) && st.st_uid == getuid() && (st.st_mode & 0077) == 0) {
        if (asprintf(&dir, "%s/far2l-asar", xdg) < 0) die("OOM");
    } else {
        if (asprintf(&dir, "/tmp/far2l-asar-%u", (unsigned)getuid()) < 0) die("OOM");
    }
    mkdir(dir, 0700);
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077)) {
        die("Unsafe lock directory: %s", dir);
    }

    uint8_t md[32];
    sha256_oneshot(archive_path, strlen(archive_path), md);
    char hex_id[65];
    hex_encode(md, 32, hex_id);

    char *lock_file;
    if (asprintf(&lock_file, "%s/%s.lock", dir, hex_id) < 0) die("OOM");
    int fd = open(lock_file, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) die("Cannot open lock '%s': %s", lock_file, strerror(errno));
    if (flock(fd, LOCK_EX) != 0) die("flock failed: %s", strerror(errno));
    free(lock_file);
    free(dir);
    return fd;
}
static json_t *ensure_parent_dir(json_t *header, const char *full_name, bool *out_unpacked) {
    json_t *curr = header;
    *out_unpacked = false;
    char *copy = xstrdup(full_name);
    char *last_slash = strrchr(copy, '/');
    if (!last_slash) {
        free(copy);
        json_t *files = json_object_get(header, "files");
        if (!json_is_object(files)) {
            files = json_object();
            json_object_set_new(header, "files", files);
        }
        return files;
    }
    *last_slash = '\0';
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, "/", &saveptr); tok; tok = strtok_r(NULL, "/", &saveptr)) {
        json_t *files = json_object_get(curr, "files");
        if (!json_is_object(files)) die("Archive parent is not a directory: %s", full_name);
        json_t *next = json_object_get(files, tok);
        if (!next) {
            next = json_object();
            json_object_set_new(next, "files", json_object());
            json_object_set_new(files, tok, next);
        } else if (!json_is_object(json_object_get(next, "files"))) {
            die("Archive parent is not an ordinary directory: %s", full_name);
        }
        if (json_is_true(json_object_get(next, "unpacked"))) *out_unpacked = true;
        curr = next;
    }
    free(copy);
    return json_object_get(curr, "files");
}

static void assign_offsets(json_t *node, uint64_t *pos) {
    json_t *files = json_object_get(node, "files");
    if (!json_is_object(files)) return;
    const char *key;
    json_t *child;
    json_object_foreach(files, key, child) {
        if (json_is_object(json_object_get(child, "files"))) {
            assign_offsets(child, pos);
        } else if (!json_object_get(child, "link") && !json_is_true(json_object_get(child, "unpacked"))) {
            char off_buf[32];
            snprintf(off_buf, sizeof(off_buf), "%" PRIu64, *pos);
            json_object_set_new(child, "offset", json_string(off_buf));
            *pos += node_size(child);
        }
    }
}

typedef struct {
    char *arc_name;
    char *src_path;
    bool executable;
} ChangedMap;

static const ChangedMap *find_changed(const ChangedMap *map, size_t count, const char *name) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(map[i].arc_name, name) == 0) return &map[i];
    }
    return NULL;
}

static json_t *find_old_node(json_t *root_header, const char *vpath) {
    json_t *curr = root_header;
    char *copy = xstrdup(vpath);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, "/", &saveptr); tok; tok = strtok_r(NULL, "/", &saveptr)) {
        json_t *files = json_object_get(curr, "files");
        if (!json_is_object(files)) { free(copy); return NULL; }
        curr = json_object_get(files, tok);
        if (!curr) { free(copy); return NULL; }
    }
    free(copy);
    return curr;
}

static void write_entries_data(Archive *old_ar, json_t *node, const char *prefix,
                               const ChangedMap *changed, size_t ch_count,
                               FILE *out_asar, const char *staged_unpacked) {
    json_t *files = json_object_get(node, "files");
    if (!json_is_object(files)) return;
    const char *key;
    json_t *child;
    json_object_foreach(files, key, child) {
        char *vpath;
        if (asprintf(&vpath, "%s%s%s", prefix, prefix[0] ? "/" : "", key) < 0) die("OOM");
        if (json_is_object(json_object_get(child, "files"))) {
            write_entries_data(old_ar, child, vpath, changed, ch_count, out_asar, staged_unpacked);
        } else if (!json_object_get(child, "link")) {
            const ChangedMap *cm = find_changed(changed, ch_count, vpath);
            bool is_unpacked = json_is_true(json_object_get(child, "unpacked"));
            if (is_unpacked && !cm) {
                free(vpath);
                continue;
            }
            FILE *target = out_asar;
            char *ext_file = NULL;
            if (is_unpacked) {
                ext_file = check_destination(staged_unpacked, vpath);
                char *pdir = parent_dir(ext_file);
                mkdir_p(pdir);
                free(pdir);
                target = fopen(ext_file, "wb");
                if (!target) die("Cannot create unpacked file '%s': %s", ext_file, strerror(errno));
            }
            if (!cm) {
                json_t *old_node = find_old_node(old_ar->header, vpath);
                if (!old_node) die("Internal error: missing old node for %s", vpath);
                copy_node_data(old_ar, vpath, old_node, target);
            } else {
                FILE *in = fopen(cm->src_path, "rb");
                if (!in) die("Cannot read '%s': %s", cm->src_path, strerror(errno));
                uint8_t *buf = xmalloc(CHUNK_SIZE);
                uint64_t total = 0;
                size_t got;
                while ((got = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
                    if (fwrite(buf, 1, got, target) != got) die("Write error packing '%s'", vpath);
                    total += got;
                }
                free(buf);
                fclose(in);
                if (total != node_size(child)) die("Source changed while packing: %s", cm->src_path);
            }
            if (target != out_asar) {
                fchmod(fileno(target), cm && cm->executable ? 0755 : 0644);
                fflush(target);
                fsync(fileno(target));
                fclose(target);
                free(ext_file);
            }
        }
        free(vpath);
    }
}
static void cmd_add(const char *raw_archive, const char *list_file, const char *raw_root) {
    struct stat lst;
    if (lstat(raw_archive, &lst) == 0 && S_ISLNK(lst.st_mode))
        die("Archive must not be a symbolic link");

    char *pdir = parent_dir(raw_archive);
    mkdir_p(pdir);
    char *real_pdir = realpath(pdir, NULL);
    if (!real_pdir) die("Invalid archive parent directory: %s", pdir);

    char *canon_archive;
    if (asprintf(&canon_archive, "%s/%s", real_pdir, basename_ptr(raw_archive)) < 0) die("OOM");

    int lock_fd = acquire_archive_lock(canon_archive);
    bool exists = (access(canon_archive, F_OK) == 0);
    Archive *old_ar = exists ? archive_open(canon_archive) : NULL;

    json_t *header = old_ar ? json_deep_copy(old_ar->header) : json_object();
    if (!old_ar) json_object_set_new(header, "files", json_object());

    char *root = safe_name(raw_root, true);
    size_t req_count = 0;
    char **req = read_response_lines(list_file, &req_count);
    IncomingList incoming = {0};

    for (size_t i = 0; i < req_count; i++) {
        char *rp = realpath(req[i], NULL);
        if (!rp) die("Input path not found: %s", req[i]);
        if (req[i][0] == '/') {
            incoming_visit(&incoming, rp, basename_ptr(rp), 0);
        } else {
            incoming_visit(&incoming, rp, req[i], 0);
        }
        free(rp);
        free(req[i]);
    }
    free(req);
    if (incoming.count == 0) die("No files selected for adding");

    ChangedMap *changed = xmalloc(incoming.count * sizeof(ChangedMap));
    size_t ch_count = 0;
    bool external_changed = false;

    for (size_t i = 0; i < incoming.count; i++) {
        IncomingItem *it = &incoming.items[i];
        char *arc_name;
        if (root[0] != '\0') {
            if (asprintf(&arc_name, "%s/%s", root, it->rel_name) < 0) die("OOM");
        } else {
            arc_name = xstrdup(it->rel_name);
        }
        bool parent_unpacked = false;
        json_t *children = ensure_parent_dir(header, arc_name, &parent_unpacked);
        const char *bname = basename_ptr(arc_name);
        json_t *prev = json_object_get(children, bname);

        if (it->is_dir) {
            if (prev && !json_is_object(json_object_get(prev, "files")))
                die("Cannot replace file/link with directory: %s", arc_name);
            if (!prev) {
                json_t *dnode = json_object();
                json_object_set_new(dnode, "files", json_object());
                json_object_set_new(children, bname, dnode);
            }
            free(arc_name);
        } else {
            if (prev && json_is_object(json_object_get(prev, "files")))
                die("Cannot replace directory with file: %s", arc_name);
            if (strcmp(it->src_path, canon_archive) == 0)
                die("Cannot add the archive to itself");

            uint64_t fsize = 0;
            json_t *integ = digest_file_json(it->src_path, &fsize);
            json_t *fnode = json_object();
            json_object_set_new(fnode, "size", json_integer((json_int_t)fsize));
            json_object_set_new(fnode, "integrity", integ);
            if (it->executable) json_object_set_new(fnode, "executable", json_true());

            bool was_unpacked = prev && json_is_true(json_object_get(prev, "unpacked"));
            if (was_unpacked || parent_unpacked) {
                json_object_set_new(fnode, "unpacked", json_true());
                external_changed = true;
            }
            json_object_set_new(children, bname, fnode);
            changed[ch_count++] = (ChangedMap){arc_name, xstrdup(it->src_path), it->executable};
        }
        free(it->rel_name);
        free(it->src_path);
    }
    free(incoming.items);

    uint64_t pos = 0;
    assign_offsets(header, &pos);

    char *raw_json = json_dumps(header, JSON_COMPACT);
    if (!raw_json) die("json_dumps failed");
    size_t json_len = strlen(raw_json);
    uint32_t payload_size = (uint32_t)((4 + json_len + 3) & ~3ULL);
    uint32_t header_size = payload_size + 4;
    uint8_t preamble[16];
    write_u32_le(preamble, 4);
    write_u32_le(preamble + 4, header_size);
    write_u32_le(preamble + 8, payload_size);
    write_u32_le(preamble + 12, (uint32_t)json_len);

    char *work_tmpl;
    if (asprintf(&work_tmpl, "%s/.far2l-asar-XXXXXX", real_pdir) < 0) die("OOM");
    if (!mkdtemp(work_tmpl)) die("mkdtemp failed: %s", strerror(errno));

    char *staged_asar, *companion, *staged_companion;
    if (asprintf(&staged_asar, "%s/new.asar", work_tmpl) < 0) die("OOM");
    if (asprintf(&companion, "%s.unpacked", canon_archive) < 0) die("OOM");
    if (asprintf(&staged_companion, "%s/new.asar.unpacked", work_tmpl) < 0) die("OOM");

    if (external_changed) {
        struct stat cst;
        if (lstat(companion, &cst) == 0) {
            if (S_ISLNK(cst.st_mode)) die("ASAR companion must not be a symlink");
            copy_dir_recursive(companion, staged_companion);
        } else {
            mkdir_p(staged_companion);
        }
    }

    FILE *out = fopen(staged_asar, "wb");
    if (!out) die("Cannot create staged ASAR: %s", strerror(errno));
    fwrite(preamble, 1, 16, out);
    fwrite(raw_json, 1, json_len, out);
    size_t pad = payload_size - 4 - json_len;
    for (size_t i = 0; i < pad; i++) fputc(0, out);

    write_entries_data(old_ar, header, "", changed, ch_count, out, staged_companion);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    mode_t orig_mode = 0644;
    if (old_ar && stat(canon_archive, &lst) == 0) orig_mode = lst.st_mode & 0777;
    chmod(staged_asar, orig_mode);

    Archive *verify = archive_open(staged_asar);
    archive_close(verify);

    char *backup_asar, *backup_comp;
    if (asprintf(&backup_asar, "%s.bak-%ld-%d", canon_archive, (long)time(NULL), getpid()) < 0) die("OOM");
    if (asprintf(&backup_comp, "%s.unpacked", backup_asar) < 0) die("OOM");

    bool comp_moved = false, comp_installed = false;
    if (old_ar) {
        FILE *src_f = fopen(canon_archive, "rb");
        FILE *dst_f = fopen(backup_asar, "wb");
        if (!src_f || !dst_f) die("Backup copy failed");
        uint8_t *buf = xmalloc(CHUNK_SIZE);
        size_t n;
        while ((n = fread(buf, 1, CHUNK_SIZE, src_f)) > 0) fwrite(buf, 1, n, dst_f);
        free(buf);
        fclose(src_f);
        fclose(dst_f);
        if (access(companion, F_OK) == 0 && !external_changed)
            copy_dir_recursive(companion, backup_comp);
    }

    if (external_changed) {
        if (access(companion, F_OK) == 0) {
            if (rename(companion, backup_comp) != 0) die("Backup companion failed");
            comp_moved = true;
        }
        if (rename(staged_companion, companion) != 0) {
            if (comp_moved) rename(backup_comp, companion);
            die("Install companion failed");
        }
        comp_installed = true;
    }

    if (rename(staged_asar, canon_archive) != 0) {
        if (comp_installed) rm_rf(companion);
        if (comp_moved) rename(backup_comp, companion);
        die("Atomic replace of ASAR failed: %s", strerror(errno));
    }

    printf("Updated ASAR: %zu file(s).\n", ch_count);
    if (old_ar) {
        unlink(backup_asar);
        rm_rf(backup_comp);
    }
    rm_rf(work_tmpl);

    for (size_t i = 0; i < ch_count; i++) {
        free(changed[i].arc_name);
        free(changed[i].src_path);
    }
    free(changed);
    free(raw_json);
    json_decref(header);
    if (old_ar) archive_close(old_ar);
    close(lock_fd);
    free(root);
    free(canon_archive);
    free(real_pdir);
    free(pdir);
    free(work_tmpl);
    free(staged_asar);
    free(companion);
    free(staged_companion);
    free(backup_asar);
    free(backup_comp);
}

int main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
        printf("far2l-asar %s\n", APP_VERSION);
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <list|extract|add> <archive> [--list FILE] [--root DIR] [--flat]\n", argv[0]);
        return 2;
    }
    const char *cmd = argv[1];
    const char *archive = argv[2];
    const char *list_file = NULL;
    const char *root = "";
    bool flat = false;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--flat") == 0) {
            flat = true;
        } else if (strcmp(argv[i], "--list") == 0 && i + 1 < argc) {
            list_file = argv[++i];
        } else if (strncmp(argv[i], "--list=", 7) == 0) {
            list_file = argv[i] + 7;
        } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            root = argv[++i];
        } else if (strncmp(argv[i], "--root=", 7) == 0) {
            root = argv[i] + 7;
        } else {
            die("Unknown argument: %s", argv[i]);
        }
    }

    if (strcmp(cmd, "list") == 0) {
        cmd_list(archive);
    } else if (strcmp(cmd, "extract") == 0) {
        if (!list_file) die("extract requires --list");
        cmd_extract(archive, list_file, root, flat);
    } else if (strcmp(cmd, "add") == 0) {
        if (!list_file) die("add requires --list");
        cmd_add(archive, list_file, root);
    } else {
        die("Unknown command: %s", cmd);
    }
    return 0;
}
