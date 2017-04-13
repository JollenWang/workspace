/********************************************************************************************
* file      : func.c
* purpose   : functions of binary tool source file
* author    : Jollen Wang
* version   : 1.0
* date      :
* history   :
********************************************************************************************/

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>

#include "func.h"
#include "main.h"
#include "crc.h"


//-------------------------------------------------------------------------------------------

/*
static int SUM(const char *str)
{
    char *p = str;
    int sum = 0;

    while(*p != '\0') {
        sum += *p;
        p++;
    }

    return sum;
}
*/

#define MAX_NUMERICAL_PARAM_LEN     10
#define IS_IN_a_TO_f(c) (((c) >= 'a') && ((c) <= 'f'))
#define IS_IN_A_TO_F(c) (((c) >= 'A') && ((c) <= 'F'))
#define IS_IN_0_TO_9(c) (((c) >= '0') && ((c) <= '9'))


static int __find_numerical_start(char *str, int str_len, int *start_pos, int *is_hex)
{
    if (str_len > MAX_NUMERICAL_PARAM_LEN || str_len < 1)
        return -1;

    if (str_len == 1) {
        if (!IS_IN_0_TO_9(str[0]))
            return -1;

        *start_pos = 0;
        *is_hex = 0;
        return 0;
    }

    if (str_len > 1) {
        if (str[0] == '0') {
            if (str[1] == 'x' || str[1] == 'X') {
                *start_pos = 2;
                *is_hex = 1;
            } else {
                *start_pos = 0;
                *is_hex = 0;
            }

            return 0;
        } else {
            if (IS_IN_0_TO_9(str[0])) {
                *start_pos = 0;
                *is_hex = 0;
                return 0;
            }
        }
    }

    return -1;
}

static int __check_validity_data(char *str, int start_pos, int is_hex)
{
    char *p = str + start_pos;

    if (is_hex) {
        while(*p != '\0') {
            if (!(IS_IN_a_TO_f(*p) || IS_IN_A_TO_F(*p) || IS_IN_0_TO_9(*p)))
                return -1;
            p++;
        }
    } else {
        while(*p != '\0') {
            if (!IS_IN_0_TO_9(*p))
                return -1;
            p++;
        }
    }

    return p - (str + start_pos);
}

static unsigned char __char2hex(char c)
{
    if (IS_IN_0_TO_9(c))
        return c - '0';
    if (IS_IN_A_TO_F(c))
        return c - 'A' + 10;
    if (IS_IN_a_TO_f(c))
        return c - 'a' + 10;

    return 0;
}

int str2word(char *str, uint32_t *word)
{
    size_t str_len = strlen(str);
    int i, start_pos, is_hex, valid_len;
    uint64_t value = 0;
    uint8_t multiple;

    if (!str)
        return -1;

    if (__find_numerical_start(str, str_len, &start_pos, &is_hex)) {
        printf("#>find numerical start failed!\n");
        return -1;
    }

    valid_len = __check_validity_data(str, start_pos, is_hex);
    if (valid_len < 0)
        return -1;

    multiple = (is_hex) ? 16 : 10;
    for (i = 0; i < valid_len; i++) {
        value *= multiple;
        value += __char2hex(str[start_pos + i]);
        if (!is_hex) {
            if (value > (uint64_t)0xFFFFFFFF) {
                printf("#>decimal data %s overflow!\n", str);
                return -1;
            }
        }
    }
    *word = (uint32_t)value;

    return 0;
}

static size_t __get_fsize(FILE *fp)
{
    fseek(fp, 0, SEEK_END);
    return ftell(fp);
}

static int __file_copy(FILE *dst, FILE *src, long offset, size_t size)
{
    unsigned char *tmp_buf = malloc(size);
    size_t rw_len;

    if (!tmp_buf) {
        printf("#>allocate memeory size %ld failed!\n", size);
        return -1;
    }

    fseek(src, offset, SEEK_SET);
    rw_len = fread(tmp_buf, 1, size, src);
    if (rw_len != size) {
        printf("#>read data from src_file failed[wanted:%ld,actual:%ld]!\n", size, rw_len);
        free(tmp_buf);
        return -1;
    }

    rw_len = fwrite(tmp_buf, 1, size, dst);
    free(tmp_buf);
    if (rw_len != size) {
        printf("#>write data to dest_file failed[wanted:%ld,actual:%ld]!\n", size, rw_len);
        return -1;
    }

    printf("$>success!\n");
    return 0;

}


static void show_arguments(struct arguments *args)
{
    printf("input       : %s\n", args->input);
    printf("output      : %s\n", args->output);
    printf("operation   : %s\n", args->operation);
    printf("base addr   : 0x%08X\n", args->base_address);
    printf("size        : 0x%08X, %d\n", args->size, args->size);
}

DECLARE_LONG_OPTIONS(read2file) = {
    {"help",      no_argument,         NULL, 'h'},
    {"input",     required_argument,   NULL, 'i'},
    {"output",    required_argument,   NULL, 'o'},
    {"base_addr", required_argument,   NULL, 'b'},
    {"size",      required_argument,   NULL, 's'},
    {0,           0,                   0,    0  },
};

DECLARE_FUNC_VARIABLES(read2file, "hi:o:b:s:", "read specific size data from specific file and write to target file");

void read2file_helper(FILE *s, struct function *self)
{
    //fprintf(s, "$>%s helper function called!\n", self->caption);
    fprintf(s, "usage  : ./image+ --read2file -b START_ADDR -s SIZE -i INPUT -o OUTPUT\n");
    fprintf(s, "      -h --help           show this usage.\n");
    fprintf(s, "      -i                  specific the input file name.\n");
    fprintf(s, "      -o                  specific the output file name.\n");
    fprintf(s, "      -b                  specific the base address.\n");
    fprintf(s, "      -s                  specific the size start from base address.\n");
}

int read2file_parse_option(int argc, char **argv, struct arguments *args)
{
    struct function *self = (struct function *)args->owner;
    const char *const s_options = self->short_options;
    const struct option *l_options = self->long_options;
    int c, option_index;

    if (argc < 3) {
        printf("invalid arguments!\n");
        read2file_helper(stdout, self);
        exit(-1);
    }

    while (1) {
        c = getopt_long(argc, argv, s_options, l_options, &option_index);
        if (c == -1)    /*all options are analyse done*/
            break;

        switch(c) {
        case 'h':
            read2file_helper(stdout, self);
            exit(0);

        case 'i':
            args->input = optarg;
            continue;

        case 'o':
            args->output = optarg;
            continue;

        case 'b':
            if (str2word(optarg, &args->base_address) < 0) {
                printf("#>invalid base address:%s\n", optarg);
                exit(-1);
            }
            continue;

        case 's':
            if (str2word(optarg, &args->size) < 0) {
                printf("#>invalid size:%s\n", optarg);
                exit(-1);
            }
            continue;

        default:
            break;
        }
    }

    if (!args->input) {
        printf("#>no input file specified!\n");
        exit(-1);
    }

    if (!args->output)
        args->output = "./output/OUT.BIN";

    if (access(args->input, 0)) {
        printf("#>%s is no access!\n", args->input);
        exit(-1);
    }

    show_arguments(args);
    return 0;
}


int read2file_proc(struct arguments *arg)
{
    FILE *fsrc;
    FILE *fdst;
    size_t fsize;
    int ret = 0;

    fsrc = fopen(arg->input, "rb");
    assert(fsrc != NULL);
    fdst = fopen(arg->output, "wb+");
    assert(fdst != NULL);

    fsize = __get_fsize(fsrc);
    if (arg->base_address + arg->size > fsize) {
        printf("$>%s():read 0x%X bytes from address 0x%08X is out of file size 0x%08lX!\n", 
            __func__, arg->size, arg->base_address, fsize);
        ret = -1;
        goto __exit;
    }

    fseek(fdst, 0, SEEK_SET);
    ret = __file_copy(fdst, fsrc,arg->base_address, arg->size);

__exit:
    fclose(fdst);
    fclose(fsrc);

    return ret;
}

DECLARE_LONG_OPTIONS(create) = {
    {"help",        no_argument,         NULL, 'h'},
    {"config",      required_argument,   NULL, 'C'},
    {"output",      required_argument,   NULL, 'o'},
    {"size",        required_argument,   NULL, 's'},
    {"padding",     required_argument,   NULL, 'p'},
    {0,             0,                   0,    0  },
};

DECLARE_FUNC_VARIABLES(create, "hC:o:s:p:", "create a blank binary file padding " \
    "by target value with the specific size, or set the value with the configuration file.");

void create_helper(FILE *s, struct function *self)
{
    fprintf(s, "usage  : ./image+ --create [--config CFG_FILE] -s SIZE [-p 0xFF/0x00] -o OUTPUT\n");
    fprintf(s, "      -h --help           show this usage.\n");
    fprintf(s, "      -C --config         specific the data content value config file.\n");
    fprintf(s, "      -s                  specific the file size.\n");
    fprintf(s, "      -p                  specific the padding byte, default padding is 0x00.\n");
    fprintf(s, "      -o                  specific the output file name.\n");
}

int create_parse_option(int argc, char **argv, struct arguments *args)
{
    struct function *self = (struct function *)args->owner;
    const char *const s_options = self->short_options;
    const struct option *l_options = self->long_options;
    int c, option_index;
    uint32_t padding = 0;

    if (argc < 3) {
        printf("invalid arguments!\n");
        read2file_helper(stdout, self);
        exit(-1);
    }

    while (1) {
        c = getopt_long(argc, argv, s_options, l_options, &option_index);
        if (c == -1)    /*all options are analyse done*/
            break;

        switch(c) {
        case 'h':
            create_helper(stdout, self);
            exit(0);

        case 'C':
            args->input = optarg;
            continue;

        case 's':
            if (str2word(optarg, &args->size) < 0) {
                printf("#>invalid size:%s\n", optarg);
                exit(-1);
            }
            continue;

        case 'p':
            if (str2word(optarg, &padding) < 0) {
                printf("#>invalid padding value:%s\n", optarg);
                exit(-1);
            }
            args->private = padding;
            continue;

        case 'o':
            args->output = optarg;
            continue;

        default:
            break;
        }
    }

    if (args->input) {
        if (access(args->input, 0)) {
            printf("#>configure file %s is no access!\n", args->input);
            exit(-1);
        }
    }

    if (!args->output)
        args->output = "./output/blank.bin";

    if (args->size <= 0) {
        printf("#>file size is not specificed!\n");
        exit(-1);
    }

    show_arguments(args);
    return 0;
}

/**
* conten configuration file format
#offset, wcnt, type, vaule/start...end,
#type: 0, ignore
#      1, Multiple
#      2, r_checksum hash algorithm
#      3, crc32 hash algorithm
#      4, crc16 hash algorithm
#
#@!/image+/config
0x00000000, 1, 0, 0x46504741;
0x00000004, 1, 0, 0xFFFFFFF0;
0x00000008, 1, 0, 0x00000100;
0x0000000C, 1, 0, 0x01000100;
0x00000010, 1, 0, 0x02001000;
0x00000014, 2, 1, 0x00000000;
0x0000001C, 1, 2, 0x08, 0x18;
0x00000020, 56, 1, 0xFFFFFFFF;
#@end
*/

enum {
    IFILE = 0,
    DATA,
    PADDING,
    CRC32,
    CRC16,
    RCHECKSUM,
};

struct cmd_type {
    int32_t id;
    const char *name;
};

static struct cmd_type g_cmd_table[] = {
    {IFILE,     "file"},
    {DATA,      "data"},
    {PADDING,   "padding"},
    {CRC32,     "crc32"},
    {CRC16,     "crc16"},
    {RCHECKSUM, "rchecksum"},
    {-1,        NULL},
};

struct cc_info {
    uint32_t offset;
    struct cmd_type *type;
    char fname[MAX_FILE_NAME_LENGTH];   /*for type == file use*/
    uint32_t size;
    uint32_t value[4];
};

/*
static struct cmd_type *__seek_type(char *str)
{
    struct cmd_type *p = g_cmd_table;

    while(p->name) {
        if (!strcmp(p->name, str))
            return p;
        p++;
    }

    return NULL;
}
*/
static int32_t __seek_type(char *str, struct cmd_type **dst)
{
    struct cmd_type *p = g_cmd_table;

    while(p->name) {
        if (!strcmp(p->name, str)) {
            *dst = p;
            return 0;
        }
        p++;
    }

    return -1;
}


#define GET_NEXT_WORD_ADN_SAVE(tips, func, p2) do { \
    token = strtok(NULL, delimiters); \
    if (!token) { \
        printf("#>cmd parameter miss!\n"); \
        is_error = 1; \
        break; \
    } \
    \
    printf(tips, token); \
    if (func(token, p2)) { \
        printf("#>invalid value :%s\n", token); \
        is_error = 1; \
        break; \
    } \
} while(0)

static int __analyse_cmdlines(FILE *fp, struct cc_info *info, int info_limit)
{
    struct cc_info *p = info;
    char delimiters[] = ", \r\n";
    char *cmd = NULL;
    size_t size = 0;
    int is_error = 0, count = 0;
    ssize_t len;
    char *token;
    int i;

    while((len = getline(&cmd, &size, fp)) != -1) {
        token = strtok(cmd, delimiters);
        if (!token)
            break;

        if (token[0] == '#')
            continue;
 
        /*word0, offset*/
        printf("#>offset :%s\n", token);
        if (str2word(token, &p->offset)) {
            printf("#>invalid offset :%s\n", token);
            is_error = 1;
            break;
        }

        /*word1 cmd type*/
        GET_NEXT_WORD_ADN_SAVE("#>type :%s\n", __seek_type, &p->type);

        /*word2 data size*/
        GET_NEXT_WORD_ADN_SAVE("#>size :%s\n", str2word, &p->size);

        /*word3, for different cmd type, has different meaning*/
        switch (p->type->id) {
        case IFILE: /*get file name and the padding bytes if has*/
            GET_NEXT_WORD_ADN_SAVE("#>fname :%s\n", access, 0);
            if (strlen(token) > sizeof(p->fname) -1) {
                printf("#>file path name %s is too long![max %ld can accept]\n", token, sizeof(p->fname) - 1);
                is_error = 1;
                break;
            }
            strcpy(p->fname, token);
            GET_NEXT_WORD_ADN_SAVE("#>padding :%s\n", str2word, &p->value[0]);
            break;

        case DATA: /*get all followed data, max 4 words*/
            if (p->size > 4) {
                printf("#>data count%d overflow!\n", p->size);
                is_error = 1;
                break;
            }
            for (i = 0; i < p->size; i++)
                GET_NEXT_WORD_ADN_SAVE("#>data :%s\n", str2word, &p->value[i]);
            break;

        case PADDING:   /*get padding value*/
            GET_NEXT_WORD_ADN_SAVE("#>padding value: %s\n", str2word, &p->value[0]);
            break;

        /*for hash algorithm, get start and end address*/
        case CRC32:
        case CRC16:
        case RCHECKSUM:
            for (i = 0; i <2; i++)
                GET_NEXT_WORD_ADN_SAVE("#>address :%s\n", str2word, &p->value[i]);
            break;

        default:
            break;
        }
        printf("\r\n");

        p++;
        count++;
        if (count >= info_limit) {
            printf("#>cmdline overflow!\n");
            is_error = 1;
            break;
        }
    }

    free(cmd);
    return (is_error) ? -1 : count;
}

static void calculate_inverted_checksum(struct cc_info *p, void *base, int32_t bytes)
{
    unsigned char *src = (unsigned char *)base + p->value[0];
    uint32_t *dst = (uint32_t *)base + (p->offset >> 2);
    uint32_t checksum = 0;

    printf("$>calculate rchecksum,bytes=%d\n", bytes);
    while(bytes--) {
        printf("%02X ", *src);
        checksum += *src++;
    }
    printf("\nchecksum=0x%08X\n", checksum);
    *dst = checksum ^ 0xFFFFFFFFul;
}

static void calculate_crc32(struct cc_info *p, uint32_t *base, int32_t bytes)
{
    uint32_t crc32_cnt = p->size;
    uint32_t calculate_words = (bytes + 3) >> 2;
    uint32_t bytes_per_block = (calculate_words / crc32_cnt) << 2;
    uint32_t i, last_crc32 = 0;
    unsigned char *src = (unsigned char *)(&base[p->value[0] >> 2]);

    printf("-------->>CRC32<<--------\n");
    printf("crc32 count=%d,bytes_per_block=%d\n", crc32_cnt, bytes_per_block);
    for (i = 0; i < crc32_cnt; i++) {
        base[(p->offset >> 2) + i] = crc32(last_crc32, src + i * bytes_per_block, bytes_per_block);
        last_crc32 = base[(p->offset >> 2) + i];
    }
}

static void calculate_crc16(struct cc_info *p, uint32_t *base, int32_t bytes)
{
}

static void __dump_hex(unsigned char *src, int count)
{
    int i;

    printf("$$$$$$$$$$$$$$$$>dump hex:\r\n");
    for (i = 0; i < count; i++) {
        if (!(i % 16))
            printf("[%08X]", i);
        printf("%02X ", src[i]);
        if (!((i + 1) % 16))
            printf("\n");
    }
}

static int __write_to_buffer(uint32_t *dest, struct cc_info *pinfo, int count)
{
    struct cc_info *pi = pinfo;
    int i, j;

    /*set normal value to the specificed offset*/
    for (i = 0; i < count; i++, pi++) {
        if (pi->type->id >= CRC32)
            continue;

        if (pi->type->id == IFILE) {
            FILE *fp = fopen(pi->fname, "rb");
            assert(fp != NULL);
            size_t fsize = __get_fsize(fp);
            size_t rw_len, rsize = pi->size, psize = 0;

            fseek(fp, 0, SEEK_SET);
            printf(">>>>fsize=0x%08lX, rsize=0x%08X\n", fsize, pi->size);
            if (pi->size > fsize) {
                rsize = fsize;
                psize = pi->size - fsize;
                printf(">>>>psize=0x%08lX\n", psize);
            }
            rw_len = fread(&dest[pi->offset >> 2], 1, rsize, fp);
            fclose(fp);
            if (rw_len != rsize) {
                printf("#>read data from src_file failed[wanted:%ld,actual:%ld]!\n", rsize, rw_len);
                return -1;
            }

            /*fill padding data*/
            if (psize)
                memset((unsigned char *)(&dest[pi->offset >> 2]) + rsize, (pi->value[0] & 0xFF), psize);
        } else if (pi->type->id == PADDING){
            for (j = 0; j < pi->size; j++)
                dest[(pi->offset >> 2) + j] = pi->value[0];
        } else {
            for (j = 0; j < pi->size; j++)
                dest[(pi->offset >> 2) + j] = pi->value[j];
        }
    }

    /*calculate hash digest if needed*/
    pi = pinfo;
    for (i = 0; i < count; i++, pi++) {
        int32_t calculate_bytes;

        if (pi->type->id < CRC32)
            continue;

        calculate_bytes = (int32_t)pi->value[1] + 1 - (int32_t)pi->value[0];
        if (calculate_bytes <= 0) {
            printf("#>invalid configuration data found,algorithm=%d,start_pos=%d,end_pos=%d\r\n",
                pi->type->id, pi->value[0], pi->value[1]);
            return -1;
        }

        switch(pi->type->id) {
        case CRC32:
            calculate_crc32(pi, dest, calculate_bytes);
            break;

        case CRC16:
            calculate_crc16(pi, dest, calculate_bytes);
            break;
 
         case RCHECKSUM:
             calculate_inverted_checksum(pi, (void *)dest, calculate_bytes);
             break;

        default:
            break;
        }
    }

    return 0;
}

int create_proc(struct arguments *args)
{
    FILE *fsrc;
    FILE *fdst;
    size_t rw_len;
    unsigned char *buf;
    unsigned char pading = args->private & 0xFF;
    struct cc_info info[MAX_CONFIG_CMDLINE_LIMIT];
    int cmd_lines, ret = -1;

    buf = malloc(args->size);
    if (!buf) {
        printf("#>%s():malloc %d bytes failed!", __func__, args->size);
        return -1;
    }

    memset(info, 0 ,sizeof(info));
    if (args->input) {
        fsrc = fopen(args->input, "r");
        assert(fsrc != NULL);
        fseek(fsrc, 0, SEEK_SET);

        cmd_lines = __analyse_cmdlines(fsrc, info, MAX_CONFIG_CMDLINE_LIMIT);
        if (cmd_lines < 0) {
            printf("#>%s():cmdline analyse failed!cmd_lines=%d\n", __func__, cmd_lines);
            goto __exit0;
        }

        if (__write_to_buffer((uint32_t *)buf, info, cmd_lines)) {
            printf("#>%s():write data to buffer failed!\n", __func__);
            goto __exit0;
        }
    } else
        memset(buf, pading, args->size);

    fdst = fopen(args->output, "wb+");
    assert(fdst != NULL);
    __dump_hex(buf, (args->size > 256) ? 256 : args->size);

    fseek(fdst, 0, SEEK_SET);
    rw_len = fwrite(buf, 1, args->size, fdst);
    if (rw_len != args->size) {
        printf("#>write data to dest_file failed[wanted:%d,actual:%ld]!\n", args->size, rw_len);
        goto __exit1;
    }

    ret = 0;
    printf("$>success!\n");

__exit1:
    fclose(fdst);
__exit0:
    if (fsrc)
        fclose(fsrc);
    free(buf);

    return ret;
}


DECLARE_LONG_OPTIONS(padding) = {
    {"help",        no_argument,         NULL, 'h'},
    {"input",       required_argument,   NULL, 'i'},
    {"padval",      required_argument,   NULL, 'p'},
    {"start",       required_argument,   NULL, 'b'},
    {"size",        required_argument,   NULL, 's'},
    {"output",      required_argument,   NULL, 'o'},
    {0,             0,                   0,    0  },
};

DECLARE_FUNC_VARIABLES(padding, "hi:p:b:s:o:", "padding a file with specific value," \
    "from the specificed start address to the specificed end address.");

void padding_helper(FILE *s, struct function *self)
{
    fprintf(s, "usage  : ./image+ --padding -i INPUT [-p 0xFF/0x00] -b BASE_ADDR -s SIZE -o OUTPUT\n");
    fprintf(s, "      -h --help                             show this usage.\n");
    fprintf(s, "      -i                                    specific the input file.\n");
    fprintf(s, "      -p [optional,default:0x00]            specific the padding value.\n");
    fprintf(s, "      -b [--tail or number]                 specific the base address,can use --tail.\n");
    fprintf(s, "      -s                                    specific the size of padding data.\n");
    fprintf(s, "      -o [optional,default:padding_out.bin] specific the output file name.\n");
}

int padding_parse_option(int argc, char **argv, struct arguments *args)
{
    struct function *self = (struct function *)args->owner;
    const char *const s_options = self->short_options;
    const struct option *l_options = self->long_options;
    int c, option_index;
    uint32_t padding = 0;

    if (argc < 3) {
        printf("invalid arguments!\n");
        padding_helper(stdout, self);
        exit(-1);
    }

    while (1) {
        c = getopt_long(argc, argv, s_options, l_options, &option_index);
        if (c == -1)    /*all options are analyse done*/
            break;

        switch(c) {
        case 'h':
            padding_helper(stdout, self);
            exit(0);

        case 'i':
            args->input = optarg;
            continue;

        case 'p':
            if (str2word(optarg, &padding) < 0) {
                printf("#>invalid padding value:%s\n", optarg);
                exit(-1);
            }
            args->private = padding;
            continue;

        case 'b':
            if (!strcmp(optarg, "--tail")) {
                args->string = "--tail";
            } else {
                if (str2word(optarg, &args->base_address) < 0) {
                    printf("#>invalid base address:%s\n", optarg);
                    exit(-1);
                }
            }
            continue;

        case 's':
            if (str2word(optarg, &args->size) < 0) {
                printf("#>invalid size:%s\n", optarg);
                exit(-1);
            }
            continue;

        case 'o':
            args->output = optarg;
            continue;

        default:
            break;
        }
    }

    if (!args->input) {
        printf("#>no input file specificed!\n");
        exit(-1);
    }

    if (access(args->input, 0)) {
        printf("#>configure file %s is no access!\n", args->input);
        exit(-1);
    }

    if (!args->output)
        args->output = "./output/padding.bin";

    if (args->size <= 0) {
        printf("#>file size is not specificed!\n");
        exit(-1);
    }

    show_arguments(args);
    return 0;
}

int padding_proc(struct arguments *args)
{
    FILE *fsrc, *fdst;
    unsigned char *buf;
    unsigned char pading = args->private & 0xFF;
    size_t rw_len, fsize, new_size;
    uint32_t start_addr;
    int ret = -1;

    fsrc = fopen(args->input, "rb");
    assert(fsrc != NULL);
    fdst = fopen(args->output, "wb+");
    assert(fdst != NULL);

    fsize = __get_fsize(fsrc);
    if (!(strcmp(args->string, "--tail")))
        start_addr = (uint32_t)fsize;
    else
        start_addr = args->base_address;
    new_size = start_addr + args->size;
    if (new_size <= fsize)
        new_size = fsize;

    buf = malloc(new_size);
    if (!buf) {
        printf("#>malloc %ldBytes failed!\n", new_size);
        goto __exit;
    }

    fseek(fsrc, 0, SEEK_SET);
    rw_len = fread(buf, 1, fsize, fsrc);
    if (rw_len != fsize) {
        printf("#>read data from src_file failed[wanted:%ld,actual:%ld]!\n", fsize, rw_len);
        goto __exit1;
    }
    memset(&buf[start_addr], pading, args->size);

    fseek(fdst, 0, SEEK_SET);
    rw_len = fwrite(buf, 1, new_size, fdst);
    if (rw_len != new_size) {
        printf("#>write data to dest_file failed[wanted:%ld,actual:%ld]!\n", new_size, rw_len);
        goto __exit1;
    }

    ret = 0;
    printf("$>success!\n");

__exit1:
    free(buf);
__exit:
    fclose(fsrc);
    fclose(fdst);

    return ret;
}

DECLARE_LONG_OPTIONS(resize) = {
    {"help",        no_argument,         NULL, 'h'},
    {"input",       required_argument,   NULL, 'i'},
    {"padval",      required_argument,   NULL, 'p'},
    {"size",        required_argument,   NULL, 's'},
    {"output",      required_argument,   NULL, 'o'},
    {0,             0,                   0,    0  },
};

DECLARE_FUNC_VARIABLES(resize, "hi:p:s:o:", "resize a file to the specific size," \
    "if new size is larger, the inscreased size is padded with target padding value if it's " \
    "specificed, else cut the file.");

void resize_helper(FILE *s, struct function *self)
{
    fprintf(s, "usage  : ./image+ --resize -i INPUT [-p 0xFF/0x00] -s SIZE [-p 0xFF/0x00] -o OUTPUT\n");
    fprintf(s, "      -h --help                             show this usage.\n");
    fprintf(s, "      -i                                    specific the input file.\n");
    fprintf(s, "      -p [optional,default:0x00]            specific the padding value.\n");
    fprintf(s, "      -s                                    specific the size of padding data.\n");
    fprintf(s, "      -o [optional,default:padding_out.bin] specific the output file name.\n");
}

int resize_parse_option(int argc, char **argv, struct arguments *args)
{
    struct function *self = (struct function *)args->owner;
    const char *const s_options = self->short_options;
    const struct option *l_options = self->long_options;
    int c, option_index;
    uint32_t padding = 0;

    if (argc < 3) {
        printf("invalid arguments!\n");
        resize_helper(stdout, self);
        exit(-1);
    }

    while (1) {
        c = getopt_long(argc, argv, s_options, l_options, &option_index);
        if (c == -1)    /*all options are analyse done*/
            break;

        switch(c) {
        case 'h':
            resize_helper(stdout, self);
            exit(0);

        case 'i':
            args->input = optarg;
            continue;

        case 'p':
            if (str2word(optarg, &padding) < 0) {
                printf("#>invalid padding value:%s\n", optarg);
                exit(-1);
            }
            args->private = padding;
            continue;

        case 's':
            if (str2word(optarg, &args->size) < 0) {
                printf("#>invalid size:%s\n", optarg);
                exit(-1);
            }
            continue;

        case 'o':
            args->output = optarg;
            continue;

        default:
            break;
        }
    }

    if (!args->input) {
        printf("#>no input file specificed!\n");
        exit(-1);
    }

    if (!args->output) {
        printf("#>no output file specificed!\n");
        exit(-1);
    }

    if (access(args->input, 0)) {
        printf("#>configure file %s is no access!\n", args->input);
        exit(-1);
    }

    if (args->size <= 0) {
        printf("#>file size is not specificed!\n");
        exit(-1);
    }

    show_arguments(args);
    return 0;
}

int resize_proc(struct arguments *args)
{
    FILE *fsrc, *fdst;
    unsigned char *buf;
    unsigned char pading = args->private & 0xFF;
    size_t rw_len, fsize;
    uint32_t copy_size;
    int ret = -1;

    fsrc = fopen(args->input, "rb");
    assert(fsrc != NULL);
    fdst = fopen(args->output, "wb+");
    assert(fdst != NULL);

    fsize = __get_fsize(fsrc);
    buf = malloc(args->size);
    if (!buf) {
        printf("#>malloc %dBytes failed!\n", args->size);
        goto __exit;
    }

    /*read the original data to buffer*/
    fseek(fsrc, 0, SEEK_SET);
    copy_size = (args->size > fsize) ? fsize : args->size;
    rw_len = fread(buf, 1, copy_size, fsrc);
    if (rw_len != copy_size) {
        printf("#>read data from src_file failed[wanted:%d,actual:%ld]!\n", copy_size, rw_len);
        goto __exit1;
    }

    /*padding the extended size with padding value*/
    if (args->size > fsize)
        memset(&buf[fsize], pading, args->size - fsize);

    /*write data to file*/
    fseek(fdst, 0, SEEK_SET);
    rw_len = fwrite(buf, 1, args->size, fdst);
    if (rw_len != args->size) {
        printf("#>write data to dest_file failed[wanted:%d,actual:%ld]!\n", args->size, rw_len);
        goto __exit1;
    }

    ret = 0;
    printf("$>success!\n");

__exit1:
    free(buf);
__exit:
    fclose(fsrc);
    fclose(fdst);

    return ret;
}

DECLARE_LONG_OPTIONS(combine) = {
    {"help",        no_argument,         NULL, 'h'},
    {"input",       required_argument,   NULL, 'i'},
    {"output",      required_argument,   NULL, 'o'},
    {0,             0,                   0,    0  },
};

DECLARE_FUNC_VARIABLES(combine, "hi:o:", "combine the listed binary files to one file.");

void combine_helper(FILE *s, struct function *self)
{
    fprintf(s, "usage  : ./image+ --combine -i FILE1 [FILE2 FILE3...] -o OUTPUT\n");
    fprintf(s, "      -h --help                             show this usage.\n");
    fprintf(s, "      -i                                    specific the input file(s).\n");
    fprintf(s, "      -o [optional,default:padding_out.bin] specific the output file name.\n");
}

struct finfo {
    char *name;
    FILE *fp;
    size_t fsize;
};

struct flist {
    uint32_t count;
    struct finfo list[MAX_INPUT_FILE_COUNT];
};

static struct flist g_ftable = {0, {{NULL, NULL, 0}, },};

static void __init_flist(void)
{
    memset(&g_ftable, 0, sizeof(g_ftable));
}

static void show_io_files(struct arguments *args)
{
    struct flist *ptbl = &g_ftable;
    struct finfo *pi = ptbl->list;
    int i;

    printf("input :\n");
    for (i = 0; i < ptbl->count; i++, pi++)
        printf("file: %s\n", pi->name);
    printf("output: %s\n", args->output);
}

int combine_parse_option(int argc, char **argv, struct arguments *args)
{
    struct function *self = (struct function *)args->owner;
    const char *const s_options = self->short_options;
    const struct option *l_options = self->long_options;
    int c, option_index;
    struct flist *ptbl = &g_ftable;
    struct finfo *pi = ptbl->list;
    unsigned char last = 0xFF;
    int i;

    if (argc < 3) {
        printf("invalid arguments!\n");
        resize_helper(stdout, self);
        exit(-1);
    }

    __init_flist();
    while (1) {
        c = getopt_long(argc, argv, s_options, l_options, &option_index);
        if (c == -1)    /*all options are analyse done*/
            break;

        switch(c) {
        case 'h':
            resize_helper(stdout, self);
            exit(0);

        case 'i':
            ptbl->count++;
            pi->name = optarg;
            pi++;
            if (ptbl->count > MAX_INPUT_FILE_COUNT) {
                printf("#>input file count overfollow!\n");
                break;
            }
            last = 'i';
            continue;

        case 'o':
            args->output = optarg;
            last = 'o';
            continue;

        default:
            if ((last == 'i') || (last == 'D')) {
                ptbl->count++;
                pi->name = optarg;
                pi++;
                if (ptbl->count > MAX_INPUT_FILE_COUNT) {
                    printf("#>input file count overfollow!\n");
                    break;
                }
                last = 'D';
                continue;
            }
            break;
        }
    }

    if (!ptbl->count) {
        printf("#>no input file specificed!\n");
        exit(-1);
    }

    if (!args->output) {
        printf("#>no output file specificed!\n");
        exit(-1);
    }

    pi = ptbl->list;
    for (i = 0; i < ptbl->count; i++, pi++) {
        if (access(pi->name, 0)) {
            printf("#>configure file %s is no access!\n", pi->name);
            exit(-1);
        }
    }

    show_io_files(args);
    return 0;
}

int combine_proc(struct arguments *args)
{
    struct flist *ptbl = &g_ftable;
    struct finfo *pi = ptbl->list;
    size_t rw_len, total_size = 0;
    FILE *fdst;
    unsigned char *buf;
    int i,ret = -1;

    /*open all files and get all files's total size*/
    for (i = 0; i < ptbl->count; i++, pi++) {
        pi->fp = fopen(pi->name, "rb");
        assert(pi->fp != NULL);
        pi->fsize = __get_fsize(pi->fp);
        total_size += pi->fsize;
    }

    /*malloc buffer*/
    buf = malloc(total_size);
    if (!buf) {
        printf("#>malloc %ld Bytes failed!\n", total_size);
        goto __exit0;
    }

    /*read each file data to buffer*/
    pi = ptbl->list;
    total_size = 0;

    for (i = 0; i < ptbl->count; i++, pi++) {
        fseek(pi->fp, 0, SEEK_SET);
        rw_len = fread(&buf[total_size], 1, pi->fsize, pi->fp);
        if (rw_len != pi->fsize) {
            printf("#>read data from src_file failed[wanted:%ld,actual:%ld]!\n", pi->fsize, rw_len);
            goto __exit1;
        }
        total_size += pi->fsize;
    }

    /*write data to file*/
    fdst = fopen(args->output, "wb+");
    assert(fdst != NULL);

    fseek(fdst, 0, SEEK_SET);
    rw_len = fwrite(buf, 1, total_size, fdst);
    if (rw_len != total_size) {
        printf("#>write data to dest_file failed[wanted:%ld,actual:%ld]!\n", total_size, rw_len);
        goto __exit2;
    }
    ret = 0;

__exit2:
    fclose(fdst);
__exit1:
    free(buf);
__exit0:
    pi = ptbl->list;
    for (i = 0; i < ptbl->count; i++, pi++)
        fclose(pi->fp);

    return ret;
}


