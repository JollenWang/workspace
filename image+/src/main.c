/********************************************************************************************
* file      : main.c
* purpose   : binary file editor main source file
* author    : Jollen Wang
* version   : 1.0
* date      : 2017-03-24
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
#include <libgen.h>

#include "func.h"
#include "main.h"


//-------------------------------------------------------------------------------------------

#define MAX_IMG_SIZE        (1024*1024*16)
#define IMG_INFO_MAGEIC     0x494D4728

const char *VERSION = "v1.0.0";

static struct function f_lst[] = {
    REGISTER_FUNC(0, "read2file",   read2file,  'R' + 'D'),
    REGISTER_FUNC(1, "create",      create,     'C' + 'R' + 'E' + 'A' + 'T'),
    REGISTER_FUNC(2, "padding",     padding,    'P'),
    REGISTER_FUNC(3, "resize",      resize,     'R'),
    REGISTER_FUNC(4, "combine",     combine,    'C'),
    REGISTER_FUNC(5, "readval",     readval,    'R' + 'D' + 'V'),
    REGISTER_FUNC(6, "filesize",    filesize,   'F' + 'Z'),
/*
    {0,  "split",    "hi:o:b:s:", NULL, 'S',              common_porc, helper_func, "split file to specific size"},
    {2, "read2file", read2file_sopts, read2file_lopts, 'R'+'D', read2file_parse_option, read2file_proc, read2file_helper, read2file_comments},
    {3,  "replace",  "hi:o:b:s:", NULL, 'R'+'X',          common_porc, helper_func, "replace the content of a file"},
    {4,  "insert",   "hi:o:b:s:", NULL, 'I'+'N'+'S',      common_porc, helper_func, "insert data to a specific file"},
    {5,  "remove",   "hi:o:b:s:", NULL, 'R'+'M',          common_porc, helper_func, "remove data from a specific file"},
    {7,  "info",     "hi:o:b:s:", NULL, 'I',              common_porc, helper_func, "tell the size of a specific file"},
    {8,  "crc32",    "hi:o:b:s:", NULL, 'C'+'R'+'C'+32,   common_porc, helper_func, "calculate the CRC32 value of a specific size"},
    {9,  "crc16",    "hi:o:b:s:", NULL, 'C'+'R'+'C'+16,   common_porc, helper_func, "calculate the CRC16 value of a specific size"},
*/
    {-1,  NULL,      NULL,        NULL, 0,                NULL,        NULL,        NULL},
};

static void show_main_menu(FILE* s)
{
    struct function *f = f_lst;

    fprintf(s, "usage  : ./image+ [sub-function] [...]\n");
    fprintf(s, "      -h --help          show this usage.\n");
    fprintf(s, "      -v --version       show this image+'s verion.\n");
    while(f->caption) {
        fprintf(s, "      --%s        %s.\n", f->caption, f->comments);
        f++;
    }
}

static void show_version(void)
{
    printf("image+, binary file editor.\n");
    printf("version: %s,build @ %s %s.\r\n", VERSION, __DATE__, __TIME__);
}

static int get_func_by_value(int value)
{
    struct function *f = f_lst;

    while (f->caption) {
        if (f->key_value == value)
            return f->id;
        f++;
    }

    return -1;
}

#define __init_loption_structure(p, n, arg, flg, v)    do { \
    p->name = n; \
    p->has_arg = arg; \
    p->flag = flg; \
    p->val = v; \
}while(0)

static void init_loptions(struct option *l_options)
{
    struct option *o = l_options;
    struct function *f = f_lst;

    memset(l_options, 0, sizeof(struct option) * MAX_FUNC_SUPPORT_LIMIT);
    __init_loption_structure(o, "help", no_argument, NULL, 'h');
    o++;
    __init_loption_structure(o, "version", no_argument, NULL, 'v');
    o++;

    while(f->caption) {
        __init_loption_structure(o, f->caption, no_argument, NULL, f->key_value);
        f++;
        o++;
    }
}

static void pre_parse(int argc, char **argv, struct arguments *args)
{
    const char *const s_options = "hv";
    struct option l_options[MAX_FUNC_SUPPORT_LIMIT];
    int c, option_index;

    if (argc < 2) {
        printf("invalid arguments!\n");
        show_main_menu(stdout);
        exit(-1);
    }

    init_loptions(l_options);
    while (1) {
        c = getopt_long(argc, argv, s_options, l_options, &option_index);
        if (c == -1)    /*all options are analyse done*/
            break;

        switch(c) {
        case 'h':
            show_main_menu(stdout);
            exit(0);

        case 'v':
            show_version();
            exit(0);

        default:
            if (!args->operation) {
                args->func_id = get_func_by_value(c);
                if (args->func_id >= 0) {
                    args->operation = (char *)f_lst[args->func_id].caption;
                    return;
                }
            }
            continue;
        }
    }
}

int main(int argc, char **argv)
{
    struct arguments args;
    struct function *func;

    memset(&args, 0, sizeof(args));
    pre_parse(argc, argv, &args);
    if (!args.operation) {
        printf("#>no operation seleted!\n");
        return -1;
    }

    func = &f_lst[args.func_id];
    args.owner = func;
    func->parse_option(argc, argv, &args);
    func->proc(&args);

    return 0;
}

