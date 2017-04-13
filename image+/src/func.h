/********************************************************************************************
* file      : 
* purpose   : 
* author    : Jollen Wang
* version   : 1.0
* date      :
* history   :
********************************************************************************************/

#ifndef __FUNC_H__
#define __FUNC_H__

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>
#include <libgen.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define MAX_CONFIG_CMDLINE_LIMIT    32
#define MAX_INPUT_FILE_COUNT        32
#define MAX_FILE_NAME_LENGTH        64

#define REGISTER_FUNC(id, caption, func, key)   { \
    id, caption, func##_sopts, func##_lopts, key, func##_parse_option, func##_proc, func##_helper, func##_comments, \
}

#define DECLARE_LONG_OPTIONS(func)  struct option func##_lopts[]

#define DECLARE_FUNC_VARIABLES(func, s_opts, comments) \
    const char func##_sopts[] = s_opts; \
    const char func##_comments[] = comments;

#define DECLARE_FUNC(func) \
    extern struct option func##_lopts[]; \
    extern const char func##_sopts[]; \
    extern const char func##_comments[]; \
    int func##_parse_option(int argc, char **argv, struct arguments *args); \
    int func##_proc(struct arguments *args); \
    void func##_helper(FILE *s, struct function *self);

struct arguments {
    char *input;
    char *output;
    char *operation;
    int func_id;
    uint32_t base_address;
    uint32_t size;
    uint32_t private;
    char *string;
    void *owner;
};

struct function {
    int id;
    char *caption;
    const char *short_options;
    struct option *long_options;
    int key_value;
    int (*parse_option)(int argc, char **argv, struct arguments *args);
    int (*proc)(struct arguments *arg);
    void (*helper)(FILE *s, struct function *self);
    const char *comments;
};

int str2word(char *str, uint32_t *word);

/*declare your function here*/
DECLARE_FUNC(read2file);
DECLARE_FUNC(create);
DECLARE_FUNC(padding);
DECLARE_FUNC(resize);
DECLARE_FUNC(combine);


#ifdef  __cplusplus
}
#endif

#endif //__FUNC_H__


