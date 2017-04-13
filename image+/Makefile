
SRC_DIR := ./src
INCLUDES := ./src

sources := $(shell find $(SRC_DIR) -name "*.c")

#sources = ./src/main.c ./src/func.c

target = image+
CFLAGS = -Wall -O0 -g -I. -I./src
dirs = main

all : $(target) $(emulator) 

# $^表示所有通过目录搜索得到的依赖文件的完整路径名列表
# $<表示规则中通过目录搜索得到依赖文件列表的第一个文件
# $@表示规则的目标

$(target) : $(sources) 
	@$(CC) $^ $(CFLAGS) -o $@ 

clean : 
	@rm $(target) -rf
