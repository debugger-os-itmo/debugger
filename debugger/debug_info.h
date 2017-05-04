//#pragma once
#ifndef DEBUG_INFO_H
#define DEBUG_INFO_H


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <assert.h>
#include <map>
#include <algorithm>
#include <stdexcept>


class debug_info {
    // from PCs to lines and filenames
    std::map<unsigned long long, std::pair<std::string, unsigned long long>> lines;
    // from lines to PCs
    std::map<std::string, std::map<unsigned long long, unsigned long long>> pcs;

    void map_lines_to_pc(Dwarf_Debug);

public:
    debug_info(const std::string &);
    std::pair<std::string, unsigned long long> line_by_pc(unsigned long long);
    unsigned long long pc_by_line(const std::string &, unsigned long long);
    unsigned long long pc_by_line(unsigned long long);
    unsigned long long find_next_line(unsigned long long);
};

#endif //DEBUG_INFO_H






