#include "debug_info.h"


namespace {
    Dwarf_Half tag;
    Dwarf_Error de;
    Dwarf_Attribute atp;
    Dwarf_Unsigned ret;

    void check_ret_value(int x, char const* msg) {
        if (x == DW_DLV_ERROR) {
            errx(EXIT_FAILURE, "dwarf_error: %s", msg);        
        }
    }
    void check_ret_value(int x) {
        check_ret_value(x, dwarf_errmsg(de));
    }

    std::string diename(const Dwarf_Die &die) {
        char *name;
        check_ret_value(dwarf_diename(die, &name, &de));
        return std::string(name);
    }

    Dwarf_Half dietag(const Dwarf_Die &die) {
        check_ret_value(dwarf_tag(die, &tag, &de));
        return tag;
    }
    std::string tagname(const Dwarf_Half &tagin) {
        char const* tagname;
        check_ret_value(dwarf_get_TAG_name(tagin, &tagname), "Error while getting tag name");
        return std::string(tagname);
    }

    std::string dietagname(const Dwarf_Die &die) {
        return tagname(dietag(die));
    }

    Dwarf_Attribute dieattr(const Dwarf_Die &die, const Dwarf_Half &attr) {
        check_ret_value(dwarf_attr(die, attr, &atp, &de));
        return atp;
    }


    std::size_t dwarfsizet(const Dwarf_Attribute &atpin) {
        check_ret_value(dwarf_formudata(atpin, &ret, &de));
        return ret;
    }

}

std::map<std::string, std::pair<std::vector<char>, size_t>> variables;



void dfs(const Dwarf_Debug &dbg, Dwarf_Die die, std::string indent) {
    Dwarf_Die die0;
    Dwarf_Error de;
    Dwarf_Half tag = dietag(die);

    if (tag == DW_TAG_variable) {
        std::cout << "name=" << indent + diename(die) << " tag=" << dietagname(die) << ' ';
        std::cout << "line #" << dwarfsizet(dieattr(die, DW_AT_decl_line)) << " ";        

        Dwarf_Off offset;
        Dwarf_Die child_die;
        auto type_attr = dieattr(die, DW_AT_type);
        dwarf_global_formref(type_attr,&offset,NULL);
        dwarf_offdie_b(dbg, offset, 1,&child_die,NULL);
        auto child_tag = dietag(child_die);
        if (child_tag == DW_TAG_base_type) {
            auto location_attr = dieattr(die, DW_AT_location);

            Dwarf_Unsigned retlen;
            Dwarf_Ptr retpr;
            Dwarf_Error de;
            dwarf_formexprloc(location_attr, &retlen, &retpr, &de);
            std::vector<char> temp_vector((char*)retpr, ((char*)retpr) + retlen);
            dwarf_bytesize(child_die, &retlen, &de);

            variables[indent + diename(die)] = {temp_vector, retlen};
        }

        std::cout << "\n";
    } else if (tag == DW_TAG_subprogram) {
        indent += diename(die) + ":";
    }

    if (dwarf_child(die, &die0, &de) != DW_DLV_OK) {
        return;
    }

    do {
        die = die0;
        dfs(dbg, die, indent);

        if (dwarf_siblingof(dbg, die, &die0, &de) == DW_DLV_ERROR)
            errx(EXIT_FAILURE, "dwarf_siblingof: %s",
            dwarf_errmsg(de));
    } while (die0 != NULL && die0 != die);

}

void debug_info::extract(const Dwarf_Debug &dbg) {
    Dwarf_Off aboff;
    Dwarf_Error de;
    Dwarf_Unsigned next_cu_header;
    Dwarf_Die die0;

    if (dwarf_next_cu_header(dbg, NULL, NULL, &aboff, NULL, &next_cu_header, &de) !=  DW_DLV_OK) 
        errx(EXIT_FAILURE, "dwarf_next_cu_header: %s", dwarf_errmsg(de));

    if (dwarf_siblingof(dbg, NULL, &die0, &de) != DW_DLV_OK)
        errx(EXIT_FAILURE, "dwarf_siblingof: %s", dwarf_errmsg(de));
    
    dfs(dbg, die0, "");
}

std::pair<std::vector<char>, std::size_t> debug_info::get_address_of_variable(std::string var_name) {
    auto it = variables.find(var_name);
    static std::vector<char> empty;
    static auto empty_pair = std::make_pair(empty, (size_t) 0);
    return it == variables.end() ? empty_pair : it->second;
}

debug_info::debug_info(const std::string &exec_name) {
    Dwarf_Debug dbg = 0;
    Dwarf_Error err;
    const char* progname;
    int fd = -1;

    progname = exec_name.c_str();
    if ((fd = open(progname, O_RDONLY)) < 0) {
        throw std::invalid_argument("Failed to open executable " + exec_name);
    }

    if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg, &err) != DW_DLV_OK) {
        close(fd);
        throw std::runtime_error("Failed DWARF initialization\n");
    }
    else {

        map_lines_to_pc(dbg);
        extract(dbg);

        close(fd);
        printf("PCs\n");
        for (auto e1 : pcs) {
            printf("file %s\n", e1.first.c_str());
            for (auto e : e1.second)
                printf("PC %#llx, line %llu\n", e.second, e.first);
        }
        for (auto &x : variables) {
            std::cout << x.first << "\n";
        }

        if (dwarf_finish(dbg, &err) != DW_DLV_OK) {
            fprintf(stderr, "Failed DWARF finalization\n");
        }

    }
}

void debug_info::map_lines_to_pc(const Dwarf_Debug &dbg) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die;//, child_die;
    Dwarf_Signed i;

    while(1) {
        /* Find compilation unit header */
        int ret;
        if ((ret = dwarf_next_cu_header(
                    dbg,
                    &cu_header_length,
                    &version_stamp,
                    &abbrev_offset,
                    &address_size,
                    &next_cu_header,
                    &err)) == DW_DLV_ERROR) {
            fprintf(stderr, "Error reading DWARF cu header\n");
        }
        if (ret == DW_DLV_NO_ENTRY)
            break;

        /* Expect the CU to have a single sibling - a DIE */
        if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR)
            fprintf(stderr, "Error getting sibling of CU\n");
        printf("Lines: \n");
        Dwarf_Signed cnt;
        Dwarf_Line *linebuf;
        int sres;
        if ((sres = dwarf_srclines(cu_die, &linebuf, &cnt, &err)) != DW_DLV_OK)
            fprintf(stderr, "Error in dwarf_srclines\n");
        char *src = NULL;
        char *prev_src = NULL;
        for (i = 0; i < cnt; ++i) {
            Dwarf_Line line = linebuf[i];
            Dwarf_Addr addr;
            Dwarf_Unsigned no;
            if (dwarf_linesrc(line, &src, &err) != DW_DLV_OK)
                fprintf(stderr, "Error in dwarf_linesrc\n");
            if (!prev_src || strcmp(src, prev_src))
                printf("file %s\n", src);
            if (dwarf_lineno(line, &no, &err) != DW_DLV_OK)
                fprintf(stderr, "Error in dwarf_lineno\n");
            printf("line number %llu, ", no);
            if (dwarf_lineaddr(line, &addr, &err) != DW_DLV_OK)
                fprintf(stderr, "Error in dwarf_lineaddr\n");

            printf("pc %#8llx\n", addr);
            lines[addr] = std::make_pair(std::string(src), no);
            auto iter = pcs[std::string(src)].find(no);
            if (iter != pcs[std::string(src)].end())
                iter->second = std::min(iter->second, addr);
            else
                pcs[std::string(src)][no] = addr;
            dwarf_dealloc(dbg, linebuf[i], DW_DLA_LINE);
            if (prev_src)
                dwarf_dealloc(dbg, prev_src, DW_DLA_STRING);
            prev_src = src;
        }
        dwarf_dealloc(dbg, linebuf, DW_DLA_LIST);
        dwarf_dealloc(dbg, prev_src, DW_DLA_STRING);
    }

}


std::pair<std::string, unsigned long long> debug_info::line_by_pc(unsigned long long pc) {
    return lines.at(pc);
}

unsigned long long debug_info::pc_by_line(const std::string &src, unsigned long long line) {
    return pcs.at(src).at(line);
}

unsigned long long debug_info::pc_by_line(unsigned long long line) {
    return (pcs.begin()->second).at(line);
}

unsigned long long debug_info::find_next_line(unsigned long long line)
{
    auto it = (pcs.begin()->second).end();
    if ((pcs.begin()->second).find(line) == --it)
        return 0;
    auto ans = line + 1;
    while (pcs.begin()->second.find(ans) == pcs.begin()->second.end())
        ans++;
    return ans;
}
