#include <algorithm>
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <sstream>

#include <cstring>

#include <bpf/bpf.h>
#include <unistd.h>

#define MAX_MASKED_BITS 8
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

struct ternary_table_key_t
{
public:
    uint32_t key;

    unsigned int get_number_masked_bits()
    {
        unsigned int ret = 0;
        uint32_t tmp_key = ~(this->key);
        while (tmp_key)
        {
            ret += tmp_key & 1;
            tmp_key = tmp_key >> 1;
        }
        return ret;
    }

    ternary_table_key_t expand(const ternary_table_key_t & mask, unsigned int mask_value)
    {
        ternary_table_key_t result = *this;
        unsigned int mask_value_pos = 0, key_pos;
        result.key = result.key & mask.key;
        for (key_pos = 0; key_pos < sizeof(uint32_t) * 8; key_pos++)
        {
            // "0" means don't care, so skip "1"
            if ((mask.key & (1 << key_pos)) != 0)
                continue;

            if (mask_value & (1 << mask_value_pos))
                result.key = result.key | (1 << key_pos);
            else
                result.key = result.key & (~(1 << key_pos));
            mask_value_pos++;
        }

        return result;
    }

    // Convert string str to tuple (key, mask). Key will be set in the current object,
    // mask will be returned by this function.
    ternary_table_key_t str_to_key_mask(const std::string & str)
    {
        this->key = 0;
        ternary_table_key_t mask = {.key = ~((uint32_t) 0)};
        unsigned int pos = 0;
        for (auto iter = str.crbegin(); iter != str.crend(); ++iter, ++pos)
        {
            if (*iter == '1')
                this->key = this->key | (1 << pos);
            else if (*iter == '*')
                mask.key = mask.key & (~(1 << pos));
        }
        return mask;
    }

    bool operator<(const ternary_table_key_t & rhs) const
    {
        return this->key < rhs.key;
    }
};

struct ternary_table_entry_t
{
    uint32_t action_data;
};

typedef std::map<ternary_table_key_t, ternary_table_entry_t> ternary_table_t;

void parse_file_build_table(ternary_table_t & table, const std::string & filename);

void append_entry_to_table(ternary_table_t & table,
                           ternary_table_key_t & key,
                           ternary_table_key_t & key_mask,
                           ternary_table_entry_t & data);

void append_entry_to_table(ternary_table_t & table,
                           ternary_table_key_t & key,
                           ternary_table_entry_t & data);

int main()
{
    ternary_table_t builder;

    parse_file_build_table(builder, "expand_keys.txt");

    std::cout << "*** Table content (" << builder.size() << " entries): ***" << std::endl;
    for (auto iter = builder.begin(); iter != builder.end(); ++iter)
    {
        std::cout << iter->first.key << ": " << iter->second.action_data << std::endl;
    }

    if (builder.empty())
        return 0;

    // Now we have non-empty table, which must be send to the kernel space
    // eBPF party starts now!

    std::string map_filename = std::string(TC_GLOBAL_NS) + "/" + "ternary_table";
    std::cout << "Getting eBPF map: " << map_filename << std::endl;

    int fd = bpf_obj_get(map_filename.c_str());
    if (fd < 0)
    {
        std::cout << "Could not open map: " << std::strerror(errno) << std::endl;
        return 1;
    }

    for (auto iter = builder.begin(); iter != builder.end(); ++iter)
    {
        bpf_map_update_elem(fd, &(iter->first.key), &(iter->second.action_data), BPF_ANY);
    }

    close(fd);

    return 0;
}

void string_trim(std::string & str)
{
    // left trim
    str.erase(str.begin(),
              std::find_if(str.begin(), str.end(),
                           [](unsigned char c){ return !std::isspace(c); }));

    // right trim
    str.erase(std::find_if(str.rbegin(), str.rend(),
                           [](unsigned char c){ return !std::isspace(c); }).base(),
              str.end());
}

void parse_file_build_table(ternary_table_t & table, const std::string & filename)
{
    std::ifstream source(filename);
    std::string line;

    while(std::getline(source, line))
    {
        string_trim(line);
        if (line.length() < 1)
            continue;
        if (line[0] == '#')
            continue;
        std::cout << "Parsing line: " << line << std::endl;

        std::string key_str;
        std::istringstream iss(line);
        ternary_table_key_t key = {}, mask = {};
        ternary_table_entry_t entry = {};

        if (!(iss >> key_str >> entry.action_data))
        {
            std::cout << "Failed!" << std::endl;
            continue;
        }

        mask = key.str_to_key_mask(key_str);
        append_entry_to_table(table, key, mask, entry);
    }
}

void append_entry_to_table(ternary_table_t & table,
                           ternary_table_key_t & key,
                           ternary_table_key_t & key_mask,
                           ternary_table_entry_t & data)
{
    const unsigned int masked_bits = key_mask.get_number_masked_bits();
    if (masked_bits > MAX_MASKED_BITS)
    {
        std::cout << "Too much masked bits in key: " << key.key << "/" << key_mask.key << "!" << std::endl;
        return;
    }

    const unsigned int expanded_keys = 1 << masked_bits;
    std::cout << "Key " << key.key << "/" << key_mask.key << " will be expanded to " << expanded_keys << " entries" << std::endl;

    for (unsigned int i = 0; i < expanded_keys; i++)
    {
        auto new_key = key.expand(key_mask, i);
        append_entry_to_table(table, new_key, data);
    }
}

void append_entry_to_table(ternary_table_t & table,
                           ternary_table_key_t & key,
                           ternary_table_entry_t & data)
{
    // if entry already exists, do not replace it because it has higher priority
    if (table.count(key) > 0)
        return;

    table[key] = data;
}
