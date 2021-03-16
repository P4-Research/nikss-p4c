#ifndef P4C_COMMON_H
#define P4C_COMMON_H

struct tuple_list_key {
    // we store 20 bits (4 + 8 + 8) in unsigned int32
    __u32 mask;
};

struct tuple_list_value {
    __u32 tuple_id;
    __u32 next_tuple_mask;
};

struct tuple_key = {
__u8 field1;
__u8 field2;
__u8 field3;
};

struct tuple_value {
    __u32 action;
};

#endif //P4C_COMMON_H
