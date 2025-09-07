import json

def print_syscalls(filename, array_name):
    jsondata = open(filename);
    data = json.load(jsondata);
    dict = {}

    for func in data["syscalls"]:
        dict[func["index"]] = (func["name"], func["signature"]);
    print(f'struct syscall_s {array_name}[] = ', end=""); print("{");
    for i in range(list(dict)[-1] + 1):
        if i in dict:
            print("\t{");
            print(f'\t\t"{dict[i][0]}", {len(dict[i][1])},');
            print("\t\t\t{");
            for s in dict[i][1]:
                words = s.split();
                if (words[-1][0] == '*'):
                    if ("name" in words[-1] and "char" in words):
                        print(f'\t\t\t\tSTR,');
                    else:
                        print(f'\t\t\t\tPTR,');
                elif (words[0] == "unsigned"):
                    print(f'\t\t\t\tUINT,');
                else:
                    print(f'\t\t\t\tINT,');
            print("\t\t\t}");
            print("\t},");
        else:
            print("\t{0, 0, {}},");
    print("};");


print("#ifndef FT_SYSCALLS_H");
print("# define FT_SYSCALLS_H");
print("enum arg_type_e {STR, PTR, UINT, INT};");
print("struct syscall_s { const char* name; unsigned int arg_count; enum arg_type_e args[6]; };")
print();
print_syscalls("syscalls.json", "syscalls64");
print();
print_syscalls("syscalls32.json", "syscalls32");
print("#endif");
