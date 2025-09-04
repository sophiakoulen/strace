import json
jsondata = open("syscalls32.json");
data = json.load(jsondata);

dict = {}

for func in data["syscalls"]:
    dict[func["index"]] = func["name"];

print("const char* syscalls[] = {");
for i in range(list(dict)[-1] + 1):
    if i in dict:
        print(f'\t"{dict[i]}",');
    else:
        print("\t0,");
print("};");
