fc = open("calls.txt", "r")
fs = open("source.txt", "r")

call_lines = fc.readlines()
source_lines = fs.readlines()

call_source_map = {}
for line in call_lines:
    for sline in source_lines:
        if len(sline.split(" ")[-1].strip()) > 0:
            hex_str = sline.split(" ")[-1].strip()
            if int(hex_str[2:], 16) > int(line, 16):
                break
            if int(hex_str[2:], 16) == int(line, 16):
                call_source_map[line.strip()] = sline.strip()
                break
            call_source_map[line.strip()] = sline.strip()

for key, value in call_source_map.items():
    print(key, "->", value)

fs.close()
fc.close()
