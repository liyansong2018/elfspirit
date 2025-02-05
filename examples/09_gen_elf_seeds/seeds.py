import sys
import random
import os

class Edit:
    seed_num = 0
    def __init__(self, option, max_i, max_j, file):
        self.maxi = max_i       # row
        self.maxj = max_j       # clumn
        self.option = option    # [-H|S|P|B|D|R|I]
        self.file = file

    def run(self):
        for i in range(self.maxi):
            for j in range(self.maxj):
                # create new elf file
                new_file = self.file + "_" + self.option.strip("-") + "_" + "%03d" % Edit.seed_num
                cmd = "cp %s %s" % (self.file, new_file)
                os.system(cmd)
                Edit.seed_num = Edit.seed_num + 1
                # mutation
                cmd = "elfspirit edit %s -i %d -j %d -m %d %s" % (self.option, i, j, random.randint(1, 65535), new_file)
                os.system(cmd)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s %s %s elf_file" % (sys.argv[0], "[-H|S|P|B|D|R|I]", "row(optional)"))
        exit(0)
    elif len(sys.argv) == 3:
        num = 100
        file_name = sys.argv[2]
    else:
        num = sys.argv[2]
        file_name = sys.argv[3]

    if sys.argv[1] == "-H":
        header = Edit("-H", 13, 1, file_name)
        header.run()

    if sys.argv[1] == "-S":
        section = Edit("-S", 40, 10, file_name)
        section.run()

    if sys.argv[1] == "-P":
        segment = Edit("-P", 20, 8, file_name)
        segment.run()

    if sys.argv[1] == "-B":
        symtab = Edit("-B", num, 7, file_name)
        symtab.run()

    if sys.argv[1] == "-D":
        symtab = Edit("-D", num, 7, file_name)
        symtab.run()

    if sys.argv[1] == "-R":
        rela = Edit("-R", num, 7, file_name)
        rela.run()
    