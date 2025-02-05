import sys, os
import subprocess

def traverse_files(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_list.append(os.path.join(root, file))
    return file_list

def run(bin, dir):
    print("bin: %s, dir: %s" % (bin, dir))
    files = traverse_files(dir)
    all = len(files)
    count = 0
    for file in files:
        cmd = bin + " " + file
        try:
            result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            # 127: return, 132: illegal hardware instruction, 135: bus error
            if e.returncode not in [127, 132, 135]:
                count += 1
                print(f"Error: {e}")
    print("[%d in %d]" % (count, all))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s %s %s" % (sys.argv[0], "binary", "crash_dir"))
        exit(0)
        
    run(sys.argv[1], sys.argv[2])