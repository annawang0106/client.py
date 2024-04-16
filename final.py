import os
import re
import json
import chardet
from datetime import datetime

output_dict = {}  # 用於儲存結果的字典

c_cpp_standard_library = ["assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h", "inttypes.h", "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdalign.h", "stdarg.h", "stdatomic.h", "stdbit.h", "stdbool.h", "stdckdint.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h", "stdnoreturn.h", "string.h", "tgmath.h", "threads.h", "time.h", "uchar.h", "wchar.h", "wctype.h", "concepts", "coroutine", "any", "bitset", "chrono", "compare", "csetjmp", "csignal", "cstdarg", "cstddef", "cstdlib", "ctime", "expected", "functional", "initializer_list", "optional", "source_location", "tuple", "type_traits", "typeindex", "typeinfo", "utility", "variant", "version", "memory", "memory_resource", "new", "scoped_allocator", "cfloat", "cinttypes", "climits", "cstdint", "limits", "stdfloat", "cassert", "cerrno", "exception", "stacktrace", "stdexcept", "system_error", "cctype", "charconv", "cstring", "cuchar", "cwchar", "cwctype", "format", "string", "string_view", "array", "deque", "flat_map", "flat_set", "forward_list", "list", "map", "mdspan", "queue", "set", "span", "stack", "unordered_map", "unordered_set", "vector", "iterator", "generator", "ranges", "algorithm", "execution", "bit", "cfenv", "cmath", "complex", "numbers", "numeric", "random", "ratio", "valarray", "clocale", "codecvt", "locale", "text_encoding", "cstdio", "fstream", "iomanip", "ios", "iosfwd", "iostream", "istream", "ostream", "print", "spanstream", "sstream", "streambuf", "strstream", "syncstream", "filesystem", "regex", "atomic", "barrier", "condition_variable", "future", "hazard_pointer", "latch", "mutex", "rcu", "semaphore", "shared_mutex", "stop_token", "thread", "fenv.h", "inttypes.h", "uchar.h", "wchar.h", "stdatomic.h", "ccomplex", "complex.h", "ctgmath", "tgmath.h", "ciso646", "cstdalign", "cstdbool", "stdalign.h"]

file = open('sample.sbom.json', 'r', encoding='utf-8')
data = json.load(file)
current_timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
data['metadata']['timestamp'] = current_timestamp

#path = input("請輸入路徑:")

#for root, dirs, files in os.walk(path):
for root, dirs, files in os.walk('./sample_files/'):
    for file in files:
        file_path = os.path.join(root, file)

        file_content = []  # 用 list 儲存第三方 lib
        file_content_makefile = []
        with open(file_path, 'rb') as f:  # 以二進位模式打開文件
            result = chardet.detect(f.read())  # 檢測字符編碼
        encoding = result['encoding']
        with open(file_path, 'r', encoding=encoding,errors='ignore') as f:
            lines = f.readlines()
            for line in lines:  # 讀取檔案內容
                match = re.search(r'#include\s+["<](.+?)[>"]', line)  # 使用正規表達式擷取引號中的內容
                matches_library = re.finditer(r'\s+-l\s*(\S+)', line)
                if match:
                    included_file = match.group(1)
                    if included_file not in c_cpp_standard_library:
                        file_content.append(included_file)
                if matches_library:
                    for match_library in matches_library:
                        library_name = match_library.group(1)
                        if library_name not in c_cpp_standard_library:
                            file_content_makefile.append(library_name)
        
        #file = open('sample.sbom.json', 'r', encoding='utf-8')
        #data = json.load(file)

        for x in file_content:
            tmp = {'type': 'file', 'name': x}
            if tmp not in data['components']:
                data['components'].append(tmp)
        for y in file_content_makefile:
            tmp = {'type': 'library', 'name': y}
            if tmp not in data['components']:
                data['components'].append(tmp)
        #print(data)

with open('final.sbom.json', 'w', encoding='utf-8') as file:
    json.dump(data, file, ensure_ascii=False, indent=4)


        #if file_content:
            #output_dict[file_path] = file_content

#with open('library.json', 'w', encoding='utf-8') as file:
    #json.dump(output_dict, file, ensure_ascii=False, indent=4)


