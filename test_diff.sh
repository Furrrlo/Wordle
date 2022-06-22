#/bin/bash

set -euxo pipefail
gcc -DDEBUG -DPRINT_INPUT -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=address -g -o slow.out slow.c
gcc -DDEBUG -DPRINT_INPUT -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=address -g -o solution.out solution.c
/bin/time -v ./slow.out < $1 > slow_output.txt
/bin/time -v ./solution.out < $1 > output.txt
diff output.txt slow_output.txt > diff.txt
