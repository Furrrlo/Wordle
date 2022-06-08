Uses gcc specific extensions and bad code in general.

- array_list.c uses a big-ass list and normally filters it, but it exceeeds in time complexity.
- word_tree.c stores each character of the given alphabeth as a tree node and filters by first copying to a 
  second tree. Exceeds in space complecity.
- single_word_tree.c is the same as the above, but keeps 1 single tree and filters it each time it has to
  print or calculate its size. Still exceeds in space complexity. 

## Grading

UpTo18 test uses between 163.840 and 204.800 test strings of 5 characters each 
(found by tinkering with the array_list size).

## Testing

```
./a.out < tests/slide.txt > output.txt
diff output.txt tests/slide.output.txt
```

## Compiling

For testing

`gcc -DDEBUG -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=address -g <input>.c` 

For grading

`gcc -DEVAL -Wall -Werror -std=gnu11 -O2 -pipe -static -s -o <input>.c -lm`
