Uses gcc specific extensions and bad code in general.

- array_list.c uses a big-ass list and normally filters it, but it exceeeds in time complexity.
- word_tree.c stores each character of the given alphabeth as a tree node and filters by first copying to a 
  second tree. Exceeds in space complecity.
- single_word_tree.c is the same as the above, but keeps 1 single tree and filters it each time it has to
  print or calculate its size. Still exceeds in space complexity. 

## Grading

UpTo18 test uses between 163.840 and 204.800 test strings of 5 characters each, for 15 games 
(found by tinkering with the array_list size) with 20 re-insertions (+inserisci_inizio).

In some tests, input is messed up and doesn't respect what's indicated in the requisites, i.e. 
characters out of the given alphabeth, or instruction given at the wrong time (in particular, I think it's in the UpTo30).

This, for example, is apparently valid:
```
5
39rw7
_28Zo
wYx6_
56j-U
mUO3f
QI_9l
+inserisci_inizio
XYkRe
gJyPe
gJyPp
XJyRe
_JkPp
+inserisci_fine
+nuova_partita
``` 

## Testing

```
./a.out < tests/slide.txt > output.txt
diff output.txt tests/slide.output.txt
```

## Compiling

For testing

`gcc -DDEBUG -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=address -g <input>.c` 

For grading

`gcc -DEVAL -Wall -Werror -std=gnu11 -O2 -pipe -static -s <input>.c -lm`
