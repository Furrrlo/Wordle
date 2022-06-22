Uses gcc specific extensions and bad code in general.

- [ArrayList](../c267ccf06c604bd54f5e1df870a4347ee2184fc9/array_list.c): uses a big-ass list and normally filters it, but it exceeeds in time complexity.
- [Two naive tries](../c267ccf06c604bd54f5e1df870a4347ee2184fc9/word_tree.c) stores each character of the given alphabeth as a tree node and filters by first copying to a 
  second tree. Exceeds in space complexity. It's literally massive and wastes ton of space.
- [Naive trie](../c267ccf06c604bd54f5e1df870a4347ee2184fc9/single_word_tree.c) is the same as the above, but keeps 1 single tree and filters it each time it has to
  print or calculate its size. Still exceeds in space complexity. 
- [Red-black trie](../78ad7d16bb684987ad5a8907cd8a8fb2cee8eb5a/single_word_tree_red_black.c) trie implementation where each node keeps children in a red-black tree. Still 
  exceeds in space complexity.
- [Overengineered red-black trie](../cea2dc8d8729fe807d3a8496d40e8a4990ae5d10/single_word_tree_red_black.c) same as above, but optionally expands nodes to keep track of 
  undeleted nodes in order to iterate less. Gets killed by bad cache locality and branch missprediction.
- [ArrayList trie](./main/solution.c) working one, tries to avoid branch missprediction and cache misses in the hot loop. Got me 30L, so I'd say it works.

## Grading

UpTo18 test uses between 163.840 and 204.800 test strings of 5 characters each, for 15 games 
(found by tinkering with the array_list size) with 20 re-insertions (+inserisci_inizio).

In some tests, input is messed up and doesn't respect what's indicated in the requisites, i.e. 
characters out of the given alphabeth, or instruction given at the wrong time (in particular, I think it's in the UpTo30).

For subtasks 2 and 4 of Upto30, there seems to be strings too long provided as part of the dictionary.

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
