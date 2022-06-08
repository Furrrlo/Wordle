#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define LAMBDA(ret_type, _body) ({ ret_type _ _body _; })

#define ALPHABETH_SIZE (int)((sizeof(ALPHABETH)-1)/sizeof(char))

// ASCII ordered
char ALPHABETH[] = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

char pos_to_char(int pos)
{
  return ALPHABETH[pos];
}

int char_to_pos(char c)
{
  // This is to make it O(1)
  int offset = 0;
  if(c == '-')
    return offset;
  ++offset;
  
  if(c >= '0' && c <= '9')
    return offset + (c - '0');
  offset += ('9' - '0') + 1;
  
  if(c >= 'A' && c <= 'Z')
    return offset + (c - 'A');
  offset += ('Z' - 'A') + 1;

  if(c == '_')
    return offset;
  ++offset;

  if(c >= 'a' && c <= 'z')
    return offset + (c - 'a');
  offset += ('z' - 'a') + 1;
  
#ifdef DEBUG
  // Fallback to looping just to make sure
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
   if(ALPHABETH[i] == c)
    return i;
#endif 

  return -1;
}

typedef struct word_tree_node 
{
  struct word_tree_node **children;
  size_t size; // Even if I make it smaller, it's going to be a 16bytes struct anyway for alignment
} word_tree_t;

word_tree_t *new_word_tree()
{
  word_tree_t *ref = (word_tree_t*) malloc(sizeof(word_tree_t));
#ifdef DEBUG
  if(ref == NULL)
  {
    printf("Couldn't allocate word_tree_t\n");
    exit(-3);
    return NULL;
  }
#endif

  ref->children = NULL;
  ref->size = 0;
  return ref;
}

void word_tree_free(word_tree_t *tree)
{
  if(tree->children)
  {
    for(int i = 0; tree->size > 0 && i < ALPHABETH_SIZE; ++i)
    {  
      if(tree->children[i] != NULL)
      {
        word_tree_free(tree->children[i]);
        tree->size--;
      }
    }
    free(tree->children);
  }
  free(tree);
}

/* O(len) */
int word_tree_contains(const word_tree_t *tree, char *str)
{
  const word_tree_t *subtree = tree;
  for(int i = 0; str[i]; ++i)
  {
    int pos = char_to_pos(str[i]);
    if(subtree->children && subtree->children[pos] == NULL)
      return 0;

    subtree = subtree->children[pos];
  }

  return 1;
}

#define DELETE_SUBTREE 0
#define VISIT_SUBTREE 1
#define SKIP_SUBTREE 2

// Theta(len)
int word_tree_push_helper(word_tree_t *tree, char *str, int i)
{
  if(!str[i])
  {
    tree->size++;
    return 1;
  }

  int pos = char_to_pos(str[i]);
  if(pos == -1)
    return 0;

  if(tree->children == NULL)
  {
    tree->children = (struct word_tree_node**) malloc(ALPHABETH_SIZE * sizeof(struct word_tree_node*));
#ifdef DEBUG
    if(tree->children == NULL)
    {
      printf("Couldn't allocate word_tree_t array\n");
      exit(-38);
    }
#endif
    for(int i = 0; i < ALPHABETH_SIZE; ++i)
      tree->children[i] = NULL;
  }
  
  if(tree->children[pos] == NULL)
    tree->children[pos] = new_word_tree();

  int res = word_tree_push_helper(tree->children[pos], str, i + 1);
  if(res)
    tree->size++;
  return res;
}

int word_tree_push(word_tree_t *tree, char *str)
{
  return word_tree_push_helper(tree, str, 0);
}

void word_tree_filter_helper(word_tree_t *tree, 
                             int pos, 
                             int len, int *removed_len, 
                             char *str, int freq[ALPHABETH_SIZE], 
                             int (*filter)(int, char, int),
                             int (*func)(char*, int*))
{
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
  {
    if(tree->children == NULL || tree->children[i] == NULL)
      continue;

    word_tree_t *child = tree->children[i];

    char c = pos_to_char(i);
    int filter_res = filter(pos, c, freq[i] + 1);
    if(filter_res == SKIP_SUBTREE)
      continue;

    if(filter_res == DELETE_SUBTREE)
    {
      *removed_len += child->size;
      word_tree_free(child);
      tree->children[i] = NULL;
      continue;
    }

    str[pos] = c;
    if(pos + 1 < len)
    {
      int child_removed_len = 0;
      freq[i]++;
      word_tree_filter_helper(child, pos + 1, len, &child_removed_len, str, freq, filter, func);
      freq[i]--;
      *removed_len += child_removed_len;


      if(child->size == 0)
      {
        word_tree_free(child);
        tree->children[i] = NULL;
      }

      continue;
    }

    freq[i]++;
    int keep_leaf = func(str, freq); 
    freq[i]--;
    if(!keep_leaf)
    {
      *removed_len += child->size;
      word_tree_free(child); // Should be a leaf anyway
      tree->children[i] = NULL;
      continue;
    } 
  }

  tree->size -= *removed_len;
}

void word_tree_filter(word_tree_t *tree, 
                      int len,
                      int (*filter)(int, char, int), 
                      int (*func)(char*, int*))
{
#ifdef DEBUG
  int initial_size = tree->size;
#endif

  int removed_len = 0;
  char word[len + 1];
  word[len] = '\0';
  int freq[ALPHABETH_SIZE] = {0};
  word_tree_filter_helper(tree, 0, len, &removed_len, word, freq, filter, func);

#ifdef DEBUG
  int removed_len0 = removed_len;
  removed_len = 0;

  int size = 0;
  word_tree_filter_helper(tree, 0, len, &removed_len, word, freq,
      LAMBDA(int, (int pos, char c, int char_freq) { return VISIT_SUBTREE; }), 
      LAMBDA(int, (char *str, int *freq) { size++; return 1; }));
  if(size != tree->size)
  {
    printf("Tree size mismatch: expected %d but was %d (claim to have removed %d from %d)\n", tree->size, size, removed_len0, initial_size);
    tree->size = size;
  }
#endif
}

void word_tree_for_each_ordered(word_tree_t *tree,
                                int len,
                                int (*filter)(int, char, int),
                                void (*func)(char*, int*))
{
  word_tree_filter(
      tree, len, 
      LAMBDA(int, (int pos, char c, int char_freq) { 
        int filter_res = filter(pos, c, char_freq);
        if(filter_res == DELETE_SUBTREE)
          return SKIP_SUBTREE;
        return filter_res; 
      }), 
      LAMBDA(int, (char *str, int *freq) { func(str, freq); return 1; }));
}

// Time - Theta(n)
void populate_freq(char *word, int len, int new_freq[ALPHABETH_SIZE])
{
  // Populate frequencies of the word we were just given
  memset(new_freq, 0, ALPHABETH_SIZE * sizeof(int));
  for(int i = 0; i < len; ++i)
    new_freq[char_to_pos(word[i])]++;
}

typedef struct {
  char *word;
  int len;
  int freq[ALPHABETH_SIZE];
  char *found_chars;
  char **found_not_chars;
  int found_freq_min[ALPHABETH_SIZE];
  int found_freq_max[ALPHABETH_SIZE];
} reference_t;

void init_ref(reference_t *ref, char *word, int len)
{
  ref->word = word;
  ref->len = len;
  populate_freq(ref->word, ref->len, ref->freq);
  ref->found_chars = (char*) malloc(ref->len * sizeof(char));
  memset(ref->found_chars, 0, ref->len * sizeof(char));

  ref->found_not_chars = (char**) malloc(ref->len * sizeof(char*));
  for(int i = 0; i < ref->len; i++)
  {
    ref->found_not_chars[i] = (char*) malloc((ALPHABETH_SIZE + 1) * sizeof(char));
    ref->found_not_chars[i][0] = '\0';
  }

  memset(ref->found_freq_min, 0, sizeof(ref->found_freq_min));
  memset(ref->found_freq_max, -1, sizeof(ref->found_freq_max));
}

void ref_dispose(reference_t *ref)
{
  free(ref->found_chars);
  for(int i = 0; i < ref->len; ++i)
    free(ref->found_not_chars[i]);
  free(ref->found_not_chars);
}

void print_found_ref(reference_t *ref)
{
  printf("letters: \"");
  for(int i = 0; i < ref->len; ++i)
    printf("%c", ref->found_chars[i] == 0 ? ' ' : ref->found_chars[i]);
  printf("\"\n");

  printf("not: {");
  for(int i = 0; i < ref->len; ++i)
    if(ref->found_not_chars[i] != NULL)
      printf("%d: \"%s\", ", i, ref->found_not_chars[i]);
  printf("}\n");

  printf("min freq: {");
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
    if(ref->found_freq_min[i] > 0)
     printf("'%c': %d, ", pos_to_char(i), ref->found_freq_min[i]);
  printf("}\n");
  
  printf("max freq: {");
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
    if(ref->found_freq_max[i] >= 0)
     printf("'%c': %d, ", pos_to_char(i), ref->found_freq_max[i]);
  printf("}\n");
}

/* Time - Theta(n) */
void compare_words(reference_t *ref, char *new, char *out)
{
  // Spatial - Stack allocated, constant
  // Time - Theta(n)
  int new_freq[ALPHABETH_SIZE] = {0};
  memcpy(new_freq, ref->freq, sizeof(new_freq));

  // First pass, find letters which are the same
  // Theta(n)
  for(int i = 0; i < ref->len; ++i)
  {
    if(ref->word[i] != new[i])
      continue;

    ref->found_chars[i] = ref->word[i];
    out[i] = '+';

    int pos = char_to_pos(new[i]);
    --new_freq[pos];
    ref->found_freq_min[pos] = MAX(ref->found_freq_min[pos], ref->freq[pos] - new_freq[pos]);
  }

  // Second pass, letters which are wrong or at the wrong place
  // Theta(n)
  for(int i = 0; i < ref->len; ++i)
  {
    if(ref->word[i] == new[i])
      continue;

    int pos = char_to_pos(new[i]);
    int found_not_char = 0;
    if(new_freq[pos] <= 0)
    {
      out[i] = '/';
      found_not_char = ref->freq[pos] > 0;
      ref->found_freq_max[pos] = ref->freq[pos];
    }
    else
    {
      out[i] = '|';
      found_not_char = 1;
      --new_freq[pos];
      ref->found_freq_min[pos] = MAX(ref->found_freq_min[pos], ref->freq[pos] - new_freq[pos]);
    }

    if(found_not_char)
    {
      char *str = ref->found_not_chars[i];
      char to_append = new[i];

      int len;
      int append = 1;
      for(len = 0; str[len]; ++len)
      {
        if(str[len] == to_append)
        {
          append = 0;
          break;
        }
      }
      
      if(append)
      {
        str[len] = to_append;
        str[len + 1] = '\0';
      }
    }
  }
}

void filter_dictionary(reference_t *ref, word_tree_t *tree, void (*func)(char*))
{
  int (*known_chars_filter)(int, char, int) = LAMBDA(int, (int pos, char c, int char_freq) {
    
    if(ref->found_chars[pos] != 0 && ref->found_chars[pos] != c)
      return SKIP_SUBTREE;

    if(ref->found_not_chars[pos])
    {
      char *found_not_chars = ref->found_not_chars[pos];
      // Max ALPHABETH_SIZE, so should be fairly small
      for(int k = 0; found_not_chars[k]; ++k)
        if(c == found_not_chars[k])
          return SKIP_SUBTREE;
    }

    int alphabeth_pos = char_to_pos(c);
    if(ref->found_freq_max[alphabeth_pos] >= 0 && char_freq > ref->found_freq_max[alphabeth_pos])
      return SKIP_SUBTREE;

    return VISIT_SUBTREE;
  });
  int (*words_filter)(char*, int*) = LAMBDA(int, (char *str, int *freq) { 
      for(int i = 0; i < ALPHABETH_SIZE; ++i)
      {
        if(freq[i] < ref->found_freq_min[i])
          return 0;
      }

      return 1; 
  }); 

  // Theta(n)
  word_tree_for_each_ordered(tree, ref->len, known_chars_filter, LAMBDA(void, (char *str, int *freq) {
    if(words_filter(str, freq))
      func(str);
  }));
}

void populate_dictionary(word_tree_t *tree, int len, char *stop_command)
{
  char line[MAX(32, len) + 1];
  for(;;)
  {
    if(scanf("%s", line) < 0)
    {
      printf("Failed to read dict line\n");
      exit(-52);
      return;
    }

    if(strcmp(stop_command, line) == 0)
		  break;

#ifdef DEBUG
    if(len != strlen(line))
    {
      printf("Invalid word length %ld, expected %d for %s\n", strlen(line), len, line);
      exit(-6);
      return;
    }
#endif

    word_tree_push(tree, line);
  }
}

void check_everything_allrite()
{
#ifdef DEBUG
  int error = 0;
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
  {
    if(ALPHABETH[i] != pos_to_char(char_to_pos(ALPHABETH[i])))
    {
      printf("error in alphabeth conversion: %c %d %c\n", 
          ALPHABETH[i],
          char_to_pos(ALPHABETH[i]), 
          pos_to_char(char_to_pos(ALPHABETH[i])));
      error = 1;
    }
  }

  // Check that the alphabeth is ascii ordered
  for(int i = 0; i < ALPHABETH_SIZE - 1; ++i)
  {
    if(pos_to_char(i) >= pos_to_char(i + 1))
    {
      printf("Invalid ASCII order in alphabeth: %c >= %c\n", pos_to_char(i), pos_to_char(i + 1));
      error = 1;
    }
  }
  
  if(!error)
    return;

  printf("precondition error, fix it\n");
  exit(-2);
#endif
}

int main()
{
  check_everything_allrite();

  int len;
  if(scanf("%d", &len) < 0)
  {
    printf("Failed to read len\n");
    return -50;
  }

  if(len <= 0)
    return 0;
  
  char *out = (char*) malloc((len + 1) * sizeof(char));
  out[len] = '\0';

  word_tree_t *tree = new_word_tree();
  populate_dictionary(tree, len, "+nuova_partita");
  
  for(int quit = 0; !quit; )
  {  
    char ref_str[len + 1];
    int max_guesses;
    if(scanf("%s %d\n", ref_str, &max_guesses) < 0)
    {
      printf("Failed to read guesses\n");
      return -51;
    }

    if(max_guesses <= 0)
      return 0;

    reference_t ref;
    init_ref(&ref, ref_str, len);

    char line[MAX(len, 32) + 1];
   
    int tries = 0;
    int game_over = 0;
    for(;;)
    {
      if(scanf("%s", line) < 0)
      {
        goto quit_program;
      }

      // printf("Read %s\n", line);
      if(game_over || line[0] == '+')
      {
        if(strcmp(line, "+nuova_partita") == 0)
        {
          goto new_game;
        }
        else if(strcmp(line, "+inserisci_inizio") == 0)
        {
          populate_dictionary(tree, len, "+inserisci_fine");
        }
        else if(strcmp(line, "+stampa_filtrate") == 0)
        {
          // print_found_ref(&ref);
          filter_dictionary(&ref, tree, LAMBDA(void, (char *str) { printf("%s\n", str); }));
        }
      }
      else if(strcmp(ref.word, line) == 0)
      {
        printf("ok\n");
        game_over = 1;
      }
      else if(!word_tree_contains(tree, line)) 
      {
        printf("not_exists\n");
      }
      else
      {
        compare_words(&ref, line, out);
        printf("%s\n", out);

        size_t size = 0;
        filter_dictionary(&ref, tree, LAMBDA(void, (char *str) { size++; }));
        printf("%ld\n", size);

        if(++tries >= max_guesses)
        {
          printf("ko\n");
          game_over = 1;
        }
      }
    }

quit_program:
    quit = 1;
new_game:
    ref_dispose(&ref);
  }

  free(out);
  word_tree_free(tree);
  return 0;
}
