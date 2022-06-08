#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

typedef struct {
  char **arr;
  size_t size;
  size_t max_size;
} array_list_t;

array_list_t *new_array_list(size_t initial_size)
{
  array_list_t *ref = (array_list_t*) malloc(sizeof(array_list_t));
#ifdef DEBUG
  if(ref == NULL)
  {
    printf("Couldn't allocate array_list_t\n");
    exit(-3);
    return NULL;
  }
#endif

  ref->arr = (char**) malloc(sizeof(char*) * initial_size);
#ifdef DEBUG
  if(ref->arr == NULL)
  {
    printf("Couldn't allocate array_list_t array of %d\n", initial_size);
    exit(-3);
    return NULL;
  }
#endif

  ref->size = 0;
  ref->max_size = initial_size;
  return ref;
}

void list_free(array_list_t *list)
{
  free(list->arr);
  free(list);
}

char *list_get(array_list_t *list, size_t pos)
{
#ifdef DEBUG
  if(pos < 0 || pos >= list->size)
  {
    printf("Array index out of bounds: %ld, len: %d\n", pos, list->size);
    exit(-3);
    return NULL;
  }
#endif

  return list->arr[pos];
}

int list_contains(array_list_t *list, char *str)
{
  for(size_t i = 0; i < list->size; i++)
    if(strcmp(list->arr[i], str) == 0)
      return 1;
  return 0; 
}

void list_qsort(array_list_t *list, int (*compar)(const void*,const void*))
{
  qsort(list->arr, list->size, sizeof(char*), compar);
}

void *list_bsearch(array_list_t *list, char *key, int (*compar)(const void*,const void*))
{
  return bsearch(&key, list->arr, list->size, sizeof(char*), compar);
}

void list_copy(array_list_t *to_copy, array_list_t *into)
{
  for(size_t i = 0; i < to_copy->size; ++i)
    into->arr[i] = to_copy->arr[i];
  into->size = to_copy->size;
}

void list_push(array_list_t **list, char *string)
{
  if((*list)->size >= (*list)->max_size)
  {
    array_list_t* old = *list;
    exit(-300);
    (*list) = new_array_list(old->max_size * 2);
    list_copy(old, *list);
    list_free(old);
  }

  (*list)->arr[(*list)->size++] = string;
}

void list_clear(array_list_t *list)
{
  list->size = 0;
}

#define ALPHABETH_SIZE (int)((sizeof(ALPHABETH)-1)/sizeof(char))

char ALPHABETH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

char pos_to_char(int pos)
{
  return ALPHABETH[pos];
}

int char_to_pos(char c)
{
  // This is to make it O(1)
  int offset = 0;
  if(c >= 'A' && c <= 'Z')
    return offset + (c - 'A');
  offset += ('Z' - 'A') + 1;

  if(c >= 'a' && c <= 'z')
    return offset + (c - 'a');
  offset += ('z' - 'a') + 1;
  
  if(c >= '0' && c <= '9')
    return offset + (c - '0');
  offset += ('9' - '0');
  
  if(c == '-')
    return offset + 1;
  ++offset;

  if(c == '_')
    return offset + 1;
  ++offset;

#ifdef DEBUG
  // Fallback to looping just to make sure
  // printf("somethign wrong, no fast path for %c\n", c);

  for(int i = 0; i < ALPHABETH_SIZE; ++i)
   if(ALPHABETH[i] == c)
    return i;
#endif 

  printf("char %c is not in alphabeth\n", c);
  // exit(-52);
  return 0; // TODO: no idea how to interpret this
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
    ref->found_freq_min[pos] = ref->freq[pos] - new_freq[pos];
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
      ref->found_freq_min[pos] = ref->freq[pos] - new_freq[pos];
    }

    if(found_not_char)
    {
      ref->found_not_chars[i] = strncat(
          ref->found_not_chars[i],
          &new[i],
          1);
    }
  }
}

void check_everything_allrite()
{
#ifdef DEBUG
  int error = 0;
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
    if(ALPHABETH[i] != pos_to_char(char_to_pos(ALPHABETH[i])))
    {
      printf("error in alphabeth conversion: %c %d %c\n", 
          ALPHABETH[i],
          char_to_pos(ALPHABETH[i]), 
          pos_to_char(char_to_pos(ALPHABETH[i])));
      error = 1;
    } 
  
  if(!error)
    return;

  printf("precondition error, fix it\n");
  exit(-2);
#endif
}

int pstrcmp(const void* a, const void* b)
{
  return strcmp(*(const char**)a, *(const char**)b);
}

array_list_t *filter_dictionary(reference_t *ref, array_list_t *src, array_list_t *dst)
{
  // Theta(n * len)
  size_t new_size = 0;
  for(size_t i = 0; i < src->size; ++i)
  {
    char *curr_str = src->arr[i];

    for(int j = 0; j < ref->len; ++j)
    {
      char found_char = ref->found_chars[j];
      if(found_char != 0 && curr_str[j] != found_char)
        goto delete_curr_str;
    }

    for(int j = 0; j < ref->len; ++j)
    {
      char *found_not_chars = ref->found_not_chars[j];
      if(found_not_chars == NULL)
        continue;

      for(int k = 0; found_not_chars[k]; ++k)
        if(curr_str[j] == found_not_chars[k])
          goto delete_curr_str;
    }

    // TODO: cache these
    int curr_freq[ALPHABETH_SIZE];
    populate_freq(curr_str, ref->len, curr_freq);

    for(int i = 0; i < ALPHABETH_SIZE; ++i)
    {
      if(ref->found_freq_min[i] <= 0)
        continue;
      if(curr_freq[i] < ref->found_freq_min[i])
        goto delete_curr_str;
    }

    for(int i = 0; i < ALPHABETH_SIZE; ++i)
    {
      if(ref->found_freq_max[i] < 0)
        continue;
      if(curr_freq[i] > ref->found_freq_max[i])
        goto delete_curr_str;
    }
    
    // We don't need to worry about overwriting non-processed strings
    // as i is always gonna begreater or equal to new_size, meaning we either
    // replace a s5ring with itself or replace an already processed and moved one
    dst->arr[new_size++] = src->arr[i];
    continue;

delete_curr_str: ;
  }

  dst->size = new_size;

  // No need to resort it, it was already sorted and we just removed elements
  // list_qsort(dict, pstrcmp);
  
  return dst;
}

void populate_dictionary(array_list_t **list, array_list_t **curr_dict, int len, char *stop_command)
{
  int max_line_len = MAX(32, len);
  for(;;)
  {
    char *line = (char*) malloc(max_line_len * sizeof(char));
    if(scanf("%s", line) < 0)
    {
      printf("Failed to read dict line\n");
      exit(-52);
      return;
    }

    if(strcmp(stop_command, line) == 0)
    {
      free(line);
      break;
    }

#ifdef DEBUG
    if(len != strlen(line))
    {
      printf("Invalid word length %ld, expected %d\n", strlen(line), len);
      exit(-6);
      return;
    }
#endif

    list_push(list, line);
    if(curr_dict != NULL)
      list_push(curr_dict, line);
  }
  
  list_qsort(*list, pstrcmp);
  if(curr_dict != NULL)
    list_qsort(*curr_dict, pstrcmp);
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

  array_list_t *dict = new_array_list(8192L * 25);
  populate_dictionary(&dict, NULL, len, "+nuova_partita");
  
  array_list_t *filtered_dict = new_array_list(dict->max_size);

  for(;;)
  {
    array_list_t *curr_dict = dict;
    
    char ref_str[len];
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

    int max_line_len = MAX(len, 32);
    char *line = (char*) malloc(max_line_len * sizeof(char));
   
    int tries = 0;
    int game_over = 0;
    for(;;)
    {
      if(scanf("%s", line) < 0)
      {
        return 0;
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
          populate_dictionary(&dict, &curr_dict, len, "+inserisci_fine");
          curr_dict = filter_dictionary(&ref, curr_dict, filtered_dict);
        }
        else if(strcmp(line, "+stampa_filtrate") == 0)
        {
          for(size_t i = 0; i < curr_dict->size; ++i)
            printf("%s\n", list_get(curr_dict, i));
        }
      }
      else if(strcmp(ref.word, line) == 0)
      {
        printf("ok\n");
        game_over = 1;
      }
      else if(list_bsearch(dict, line, pstrcmp) == NULL) 
      {
        printf("not_exists\n");
      }
      else
      {
        compare_words(&ref, line, out);
        printf("%s\n", out);

        curr_dict = filter_dictionary(&ref, curr_dict, filtered_dict);
        printf("%ld\n", curr_dict->size);

        if(++tries >= max_guesses)
        {
          printf("ko\n");
          game_over = 1;
        }
      }
    }

new_game:
    free(line);
    ref_dispose(&ref);
  }

  return 0;
}

