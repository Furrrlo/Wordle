#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define LAMBDA(ret_type, _body) ({ ret_type _ _body _; })

#define ALPHABETH_SIZE (alphabeth_size_t)((sizeof(ALPHABETH)-1)/sizeof(char))
#define NOT_IN_ALPHABETH ((alphabeth_size_t) -1)

// ASCII ordered
char ALPHABETH[] = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
typedef unsigned char alphabeth_size_t; // 60 < 255, should be enough

static inline char pos_to_char(const alphabeth_size_t pos)
{
  return ALPHABETH[pos];
}

static alphabeth_size_t char_to_pos(const char c)
{
  // Valgrind says this is a hot method :I
  // I need that jump-table performance
  switch(c)
  {
    case '-': return 0;
    case '0': return 1;
    case '1': return 2;
    case '2': return 3;
    case '3': return 4;
    case '4': return 5;
    case '5': return 6;
    case '6': return 7;
    case '7': return 8;
    case '8': return 9;
    case '9': return 10;
    case 'A': return 11;
    case 'B': return 12;
    case 'C': return 13;
    case 'D': return 14;
    case 'E': return 15;
    case 'F': return 16;
    case 'G': return 17;
    case 'H': return 18;
    case 'I': return 19;
    case 'J': return 20;
    case 'K': return 21;
    case 'L': return 22;
    case 'M': return 23;
    case 'N': return 24;
    case 'O': return 25;
    case 'P': return 26;
    case 'Q': return 27;
    case 'R': return 28;
    case 'S': return 29;
    case 'T': return 30;
    case 'U': return 31;
    case 'V': return 32;
    case 'W': return 33;
    case 'X': return 34;
    case 'Y': return 35;
    case 'Z': return 36;
    case '_': return 37;
    case 'a': return 38;
    case 'b': return 39;
    case 'c': return 40;
    case 'd': return 41;
    case 'e': return 42;
    case 'f': return 43;
    case 'g': return 44;
    case 'h': return 45;
    case 'i': return 46;
    case 'j': return 47;
    case 'k': return 48;
    case 'l': return 49;
    case 'm': return 50;
    case 'n': return 51;
    case 'o': return 52;
    case 'p': return 53;
    case 'q': return 54;
    case 'r': return 55;
    case 's': return 56;
    case 't': return 57;
    case 'u': return 58;
    case 'v': return 59;
    case 'w': return 60;
    case 'x': return 61;
    case 'y': return 62;
    case 'z': return 63;
  }
#ifdef DEBUG
  // Fallback to looping just to make sure
  for(alphabeth_size_t i = 0; i < ALPHABETH_SIZE; ++i)
   if(ALPHABETH[i] == c)
    return i;
#endif 

  return NOT_IN_ALPHABETH;
}

typedef unsigned long bitset_t; // 64 bits, exactly the alphabeth size
#define BITSET_BITS (8 * sizeof(bitset_t))
#define BITSET_ARRAY_SIZE(size) (((size) + BITSET_BITS - 1) / BITSET_BITS)

static inline
void bitset_set(bitset_t bitset[], size_t pos, bool val)
{
  bitset_t mask = (bitset_t) 1 << (pos % BITSET_BITS);
  if(val)
    bitset[pos / BITSET_BITS] |= mask;
  else
    bitset[pos / BITSET_BITS] &= ~mask;
}

static inline
bool bitset_test(bitset_t bitset[], size_t pos)
{
  bitset_t mask = (bitset_t) 1 << (pos % BITSET_BITS);
  return (bitset[pos / BITSET_BITS] & mask);
}

// Important: struct size should be able to fit into a cache line
// Max children array size is 65, so it's 3 + 16 + 65 * 2 * (1 + 8) = 1189 bytes 
struct wtree_node 
{
  alphabeth_size_t children_max_size;
  alphabeth_size_t non_deleted_size;
  alphabeth_size_t deleted_size;
  alphabeth_size_t *leaf;
  struct wtree_edge *children;
};

struct wtree_edge
{
  alphabeth_size_t alphabeth_pos;
  struct wtree_node *node;
};

typedef struct {
  struct wtree_node *root;
  bool invalidated;
} wtree_t;

static inline struct wtree_node *new_wtree_node(alphabeth_size_t children_size,
                                                alphabeth_size_t leaf_size)
{
  struct wtree_node *node = malloc(sizeof(*node) 
      + children_size * sizeof(node->children[0]) 
      + leaf_size * sizeof(node->leaf[0]));
  if(node == NULL)
    return NULL;

  node->children_max_size = children_size;
  node->non_deleted_size = 0;
  node->deleted_size = 0;
  node->leaf = leaf_size == 0 ? NULL : (void*) (&node->children + 1);
  node->children = children_size == 0 ? NULL : (void*) (&node->children + 1);
  return node;
}

static inline wtree_t *new_word_tree()
{
  wtree_t *tree = malloc(sizeof(*tree));
  if(tree == NULL)
    return NULL;

  tree->root = new_wtree_node(1, 0);
  if(tree->root == NULL)
  {
    free(tree);
    return NULL;
  }
  
  tree->invalidated = false;
  return tree;
}

static inline void wtree_node_free(struct wtree_node *node)
{
  if(node == NULL)
    return;

  for(size_t i = 0; i < node->non_deleted_size; ++i)
  {
    struct wtree_edge *edge = &node->children[i];
    wtree_node_free(edge->node);
  }

  for(size_t i = node->children_max_size - node->deleted_size; i < node->children_max_size; ++i)
  {
    struct wtree_edge *edge = &node->children[i];
    wtree_node_free(edge->node);
  }

  free(node);
}

static inline void wtree_free(wtree_t *tree)
{
  wtree_node_free(tree->root);
  free(tree);
}

static inline int wtree_edge_cmp(const void *o1, const void *o2)
{
  return ((struct wtree_edge*) o1)->alphabeth_pos - ((struct wtree_edge*) o2)->alphabeth_pos;
}

static struct wtree_edge *wtree_node_get_child(const struct wtree_node *const node, 
                                               const alphabeth_size_t alphabeth_pos,
                                               bool *const is_deleted,
                                               size_t *const deleted_pos)
{
  if(node->children == NULL)
    return NULL;

  struct wtree_edge lookup = { .alphabeth_pos = alphabeth_pos };
  struct wtree_edge *child = bsearch(
      &lookup,
      node->children,
      node->non_deleted_size,
      sizeof(node->children[0]),
      wtree_edge_cmp);
  if(child != NULL)
  {
    if(is_deleted != NULL) *is_deleted = false;
    return child;
  }

  // TODO: optimize?
  for(size_t i = node->children_max_size - node->deleted_size; i < node->children_max_size; ++i)
  {
    child = &node->children[i];
    if(child->alphabeth_pos == alphabeth_pos)
    {
      if(is_deleted != NULL) *is_deleted = true;
      if(deleted_pos != NULL) *deleted_pos = i;
      return child;
    }
  }

  return NULL;
}

static bool wtree_contains(const wtree_t *const tree, 
                           const char *const str,
                           const size_t len)
{
  const struct wtree_node *subtree = tree->root;
  size_t i;
  for(i = 0; str[i] && subtree->leaf == NULL; ++i)
  {
    if(subtree == NULL)
      return false;
    
    struct wtree_edge *edge = wtree_node_get_child(subtree, char_to_pos(str[i]), NULL, NULL);
    if(edge == NULL)
      return false;
    
    subtree = edge->node;
  }

  if(subtree != NULL && subtree->leaf != NULL)
  {
    for(size_t j = 0; str[i]; ++i, ++j)
      if(char_to_pos(str[i]) != subtree->leaf[j])
        return false;
  }

  return i == len;
}

static void wtree_undelete_child(struct wtree_node *const subtree,
                                 const struct wtree_edge *const child,
                                 const size_t deleted_pos)
{
  struct wtree_edge tmp_child = *child;

  subtree->deleted_size--;
  size_t first = subtree->children_max_size - subtree->deleted_size;
  for(size_t i = deleted_pos; i >= first; --i)
    subtree->children[i] = subtree->children[i - 1];

  subtree->children[subtree->non_deleted_size++] = tmp_child;
  qsort(
    subtree->children,
    subtree->non_deleted_size,
    sizeof(subtree->children[0]),
    wtree_edge_cmp);
}

static void wtree_ensure_children_size(struct wtree_node **const subtree_ptr, size_t to_grow)
{
  struct wtree_node* subtree = *subtree_ptr;
  
  alphabeth_size_t curr_size = subtree->non_deleted_size + subtree->deleted_size;
  if(curr_size + to_grow > subtree->children_max_size)
  {
    struct wtree_node *old = subtree;
    *subtree_ptr = (subtree = new_wtree_node(MAX(1, old->children_max_size * 2), 0));
    subtree->non_deleted_size = old->non_deleted_size;
    subtree->deleted_size = old->deleted_size;
    if(old->children)
    {
      memcpy(subtree->children, old->children, old->non_deleted_size * sizeof(subtree->children[0]));
      memcpy(
          &subtree->children[subtree->children_max_size - subtree->deleted_size], 
          &old->children[old->children_max_size - old->deleted_size], 
          old->deleted_size * sizeof(subtree->children[0]));
    }
    free(old);
  }
}

static void wtree_append_new_child(struct wtree_node **const subtree_ptr,
                                   const alphabeth_size_t alphabeth_pos,
                                   const struct wtree_node *const new_child_node,
                                   const bool is_tree_invalidated)
{
  wtree_ensure_children_size(subtree_ptr, 1);
  
  struct wtree_node* subtree = *subtree_ptr;
  struct wtree_edge *child = &subtree->children[subtree->non_deleted_size++];
  child->alphabeth_pos = alphabeth_pos;
  child->node = (struct wtree_node*) new_child_node;

  if(!is_tree_invalidated)
  {
    qsort(
        subtree->children,
        subtree->non_deleted_size,
        sizeof(subtree->children[0]),
        wtree_edge_cmp);
  }
}

static bool wtree_push_helper(struct wtree_node **const subtree, 
                              const char *const str, 
                              const size_t i,
                              const size_t len,
                              const bool is_tree_invalidated)
{
  if(!str[i])
  {
    // words can't be duped (I think), so no need to try
    // avoiding node undeletion if the input string is already
    // present
    return i == len; 
  }
  // If subtree is null, it means we are trying to push into
  // a subleaf, meaning the string is longer than len.
  if(*subtree == NULL)
    return false;

  alphabeth_size_t alphabeth_pos = char_to_pos(str[i]);
  if(alphabeth_pos == NOT_IN_ALPHABETH)
    return false;

  // If it's a leaf node, un-leaf it and then proceed normally
  bool is_leaf = (*subtree)->leaf != NULL;
  if(is_leaf)
  {
    const alphabeth_size_t leaf_alfabeth_pos = (*subtree)->leaf[0]; 
    const size_t new_leaf_size = len - i - 1;
    struct wtree_node *new_child_node = NULL;
    if(new_leaf_size > 0)
    {
      new_child_node = new_wtree_node(0, new_leaf_size);
      if(new_child_node == NULL)
        return false;
      // Copy the old leaf, skipping the 1st char
      for(size_t j = 0; j < new_leaf_size; ++j)
        new_child_node->leaf[j] = (*subtree)->leaf[j + 1];
    }

    wtree_append_new_child(subtree, leaf_alfabeth_pos, new_child_node, is_tree_invalidated);
  }

  bool is_deleted;
  size_t deleted_pos;
  struct wtree_edge *child = wtree_node_get_child(*subtree, alphabeth_pos, &is_deleted, &deleted_pos);
  if(child != NULL)
  {
    bool res = wtree_push_helper(&child->node, str, i + 1, len, is_tree_invalidated);
    if(!res || !is_deleted || is_tree_invalidated)
      return res;
    // Added something down the line, need to undelete this one
    wtree_undelete_child(*subtree, child, deleted_pos); 
    return res;
  }

  // Not found, allocate a new child node which is gonna be a leaf
  struct wtree_node *new_child_node = NULL;
  if(len - i - 1 > 0)
  {
    int leaf_len = len - i - 1; 
    new_child_node = new_wtree_node(0, leaf_len);
    if(new_child_node == NULL)
      return false;
    
    size_t j = i + 1; 
    for(size_t k = 0; str[j]; ++j, ++k)
    {
      alphabeth_size_t curr_leaf_alphabeth_pos = char_to_pos(str[j]);
      if(curr_leaf_alphabeth_pos == NOT_IN_ALPHABETH)
        goto fail;
      if(k >= leaf_len)
        goto fail;

      new_child_node->leaf[k] = curr_leaf_alphabeth_pos;
    }

    if(j == len)
      goto pass;
fail:
      free(new_child_node);
      return false;
pass: ;
  }

  wtree_append_new_child(subtree, alphabeth_pos, new_child_node, is_tree_invalidated);
  return true;
}

static inline bool wtree_push(wtree_t *const tree, 
                              const char *const str,
                              const size_t len)
{
  return wtree_push_helper(&tree->root, str, 0, len, tree->invalidated);
}

typedef enum {
  VISIT_SUBTREE = 1,
  MARK_KEPT = 3,
  MARK_DELETED = 4,
} __attribute__ ((__packed__)) iter_res_t;

struct wtree_for_each_params 
{
  size_t len; 
  
  char *curr_str; 
  int curr_freq[ALPHABETH_SIZE];

  iter_res_t (*char_filter)(size_t, char, alphabeth_size_t, int, void*);
  iter_res_t (*word_filter)(const char*, const int*, void*);
  void (*word_func)(const char*, void*);
  void *args;
};

static inline
void wtree_reappend_child(struct wtree_node *const parent,
                          struct wtree_edge *const deleted_array,
                          size_t *deleted_idx,
                          const alphabeth_size_t alphabeth_pos, 
                          const struct wtree_node *const child,
                          const bool is_deleted)
{
  // Keep this as branchless as possible, it's in a hot loop
  // and I don't want the branch predictor to screw me over

  struct wtree_edge *arr = (struct wtree_edge*) ( 
    ((uintptr_t) is_deleted * (uintptr_t) deleted_array) + 
    ((uintptr_t) !is_deleted * (uintptr_t) parent->children));
  alphabeth_size_t idx = (!is_deleted * parent->non_deleted_size) + (is_deleted * (*deleted_idx - 1));

  arr[idx].alphabeth_pos = alphabeth_pos;
  arr[idx].node = (struct wtree_node*) child;

  parent->non_deleted_size += !is_deleted;
  *deleted_idx -= is_deleted;
}

static inline
bool __wtree_for_each_leaf(struct wtree_node *const tree,
                           struct wtree_for_each_params *const params,
                           const size_t pos)
{
  bool kept = true;
  size_t i;
  for(i = 0; kept && i < params->len - pos; ++i)
  {
    alphabeth_size_t alphabeth_pos = tree->leaf[i];
    char c = params->curr_str[pos + i] = pos_to_char(alphabeth_pos);
    int char_freq = ++params->curr_freq[alphabeth_pos];

    iter_res_t filter_res = params->char_filter(pos + i, c, alphabeth_pos, char_freq, params->args);
    kept = filter_res != MARK_DELETED;
  }

  if(kept)
    kept = params->word_filter(params->curr_str, params->curr_freq, params->args) != MARK_DELETED;          
 
  for(; i > 0; --i)
  {
    alphabeth_size_t alphabeth_pos = tree->leaf[i - 1];
    --params->curr_freq[alphabeth_pos];
  }

  if(kept)
    params->word_func(params->curr_str, params->args);
  return kept;
}

#define __WTREE_FOR_EACH_DELETION_LOOP(__condition_statement__) {                                               \
  /* We are going to be overwriting these nodes while iterating, so save their size */                          \
  alphabeth_size_t non_deleted_size = tree->non_deleted_size;                                                   \
  tree->non_deleted_size = 0;                                                                                   \
  /* Since we can't safely override deleted nodes while iterating (we would override) 
     for sure some non processed nodes if the array was full), save them in an tmp array. */                    \
  size_t deleted_idx = non_deleted_size;                                                                        \
  struct wtree_edge deleted[MAX(deleted_idx, 1)]; /* VLA size 0 are UB */                                       \
                                                                                                                \
  for(size_t i = 0; i < non_deleted_size; ++i)                                                                  \
  {                                                                                                             \
    struct wtree_edge *edge = &tree->children[i];                                                               \
                                                                                                                \
    alphabeth_size_t alphabeth_pos = edge->alphabeth_pos;                                                       \
                                                                                                                \
    bool is_deleted;                                                                                            \
    { __condition_statement__ }                                                                                 \
    wtree_reappend_child(                                                                                       \
        tree, deleted, &deleted_idx,                                                                            \
        alphabeth_pos, edge->node, is_deleted);                                                                 \
  }                                                                                                             \
  /* Copy the deleted array back into children, appending to the ones already present */                        \
  size_t new_deleted_size = non_deleted_size - deleted_idx;                                                   \
  tree->deleted_size += new_deleted_size;                                                                       \
  memcpy(                                                                                                       \
    &tree->children[tree->children_max_size - tree->deleted_size],                                              \
    &deleted[deleted_idx],                                                                                      \
    new_deleted_size * sizeof(tree->children[0]));                                                              \
}

#define WTREE_FOR_EACH_HELPER(fn_name, invalidate)                                                              \
  static bool fn_name(struct wtree_node *const tree,                                                            \
                      struct wtree_for_each_params *const params,                                               \
                      const size_t pos)                                                                         \
  {                                                                                                             \
    if(tree == NULL || tree->leaf != NULL)                                                                      \
      return __wtree_for_each_leaf(tree, params, pos);                                                          \
                                                                                                                \
    /* I need to move the deleted array to be adjacent to the non_deleted part.
       I need to pay attention to how I use memcpy, as it doesn't work on overlapping memory,
       but since I don't have to care about the order, I can just fill the hole in the middle of
       the two arrays.                                                                            */            \
    if((invalidate)) {                                                                                          \
      size_t hole_size = tree->children_max_size - tree->deleted_size - tree->non_deleted_size;                 \
      size_t to_move_size = MIN(hole_size, tree->deleted_size);                                                 \
      if(to_move_size > 0)                                                                                      \
        memcpy(                                                                                                 \
            &tree->children[tree->non_deleted_size],                                                            \
            &tree->children[tree->children_max_size - to_move_size],                                            \
            to_move_size * sizeof(tree->children[0]));                                                          \
      tree->non_deleted_size += tree->deleted_size;                                                             \
      tree->deleted_size = 0;                                                                                   \
    }                                                                                                           \
                                                                                                                \
    /* This first loop _should_ be branchless and be able to keep                                               
       all the data in cache, as it won't follow edge pointers */                                               \
    __WTREE_FOR_EACH_DELETION_LOOP({                                                                            \
        char c = pos_to_char(alphabeth_pos);                                                                    \
        int char_freq = params->curr_freq[alphabeth_pos] + 1;                                                   \
        iter_res_t res = params->char_filter(pos, c, alphabeth_pos, char_freq, params->args);                   \
        is_deleted = res == MARK_DELETED;                                                                       \
    });                                                                                                         \
                                                                                                                \
    if((invalidate)) {                                                                                          \
      qsort(                                                                                                    \
        tree->children,                                                                                         \
        tree->non_deleted_size,                                                                                 \
        sizeof(tree->children[0]),                                                                              \
        wtree_edge_cmp);                                                                                        \
    }                                                                                                           \
                                                                                                                \
    /* Second loop follows pointers, messing up caches */                                                       \
    bitset_t child_any_not_deleted[MAX(BITSET_ARRAY_SIZE(tree->non_deleted_size), 1)];                          \
    for(size_t i = 0; i < tree->non_deleted_size; ++i)                                                          \
    {                                                                                                           \
      struct wtree_edge *edge = &tree->children[i];                                                             \
                                                                                                                \
      params->curr_str[pos] = pos_to_char(edge->alphabeth_pos);                                                 \
      params->curr_freq[edge->alphabeth_pos]++;                                                                 \
      bitset_set(child_any_not_deleted, i, fn_name(edge->node, params, pos + 1));                               \
      params->curr_freq[edge->alphabeth_pos]--;                                                                 \
    }                                                                                                           \
                                                                                                                \
    bool any_not_deleted = false;                                                                               \
    __WTREE_FOR_EACH_DELETION_LOOP({                                                                            \
      bool curr_any_not_deleted = bitset_test(child_any_not_deleted, i);                                        \
      any_not_deleted |= curr_any_not_deleted;                                                                  \
      is_deleted = !curr_any_not_deleted;                                                                       \
    });                                                                                                         \
                                                                                                                \
    return any_not_deleted;                                                                                     \
  }

WTREE_FOR_EACH_HELPER(__wtree_for_each_ordered_helper, false)
WTREE_FOR_EACH_HELPER(__wtree_for_each_ordered_helper_invalidated, true)

static inline
void wtree_for_each_ordered(wtree_t *const tree, 
                            const size_t len,
                            iter_res_t (*char_filter)(size_t, char, alphabeth_size_t, int, void*), 
                            iter_res_t (*word_filter)(const char*, const int*, void*),
                            void (*word_func)(const char*, void*),
                            void *const args)
{
  struct wtree_for_each_params params;
  params.len = len;

  char word[len + 1];
  word[len] = '\0';
  params.curr_str = word; 
  memset(params.curr_freq, 0, sizeof(params.curr_freq));

  params.char_filter = char_filter;
  params.word_filter = word_filter;
  params.word_func = word_func;
  params.args = args;

  if(!tree->invalidated)
    __wtree_for_each_ordered_helper(tree->root, &params, 0);
  else
    __wtree_for_each_ordered_helper_invalidated(tree->root, &params, 0);
  tree->invalidated = false;
}


static inline void wtree_undelete_all(wtree_t *const tree)
{
  tree->invalidated = true;
}

// Time - Theta(n)
static void populate_freq(const char *const word, 
                          const size_t len, 
                          int new_freq[ALPHABETH_SIZE])
{
  // Populate frequencies of the word we were just given
  memset(new_freq, 0, ALPHABETH_SIZE * sizeof(new_freq[0]));
  for(size_t i = 0; i < len; ++i)
    new_freq[char_to_pos(word[i])]++;
}

typedef struct
{
  alphabeth_size_t alphabeth_pos;
  unsigned short n;
} char_freq_t; 

typedef struct
{
  char_freq_t arr[ALPHABETH_SIZE];
  alphabeth_size_t size;
} char_freqs_t;

static inline int freq_compare(const void *o1, const void *o2) {
  return (((char_freq_t*) o1)->alphabeth_pos - ((char_freq_t*) o2)->alphabeth_pos);
}

static inline
unsigned short freq_find_by_pos(const char_freqs_t *const freq, 
                                const alphabeth_size_t alphabeth_pos)
{
  const char_freq_t lookup = { .alphabeth_pos = alphabeth_pos };
  char_freq_t *found = (char_freq_t*) bsearch(
      &lookup, 
      freq->arr, 
      freq->size, 
      sizeof(char_freq_t), 
      freq_compare); 
  return found ? found->n : 0;
}

#define freq_update_for_pos(freq, alphabeth_pos, to_update, body) { \
      bool ____requires_sorting____;\
      unsigned short *to_update = __freq_to_update_for_pos(freq, alphabeth_pos, &____requires_sorting____); \
      { body } \
      if(____requires_sorting____)\
        qsort((freq)->arr, (freq)->size, sizeof(char_freq_t), freq_compare); \
    }

static
unsigned short *__freq_to_update_for_pos(char_freqs_t *const freq, 
                                         const alphabeth_size_t alphabeth_pos,
                                         bool *const requires_sorting)
{
  const char_freq_t lookup = { .alphabeth_pos = alphabeth_pos };
  char_freq_t *found = (char_freq_t*) bsearch(
      &lookup,
      freq->arr,
      freq->size,
      sizeof(char_freq_t),
      freq_compare);
  if(found)
  {
    *requires_sorting = false;
    return &found->n;
  }

  char_freq_t *new = &freq->arr[freq->size++];
  new->alphabeth_pos = alphabeth_pos;
  new->n = 0;
  *requires_sorting = true;
  return &new->n;
}

typedef struct
{
  const char *word;
  size_t len;
  int freq[ALPHABETH_SIZE];
  char *found_chars;
  bitset_t (*found_not_chars)[BITSET_ARRAY_SIZE(ALPHABETH_SIZE)];
  char_freqs_t found_freq_min;
  int found_freq_max[ALPHABETH_SIZE];
} reference_t;

static inline 
void init_ref(reference_t *const ref, const char *const word, const size_t len)
{
  ref->word = word;
  ref->len = len;
  populate_freq(ref->word, ref->len, ref->freq);
  ref->found_chars = calloc(ref->len, sizeof(ref->found_chars[0])); 
  ref->found_not_chars = calloc(ref->len, sizeof(*ref->found_not_chars));
  ref->found_freq_min.size = 0;
  memset(ref->found_freq_max, -1, sizeof(ref->found_freq_max));
}

static inline void ref_dispose(reference_t *ref)
{
  free(ref->found_chars);
  free(ref->found_not_chars);
}

void print_found_ref(const reference_t *const ref)
{
  printf("letters: \"");
  for(int i = 0; i < ref->len; ++i)
    printf("%c", ref->found_chars[i] == 0 ? ' ' : ref->found_chars[i]);
  printf("\"\n");

  printf("not: {");
  for(int i = 0; i < ref->len; ++i)
  {
    bool first = true;
    for(int j = 0; j < ALPHABETH_SIZE; ++j)
    {
      if(bitset_test(ref->found_not_chars[i], j))
      {
        if(first)
          printf("%d: \"", i);
        first = false;
        printf("%c", pos_to_char(j));
      }
    }

    if(!first)
      printf("\", ");
  }
  printf("}\n");

  printf("min freq: {");
  for(int i = 0; i < ref->found_freq_min.size; ++i)
    if(ref->found_freq_min.arr[i].n > 0)
     printf("'%c': %d, ", pos_to_char(ref->found_freq_min.arr[i].alphabeth_pos), ref->found_freq_min.arr[i].n);
  printf("}\n");
  
  printf("max freq: {");
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
    if(ref->found_freq_max[i] >= 0)
     printf("'%c': %d, ", pos_to_char(i), ref->found_freq_max[i]);
  printf("}\n");
}

/* Time - Theta(n) */
static bool compare_words(reference_t *const ref, 
                          const char *const new, 
                          char *const out)
{
  // Spatial - Stack allocated, constant
  // Time - Theta(n)
  int new_freq[ALPHABETH_SIZE];
  memcpy(new_freq, ref->freq, sizeof(new_freq));

  bool anything_changed = false;
  // First pass, find letters which are the same
  // Theta(n)
  for(size_t i = 0; i < ref->len; ++i)
  {
    if(ref->word[i] != new[i])
      continue;
    
    out[i] = '+';
    if(ref->found_chars[i] != ref->word[i])
    {
      ref->found_chars[i] = ref->word[i];
      anything_changed = true;
    }

    alphabeth_size_t pos = char_to_pos(new[i]);
    --new_freq[pos];

    int min_freq = ref->freq[pos] - new_freq[pos];
    freq_update_for_pos(&ref->found_freq_min, pos, saved_min_freq, {
      if(min_freq > *saved_min_freq)
      {
        *saved_min_freq = min_freq;
        anything_changed = true;
      }
    });
  }

  // Second pass, letters which are wrong or at the wrong place
  // Theta(n)
  for(size_t i = 0; i < ref->len; ++i)
  {
    if(ref->word[i] == new[i])
      continue;

    alphabeth_size_t pos = char_to_pos(new[i]);
    bool found_not_char = false;
    if(new_freq[pos] <= 0)
    {
      out[i] = '/';
      found_not_char = ref->freq[pos] > 0;
      
      if(ref->found_freq_max[pos] != ref->freq[pos])
      {
        ref->found_freq_max[pos] = ref->freq[pos];
        anything_changed = true;
      }
    }
    else
    {
      out[i] = '|';
      found_not_char = true;
      --new_freq[pos];

      int min_freq = ref->freq[pos] - new_freq[pos];
      freq_update_for_pos(&ref->found_freq_min, pos, saved_min_freq, {
        if(min_freq > *saved_min_freq)
        {
          *saved_min_freq = min_freq;
          anything_changed = true;
        }
      });
    }

    if(found_not_char)
    {
      if(!bitset_test(ref->found_not_chars[i], pos))
        anything_changed = true;
      bitset_set(ref->found_not_chars[i], pos, 1);
    }
  }

  return anything_changed;
}

static iter_res_t known_chars_filter(const size_t pos, 
                                     const char c, 
                                     const alphabeth_size_t alphabeth_pos, 
                                     const int char_freq,
                                     void *args)
{
  const reference_t *ref = args;
  // This is in a hot loop, make it branchless at the expense of evaluating multiple conditions
  bool delete = 
    (ref->found_chars[pos] != 0 && ref->found_chars[pos] != c) |
    bitset_test(ref->found_not_chars[pos], alphabeth_pos) |
    (ref->found_freq_max[alphabeth_pos] >= 0 && char_freq > ref->found_freq_max[alphabeth_pos]);
  return (delete * MARK_DELETED) + (!delete * VISIT_SUBTREE);
}

static iter_res_t words_filter(const char *const str, 
                               const int *const freq,
                               void *args)
{
  const reference_t *ref = args;
  for(int i = 0; i < ref->found_freq_min.size; ++i)
  {
    const char_freq_t *min_freq = &ref->found_freq_min.arr[i];
    if(freq[min_freq->alphabeth_pos] < min_freq->n)
      return MARK_DELETED;
  }
  
  return MARK_KEPT;
}

static inline
void filter_dictionary(const reference_t *const ref, 
                       wtree_t *const tree, 
                       void (*func)(const char*, void*))
{
  wtree_for_each_ordered(
      tree, ref->len, 
      known_chars_filter, 
      words_filter,
      func, 
      (void*) ref);
}

static void populate_dictionary(wtree_t *const tree, 
                                const size_t len, 
                                const char *const stop_command)
{
  char line[MAX(32, len) + 1];
  for(;;)
  {
    if(scanf("%s", line) != 1)
    {
      printf("Failed to read dict line\n");
      exit(-52);
      return;
    }

#ifdef PRINT_INPUT
    printf("Read for populating dict %s\n", line);
#endif
    if(strcmp(stop_command, line) == 0)
      break;

#ifdef DEBUG
    if(len != strlen(line))
      printf("Invalid word length %ld, expected %ld for %s\n", strlen(line), len, line);
    else if(!wtree_push(tree, line, len))
      printf("Invalid word %s (probably char out of alphabeth\n", line);
#else
    wtree_push(tree, line, len);
#endif
  }
}

static inline void check_everything_allrite()
{
#ifdef DEBUG
  bool error = false;
  for(int i = 0; i < ALPHABETH_SIZE; ++i)
  {
    if(ALPHABETH[i] != pos_to_char(char_to_pos(ALPHABETH[i])))
    {
      printf("error in alphabeth conversion: %c %d %c\n", 
          ALPHABETH[i],
          char_to_pos(ALPHABETH[i]), 
          pos_to_char(char_to_pos(ALPHABETH[i])));
      error = true;
    }
  }

  // Check that the alphabeth is ascii ordered
  for(int i = 0; i < ALPHABETH_SIZE - 1; ++i)
  {
    if(pos_to_char(i) >= pos_to_char(i + 1))
    {
      printf("Invalid ASCII order in alphabeth: %c >= %c\n", pos_to_char(i), pos_to_char(i + 1));
      error = true;
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

  size_t len;
  if(scanf("%ld", &len) != 1)
  {
    printf("Failed to read len\n");
    return -50;
  }

  if(len <= 0)
    return 0;
  
  char *out = malloc((len + 1) * sizeof(char));
  out[len] = '\0';

  wtree_t *tree = new_word_tree();
  populate_dictionary(tree, len, "+nuova_partita");
 
  for(bool quit = false; !quit; )
  {
    char ref_str[len + 1];
    int max_guesses;
    if(scanf("%s %d\n", ref_str, &max_guesses) != 2)
    {
      printf("Failed to read guesses\n");
      return -51;
    }

    if(max_guesses <= 0)
      return 0;

    reference_t ref;
    init_ref(&ref, ref_str, len);
 
    size_t last_size = -1;
    
    char line[MAX(len, 32) + 1];
   
    int tries = 0;
    bool game_over = false;
    for(;;)
    {
      int read = scanf("%s", line);
      if(read == EOF)
        goto quit_program;
      if(read != 1)
      {
        printf("Failed to read line\n");
        return -54;
      }

#ifdef PRINT_INPUT
      printf("Read %s\n", line);
#endif
      // Commands that can always be run
      if(strcmp(line, "+nuova_partita") == 0)
      {
        goto new_game;
      }
      else if(strcmp(line, "+inserisci_inizio") == 0)
      {
        populate_dictionary(tree, len, "+inserisci_fine");
        last_size = -1;
      }
      // Stuff that can be run only during games
      else if(!game_over)
      {
        if(strcmp(line, "+stampa_filtrate") == 0)
        {
          // print_found_ref(&ref);
          filter_dictionary(&ref, tree, LAMBDA(void, (const char *str, void *args) { printf("%s\n", str); }));
        }
        else if(strcmp(ref.word, line) == 0)
        {
          printf("ok\n");
          game_over = true;
        }
        else if(!wtree_contains(tree, line, len)) 
        {
          printf("not_exists\n");
        }
        else
        {
          bool changed = compare_words(&ref, line, out);
          printf("%s\n", out);
        
          if(last_size == (size_t) -1 || changed)
          {
            last_size = 0;
            filter_dictionary(&ref, tree, LAMBDA(void, (const char *str, void* args) { last_size++; }));
          }
          printf("%ld\n", last_size);

          if(++tries >= max_guesses)
          {
            printf("ko\n");
            game_over = true;
          }
        }
      }
    }

quit_program:
    quit = true;
new_game:
    wtree_undelete_all(tree);
    ref_dispose(&ref);
  }

  free(out);
  wtree_free(tree);
  return 0;
}
