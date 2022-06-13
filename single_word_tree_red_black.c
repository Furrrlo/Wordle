#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define LAMBDA(ret_type, _body) ({ ret_type _ _body _; })

#define ALPHABETH_SIZE (alphabeth_size_t)((sizeof(ALPHABETH)-1)/sizeof(char))

// ASCII ordered
char ALPHABETH[] = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
typedef unsigned char alphabeth_size_t; // 60 < 255, should be enough
typedef unsigned short deletion_level_t; 

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

  return -1;
}

struct rb_tree;
typedef struct word_tree_node 
{
  unsigned long _children_or_expanded;
  alphabeth_size_t alphabeth_pos;
  deletion_level_t deletion_level;
} word_tree_t;

struct expanded_word_tree_node
{
  struct rb_tree *children;
  alphabeth_size_t non_deleted_size;
  deletion_level_t non_deleted_deletion_level;
  word_tree_t *non_deleted_children[ALPHABETH_SIZE];
};

typedef enum { BLACK, RED } __attribute__ ((__packed__)) rb_color_t;

typedef struct rb_tree
{
  struct word_tree_node value;

  unsigned long _parent_color; 
  struct rb_tree *right;
  struct rb_tree *left;
} rb_tree_t;

struct rb_tree global_rb_tree_nodes[8192 * 250];
int global_rb_tree_nodes_cursor = 0;

static inline rb_tree_t *new_rb_tree()
{
  return NULL;
}

static inline void rb_tree_free(rb_tree_t *tree)
{
  if(tree == NULL)
    return;

  // rb_tree_free(tree->value.children);
  // rb_tree_free(tree->right);
  // rb_tree_free(tree->left);
  // free(tree);
}

static inline bool rb_tree_is_empty(const rb_tree_t *const tree)
{
  return tree == NULL;
}

static inline struct rb_tree *rb_tree_parent(const struct rb_tree *node)
{
  return (struct rb_tree*) (node->_parent_color & ~3); 
}

static inline rb_color_t rb_tree_color(const struct rb_tree *const node)
{
  return node->_parent_color & 3; 
}

static inline void rb_tree_set_parent(struct rb_tree *const node, const struct rb_tree *const parent)
{
  node->_parent_color = (unsigned long) parent | rb_tree_color(node);
}

static inline void rb_tree_set_color(struct rb_tree *const node, const rb_color_t color)
{
  node->_parent_color = (node->_parent_color & ~3) | (color & 3);
}

static void rb_tree_for_each_ordered(rb_tree_t *const tree, 
                                     const deletion_level_t deletion_level,
                                     void (*func)(alphabeth_size_t, word_tree_t *))
{
  if(rb_tree_is_empty(tree))
      return;

  if(!rb_tree_is_empty(tree))
    rb_tree_for_each_ordered(tree->left, deletion_level, func);
  
  if(tree->value.deletion_level < deletion_level)
    func(tree->value.alphabeth_pos, &tree->value);
  
  if(!rb_tree_is_empty(tree))
    rb_tree_for_each_ordered(tree->right, deletion_level, func);
}

static struct word_tree_node *rb_tree_get(const rb_tree_t *const tree, 
                                          const alphabeth_size_t key)
{
  if(rb_tree_is_empty(tree))
    return NULL;

  if(tree->value.alphabeth_pos == key)
    return (struct word_tree_node*) &tree->value;

  if(key < tree->value.alphabeth_pos)
    return rb_tree_get(tree->left, key);
  return rb_tree_get(tree->right, key);
}

static struct rb_tree *rb_tree_bst(rb_tree_t **const tree, struct rb_tree *const node, const bool allow_duplicates)
{
  if(rb_tree_is_empty(*tree))
  {
    *tree = node;
    return NULL;
  }

  alphabeth_size_t node_key = node->value.alphabeth_pos;
  alphabeth_size_t tree_key = (*tree)->value.alphabeth_pos;
  if(!allow_duplicates && node_key == tree_key)
    return *tree;

  if(node_key < tree_key)
  {
    struct rb_tree *res = rb_tree_bst(&(*tree)->left, node, allow_duplicates);
    if(res == NULL)
      rb_tree_set_parent((*tree)->left, *tree);
    return res;
  }
  
  struct rb_tree *res = rb_tree_bst(&(*tree)->right, node, allow_duplicates);
  if(res == NULL)
    rb_tree_set_parent((*tree)->right, *tree);
  return res;
}

#ifdef DEBUG
static bool rb_tree_is_balanced_helper(const rb_tree_t *const tree, 
                                       int *const maxh, 
                                       int *const minh)
{
    if(tree == NULL)
    {
        *maxh = *minh = 0;
        return true;
    }
 
    int lmxh, lmnh;
    if(!rb_tree_is_balanced_helper(tree->left, &lmxh, &lmnh))
        return false;
    int rmxh, rmnh;
    if(!rb_tree_is_balanced_helper(tree->right, &rmxh, &rmnh))
        return false;
 
    *maxh = MAX(lmxh, rmxh) + 1;
    *minh = MIN(lmnh, rmnh) + 1; 
    return *maxh <= 2 * *minh;
}

static inline bool rb_tree_is_balanced(const rb_tree_t *const tree)
{
  int maxh, minh;
  return rb_tree_is_balanced_helper(tree, &maxh, &minh);
}
#endif

static void rb_tree_rrotate(rb_tree_t **const tree, struct rb_tree *const node)
{
    struct rb_tree *left = node->left;
    node->left = left->right;
    if(node->left)
      rb_tree_set_parent(node->left, node);
    rb_tree_set_parent(left, rb_tree_parent(node));
    if (!rb_tree_parent(node))
      *tree = left;
    else if (node == rb_tree_parent(node)->left)
      rb_tree_parent(node)->left = left;
    else
      rb_tree_parent(node)->right = left;
    left->right = node;
    rb_tree_set_parent(node, left);
}

static void rb_tree_lrotate(rb_tree_t **const tree, struct rb_tree *const node)
{
    struct rb_tree *right = node->right;
    node->right = right->left;
    if(node->right)
      rb_tree_set_parent(node->right, node);
    rb_tree_set_parent(right, rb_tree_parent(node));
    if(!rb_tree_parent(node))
      *tree = right;
    else if (node == rb_tree_parent(node)->left)
      rb_tree_parent(node)->left = right;
    else
      rb_tree_parent(node)->right = right;
    right->left = node;
    rb_tree_set_parent(node, right);
}

static void rb_tree_fixup(rb_tree_t **const tree, struct rb_tree *node)
{
  struct rb_tree *parent = NULL;
  struct rb_tree *grand_parent = NULL;

  while(node != *tree && rb_tree_color(node) != BLACK && rb_tree_color(rb_tree_parent(node)) == RED)
  {
    parent = rb_tree_parent(node);
    grand_parent = rb_tree_parent(parent);

    if(parent == grand_parent->left)
    {
      struct rb_tree *uncle = grand_parent->right;

      if(uncle != NULL && rb_tree_color(uncle) == RED)
      {
        rb_tree_set_color(grand_parent, RED);
        rb_tree_set_color(parent, BLACK);
        rb_tree_set_color(uncle, BLACK);
        node = grand_parent;
        continue;
      }

      // uncle == NULL || rb_tree_color(uncle) == BLACK
      if(node == parent->right)
      {
        rb_tree_lrotate(tree, parent);
        node = parent;
        parent = rb_tree_parent(node);
      }

      rb_tree_rrotate(tree, grand_parent);
      rb_color_t tmp = rb_tree_color(parent);
      rb_tree_set_color(parent, rb_tree_color(grand_parent));
      rb_tree_set_color(grand_parent, tmp);
      node = parent;
      continue;
    }

    // parent == grand_parent->right
    struct rb_tree *uncle = grand_parent->left;

    if(uncle != NULL && rb_tree_color(uncle) == RED)
    {
      rb_tree_set_color(grand_parent, RED);
      rb_tree_set_color(parent, BLACK);
      rb_tree_set_color(uncle, BLACK);
      node = grand_parent;
      continue;
    }
     
    // uncle == NULL || rb_tree_color(uncle) == BLACK 
    if(node == parent->left)
    {
      rb_tree_rrotate(tree, parent);
      node = parent;
      parent = rb_tree_parent(node);
    }

    rb_tree_lrotate(tree, grand_parent);
    rb_color_t tmp = rb_tree_color(parent);
    rb_tree_set_color(parent, rb_tree_color(grand_parent));
    rb_tree_set_color(grand_parent, tmp);
    node = parent;
  }

  rb_tree_set_color(*tree, BLACK);
#ifdef DEBUG
  if(!rb_tree_is_balanced(*tree))
  {
    printf("Tree is not balanced\n");
    exit(-104);
  }
#endif
}

static struct word_tree_node *rb_tree_do_put(rb_tree_t **const tree, 
                                             const alphabeth_size_t key, 
                                             const bool allow_duplicates)
{
  // struct rb_tree *new_node = malloc(sizeof(*new_node));
  if(global_rb_tree_nodes_cursor >= sizeof(global_rb_tree_nodes) / sizeof(struct rb_tree))
  {
    printf("No more rb_tree nodes\n");
    exit(-20);
    return NULL;
  }
  
  struct rb_tree *new_node = &global_rb_tree_nodes[global_rb_tree_nodes_cursor++];
#ifdef DEBUG
  if(new_node == NULL)
  {
    printf("Failed to allocate rb_tree\n");
    exit(-40);
    return NULL;
  }
#endif
  
  new_node->value.alphabeth_pos = key;
  new_node->value._children_or_expanded = (unsigned long) new_rb_tree();
  new_node->value.deletion_level = 0;
  rb_tree_set_color(new_node, RED);
  new_node->right = NULL;
  new_node->left = NULL;
  rb_tree_set_parent(new_node, NULL);

  struct rb_tree *already_present = rb_tree_bst(tree, new_node, allow_duplicates);
  if(already_present != NULL)
  {
    // rb_tree_free(new_node);
    global_rb_tree_nodes_cursor--;
    return &already_present->value;
  }

  rb_tree_fixup(tree, new_node);
  return &new_node->value;
}

static inline struct word_tree_node *rb_tree_put(rb_tree_t **const tree, const alphabeth_size_t key)
{
  return rb_tree_do_put(tree, key, true);
}

static inline struct word_tree_node *rb_tree_put_if_absent(rb_tree_t **const tree, const alphabeth_size_t key)
{
  return rb_tree_do_put(tree, key, false);
}

static inline word_tree_t *new_word_tree()
{
  word_tree_t *ref = malloc(sizeof(*ref));
#ifdef DEBUG
  if(ref == NULL)
  {
    printf("Couldn't allocate word_tree_t\n");
    exit(-3);
    return NULL;
  }
#endif

  ref->_children_or_expanded = (unsigned long) new_rb_tree();
  ref->deletion_level = 1;
  return ref;
}

static inline bool word_tree_is_expanded(const word_tree_t *const node)
{
  return node->_children_or_expanded & 3;
}

static inline 
struct expanded_word_tree_node *word_tree_get_expanded(const word_tree_t *const node)
{
  if(!word_tree_is_expanded(node))
    return NULL;

  return (struct expanded_word_tree_node*) (node->_children_or_expanded & ~3);
}

static inline 
bool word_tree_expanded_is_invalidated(const struct expanded_word_tree_node *const expanded,
                                       const deletion_level_t deletion_level)
{
  return expanded->non_deleted_deletion_level < deletion_level;
}

static inline 
void word_tree_set_deletion_level_if_expanded(word_tree_t *const node, 
                                              const deletion_level_t deletion_level)
{
  struct expanded_word_tree_node *expanded = word_tree_get_expanded(node);
  if(expanded == NULL)
    return;
  
  expanded->non_deleted_deletion_level = deletion_level;
}

static inline
void word_tree_undelete_child_if_expanded(word_tree_t *const node,
                                          const word_tree_t *const child,
                                          const deletion_level_t deletion_level)
{
  struct expanded_word_tree_node *expanded = word_tree_get_expanded(node);
  if(expanded == NULL || word_tree_expanded_is_invalidated(expanded, deletion_level))
    return;

  size_t arr_max_len = sizeof(expanded->non_deleted_children) / sizeof(expanded->non_deleted_children[0]);
  if(expanded->non_deleted_size >= arr_max_len)
    return;

  int (*node_pointer_cmp)(const void*, const void*) = LAMBDA(int, (const void *o1, const void *o2) {
    return (*((word_tree_t**) o1))->alphabeth_pos - (*((word_tree_t**) o2))->alphabeth_pos;
  });

  word_tree_t *found = bsearch(
      &child,
      expanded->non_deleted_children,
      expanded->non_deleted_size,
      sizeof(expanded->non_deleted_children[0]),
      node_pointer_cmp);
  if(found != NULL)
    return;

  expanded->non_deleted_children[expanded->non_deleted_size++] = (word_tree_t*) child;
  qsort(
      expanded->non_deleted_children,
      expanded->non_deleted_size,
      sizeof(expanded->non_deleted_children[0]),
      node_pointer_cmp);
}

static inline rb_tree_t *word_tree_children(const word_tree_t *const node)
{
  struct expanded_word_tree_node *expanded = word_tree_get_expanded(node); 
  if(expanded == NULL)
    return (rb_tree_t*) (node->_children_or_expanded & ~3); 
  return expanded->children;
}

static inline void word_tree_put_children(word_tree_t *const node,
                                          const rb_tree_t *children)
{
  struct expanded_word_tree_node *expanded = word_tree_get_expanded(node);
  if(expanded == NULL)
  {
    node->_children_or_expanded = (unsigned long) children;
    return;
  }

  expanded->children = (rb_tree_t*) children;
}

static inline void word_tree_expand(word_tree_t *const node)
{
  if(word_tree_is_expanded(node))
    return;

  struct expanded_word_tree_node *expanded = malloc(sizeof(*expanded));
  expanded->children = (rb_tree_t*) node->_children_or_expanded;
  expanded->non_deleted_size = 0;
  expanded->non_deleted_deletion_level = 0;
  node->_children_or_expanded = ((unsigned long) expanded) | 1;
}

static inline void word_tree_expanded_free(word_tree_t *tree,
                                           struct expanded_word_tree_node *expanded)
{
  if(expanded == NULL)
    return;

  rb_tree_free(word_tree_children(tree));
  free(expanded);
}

static inline void word_tree_free(word_tree_t *tree)
{
  if(tree == NULL)
    return;

  if(word_tree_is_expanded(tree))
    word_tree_expanded_free(tree, word_tree_get_expanded(tree));
  else
    rb_tree_free(word_tree_children(tree));
  free(tree);
}

/* O(len) */
static bool word_tree_contains(const word_tree_t *const tree, const char *const str)
{
  const word_tree_t *subtree = tree;
  for(size_t i = 0; str[i]; ++i)
  {
    const word_tree_t *child = rb_tree_get(
        word_tree_children(subtree), char_to_pos(str[i]));
    if(child == NULL)
      return false;

    subtree = child;
  }

  return true;
}

static bool word_tree_push_helper(word_tree_t *const tree, 
                                  const char *const str, 
                                  const deletion_level_t deletion_level,
                                  const size_t i)
{
  if(!str[i])
    // Undeletion shouldn't matter if it's already present, 
    // words can't be duped (I think)
    return true; 

  alphabeth_size_t pos = char_to_pos(str[i]);
  if(pos == -1)
    return false;

  rb_tree_t *children = word_tree_children(tree);
  word_tree_t *child = rb_tree_put_if_absent(&children, pos);
  word_tree_put_children(tree, children);

  // Should still be O(logn), accurate enough
  int height_hint = 0;
  for(rb_tree_t *curr = children; curr; curr = curr->left)
    height_hint++;

  int size_hint = 1 << height_hint; // pow(2, height_hint)
  if(size_hint >= ALPHABETH_SIZE / 2)
    word_tree_expand(tree);

  bool res = word_tree_push_helper(child, str, deletion_level, i + 1);
  if(res)
  {
    tree->deletion_level = 0;
    word_tree_undelete_child_if_expanded(tree, child, deletion_level);
  }
  return res;
}

static inline bool word_tree_push(word_tree_t *const tree, const char *const str)
{
  deletion_level_t root_deletion_level = tree->deletion_level;
  bool res = word_tree_push_helper(tree, str, root_deletion_level, 0);
  // Make sure it's not reset to 0
  tree->deletion_level = root_deletion_level;
  return res;
}

typedef enum {
  VISIT_SUBTREE = 1,
  SKIP_SUBTREE = 2,
  MARK_KEPT = 3,
  MARK_DELETED = 4,
} __attribute__ ((__packed__)) iter_res_t;

struct word_tree_for_each_params 
{
  size_t len; 
  deletion_level_t deletion_level; 
  const char *hint;
  
  char *curr_str; 
  int curr_freq[ALPHABETH_SIZE];

  iter_res_t (*filter)(size_t, char, alphabeth_size_t, int);
  iter_res_t (*word_func)(char*, int*);
};

static 
void word_tree_for_each_ordered_helper(word_tree_t *const, 
                                       struct word_tree_for_each_params *const, 
                                       const size_t pos);

static
bool word_tree_for_each_ordered_visitor(const alphabeth_size_t alphabeth_pos, 
                                        word_tree_t *const child,
                                        struct expanded_word_tree_node *const expanded,
                                        bool any_not_deleted,
                                        struct word_tree_for_each_params *const params, 
                                        const size_t pos)
{
  char c = pos_to_char(alphabeth_pos);
  iter_res_t filter_res = params->filter(pos, c, alphabeth_pos, params->curr_freq[alphabeth_pos] + 1);
  if(filter_res == SKIP_SUBTREE)
    return any_not_deleted;

  if(filter_res == MARK_DELETED)
  {
    child->deletion_level = params->deletion_level;
    return any_not_deleted;
  }

  params->curr_str[pos] = c;
  if(pos + 1 < params->len)
  {
    params->curr_freq[alphabeth_pos]++;
    word_tree_for_each_ordered_helper(child, params, pos + 1);
    params->curr_freq[alphabeth_pos]--;
  }
  else
  {
    params->curr_freq[alphabeth_pos]++;
    if(params->word_func(params->curr_str, params->curr_freq) == MARK_DELETED)
      child->deletion_level = params->deletion_level;
    params->curr_freq[alphabeth_pos]--;
  }

  if(child->deletion_level < params->deletion_level)
  {
    if(expanded)
      expanded->non_deleted_children[expanded->non_deleted_size++] = child;
    any_not_deleted = true;
  }

  return any_not_deleted;
}

static
void word_tree_for_each_ordered_helper(word_tree_t *const tree, 
                                       struct word_tree_for_each_params *const params, 
                                       const size_t pos)
{
  struct expanded_word_tree_node *expanded = word_tree_get_expanded(tree);

  bool any_not_deleted = false;
  void (*visit_func)(alphabeth_size_t, word_tree_t*) = LAMBDA(void, (alphabeth_size_t i, word_tree_t *child) {
    any_not_deleted = word_tree_for_each_ordered_visitor(
        i, child, expanded, any_not_deleted, params, pos);
  });

  if(params->hint != NULL && params->hint[pos] != 0)
  {
    alphabeth_size_t hint_pos = char_to_pos(params->hint[pos]);
    word_tree_t *child;
    
    bool is_expanded = expanded != NULL && !word_tree_expanded_is_invalidated(expanded, params->deletion_level);
    if(is_expanded && expanded->non_deleted_size <= 1)
    {
      child = expanded->non_deleted_size == 0 ? NULL :
        expanded->non_deleted_children[0]->alphabeth_pos != hint_pos ? NULL :
          expanded->non_deleted_children[0]; 
    }
    else if(is_expanded)
    {
      word_tree_t lookup = { .alphabeth_pos = hint_pos };
      word_tree_t *lookup_ptr = &lookup;
      child = bsearch(
          &lookup_ptr,
          expanded->non_deleted_children,
          expanded->non_deleted_size,
          sizeof(expanded->non_deleted_children[0]),
          LAMBDA(int, (const void* o1, const void* o2) {
            return (*((word_tree_t**) o1))->alphabeth_pos - (*((word_tree_t**) o2))->alphabeth_pos;
          }));
    }
    else
    {
      child = rb_tree_get(word_tree_children(tree), hint_pos);
    }

    if(child != NULL)
    {
      if(expanded)
        expanded->non_deleted_size = 0;
      visit_func(hint_pos, child);
    }
    
    word_tree_set_deletion_level_if_expanded(tree, params->deletion_level);
  }
  else if(expanded != NULL && !word_tree_expanded_is_invalidated(expanded, params->deletion_level))
  {
    size_t len = expanded->non_deleted_size;
    expanded->non_deleted_size = 0;

    for(size_t i = 0; i < len; ++i)
    {
      word_tree_t *child = expanded->non_deleted_children[i];
      visit_func(child->alphabeth_pos, child);
    }
  }
  else
  {
    if(expanded)
      expanded->non_deleted_size = 0;
    rb_tree_for_each_ordered(word_tree_children(tree), params->deletion_level, visit_func);
    word_tree_set_deletion_level_if_expanded(tree, params->deletion_level);
  }

  if(!any_not_deleted)
    tree->deletion_level = params->deletion_level;
}

static inline
void word_tree_for_each_ordered(word_tree_t *const tree, 
                                const size_t len, const char *const hint,
                                iter_res_t (*filter)(size_t, char, alphabeth_size_t, int), 
                                iter_res_t (*word_func)(char*, int*))
{
  struct word_tree_for_each_params params;
  params.len = len;
  params.deletion_level = tree->deletion_level;
  params.hint = hint;

  char word[len + 1];
  word[len] = '\0';
  params.curr_str = word; 
  memset(params.curr_freq, 0, sizeof(params.curr_freq));

  params.filter = filter;
  params.word_func = word_func;

  word_tree_for_each_ordered_helper(tree, &params, 0);
}

static inline void word_tree_undelete_all(word_tree_t *const tree)
{
  tree->deletion_level++;
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

#define BITSET_SIZE(size) (((size) + 7) / 8)
typedef unsigned char bitset_t;

static inline
void bitset_set(bitset_t bitset[], size_t pos, bool val)
{
  if(val)
    bitset[pos / 8] |= (1 << (pos % 8));
  else
    bitset[pos / 8] &= ~(1 << (pos % 8));
}

static inline
bool bitset_test(bitset_t bitset[], size_t pos)
{
  return (bitset[pos / 8] & (1 << (pos % 8)));
}

typedef struct
{
  const char *word;
  size_t len;
  int freq[ALPHABETH_SIZE];
  char *found_chars;
  bitset_t (*found_not_chars)[BITSET_SIZE(ALPHABETH_SIZE)];
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

static iter_res_t known_chars_filter(const reference_t *const ref,
                                     const size_t pos, 
                                     const char c, 
                                     const alphabeth_size_t alphabeth_pos, 
                                     const int char_freq)
{
  if(ref->found_freq_max[alphabeth_pos] >= 0 && char_freq > ref->found_freq_max[alphabeth_pos])
    return MARK_DELETED;
  if(bitset_test(ref->found_not_chars[pos], alphabeth_pos))
    return MARK_DELETED;
  return VISIT_SUBTREE;
}

static iter_res_t words_filter(const reference_t *const ref, 
                               const char *const str, 
                               const int *const freq)
{
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
                       word_tree_t *const tree, 
                       void (*func)(char*))
{
  // O(n)
  word_tree_for_each_ordered(tree, ref->len, ref->found_chars, 
      LAMBDA(iter_res_t, (size_t pos, char c, alphabeth_size_t alphabeth_pos, int char_freq) { 
        return known_chars_filter(ref, pos, c, alphabeth_pos, char_freq);
      }), 
      LAMBDA(iter_res_t, (char *str, int *freq) {
        iter_res_t res = words_filter(ref, str, freq);
        if(res == MARK_KEPT)
          func(str);
        return res;
      }));
}

static void populate_dictionary(word_tree_t *const tree, 
                                const size_t len, 
                                const char *const stop_command)
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
  if(scanf("%ld", &len) < 0)
  {
    printf("Failed to read len\n");
    return -50;
  }

  if(len <= 0)
    return 0;
  
  char *out = malloc((len + 1) * sizeof(char));
  out[len] = '\0';

  size_t last_size = -1;

  word_tree_t *tree = new_word_tree();
  populate_dictionary(tree, len, "+nuova_partita");
 
  for(bool quit = false; !quit; )
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

    word_tree_undelete_all(tree);
    
    char line[MAX(len, 32) + 1];
   
    int tries = 0;
    bool game_over = false;
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
        game_over = true;
      }
      else if(!word_tree_contains(tree, line)) 
      {
        printf("not_exists\n");
      }
      else
      {
        bool changed = compare_words(&ref, line, out);
        printf("%s\n", out);

        if(last_size == -1 || changed)
        {
          last_size = 0;
          filter_dictionary(&ref, tree, LAMBDA(void, (char *str) { last_size++; }));
        }
        printf("%ld\n", last_size);

        if(++tries >= max_guesses)
        {
          printf("ko\n");
          game_over = true;
        }
      }
    }

quit_program:
    quit = true;
new_game:
    ref_dispose(&ref);
  }

  free(out);
  // word_tree_free(tree);
  return 0;
}
