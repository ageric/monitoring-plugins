#include <unistd.h>
#include <stdlib.h>

/**
 * @file bitmap.h
 * @brief Bit map API
 *
 * The bitmap api is useful for running set operations on objects
 * indexed by unsigned integers.
 * @{
 */
struct bitmap;
typedef struct bitmap bitmap;

/**
 * Resize a bitmap
 * If the bitmap is made smaller, data will silently be lost.
 *
 * @param bm The bitmap to resize
 * @param size The new desired size of the bitmap
 * @return 0 on success, -1 on errors.
 */
extern int bitmap_resize(bitmap *bm, unsigned long size);

/**
 * Create a bitmap of size 'size'
 * @param size Desired storage capacity
 * @return A bitmap pointer on success, NULL on errors
 */
extern bitmap *bitmap_create(unsigned long size);

/**
 * Destroy a bitmap by freeing all the memory it uses
 * @param bm The bitmap to destroy
 */
extern void bitmap_destroy(bitmap *bm);

/**
 * Copy a bitmap
 * @param bm The bitmap to copy
 * @return Pointer to an identical bitmap on success, NULL on errors
 */
extern bitmap *bitmap_copy(const bitmap *bm);

/**
 * Set a bit in the map
 * @param bm The bitmap to operate on
 * @param pos Position of the bit to set
 * @return 0 on success, -1 on errors
 */
extern int bitmap_set(bitmap *bm, unsigned long pos);

/**
 * Check if a particular bit is set in the map
 * @param bm The bitmap to check
 * @param pos Position of the bit to check
 * @return 1 if set, otherwise 0
 */
extern int bitmap_isset(const bitmap *bm, unsigned long pos);

/**
 * Unset a particular bit in the map
 * @param bm The bitmap to operate on
 * @param pos Position of the bit to unset
 */
extern int bitmap_unset(bitmap *bm, unsigned long pos);

/**
 * Obtain cardinality (max number of elements) of the bitmap
 * @param bm The bitmapt to check
 * @return The cardinality of the bitmap
 */
extern unsigned long bitmap_cardinality(const bitmap *bm);
#define bitmap_size bitmap_cardinality

/**
 * Count set bits in map. Completed in O(n/8) time.
 * @param bm The bitmap to count bits in
 * @return The number of set bits
 */
extern unsigned long bitmap_count_set_bits(const bitmap *bm);

/**
 * Count unset bits in map. Completed in O(n/8) time.
 * @param bm The bitmap to count bits in
 * @return The number of set bits
 */
extern unsigned long bitmap_count_unset_bits(const bitmap *bm);

/**
 * Unset all bits in a bitmap
 * @param bm The bitmap to clear
 */
extern void bitmap_clear(bitmap *bm);

/**
 * Calculate intersection of two bitmaps
 * The intersection is defined as all bits that are members of
 * both A and B. It's equivalent to bitwise AND.
 * This function completes in O(n/sizeof(long)) operations.
 * @param a The first bitmap
 * @param b The second bitmap
 * @return NULL on errors; A newly created bitmap on success.
 */
extern bitmap *bitmap_intersect(const bitmap *a, const bitmap *b);

/**
 * Calculate union of two bitmaps
 * The union is defined as all bits that are members of
 * A or B or both A and B. It's equivalent to bitwise OR.
 * This function completes in O(n/sizeof(long)) operations.
 * @param a The first bitmap
 * @param b The second bitmap
 * @return NULL on errors; A newly created bitmap on success.
 */
extern bitmap *bitmap_union(const bitmap *a, const bitmap *b);

/**
 * Calculate union of two bitmaps and store result in one of them
 * @param res The first bitmap
 * @param addme The bitmap to unite to the first bitmap
 * @return NULL on errors, res on success
 */
extern bitmap *bitmap_unite(bitmap *res, const bitmap *addme);

/**
 * Calculate set difference between two bitmaps
 * The set difference of A / B is defined as all members of A
 * that isn't members of B. Note that parameter ordering matters
 * for this function.
 * This function completes in O(n/sizeof(long)) operations.
 * @param a The first bitmap (numerator)
 * @param b The first bitmap (denominator)
 * @return NULL on errors; A newly created bitmap on success.
 */
extern bitmap *bitmap_diff(const bitmap *a, const bitmap *b);

/**
 * Calculate symmetric difference between two bitmaps
 * The symmetric difference between A and B is the set that
 * contains all elements in either set but not in both.
 * This function completes in O(n/sizeof(long)) operations.
 * @param a The first bitmap
 * @param b The second bitmap
 */
extern bitmap *bitmap_symdiff(const bitmap *a, const bitmap *b);

/**
 * Compare two bitmaps for equality
 * @param a The first bitmap
 * @param b The other bitmap
 * @return Similar to memcmp(), with tiebreaks determined by cardinality
 */
extern int bitmap_cmp(const bitmap *a, const bitmap *b);
/** @} */

