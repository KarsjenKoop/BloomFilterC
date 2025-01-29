

#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/**
 * \brief Basic Bloom Filter structure:
 *   - bit_array: dynamically allocated array of bits
 *   - bit_size:  total number of bits
 *   - byte_size: bit_size/8
 *   - hash_count: how many hash functions are used
 *
 * This implementation uses macros for:
 *   - creation, destruction
 *   - load/export
 *   - add/check
 *   - clearing
 */
typedef struct {
    uint8_t *bit_array;
    size_t   bit_size;
    size_t   byte_size;
    int      hash_count;
} bloom_filter_t;

/* --------------------------------------------------------------------------
 *                             Helper Hash Macros
 * -------------------------------------------------------------------------- */

/**
 * \brief FNV-1a hash parameters
 */
#define FNV1A_HASH_INIT  (2166136261u)
#define FNV1A_HASH_PRIME (16777619u)

/**
 * \brief Compute a 32-bit FNV-1a hash into variable \p out_hash.
 *
 * Example usage:
 *   uint32_t my_hash;
 *   FNV1A_HASH(data_ptr, data_len, my_hash);
 */
#define FNV1A_HASH(data_ptr, data_len, out_hash)                                                \
do {                                                                                            \
    const uint8_t *_fnv_bytes = (const uint8_t *)(data_ptr);                                    \
    size_t _fnv_len = (size_t)(data_len);                                                       \
    uint32_t _fnv_hash = FNV1A_HASH_INIT;                                                       \
    for (size_t _i = 0; _i < _fnv_len; _i++) {                                                  \
        _fnv_hash ^= _fnv_bytes[_i];                                                            \
        _fnv_hash *= FNV1A_HASH_PRIME;                                                          \
    }                                                                                           \
    (out_hash) = _fnv_hash;                                                                     \
} while (0)

/**
 * \brief DJB2 hash
 */
#define DJB2_HASH(data_ptr, data_len, out_hash)                                                 \
do {                                                                                            \
    const uint8_t *_djb2_bytes = (const uint8_t *)(data_ptr);                                   \
    size_t _djb2_len = (size_t)(data_len);                                                      \
    uint32_t _djb2_hash = 5381;                                                                 \
    for (size_t _i = 0; _i < _djb2_len; _i++) {                                                 \
        _djb2_hash = ((_djb2_hash << 5) + _djb2_hash) + _djb2_bytes[_i];                        \
    }                                                                                           \
    (out_hash) = _djb2_hash;                                                                    \
} while (0)

/**
 * \brief A utility macro to 'mix' a base hash with a seed,
 *        producing a pseudo-distinct hash each time.
 */
#define HASH_MIX(base_hash, seed) \
    ((uint32_t)((base_hash) ^ (seed)) * (uint32_t)(0x9e3779b1))

/* --------------------------------------------------------------------------
 *                             Bit Manipulation
 * -------------------------------------------------------------------------- */

/**
 * \brief Sets the bit at index \p bit_index in bloom filter \p bf.
 */
#define BLOOM_FILTER_SET_BIT(bf, bit_index)                                                     \
do {                                                                                            \
    (bf).bit_array[(bit_index) / 8] |= (1U << ((bit_index) % 8));                               \
} while(0)

/**
 * \brief Tests (reads) the bit at index \p bit_index in bloom filter \p bf.
 *        Expands to a boolean expression (not a statement).
 */
#define BLOOM_FILTER_TEST_BIT(bf, bit_index)                                                    \
    (((bf).bit_array[(bit_index) / 8] & (1U << ((bit_index) % 8))) != 0)

/* --------------------------------------------------------------------------
 *                    Creating / Destroying Bloom Filter
 * -------------------------------------------------------------------------- */

/**
 * \brief Macro to create (allocate) a bloom_filter_t pointer named \p var_name.
 *
 * \param var_name   The name of the bloom_filter_t* variable to create.
 * \param bits       The total number of bits (multiple of 8).
 * \param hcount     Number of hash functions to apply.
 *
 * If allocation fails, \p var_name is set to NULL.
 */
#define BLOOM_FILTER_CREATE_PTR(var_name, bits, hcount)                                         \
do {                                                                                            \
    if ((hcount) <= 0) {                                                                        \
        (var_name) = NULL;                                                                      \
        break;                                                                                  \
    }                                                                                           \
    if ((bits) == 0 || ((bits) % 8) != 0) {                                                     \
        (var_name) = NULL;                                                                      \
        break;                                                                                  \
    }                                                                                           \
    (var_name) = (bloom_filter_t *)malloc(sizeof(bloom_filter_t));                              \
    if ((var_name) != NULL) {                                                                   \
        (var_name)->bit_size   = (bits);                                                        \
        (var_name)->byte_size  = (bits) / 8;                                                    \
        (var_name)->hash_count = (hcount);                                                      \
        (var_name)->bit_array  = (uint8_t *)malloc((var_name)->byte_size);                      \
        if (!(var_name)->bit_array) {                                                           \
            free(var_name);                                                                     \
            (var_name) = NULL;                                                                  \
        } else {                                                                                \
            memset((var_name)->bit_array, 0, (var_name)->byte_size);                            \
        }                                                                                       \
    }                                                                                           \
} while(0)

/**
 * \brief Macro to free a bloom_filter_t pointer created by BLOOM_FILTER_CREATE_PTR.
 *
 * \param var_name  The pointer to free.
 */
#define BLOOM_FILTER_DESTROY_PTR(var_name)                                                      \
do {                                                                                            \
    if ((var_name) != NULL) {                                                                   \
        free((var_name)->bit_array);                                                            \
        free(var_name);                                                                         \
        (var_name) = NULL;                                                                      \
    }                                                                                           \
} while(0)

/* --------------------------------------------------------------------------
 *                    Loading / Exporting Bloom Filter Data
 * -------------------------------------------------------------------------- */

/**
 * \brief Copies the raw bit array \p src_bits into the bloom filter \p bf,
 *        effectively "loading" an existing bloom filter state.
 *
 * \param bf       A bloom_filter_t struct (not a pointer).
 * \param src_bits Pointer to the source raw bytes.
 * \param len      The length in bytes of \p src_bits, which should match bf.byte_size.
 */
#define BLOOM_FILTER_LOAD(bf, src_bits, len)                                                    \
do {                                                                                            \
    if ((bf).bit_array != NULL && (src_bits) != NULL && ((size_t)(len)) == (bf).byte_size) {    \
        memcpy((bf).bit_array, (src_bits), (bf).byte_size);                                     \
    }                                                                                           \
} while(0)

/**
 * \brief Copies the bloom filter's internal bit array into \p dest_bits,
 *        allowing you to transmit or store it.
 *
 * \param bf        A bloom_filter_t struct (not a pointer).
 * \param dest_bits Destination buffer to copy into.
 * \param len       The size of the destination buffer in bytes (should match bf.byte_size).
 */
#define BLOOM_FILTER_EXPORT(bf, dest_bits, len)                                                 \
do {                                                                                            \
    if ((bf).bit_array != NULL && (dest_bits) != NULL && ((size_t)(len)) >= (bf).byte_size) {   \
        memcpy((dest_bits), (bf).bit_array, (bf).byte_size);                                    \
    }                                                                                           \
} while(0)

/* --------------------------------------------------------------------------
 *                         Clear / Add / Check
 * -------------------------------------------------------------------------- */

/**
 * \brief Clears all bits in the filter (sets them to 0).
 *
 * \param bf A bloom_filter_t struct (not a pointer!).
 *           If you have a pointer, do BLOOM_FILTER_CLEAR(*my_ptr).
 */
#define BLOOM_FILTER_CLEAR(bf) \
    memset((bf).bit_array, 0, (bf).byte_size)

/**
 * \brief Adds arbitrary data \p data_ptr of length \p data_len to bloom filter \p bf.
 *
 * Steps:
 *   - Compute 2 base hashes (FNV1A and DJB2).
 *   - For i in [0..(bf).hash_count-1], mix them to produce a unique pseudo-hash.
 *   - Set the corresponding bit in the filter.
 *
 * \param bf         A bloom_filter_t struct (not a pointer).
 * \param data_ptr   Pointer to the data to add.
 * \param data_len   Length (in bytes) of the data.
 */
#define BLOOM_FILTER_ADD(bf, data_ptr, data_len)                                                \
do {                                                                                            \
    if ((bf).bit_array != NULL && (data_ptr) != NULL && (data_len) > 0) {                       \
        uint32_t _hash1, _hash2;                                                                \
        FNV1A_HASH((data_ptr), (data_len), _hash1);                                             \
        DJB2_HASH((data_ptr), (data_len), _hash2);                                              \
        for (int _i = 0; _i < (bf).hash_count; _i++) {                                          \
            uint32_t _combined = HASH_MIX(_hash1, _i) ^ HASH_MIX(_hash2, _i+42);                \
            _combined %= (uint32_t)((bf).bit_size);                                             \
            BLOOM_FILTER_SET_BIT((bf), _combined);                                              \
        }                                                                                       \
    }                                                                                           \
} while(0)

/**
 * \brief Checks if \p data_ptr (of length \p data_len) might be in the bloom filter \p bf.
 *
 * \param bf         A bloom_filter_t struct (not a pointer).
 * \param data_ptr   Pointer to the data to check.
 * \param data_len   Length in bytes of data to check.
 * \param out_bool   A bool variable that will be assigned true/false result.
 *                   - true => data is possibly in the set
 *                   - false => data is definitely not in the set
 *
 * Example usage:
 *   bool found;
 *   BLOOM_FILTER_CHECK(my_bf, key, key_len, found);
 *   if (found) { ... }
 */
#define BLOOM_FILTER_CHECK(bf, data_ptr, data_len, out_bool)                                    \
do {                                                                                            \
    (out_bool) = false;                                                                         \
    if ((bf).bit_array != NULL && (data_ptr) != NULL && (data_len) > 0) {                       \
        bool _present = true;                                                                   \
        uint32_t _hash1, _hash2;                                                                \
        FNV1A_HASH((data_ptr), (data_len), _hash1);                                             \
        DJB2_HASH((data_ptr), (data_len), _hash2);                                              \
        for (int _i = 0; _i < (bf).hash_count; _i++) {                                          \
            uint32_t _combined = HASH_MIX(_hash1, _i) ^ HASH_MIX(_hash2, _i+42);                \
            _combined %= (uint32_t)((bf).bit_size);                                             \
            if (!BLOOM_FILTER_TEST_BIT((bf), _combined)) {                                      \
                _present = false;                                                               \
                break;                                                                          \
            }                                                                                   \
        }                                                                                       \
        (out_bool) = _present;                                                                  \
    }                                                                                           \
} while(0)

#endif // BLOOM_FILTER_H