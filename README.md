This repository provides a single-header C implementation of a Bloom Filter. Bloom Filters are a space-efficient probabilistic data structure used for testing set membership, with the possibility of false positives but no false negatives.

### Features
	•	Single Header-Only: Just include bloom_filter.h in your project; no external library dependencies.
	•	Multiple Hash Functions: Uses two base hash functions (FNV-1a and DJB2) and mixes them to generate multiple hashes.
	•	Macro-Based API: Macros for:
	•	Creating and destroying Bloom Filter instances
	•	Adding items and checking membership
	•	Clearing, loading, and exporting filter state

### Quick Start:
	  1.	Clone or download this repository.
	  2.	Copy the bloom_filter.h file into your project’s include path.
	  3.	Include it in your C/C++ code:
	  4.	Use the provided macros to create a bloom filter, add items, and check membership.

```c
#include "bloom_filter.h"
```

### Example Usage

Below is a minimal C example demonstrating how to use the macros:
```c
#include <stdio.h>
#include <string.h>
#include "bloom_filter.h"

int main(void) {
    // 1. Create a Bloom Filter pointer with 1024 bits and 5 hash functions.
    bloom_filter_t *bf;
    BLOOM_FILTER_CREATE_PTR(bf, 1024, 5);
    if (bf == NULL) {
        fprintf(stderr, "Failed to create bloom filter.\n");
        return 1;
    }

    // 2. Add some data to the bloom filter.
    const char *someData = "Hello World";
    BLOOM_FILTER_ADD(*bf, someData, strlen(someData));

    // 3. Check if the data might be in the bloom filter.
    bool found = false;
    BLOOM_FILTER_CHECK(*bf, someData, strlen(someData), found);
    if (found) {
        printf("Data is possibly in the bloom filter.\n");
    } else {
        printf("Data is definitely NOT in the bloom filter.\n");
    }

    // 4. Destroy the bloom filter and free memory.
    BLOOM_FILTER_DESTROY_PTR(bf);
    return 0;
}
```
### Macros and Their Usage

#### Creation & Destruction
	BLOOM_FILTER_CREATE_PTR(var_name, bits, hcount)
Creates a new bloom_filter_t* called var_name with:
	•	bits: total number of bits (must be a multiple of 8).
	•	hcount: number of hash functions to apply.

```c
bloom_filter_t *my_bf;
BLOOM_FILTER_CREATE_PTR(my_bf, 1024, 5);
if (my_bf == NULL) {
    // handle error
}

```


•	BLOOM_FILTER_DESTROY_PTR(var_name)
Frees the memory allocated by BLOOM_FILTER_CREATE_PTR.
```c
BLOOM_FILTER_DESTROY_PTR(my_bf);
```


### Add & Check
•	BLOOM_FILTER_ADD(bf, data_ptr, data_len)
Adds an item (arbitrary bytes) to the filter.
	•	bf is a bloom_filter_t struct (not a pointer).
	•	data_ptr points to the data to add.
	•	data_len is the size of the data in bytes.

```c
const char *my_key = "ABC";
BLOOM_FILTER_ADD(*my_bf, my_key, strlen(my_key));
```

•	BLOOM_FILTER_CHECK(bf, data_ptr, data_len, out_bool)
Checks if an item might be in the set.
	•	bf is a bloom_filter_t struct (not a pointer).
	•	out_bool is a boolean variable that will be set:
	•	true => possibly in the set
	•	false => definitely not in the set

```c
bool result;
BLOOM_FILTER_CHECK(*my_bf, my_key, strlen(my_key), result);
if (result) {
    // possibly in set
} else {
    // definitely not in set
}
```


### Clearing
•	BLOOM_FILTER_CLEAR(bf)
Sets all bits in the Bloom Filter to 0.
```c
BLOOM_FILTER_CLEAR(*my_bf);
```


### Load & Export
	•	BLOOM_FILTER_LOAD(bf, src_bits, len)
Copies the raw bit array from src_bits (byte buffer) into the filter.
Allows you to load a previously saved Bloom Filter state.
```c
// Suppose you have some external storage or network buffer 'existing_bits'
BLOOM_FILTER_LOAD(*my_bf, existing_bits, my_bf->byte_size);
```

•	BLOOM_FILTER_EXPORT(bf, dest_bits, len)
Copies the Bloom Filter’s bit array into dest_bits.
Useful for saving the current filter state or transmitting it over a network.
```c
// Suppose 'buffer' is a byte array with at least bf->byte_size capacity
BLOOM_FILTER_EXPORT(*my_bf, buffer, bf->byte_size);
```


### How It Works
	1.	Hashing: Two base hash functions (FNV-1a and DJB2) are computed on the input data.
	2.	Hash Mixing: These are then “mixed” to generate a pseudo-unique series of hashes (up to hash_count times).
	3.	Bit Setting/Checking: Each hash mod the filter size corresponds to a specific bit index. For an “add,” that bit is set; for a “check,” that bit is tested.

Bloom Filters typically have a tunable false-positive rate determined by the filter size and the number of hash functions.

Notes and Considerations
* False Positives: Bloom filters may yield false positives (reporting membership when the item is not actually present). However, there are no false negatives.
* Memory Alignment: Ensure your bits parameter is a multiple of 8. Otherwise, the macro returns NULL.
* Thread-Safety: This implementation is not inherently thread-safe. Synchronize access if multiple threads share a filter.
* Non-Cryptographic Hashes: FNV-1a and DJB2 are fast, but not cryptographically secure.

Contributing

Contributions, bug reports, and feature requests are welcome. Please:
1. Fork the repo
2.	Create a branch for your changes
3.	Submit a Pull Request describing your changes

License

This header-only Bloom Filter is provided under the MIT License. You’re free to use it in both open-source and commercial projects, subject to the terms of that license.

Happy filtering! If you have any questions or suggestions, feel free to open an issue.
