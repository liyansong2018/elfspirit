#include <elf.h>
#include "common.h"
#include "parse.h"

extern struct MyStr g_dynsym;
extern parser_opt_t po;

// compute symbol hash
uint32_t dl_new_hash(const char* name) {
    uint32_t h = 5381;

    for (unsigned char c = *name; c != '\0'; c = *++name) {
        h = h * 33 + c;
    }

    return h & 0xffffffff;
}

/* 重新计算hash表 */
/* Mainly inspired from LIEF */
int set_hash_table32(char *elf_name) {
    uint32_t size;
    uint32_t offset;
    int seg_i;
    int ret;
    offset = get_section_offset(elf_name, ".gnu.hash");
    size =  get_section_size(elf_name, ".gnu.hash");
    gnuhash_t *src_gnuhash = malloc(size);
    if (!src_gnuhash) {
        return -1;
    }

    memset(src_gnuhash, 0, size);
    ret = read_file_offset(elf_name, offset, size, &src_gnuhash);
    if (ret == -1) {
        free(src_gnuhash);
        return -1;
    }

    /* init symbol string table*/
    parse(elf_name, &po, 0);

    size = 4 * sizeof(uint32_t) +                           // header
            src_gnuhash->maskbits * 4 +                     // bloom filters
            src_gnuhash->nbuckets * sizeof(uint32_t) +      // buckets
            (g_dynsym.count - src_gnuhash->symndx) * sizeof(uint32_t); // hash values

    gnuhash_t *raw_gnuhash = malloc(size);
    if (!raw_gnuhash) {
        free(src_gnuhash);
        return -1;
    }
    memset(raw_gnuhash, 0, size);
    
    /* set header */
    raw_gnuhash->nbuckets = src_gnuhash->nbuckets;
    raw_gnuhash->symndx =  src_gnuhash->symndx;
    raw_gnuhash->maskbits =  src_gnuhash->maskbits;
    raw_gnuhash->shift =  src_gnuhash->shift;

    /* compute bloom filter */
    size_t bloom_size = sizeof(uint32_t) * raw_gnuhash->maskbits;
    uint32_t *bloom_filters = malloc(bloom_size);
    if (!bloom_filters) {
        free(src_gnuhash);
        free(raw_gnuhash);
        return -1;
    }
    memset(bloom_filters, 0, bloom_size);
    size_t C = 32;          // 32 for ELF, 64 for ELF64

    for (size_t i = raw_gnuhash->symndx; i < g_dynsym.count; ++i) {
        const uint32_t hash = dl_new_hash(g_dynsym.name[i]);
        const size_t pos = (hash / C) & (raw_gnuhash->maskbits - 1);
        uint32_t tmp = 1;   // 32 for ELF, 64 for ELF64
        uint32_t V = (tmp << (hash % C)) |
                (tmp << ((hash >> raw_gnuhash->shift) % C));
        bloom_filters[pos] |= V;
    }
    for (size_t idx = 0; idx < raw_gnuhash->maskbits; ++idx) {
        DEBUG("Bloom filter [%d]: 0x%x\n", idx, bloom_filters[idx]);
    }

    uint32_t *bloom_filters_raw = raw_gnuhash->buckets;
    memcpy(bloom_filters_raw, bloom_filters, bloom_size);

    /* set buckets */
    int previous_bucket = -1;
    size_t hash_value_idx = 0;
    size_t buckets_size = sizeof(uint32_t) * raw_gnuhash->nbuckets;
    size_t hash_chain_size = sizeof(uint32_t) * (g_dynsym.count - raw_gnuhash->symndx);
    uint32_t *buckets = malloc(buckets_size);
    uint32_t *hash_chain = malloc(hash_chain_size);
    memset(buckets, 0, buckets_size);
    memset(hash_chain, 0, hash_chain_size);

    for (size_t i = raw_gnuhash->symndx; i < g_dynsym.count; ++i) {
        DEBUG("Dealing with symbol %s", g_dynsym.name[i]);
        const uint32_t hash = dl_new_hash(g_dynsym.name[i]);
        int bucket = hash % raw_gnuhash->nbuckets;

        if (bucket < previous_bucket) {
            ERROR("Previous bucket is greater than the current one (%s < %s)",
                    bucket, previous_bucket);
            return 0;
        }

        if (bucket != previous_bucket) {
            buckets[bucket] = i;
            previous_bucket = bucket;
            if (hash_value_idx > 0) {
                hash_chain[hash_value_idx - 1] |= 1;
            }
        }

        hash_chain[hash_value_idx] = hash & ~1;
        ++hash_value_idx;
    }

    if (hash_value_idx > 0) {
        hash_chain[hash_value_idx - 1] |= 1;
    }

    uint32_t *buckets_raw = &bloom_filters_raw[raw_gnuhash->maskbits];
    memcpy(buckets_raw, buckets, buckets_size);
    uint32_t *hash_chain_raw = &buckets_raw[raw_gnuhash->nbuckets];
    memcpy(hash_chain_raw, hash_chain, hash_chain_size);

    /* add hash table*/
    seg_i = add_hash_segment(elf_name, raw_gnuhash, size);

    free(hash_chain);
    free(buckets);
    free(bloom_filters);
    free(raw_gnuhash);
    free(src_gnuhash);
    return 0;
}

int set_hash_table64(char *elf_name) {
    uint64_t size;
    uint64_t offset;
    int seg_i;
    int ret;
    offset = get_section_offset(elf_name, ".gnu.hash");
    size =  get_section_size(elf_name, ".gnu.hash");
    gnuhash_t *src_gnuhash = malloc(size);
    if (!src_gnuhash) {
        return -1;
    }

    memset(src_gnuhash, 0, size);
    ret = read_file_offset(elf_name, offset, size, &src_gnuhash);
    if (ret == -1) {
        free(src_gnuhash);
        return -1;
    }

    /* init symbol string table*/
    parse(elf_name, &po, 0);

    size = 4 * sizeof(uint32_t) +                           // header
            src_gnuhash->maskbits * 8 +                     // bloom filters
            src_gnuhash->nbuckets * sizeof(uint32_t) +      // buckets
            (g_dynsym.count - src_gnuhash->symndx) * sizeof(uint32_t); // hash values

    gnuhash_t *raw_gnuhash = malloc(size);
    if (!raw_gnuhash) {
        free(src_gnuhash);
        return -1;
    }
    memset(raw_gnuhash, 0, size);
    
    /* set header */
    raw_gnuhash->nbuckets = src_gnuhash->nbuckets;
    raw_gnuhash->symndx =  src_gnuhash->symndx;
    raw_gnuhash->maskbits =  src_gnuhash->maskbits;
    raw_gnuhash->shift =  src_gnuhash->shift;

    /* compute bloom filter */
    size_t bloom_size = sizeof(uint64_t) * raw_gnuhash->maskbits;
    uint64_t *bloom_filters = malloc(bloom_size);
    if (!bloom_filters) {
        free(src_gnuhash);
        free(raw_gnuhash);
        return -1;
    }
    memset(bloom_filters, 0, bloom_size);
    size_t C = 64;          // 32 for ELF, 64 for ELF64

    for (size_t i = raw_gnuhash->symndx; i < g_dynsym.count; ++i) {
        const uint32_t hash = dl_new_hash(g_dynsym.name[i]);
        const size_t pos = (hash / C) & (raw_gnuhash->maskbits - 1);
        uint64_t tmp = 1;   // 32 for ELF, 64 for ELF64
        uint64_t V = (tmp << (hash % C)) |
                (tmp << ((hash >> raw_gnuhash->shift) % C));
        bloom_filters[pos] |= V;
    }
    for (size_t idx = 0; idx < raw_gnuhash->maskbits; ++idx) {
        DEBUG("Bloom filter [%d]: 0x%x\n", idx, bloom_filters[idx]);
    }

    uint64_t *bloom_filters_raw = raw_gnuhash->buckets;
    memcpy(bloom_filters_raw, bloom_filters, bloom_size);

    /* set buckets */
    int previous_bucket = -1;
    size_t hash_value_idx = 0;
    size_t buckets_size = sizeof(uint32_t) * raw_gnuhash->nbuckets;
    size_t hash_chain_size = sizeof(uint32_t) * (g_dynsym.count - raw_gnuhash->symndx);
    uint32_t *buckets = malloc(buckets_size);
    uint32_t *hash_chain = malloc(hash_chain_size);
    memset(buckets, 0, buckets_size);
    memset(hash_chain, 0, hash_chain_size);

    for (size_t i = raw_gnuhash->symndx; i < g_dynsym.count; ++i) {
        DEBUG("Dealing with symbol %s", g_dynsym.name[i]);
        const uint32_t hash = dl_new_hash(g_dynsym.name[i]);
        int bucket = hash % raw_gnuhash->nbuckets;

        if (bucket < previous_bucket) {
            ERROR("Previous bucket is greater than the current one (%s < %s)",
                    bucket, previous_bucket);
            return 0;
        }

        if (bucket != previous_bucket) {
            buckets[bucket] = i;
            previous_bucket = bucket;
            if (hash_value_idx > 0) {
                hash_chain[hash_value_idx - 1] |= 1;
            }
        }

        hash_chain[hash_value_idx] = hash & ~1;
        ++hash_value_idx;
    }

    if (hash_value_idx > 0) {
        hash_chain[hash_value_idx - 1] |= 1;
    }

    uint32_t *buckets_raw = &bloom_filters_raw[raw_gnuhash->maskbits];
    memcpy(buckets_raw, buckets, buckets_size);
    uint32_t *hash_chain_raw = &buckets_raw[raw_gnuhash->nbuckets];
    memcpy(hash_chain_raw, hash_chain, hash_chain_size);

    /* add hash table*/
    seg_i = add_hash_segment(elf_name, raw_gnuhash, size);

    free(hash_chain);
    free(buckets);
    free(bloom_filters);
    free(raw_gnuhash);
    free(src_gnuhash);
    return 0;
}