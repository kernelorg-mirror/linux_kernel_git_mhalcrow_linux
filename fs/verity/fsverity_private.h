/*
 * fsverity.h: common declarations for per-file verity
 *
 * Copyright (C) 2017, Google, Inc.
 *
 * Written by Jaegeuk Kim, 2017.
 *  : lots of codes are borrowed from dm-verity.
 */

#ifndef _FSVERITY_PRIVATE_H
#define _FSVERITY_PRIVATE_H

#include <linux/fsverity.h>
#include <linux/workqueue.h>

#define FS_VERITY_MAGIC		"TrueBrew"
#define FS_VERITY_SALT_SIZE	8

struct fsverity_header {
	u8 magic[8];		/* Must be FS_VERITY_MAGIC */
	u8 maj_version;		/* Must be FS_VERITY_MAJOR */
	u8 min_version;		/* Must be FS_VERITY_MINOR */
	u8 log_blocksize;	/* log2(data-bytes-per-hash) - 12 for (4Kb) */
	u8 log_arity;	/* log2(leaves-per-node) (E.g., 7 for SHA2 ) */
	__le16 meta_algorithm;	/* Cryptographic digest for tree blocks */
	__le16 data_algorithm;	/* Cryptographic digest for data blocks */
	__le32 flags;		/* No flags for now */
	__le32 reserved1;	/* Must be 0 */
	__le64 size;		/* Size of the original, unpadded data. */
	/* The number of blocks from the start of this header where
	 * the authenticated data structure resides */
	u8 auth_blk_offset;
	u8 extension_count;	/* The number of extensions */
	u8 salt[FS_VERITY_SALT_SIZE];
	u8 reserved2[22];	/* Must be 0 */
	/* This structure is 64 bytes long */
} __packed;

struct fsverity_extension {
	__le16 length; /* The length (zero-padded to 64 bits) of the
			* extension item that follows aligned-up to 8 bytes */
	u8 type;
	u8 reserved[5];
} __packed;

struct fsverity_extension_elide {
	__le64 offset;
	__le64 length;
} __packed;

struct fsverity_extension_patch {
	__le64 offset;
	u8 length;
	u8 reserved[7];
	u8 databytes[];
} __packed;

/* Supported algorithms */
enum {
	CRC32_MODE = 0,
	SHA256_MODE,
	AVAIL_ALGS,
};

enum {
	DATA_INTEGRITY_VISIBLE,
};

#define FS_VERITY_MAX_LEVELS	64
#define FS_VERITY_BLOCK_BITS	12

struct fsverity_info {
	struct crypto_ahash *tfm;
	char *alg_name;		/* algorithm name */
	u16 meta_algorithm;		/* metadata hash algorithm */
	u16 data_algorithm;		/* data hash algorithm */

	char depth;		/* Depth of the merkle tree */
	u32 flags;		/* flags */
	u8 salt[8];		/* Used to salt the hash */

	size_t i_size;		/* original data i_size */
	size_t verity_i_size;	/* i_size including verity metadata */
	size_t tree_size;	/* Size of the tree */
	unsigned hashes_per_block_bits;	/* log_2(blk_sz / hash_sz) */

	bool root_hashed;
	char root_hash[SHA256_DIGEST_SIZE];	/* Merkle tree root hash */
	bool fail;		/* File authenticity check failed */

	/* starting blocks for each tree level. 0 is the lowest level. */
	sector_t hash_lvl_region_idx[FS_VERITY_MAX_LEVELS];
} __packed;

extern struct workqueue_struct *fsverity_read_workqueue;

#endif /* _FSVERITY_PRIVATE_H */
