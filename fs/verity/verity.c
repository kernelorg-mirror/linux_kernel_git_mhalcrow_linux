/*
 * Read-only file-based authenticity.
 *
 * Copyright (C) 2018, Google, Inc.
 *
 * This contains file-based verity functions.
 *
 * Written by Jaegeuk Kim and Michael Halcrow.
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/list.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include "fsverity_private.h"

struct workqueue_struct *fsverity_read_workqueue;
struct kmem_cache *fsverity_info_cachep;

static bool __is_verity_doable(struct inode *inode)
{
	if (!inode->i_sb)
		return false;
	if (!inode->i_sb->s_vop)
		return false;
	if (!inode->i_sb->s_vop->is_verity)
		return false;
	if (!inode->i_sb->s_vop->set_verity)
		return false;
	if (!inode->i_sb->s_vop->read_file_page)
		return false;
	return true;
}


static int __sanity_check_header(struct fsverity_header *header)
{
	if (memcmp(header->magic, FS_VERITY_MAGIC, 8)) {
		return -EINVAL;
	}
	if (header->maj_version != 1) {
		return -EINVAL;
	}
	if (header->min_version != 0) {
		return -EINVAL;
	}
	if (header->log_blocksize != FS_VERITY_BLOCK_BITS) {
		return -EINVAL;
	}
	if (le16_to_cpu(header->data_algorithm) != SHA256_MODE ||
	    le16_to_cpu(header->meta_algorithm) != SHA256_MODE) {
		return -EINVAL;
	}
	return 0;
}

static int __measure_fs_verity_root_hash(
	struct fsverity_info *vi, const char *root, const char *hdr_virt,
	unsigned hdr_len, const struct fsverity_root_hash *root_hash,
	struct crypto_shash *tfm, char *salt)
{
	char fsverity_root_hash[SHA256_DIGEST_SIZE];
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;

	desc->tfm = tfm;
	desc->flags = 0;

	err = crypto_shash_init(desc);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing tree: "
				    "init returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_update(desc, salt, FS_VERITY_SALT_SIZE);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing root salt: "
				    "update 1 returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_update(desc, root, PAGE_SIZE);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing root: "
				    "update 2 returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_final(desc, vi->root_hash);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing root: "
				    "final returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_init(desc);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing header: "
				    "init returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_update(desc, hdr_virt, hdr_len);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing header "
				    ": update 1 returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_update(desc, vi->root_hash, SHA256_DIGEST_SIZE);
	if (err) {
		pr_warn_ratelimited("fsverity: Error hashing root hash "
				    ": update 2 returned [%d]\n", err);
		goto out;
	}
	err = crypto_shash_final(desc, fsverity_root_hash);
	if (err) {
		pr_warn_ratelimited("fsverity: Error finalizing fsverity "
				    "root hash: final returned [%d]\n", err);
		goto out;
	}
	/* TODO(mhalcrow): Drop support for this behavior from the
	 * prototype once we have root-of-trust wired in. */
	if (!root_hash) {
		pr_warn_ratelimited("fsverity: WARNING: root_hash not "
				    "present. No root-of-trust validation of "
				    "the hashes being done.\n");
		goto out;
	}
	if (crypto_memneq(root_hash->root_hash, fsverity_root_hash,
			  SHA256_DIGEST_SIZE)) {
		err = -EINVAL;
	}
out:
	return err;
}

static int __full_header_size(const char *hdr_virt)
{
	const struct fsverity_header *header;
	unsigned ext_pos = 0;
	u8 extension_count;

	header = (struct fsverity_header *)hdr_virt;
	ext_pos = sizeof(struct fsverity_header);
	if (!(le32_to_cpu(header->flags) & 1))	/* No extensions */
		goto out;
	extension_count = header->extension_count;
	if (extension_count == 0) {
		printk(KERN_WARNING "%s: Extension flag set, but extension "
		       "count is 0\n", __func__);
		goto out;
	}
	do {
		struct fsverity_extension *ext;

		if (ext_pos + sizeof(struct fsverity_extension) > PAGE_SIZE) {
			ext_pos = 0;
			goto out;
		}
		ext = (struct fsverity_extension *)&hdr_virt[ext_pos];
		ext_pos = ext_pos + le16_to_cpu(ext->length);
		if (ext_pos > PAGE_SIZE) {
			ext_pos = 0;
			goto out;
		}
		extension_count--;
	} while (extension_count > 0);
out:
	return ext_pos;
}

static void __set_depth_and_hashes_per_blk(struct fsverity_info *info)
{
	unsigned block_size = PAGE_SIZE;
	loff_t data_blocks = (info->i_size + (block_size - 1)) / block_size;
	unsigned block_bits = __ffs(block_size);
	unsigned digest_size = SHA256_DIGEST_SIZE;
	unsigned digests_per_block = (1 << block_bits) / digest_size;
	unsigned hash_per_block_bits = __ffs(digests_per_block);
	unsigned levels = 0;

	while (hash_per_block_bits * levels < 64 &&
	       (unsigned long long)(data_blocks - 1) >>
	       (hash_per_block_bits * levels)) {
		levels++;
	}
	info->depth = levels;
	info->hashes_per_block_bits = hash_per_block_bits;
}

/**
 *
 *
 * Return: Real size of the file, including header and tree content
 */
static loff_t __set_hash_lvl_region_idxs(struct fsverity_info *info)
{
	unsigned i;
	loff_t tree_lvl_start_block;
	loff_t tree_lvl_region_nr_blocks;

	/* TODO(mhalcrow): This is pre-header-on-end-only 
	tree_lvl_start_block = ((info->i_size + (PAGE_SIZE - 1)) / PAGE_SIZE)
		+ 1;
	*/
	/* TODO(mhalcrow): Isn't there a round-up macro in the kernel? */
	tree_lvl_start_block = ((info->i_size + (PAGE_SIZE - 1)) / PAGE_SIZE);
	tree_lvl_region_nr_blocks = 1;
	for (i = 0; i < info->depth; i++) {
		info->hash_lvl_region_idx[i] = tree_lvl_start_block;
		tree_lvl_start_block += tree_lvl_region_nr_blocks;
		tree_lvl_region_nr_blocks <<= info->hashes_per_block_bits;
	}
	if (info->depth > 0) {
		loff_t start_last_region =
			info->hash_lvl_region_idx[info->depth - 1];
		loff_t hashes_in_last_region =
			(info->i_size + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
		loff_t hashes_per_block = 1 << info->hashes_per_block_bits;
		loff_t num_blocks_last_region =
			(hashes_in_last_region + (hashes_per_block - 1)) >>
			info->hashes_per_block_bits;
		loff_t last_region_size = num_blocks_last_region * PAGE_SIZE;
		info->tree_size =
			((start_last_region - info->hash_lvl_region_idx[0]) *
			 PAGE_SIZE) + last_region_size;
	} else {
		info->tree_size = 0;
	}
	return tree_lvl_start_block << PAGE_SHIFT;
}

static int __read_fsverity_header(struct inode *inode,
				  struct fsverity_info *info,
				  const struct fsverity_root_hash *root_hash)
{
	struct fsverity_header *header;
	struct page *hdr_page = NULL;
	struct page *root_page = NULL;
	char *hdr_virt;
	char *root = NULL;
	unsigned hdr_len;
	loff_t last_off;
	__le16 root_hash_algo;
	__le32 hdr_reverse_offset;
	loff_t full_file_size;
	unsigned hdr_sz_offset_within_pg;
	struct crypto_shash *tfm = NULL;
	int err = 0;

	full_file_size = i_size_read(inode);
	/* TODO(mhalcrow): This logic only works with full-size Merkle
	 * trees that include all padding and/or when header/extent
	 * content fits in one page. */
	last_off = full_file_size >> PAGE_SHIFT;
	/* TODO(mhalcrow): ->read_locked_file_page() instead? */
	hdr_page = inode->i_sb->s_vop->read_file_page(inode, last_off, NULL);
	if (IS_ERR(hdr_page)) {
		printk_ratelimited(KERN_ERR "%s: can't find header block\n",
				   __func__);
		return PTR_ERR(hdr_page);
	}
	/* TODO(mhalcrow): What's keeping hdr_page from being evicted
	 * before the kmap()? Is it locked? If so, when should we
	 * unlock? */
	hdr_virt = kmap(hdr_page);
	hdr_sz_offset_within_pg =
		((full_file_size - sizeof(hdr_reverse_offset)) % PAGE_SIZE);
	hdr_reverse_offset = *((__le32*)&hdr_virt[hdr_sz_offset_within_pg]);
	/* TODO(mhalcrow): Great! Now we ignore hdr_reverse_offset
	 * because we know the header should immediately follow the
	 * page-aligned tree, and the size of the header fits within a
	 * page. When that's not longer the case, hdr_reverse_offset
	 * will matter. Maybe just validate it at this point? */
	header = (struct fsverity_header *)hdr_virt;
	err = __sanity_check_header(header);
	if (err) {
		printk_ratelimited(KERN_ERR "%s: fs-verity header failed "
				   "validation\n", __func__);
		goto put_out;
	}

	info->meta_algorithm = le16_to_cpu(header->meta_algorithm);
	info->data_algorithm = le16_to_cpu(header->data_algorithm);
	info->flags = le32_to_cpu(header->flags);
	info->i_size = le64_to_cpu(header->size);
	__set_depth_and_hashes_per_blk(info);
	info->verity_i_size = __set_hash_lvl_region_idxs(info);

	memcpy(info->salt, header->salt, FS_VERITY_SALT_SIZE);

	hdr_len = __full_header_size(hdr_virt);
	if (hdr_len == 0) {
		err = -EINVAL;
		goto put_out;
	}

	if (!root_hash) {
		/* TODO(mhalcrow): Drop support for root_hash-less
		 * mode of operation after prototype. */
		root_hash_algo = FS_VERITY_ROOT_HASH_ALGO_SHA256;
		if (!inode->i_verity_info)
			goto put_out;
	} else {
		root_hash_algo = le16_to_cpu(root_hash->root_hash_algorithm);
	}
	if (root_hash_algo != FS_VERITY_ROOT_HASH_ALGO_SHA256) {
		printk_ratelimited(KERN_ERR
				   "%s: Invalid fsverity root hash algo: "
				   "[%d]; expected [%d]\n", __func__,
				   root_hash_algo,
				   FS_VERITY_ROOT_HASH_ALGO_SHA256);
		err = -EINVAL;
		goto put_out;
	}

	/* TODO(mhalcrow): Skip past auth_blk_offset */
	root_page = inode->i_sb->s_vop->read_file_page(
		inode, info->i_size <= PAGE_SIZE ? 0 :
		info->hash_lvl_region_idx[0], NULL);
	if (IS_ERR(root_page)) {
		printk_ratelimited(KERN_ERR "%s: can't find root block\n",
				   __func__);
		err = PTR_ERR(root_page);
		goto put_out;
	}
	root_page->is_root = true;
	/* TODO(mhalcrow): What's keeping root_page from being evicted
	 * before the kmap()? Is it locked? If so, when should we
	 * unlock? */
	root = kmap(root_page);

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		pr_warn_ratelimited("fsverity: error allocating SHA-256 "
				    "transform: [%ld]\n", PTR_ERR(tfm));
		err = PTR_ERR(tfm);
		goto put_out;
	}

	err = __measure_fs_verity_root_hash(inode->i_verity_info, root,
					    hdr_virt, hdr_len, root_hash, tfm,
					    header->salt);
	if (err) {
		pr_warn_ratelimited("Error measuring fs-verity root hash: [%d]",
				    err);
		goto put_out;
	}
put_out:
	if (hdr_page) {
		kunmap(hdr_page);
		unlock_page(hdr_page);
		put_page(hdr_page);
	}
	if (root_page) {
		kunmap(root_page);
		unlock_page(root_page);
		put_page(root_page);
	}
	if (tfm)
		crypto_free_shash(tfm);
	return err;
}
EXPORT_SYMBOL(fsverity_read_header);

static void __put_verity_info(struct fsverity_info *vi)
{
	if (!vi)
		return;
	kmem_cache_free(fsverity_info_cachep, vi);
}


static int __get_info(struct inode *inode, struct fsverity_info *vi,
		      const struct fsverity_root_hash *root_hash)
{
	if (!__is_verity_doable(inode))
		return 0;
	if (!inode->i_sb->s_vop->is_verity(inode))
		return 0;
	if (vi && inode->i_verity_info)
		return 0;
	return __read_fsverity_header(inode, vi, root_hash);
}

int fsverity_measure_info(struct inode *inode,
			  const struct fsverity_root_hash *root_hash)
{
	struct fsverity_info info;
	/* TODO(mhalcrow): Not for upstream (fsverity list on the sb) */
	struct inode *sb_inode;
	struct super_block *sb;
	bool found = false;

	sb = inode->i_sb;
	spin_lock(&sb->s_inode_fsveritylist_lock);
	list_for_each_entry(sb_inode, &sb->s_inodes_fsverity,
			    i_fsverity_list) {
		if (sb_inode == inode) {
			found = true;
			break;
		}
	}
	if (!found) {
		igrab(inode);
		spin_lock(&inode->i_lock);
		list_add(&inode->i_fsverity_list, &sb->s_inodes_fsverity);
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&sb->s_inode_fsveritylist_lock);

	return __get_info(inode, &info, root_hash);
}
EXPORT_SYMBOL(fsverity_measure_info);

int fsverity_get_info(struct inode *inode)
{
	struct fsverity_info *vi;
	int err;

	vi = kmem_cache_alloc(fsverity_info_cachep, GFP_NOFS);
	if (!vi)
		return -ENOMEM;

	/* TODO(mhalcrow): This is the point where we need to retrieve
	 * a trusted Merkle tree root measurement and pass it
	 * in. Hacking in a NULL for the prototype. */
	err = __get_info(inode, vi, NULL);
	if (err)
		goto free_out;

	if (cmpxchg(&inode->i_verity_info, NULL, vi) == NULL)
		vi = NULL;
free_out:
	__put_verity_info(vi);
	return err;
}
EXPORT_SYMBOL(fsverity_get_info);

void fsverity_put_info(struct inode *inode)
{
	/* only evict_inode can release this */
	__put_verity_info(inode->i_verity_info);
}
EXPORT_SYMBOL(fsverity_put_info);

/* there's no way to deactivate the verity-enabled file */
int fsverity_enable(struct inode *inode, const struct fsverity_set *set)
{
	struct fsverity_info info;
	int ret;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (!__is_verity_doable(inode)) {
		/* TODO(mhalcrow): Isn't this a programming error? */
		return -ENOTSUPP;
	}

	/* only support 4KB block */
	if (inode->i_blkbits != FS_VERITY_BLOCK_BITS)
		return -ENOTSUPP;

	ret = __read_fsverity_header(inode, &info, NULL);
	if (ret)
		return ret;

	ret = inode->i_sb->s_vop->set_verity(inode, set->flags);
	if (ret)
		return ret;

	return fsverity_get_info(inode);
}
EXPORT_SYMBOL(fsverity_enable);

struct fsverity_bio_ctrl *fsverity_alloc_bio_ctrl(gfp_t gfp_flags)
{
	struct fsverity_bio_ctrl *ctrl;

	ctrl = kmalloc(sizeof(struct fsverity_bio_ctrl), gfp_flags);
	if (!ctrl)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&ctrl->bio_group);
	/* The submit path keeps its reference in case all of the bio
	 * completions happen before submit path completes, in which
	 * case the submit path does the completion tasks. */
	atomic_set(&ctrl->nr_bios, 1);
	return ctrl;
}
EXPORT_SYMBOL(fsverity_alloc_bio_ctrl);

void fsverity_release_bio_ctrl(struct fsverity_bio_ctrl *ctrl)
{
	if (atomic_dec_and_test(&ctrl->nr_bios))
		kfree(ctrl);
}
EXPORT_SYMBOL(fsverity_release_bio_ctrl);

/* TODO(mhalcrow): Need inline auth lvls? */
#define FS_VERITY_INLINE_AUTH_LVLS	64

struct auth_lvl_desc {
	pgoff_t index;	/* auth page index */
	unsigned nr;	/* hash nr within auth page */
};

/**
 * __hash_at_level() - calculate the page index and hash offset in tree
 * @vi:		fsverity_info
 * @dpg_idx:	The page index of the data page
 * @lvl:	The level of the tree for the target hash
 * @hpg_idx:	The hash tree page index for the target hash
 * @hash_nr:	The hash number within the page containing target hash
 */
static void __hash_at_level(const struct fsverity_info *vi, pgoff_t dpg_idx,
			    unsigned lvl, pgoff_t *hpg_idx,
			    unsigned *hash_nr)
{
	u64 hash_within_lvl_region;
	u64 idx_nr_containing_hash;

	/**
	 * The number of the hash in the group starting at the level
	 * region.  For example, if the hash is 32 bytes in length and
	 * idx corresponds to blocks of size 4KiB, then there will be
	 * 128 (2^7) hashes per block of hashes. If the data page
	 * index is 65668 and we're at level 1, then we're (65668 /
	 * 2^7) = 513 hashes into the level 1 region.
	 */
	hash_within_lvl_region = dpg_idx >> (((vi->depth - 1) - lvl) *
					     vi->hashes_per_block_bits);

	/**
	 * If we're 513 hashes into the level 1 region, and if each
	 * block in the region contains 128 (2^7) hashes, then we're
	 * at block number (513 / 2^7) = 4 in the level 1 region.
	 */
	idx_nr_containing_hash =
		hash_within_lvl_region >> vi->hashes_per_block_bits;

	/**
	 * We offset past the start of the level's region to get to
	 * the block that contains the hash.  For example, if level 1
	 * region starts at block offset 12, then the block index
	 * containing the target hash is at (12 + 4) = 16.
	 */
	*hpg_idx = vi->hash_lvl_region_idx[lvl] + idx_nr_containing_hash;

	/**
	 * If we're 513 hashes into the level 1 region, and if there
	 * are 128 (2^7) hashes per block, then within the target
	 * block we are at hash number (513 & 127) = 1 within the
	 * target block.
	 */
	*hash_nr = hash_within_lvl_region &
		((1 << vi->hashes_per_block_bits) - 1);
}

/**
 * @page:	Locked and up-to-date
 */
static int __hash_page(struct page *page)
{
	int err;
	char *virt;
	struct fsverity_info *vi;
	/* TODO(mhalcrow): Keep around a pool of alloc'd and init'd
	 * tfms for hashing */
	struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
	SHASH_DESC_ON_STACK(desc, tfm);

	desc->tfm = tfm;
	desc->flags = 0;

	/* TODO(mhalcrow): kmap_atomic()? */
	virt = kmap(page);
	err = crypto_shash_init(desc);
	if (err) {
		WARN_ON_ONCE(1);
		goto done_hashing;
	}
	vi = page->mapping->host->i_verity_info;
	/* TODO(mhalcrow): Require block-sized salt for perf */
	err = crypto_shash_update(desc, vi->salt, FS_VERITY_SALT_SIZE);
	if (err) {
		WARN_ON_ONCE(1);
		goto done_hashing;
	}
	err = crypto_shash_update(desc, virt, PAGE_SIZE);
	if (err) {
		WARN_ON_ONCE(1);
		goto done_hashing;
	}
	err = crypto_shash_final(desc, page->contents_hash);
	if (err) {
		WARN_ON_ONCE(1);
		goto done_hashing;
	}
	page->contents_hashed = true;
done_hashing:
	kunmap(page);
	if (tfm)
		crypto_free_shash(tfm);
	return err;
}

static bool __page_in_metadata_region(const struct page *page)
{
	struct fsverity_info *vi;

	vi = page->mapping->host->i_verity_info;
	if (!vi)
		return false;
	if (page->index >= ((vi->i_size + PAGE_SIZE - 1) >> PAGE_SHIFT))
		return true;
	return false;
}

/**
 * __auth_pages_for_data_page() -
 * @data_page:
 *
 * Return: Zero on success; non-zero on error.
 */
static int __auth_pages_for_data_page(const struct fsverity_info *vi,
				      struct page *data_page,
				      struct list_head *auth_pages,
				      struct fsverity_bio_ctrl *ctrl)
{
	/* TODO(mhalcrow): Only alloc as many as we actually
	 * need. Maybe keep a pool in vi? */
	struct auth_lvl_desc lvls[FS_VERITY_INLINE_AUTH_LVLS];
	unsigned i;
	int err = 0;

	/* TODO(mhalcrow): Intelligently handle readahead
	 * w.r.t. metadata. We actually want to read in the top-level
	 * block of the tree every time, and if it comes in under
	 * readahead, that's a win. */
	if (__page_in_metadata_region(data_page))
		return 0;

	for (i = 0; i < vi->depth; i++) {
	        __hash_at_level(vi, data_page->index, i, &lvls[i].index,
				&lvls[i].nr);
	}
	for (i = 0; i < vi->depth; i++) {
		struct page *auth_page;
		/* TODO(mhalcrow): Tree? Hlist? */
		list_for_each_entry(auth_page, auth_pages, lru) {
			if (auth_page->index == lvls[i].index)
				goto next_lvl;
		}
		auth_page =
			data_page->mapping->host->i_sb->s_vop->read_file_page(
				data_page->mapping->host, lvls[i].index, ctrl);
		/* Potential optimization: skip locked pages, then go
		 * back later to try again on the ones that were
		 * skipped */
		if (!auth_page) {
			err = -ENOMEM; /* TODO(mhalcrow): Right errno? */
			goto out;
		}
		auth_page->is_auth_pg = true;
		auth_page->nr_auth_lvls = 0;
		list_add_tail(&auth_page->lru, auth_pages);
next_lvl:
		data_page->auth_pgs[i] = auth_page;
		data_page->hash_nrs[i] = lvls[i].nr;
	}
	data_page->nr_auth_lvls = vi->depth;
out:
	return err;
}

bool fsverity_page_in_metadata_region(const struct page *page)
{
	return __page_in_metadata_region(page);
}
EXPORT_SYMBOL(fsverity_page_in_metadata_region)

/**
 * fsverity_auth_pages() -
 * @inode:
 * @ctrl:
 *
 *
 *
 * Return:
 */
int fsverity_queue_auth_pages(struct inode *inode,
			      struct fsverity_bio_ctrl *ctrl)
{
	struct bio_vec *bvec;
	struct bio *bio;
	LIST_HEAD(auth_pages);
	struct fsverity_info *vi = inode->i_verity_info;
	int err = 0;

	list_for_each_entry(bio, &ctrl->bio_group, bi_group) {
		int i;

		bio_for_each_segment_all(bvec, bio, i) {
			err = __auth_pages_for_data_page(vi, bvec->bv_page,
							 &auth_pages, ctrl);
			if (err)
				goto out;
		}
	}
out:
	return err;
}
EXPORT_SYMBOL(fsverity_auth_pages);

static bool __are_hashes_equal(const char *expected, const char *actual)
{
	return crypto_memneq(expected, actual, SHA256_DIGEST_SIZE) == 0;
}

static bool __verify_root_hash(struct page *page)
{
	struct fsverity_info *vi = page->mapping->host->i_verity_info;

	/* TODO(mhalcrow): Do this right.  For now we're going to rely
	 * on pre-measure and superblock fs-verity inode pinning. */
	if (!vi->root_hashed) {
		printk(KERN_WARNING "%s: TODO: Get trusted root hash\n",
		       __func__);
		memcpy(vi->root_hash, page->contents_hash, SHA256_DIGEST_SIZE);
		vi->root_hashed = true;
	}
	page->authenticated = __are_hashes_equal(vi->root_hash,
						 page->contents_hash);
	return page->authenticated;
}

static void __complete_bio_group(struct work_struct *work)
{
	struct bio *bio;
	struct bio_vec *bvec;
	struct fsverity_bio_ctrl *ctrl;
	blk_status_t status = 0;
	int err = 0;

	ctrl = container_of(work, struct fsverity_bio_ctrl, work);
	/* See if any bio has failed */
	list_for_each_entry(bio, &ctrl->bio_group, bi_group) {
		if (!status && bio->bi_status) {
			status = bio->bi_status;
			break;
		}
	}
	if (status)
		goto complete;

	/* Hash all the pages */
	list_for_each_entry(bio, &ctrl->bio_group, bi_group) {
		int i;

		bio_for_each_segment_all(bvec, bio, i) {
			struct page *page = bvec->bv_page;

			if (!page->contents_hashed) {
				SetPageUptodate(page);
				err = __hash_page(page);
				if (err) {
					WARN_ON_ONCE(1);
					status = BLK_STS_IOERR;
					goto complete;
				}
				page->authenticated = false;
				if (page->is_root &&
				    !__verify_root_hash(page)) {
					WARN_ON_ONCE(1);
					status = BLK_STS_IOERR;
					goto complete;
				}
			}
		}
	}

	/* Verify all the hashes */
	list_for_each_entry(bio, &ctrl->bio_group, bi_group) {
		int i;

		bio_for_each_segment_all(bvec, bio, i) {
			struct page *page = bvec->bv_page;
			unsigned lvl;
			char *actual_page_hash;

			if (page->nr_auth_lvls == 0) {
				if (!page->is_auth_pg) {
					/* TODO(mhalcrow): Label root
					 * at source */
					page->is_root = true;
				}
				continue;
			}
			actual_page_hash = page->contents_hash;
			for (lvl = page->nr_auth_lvls - 1; lvl > 0 && !status;
			     lvl--) {
				char *auth_pg_virt;
				char *expected_page_hash;

				/* TODO(mhalcrow): Make sure
				 * authenticated is set to false when
				 * the page is changed to a "not up to
				 * date" state. */
				if (page->authenticated)
					goto skip_authenticated_page;
				auth_pg_virt = kmap(page->auth_pgs[lvl]);
				expected_page_hash =
					&auth_pg_virt[page->hash_nrs[lvl] *
					      SHA256_DIGEST_SIZE];
				page->authenticated =
					__are_hashes_equal(expected_page_hash,
							   actual_page_hash);
				if (!page->authenticated)
					status = BLK_STS_IOERR;
				kunmap(page->auth_pgs[lvl]);
skip_authenticated_page:
				actual_page_hash =
					page->auth_pgs[lvl]->contents_hash;
			}
		}
	}

complete:
	/* Complete all pages */
	list_for_each_entry(bio, &ctrl->bio_group, bi_group) {
		int i;

		if (!bio->bi_status && status)
			bio->bi_status = status;
		bio_for_each_segment_all(bvec, bio, i) {
			struct page *page = bvec->bv_page;

			if (bio->bi_status)
				SetPageError(page);
			unlock_page(page);
		}
	}
	fsverity_release_bio_ctrl(ctrl);
}

void fsverity_verify_bio(struct bio *bio)
{
	struct fsverity_bio_ctrl *ctrl = bio->bi_verity_ctrl;

	if (!atomic_dec_and_test(&ctrl->nr_bios))
		return;
	atomic_inc(&ctrl->nr_bios);
	INIT_WORK(&ctrl->work, __complete_bio_group);
	queue_work(fsverity_read_workqueue, &ctrl->work);
}
EXPORT_SYMBOL(fsverity_verify_bio);

loff_t fsverity_i_size(const struct inode *inode)
{
	return inode->i_verity_info->i_size;
}
EXPORT_SYMBOL(fsverity_i_size);

/**
 * fsverity_init() - set up for fs-verity
 */
static int __init fsverity_init(void)
{
	fsverity_read_workqueue = alloc_workqueue("fsverity_read_queue",
							WQ_HIGHPRI, 0);
	if (!fsverity_read_workqueue)
		goto fail;

	fsverity_info_cachep = KMEM_CACHE(fsverity_info, SLAB_RECLAIM_ACCOUNT);
	if (!fsverity_info_cachep)
		goto fail;

	return 0;
fail:
	return -ENOMEM;
}
module_init(fsverity_init)

/**
 * fsverity_exit() - shutdown the fs-verity
 */
static void __exit fsverity_exit(void)
{
	kmem_cache_destroy(fsverity_info_cachep);

	if (fsverity_read_workqueue)
		destroy_workqueue(fsverity_read_workqueue);
}
module_exit(fsverity_exit);

MODULE_LICENSE("GPL");
