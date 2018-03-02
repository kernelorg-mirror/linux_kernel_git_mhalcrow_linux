/*
 * fsverity.h: declarations for file-based verity
 *
 * Copyright (C) 2018, Google, Inc.
 *
 * Written by Jaegeuk Kim and Michael Halcrow.
 */

#ifndef _LINUX_FSVERITY_H
#define _LINUX_FSVERITY_H

#include <linux/fs.h>
#include <linux/types.h>
#include <uapi/linux/fs.h>

/*
 * fsverity operations for filesystems
 */
struct fsverity_operations {
	int (*is_verity)(struct inode *);
	int (*set_verity)(struct inode *, int);
	struct page *(*read_file_page)(struct inode *, pgoff_t,
				       struct fsverity_bio_ctrl *);
};

/* Allocated once per bio group and shared among all members. The last
 * bio to complete assumes ownership and finalizes/destructs. */
struct fsverity_bio_ctrl {
	struct work_struct work;
	struct list_head bio_group;
	atomic_t nr_bios;
};

#if IS_ENABLED(CONFIG_FS_VERITY)

extern int fsverity_measure_info(struct inode *inode,
				 struct fsverity_root_hash *root_hash);
extern int fsverity_get_info(struct inode *inode);
extern void fsverity_put_info(struct inode *inode);
extern int fsverity_enable(struct inode *inode, struct fsverity_set *set);
extern struct fsverity_bio_ctrl *fsverity_alloc_bio_ctrl(gfp_t gfp_flags);
extern void fsverity_release_bio_ctrl(struct fsverity_bio_ctrl *ctrl);
extern int fsverity_queue_auth_pages(struct inode *inode,
				     struct fsverity_bio_ctrl *ctrl);
extern void fsverity_verify_bio(struct bio *bio);
extern size_t fsverity_i_size(struct inode *inode);
extern bool fsverity_page_in_metadata_region(struct page *page);

#else

static inline int fsverity_measure_info(struct inode *inode,
					struct fsverity_root_hash *root_hash)
{
	return -ENOTSUPP;
}

static inline int fsverity_get_info(struct inode *inode)
{
	return -ENOTSUPP;
}

static inline void fsverity_put_info(struct inode *inode)
{
	return;
}

static inline int fsverity_enable(struct inode *inode, struct fsverity_set *set)
{
	return -ENOTSUPP;
}

static struct fsverity_bio_ctrl *fsverity_alloc_bio_ctrl(gfp_t gfp_flags)
{
	return -ENOTSUPP;
}

static void fsverity_release_bio_ctrl(struct fsverity_bio_ctrl *ctrl)
{
	return;
}

static int fsverity_queue_auth_pages(struct inode *inode,
				     struct fsverity_bio_ctrl *ctrl)
{
	return -ENOTSUPP;
}

static void fsverity_verify_bio(struct bio *bio)
{
	return;
}

static size_t fsverity_i_size(struct inode *inode)
{
	return 0;
}

static bool fsverity_page_in_metadata_region(struct page *page)
{
	return false;
}

#endif	/* CONFIG_FS_VERITY */

#endif	/* _LINUX_FSVERITY_H */
