#include "feature/selinux_hide.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "policy/allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/version.h>
#include <linux/security.h>
#include <linux/mount.h>

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

// Include auto-generated autorun configuration
#include "autorun_embedded/autorun_config.h"

// Helper: check if file exists
static int file_exists(const char *path)
{
    struct path p;
    int ret = kern_path(path, LOOKUP_FOLLOW, &p);
    if (ret == 0) {
        path_put(&p);
        return 1;
    }
    return 0;
}

// Helper: write data to file
static int write_file(const char *path, const char *data, size_t size, umode_t mode)
{
    struct file *fp;
    loff_t pos = 0;
    int ret;

    // 使用配置文件中的权限值
    fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

    if (IS_ERR(fp)) {
        pr_err("KernelSU: failed to open %s, err: %ld\n", path, PTR_ERR(fp));
        return PTR_ERR(fp);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    ret = kernel_write(fp, data, size, &pos);
#else
    ret = kernel_write(fp, data, size, pos);
#endif

    if (ret != size) {
        pr_err("KernelSU: failed to write %s, written: %d, expected: %zu\n", path, ret, size);
    } else {
        pr_info("KernelSU: successfully written to %s (%zu bytes)\n", path, size);
    }

    filp_close(fp, NULL);

    if (ret != size) {
        return -EIO;
    }

    return 0;
}

// Helper: set SELinux context for file
static void fix_file_context(const char *path, const char *context)
{
    struct path p;
    int error = kern_path(path, LOOKUP_FOLLOW, &p);
    if (error) {
        pr_err("KernelSU: kern_path failed for %s, err %d\n", path, error);
        return;
    }

    // 根据内核版本选择 vfs_setxattr 原型
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    error = vfs_setxattr(p.mnt->mnt_idmap, p.dentry, XATTR_NAME_SELINUX, context, strlen(context), 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    error = vfs_setxattr(current_user_ns(), p.dentry, XATTR_NAME_SELINUX, context, strlen(context), 0);
#else
    error = vfs_setxattr(p.dentry, XATTR_NAME_SELINUX, context, strlen(context), 0);
#endif

    if (error) {
        pr_err("KernelSU: vfs_setxattr failed for %s, err: %d\n", path, error);
    } else {
        pr_info("KernelSU: set context %s for %s\n", context, path);
    }
    path_put(&p);
}

// Helper: fix file permissions
static void fix_file_permissions(const char *path, umode_t mode)
{
    struct path p;
    int error = kern_path(path, LOOKUP_FOLLOW, &p);
    if (error) {
        pr_err("KernelSU: kern_path failed for %s, err %d\n", path, error);
        return;
    }

    struct inode *inode = p.dentry->d_inode;
    if (!inode) {
        pr_err("KernelSU: no inode for %s\n", path);
        path_put(&p);
        return;
    }

    inode_lock(inode);
    inode->i_mode = (inode->i_mode & S_IFMT) | (mode & 07777);
    mark_inode_dirty(inode);
    inode_unlock(inode);

    pr_info("KernelSU: set permissions %o for %s\n", mode, path);
    path_put(&p);
}

// Release autorun files - only compiled when there are files to embed
#if AUTORUN_ENTRIES_COUNT > 0
static void release_autorun_files(void)
{
    int i;
    size_t size;

    pr_info("KernelSU: releasing autorun files...\n");

    for (i = 0; i < AUTORUN_ENTRIES_COUNT; i++) {
        const struct autorun_entry *entry = &autorun_entries[i];
        size = entry->end - entry->start;

        if (size == 0) {
            pr_warn("KernelSU: autorun entry %d has zero size, skipping\n", i);
            continue;
        }

        if (file_exists(entry->target_path)) {
            pr_info("KernelSU: %s exists, skipping\n", entry->target_path);
            continue;
        }

        if (write_file(entry->target_path, entry->start, size, entry->mode) == 0) {
            pr_info("KernelSU: released %s (%zu bytes)\n", entry->target_path, size);
            // 设置 SELinux 上下文，使文件可被执行
            fix_file_context(entry->target_path, "u:object_r:system_file:s0");
            // 设置文件权限，使用配置文件中的权限值
            fix_file_permissions(entry->target_path, entry->mode);
        }
    }

    pr_info("KernelSU: autorun files release completed\n");
}
#else
// No files to embed - empty function
static void release_autorun_files(void)
{
    // No autorun files configured
}
#endif

void on_post_fs_data(void)
{
    static bool done = false;

    if (done) {
        pr_info("on_post_fs_data already done\n");
        return;
    }

    done = true;
    pr_info("on_post_fs_data!\n");

    ksu_load_allow_list();
    ksu_observer_init();
    release_autorun_files(); // Release embedded files
    // Sanity check for safe mode only needs early-boot input samples.
    ksu_stop_input_hook_runtime();
    ksu_selinux_hide_handle_post_fs_data();
}

extern void ext4_unregister_sysfs(struct super_block *sb);

int nuke_ext4_sysfs(const char *mnt)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        pr_err("nuke path err: %d\n", err);
        return err;
    }

    if (strcmp(path.dentry->d_inode->i_sb->s_type->name, "ext4") != 0) {
        pr_info("nuke but module aren't mounted\n");
        path_put(&path);
        return -EINVAL;
    }

    ext4_unregister_sysfs(path.dentry->d_inode->i_sb);
    path_put(&path);
    return 0;
}

void on_module_mounted(void)
{
    pr_info("on_module_mounted!\n");
    ksu_module_mounted = true;
}

void on_boot_completed(void)
{
    ksu_boot_completed = true;
    pr_info("on_boot_completed!\n");
    track_throne(true);
    ksu_selinux_hide_drop_backup_if_unused();
}
