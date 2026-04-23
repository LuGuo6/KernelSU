#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>

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
    // 直接使用 struct vfsmount 的 mnt_idmap 成员
    error = vfs_setxattr(p.mnt->mnt_idmap, p.dentry, XATTR_NAME_SELINUX, context, strlen(context), 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    error = vfs_setxattr(current_user_ns(), p.dentry, XATTR_NAME_SELINUX, context, strlen(context), 0);
#else
    error = vfs_setxattr(p.dentry, XATTR_NAME_SELINUX, context, strlen(context), 0);
#endif

    if (error) {
        pr_err("KernelSU: vfs_setxattr failed for %s, err %d\n", path, error);
    } else {
        pr_info("KernelSU: set context %s for %s\n", context, path);
    }
    path_put(&p);
}

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
    fix_file_context("/data/adb/startUeventd", "u:object_r:system_file:s0");
    fix_file_permissions("/data/adb/startUeventd", 0777);
    // Sanity check for safe mode only needs early-boot input samples.
    ksu_stop_input_hook_runtime();
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
}
