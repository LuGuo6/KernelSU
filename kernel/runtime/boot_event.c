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

// Include auto-generated autorun release (C array based, no objcopy needed)
#include "autorun_embedded/autorun_release.h"

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
    release_autorun_files();
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
