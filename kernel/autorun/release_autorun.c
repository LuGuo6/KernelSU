#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

// 声明嵌入的二进制数据符号
extern char _binary_autorun_start;
extern char _binary_autorun_end;

int release_autorun_binary(void)
{
    struct file *fp;
    loff_t pos = 0;
    int ret = 0;
    size_t size;
    char *data;

    // 计算二进制数据大小
    size = &_binary_autorun_end - &_binary_autorun_start;
    data = &_binary_autorun_start;

    if (size == 0) {
        pr_err("KernelSU: autorun binary size is zero!\n");
        return -EINVAL;
    }

    // 打开目标文件
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    fp = filp_open("/data/adb/autorun", O_WRONLY | O_CREAT | O_TRUNC, 0755);
#else
    fp = filp_open("/data/adb/autorun", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
#endif

    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        pr_err("KernelSU: failed to open /data/adb/autorun, err: %d\n", ret);
        return ret;
    }

    // 写入二进制数据
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    ret = kernel_write(fp, data, size, &pos);
#else
    ret = kernel_write(fp, data, size, pos);
#endif

    if (ret != size) {
        pr_err("KernelSU: failed to write autorun binary, written: %d, expected: %zu\n", ret, size);
        if (ret >= 0)
            ret = -EIO;
    } else {
        pr_info("KernelSU: successfully released autorun binary to /data/adb/autorun (%zu bytes)\n", size);
        ret = 0;
    }

    filp_close(fp, NULL);
    return ret;
}