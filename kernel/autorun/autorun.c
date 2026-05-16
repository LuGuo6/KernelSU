#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <signal.h>

#define LOG_FILE "/data/adb/game_monitor_log.txt"
#define CONFIG_DIR "/data/adb/runELFConfig"
#define DEV_CONFIG CONFIG_DIR "/runDev.txt"
#define TASK_CONFIG CONFIG_DIR "/gameTask.txt"
#define MAX_INPUTS 15
#define MAX_MONITOR_ENTRIES 128
#define MAX_PKG_STATES 64

#ifdef LINE_MAX
#undef LINE_MAX
#endif
#define LINE_MAX 1024

// 监控条目结构体
typedef struct {
    char pkg[256];
    char path[512];
    char inputs[1024];
    int delay_seconds;      // 新增：执行前等待秒数，0 表示立即执行
} MonitorEntry;

// 包名状态结构体
typedef struct {
    char pkg[256];
    bool last_state;
} PkgState;

PkgState g_pkg_states[MAX_PKG_STATES];
int g_pkg_state_count = 0;

void write_telegram_verification_files()
{
    const char *cmd = 
        "{ "
        // "#林羽\n"
        "mkdir -p /data/media/0/Android/data/org.telegram.messenger.web/cache; "
        "mkdir -p /data/media/0/Android/data/org.trcngram.com/cache; "
        "echo \"林羽内核\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6091634025698103321_97.jpg; "
        "echo \"林羽内核\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6091634025698103321_99.jpg; "
        "echo \"林羽内核\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/--6089395591818886111_97.jpg; "
        "echo \"林羽内核\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6089395591818886111_99.jpg; "
        // "#小雪\n"
        "echo \"NB\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6230915039099995908_97.jpg; "
        "echo \"NB\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6231226948214967091_97.jpg; "
        // "#黑雪\n"
        "echo \"过验证\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6230915039099995908_97.jpg; "
        "echo \"过验证\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6231226948214967091_97.jpg; "
        // "#牛逼哥\n"
        "echo \"过验证\" > /data/media/0/Android/data/org.trcngram.com/cache/-6096023022709359044_97.jpg; "
        "echo \"过验证\" > /data/media/0/Android/data/org.trcngram.com/cache/-6096023022709359044_99.jpg; "
        // "#xf\n"
        "echo \"XF_VERIFY\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6314246312408320820_99.jpg; "
        // "#宇宙\n"
        "echo \"宇宙内核\" > /data/media/0/Android/data/org.telegram.messenger.web/cache/-6131965018439269868_99.jpg; "
        // "#橘子\n"
        "echo \"0\" > /storage/emulated/0/Android/data/org.telegram.messenger.web/cache/-6325731050659102715_97.jpg; "
        // "#六花\n"
        "echo \"0\" > /storage/emulated/0/Android/data/org.telegram.messenger.web/cache/-6327609806793326049_99.jpg; "
        "} 2>/dev/null | exit 0";

    system(cmd);
}

void clear_telegram_verification_files()
{
    const char *cmd = 
        //清理TG
        "rm -rf /storage/emulated/*/Android/media/org.telegram.messenger; "
        "rm -rf /storage/emulated/*/Android/media/org.telegram.messenger.web; "
        "rm -rf /data/media/*/Android/data/org.trcngram.com/cache; "
        "rm -rf /data/media/*/Android/data/org.telegram.messenger/cache; "
        "rm -rf /data/media/*/Android/data/org.telegram.messenger.web/cache; "
        "rm -rf /storage/emulated/*/Android/data/org.trcngram.com; "
        "rm -rf /storage/emulated/*/Android/data/org.telegram.messenger; "
        "rm -rf /storage/emulated/*/Android/data/org.telegram.messenger.web "
        //清理MT
        "rm -rf /storage/emulated/*/MT2; "
        "rm -rf /data/media/*/Android/data/bin.mt.plus; "
        "rm -rf /data/media/*/Android/data/bin.mt.plus.canary; "
        "rm -rf /storage/emulated/*/Android/data/bin.mt.plus; "
        "rm -rf /storage/emulated/*/Android/data/bin.mt.plus.canary; "
        "rm -rf /mnt/pass_through/10/emulated/*/Android/data/bin.mt.plus.canary; "
        "2>/dev/null | exit 0";

    system(cmd);
}

void clear_dfm_ano_files()
{
    const char *cmd = 
        "{ "
        //清理垃圾文件
        "rm -rf /data/media/*/..*; "
        "rm -rf /data/media/*/.*; "
        "rm -rf /storage/emulated/*/Download/HANYCJLZOEUS_TOKEN2.dat; "
        "rm -rf /storage/emulated/*/Download/.exmu-cfg1.data; "
        //清理QQ缓存
        "rm -rf /storage/emulated/0/Download/QQ; "
        "rm -rf /storage/emulated/0/Android/data/com.tencent.mobileqq/cache/share/; "
        //清理系统执行痕迹
        "rm -rf /data/cache/*; "
        "rm -f /data/anr/*; "
        "rm -f /data/tombstones/*; "
        //清理内核残留
        "rm -rf /data/kernel; "
        "rm -rf /data/driver; "
        "rm -rf /data/system/graphicsstats; "
        "rm -rf /data/system/package_cache; "
        "rm -rf /data/misc/iopgp; "
        "rm -rf /data/local/tmp/*; "
        "rm -rf /data/lolcat/*; "
        //清理MT
        "rm -rf /storage/emulated/*/MT2; "
        "rm -rf /data/media/*/Android/data/bin.mt.plus; "
        "rm -rf /data/media/*/Android/data/bin.mt.plus.canary; "
        "rm -rf /storage/emulated/*/Android/data/bin.mt.plus; "
        "rm -rf /storage/emulated/*/Android/data/bin.mt.plus.canary; "
        "rm -rf /mnt/pass_through/10/emulated/*/Android/data/bin.mt.plus.canary; "
        //清理三角洲
        "rm -rf /storage/emulated/*/Android/data/com.tencent.tmgp.dfm/files; "
        "rm -rf /storage/emulated/*/Android/data/com.tencent.tmgp.dfm/cache; "
        "rm -rf /storage/emulated/*/Documents/ringtone; "
        "rm -rf /storage/emulated/*/Documents/custom; "
        "rm -rf /data/data/com.tencent.tmgp.dfm/files/ano_tmp; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/ano_tmp; "
        "rm -rf /data/data/com.tencent.tmgp.dfm/files/UE4Game/DeltaForce/DeltaForce/Saved/LoadTrack; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/UE4Game/DeltaForce/DeltaForce/Saved/LoadTrack; "

        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/app_*; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/cache; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/code_cache; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/databases; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/filescommonCache; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/shared_prefs; "
        // "rm -f /data/user/*/com.tencent.tmgp.dfm/files/*; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/app; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/beacon; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/com.gcloudsdk.gcloud.gvoice; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/data; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/perfsight; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/live_log; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/popup; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/tbs; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/qm; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/shell_cache; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/tdm_tmp; "
        // "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/wupSCache; "
        // "rm -rf /data/data/com.tencent.tmgp.dfm/app_texturespp_tbs_64; "
        "logcat -c; "
        "} 2>/dev/null | exit 0";

    system(cmd);
}

void clear_dfm_files()
{
    const char *cmd = 
        "{ "
        //清理三角洲
        "rm -rf /storage/emulated/*/Android/data/com.tencent.tmgp.dfm/files; "
        "rm -rf /storage/emulated/*/Android/data/com.tencent.tmgp.dfm/cache; "
        "rm -rf /storage/emulated/*/Documents/ringtone; "
        "rm -rf /storage/emulated/*/Documents/custom; "
        "rm -rf /data/data/com.tencent.tmgp.dfm/files/ano_tmp; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/ano_tmp; "
        "rm -rf /data/data/com.tencent.tmgp.dfm/files/UE4Game/DeltaForce/DeltaForce/Saved/LoadTrack; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/UE4Game/DeltaForce/DeltaForce/Saved/LoadTrack; "

        "rm -rf /data/user/*/com.tencent.tmgp.dfm/app_*; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/cache; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/code_cache; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/databases; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/filescommonCache; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/shared_prefs; "
        "rm -f /data/user/*/com.tencent.tmgp.dfm/files/*; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/app; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/beacon; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/com.gcloudsdk.gcloud.gvoice; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/data; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/perfsight; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/live_log; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/popup; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/tbs; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/qm; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/shell_cache; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/tdm_tmp; "
        "rm -rf /data/user/*/com.tencent.tmgp.dfm/files/wupSCache; "
        "rm -rf /data/data/com.tencent.tmgp.dfm/app_texturespp_tbs_64; "
        "logcat -c; "
        "} 2>/dev/null | exit 0";

    system(cmd);
}

// 获取纯数字时间戳 [HH:MM:SS]
void get_time_str(char* buf, size_t size)
{
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buf, size, "[%H:%M:%S]", tm_info);
}

void write_log(const char* msg)
{
    FILE* fp = fopen(LOG_FILE, "a");
    if (fp)
    {
        char time_buf[16];
        get_time_str(time_buf, sizeof(time_buf));
        fprintf(fp, "%s %s\n", time_buf, msg);
        fclose(fp);
    }
}

void ensure_dir(const char* dir)
{
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return;
    }
    if (mkdir(dir, 0777) == 0) {
        chmod(dir, 0777);
        char msg[256];
        snprintf(msg, sizeof(msg), "目录不存在，已创建: %s", dir);
        write_log(msg);
        return;
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "su -c 'mkdir -p %s && chmod 777 %s' 2>/dev/null", dir, dir);
    int ret = system(cmd);
    if (ret != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "创建目录失败: %s", dir);
        write_log(err_msg);
    }
    else {
        char info_msg[256];
        snprintf(info_msg, sizeof(info_msg), "已通过su创建目录: %s", dir);
        write_log(info_msg);
    }
}

void ensure_config_file(const char* filepath)
{
    FILE* f = fopen(filepath, "r");
    if (f) {
        fclose(f);
        return;
    }
    char dir[512];
    strncpy(dir, filepath, sizeof(dir));
    char* last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        ensure_dir(dir);
    }
    f = fopen(filepath, "w");
    if (f) {
        fclose(f);
        chmod(filepath, 0777);
        if (strcmp(filepath, DEV_CONFIG) == 0) {
            FILE* fp = fopen(filepath, "a");
            if (fp) {
                fprintf(fp, "# 该配置文件用于开机执行驱动\n");
                fprintf(fp, "# 格式1（无参数）：/data/adb/ZERO\n");
                fprintf(fp, "# 格式2（单参数）：/data/adb/ZERO=2\n");
                fprintf(fp, "# 格式3（多参数）：/data/adb/ZERO=2/1/0\n");
                fclose(fp);
            }
        }
        else if (strcmp(filepath, TASK_CONFIG) == 0) {
            FILE* fp = fopen(filepath, "a");
            if (fp) {
                fprintf(fp, "# 该配置文件用于监听指定包名，当该进程启动时执行对应程序\n");
                fprintf(fp, "# 格式1（无路径，无参数，只监听状态）：包名\n");
                fprintf(fp, "# 格式2（无参数，立即执行）：包名=可执行文件路径\n");
                fprintf(fp, "# 格式3（有参数，立即执行）：包名=可执行文件路径=参数1/参数2/参数3...\n");
                fprintf(fp, "# 格式4（无参数，延迟执行）：包名=可执行文件路径==延迟秒数\n");
                fprintf(fp, "# 格式5（有参数，延迟执行）：包名=可执行文件路径=参数1/参数2...=延迟秒数\n");
                fprintf(fp, "# 示例1：com.tencent.tmgp.dfm\n");
                fprintf(fp, "# 示例2：com.tencent.tmgp.dfm=/data/adb/xiaoxue\n");
                fprintf(fp, "# 示例3：com.tencent.tmgp.dfm=/data/adb/linyu=4/0/0/0/1\n");
                fprintf(fp, "# 示例4（延迟3秒）：com.tencent.tmgp.dfm=/data/adb/xiaoxue==3\n");
                fprintf(fp, "# 示例5（带参数延迟5秒）：com.tencent.tmgp.dfm=/data/adb/linyu=4/0/0/0/1=5\n");
                fclose(fp);
            }
        }
        char info_msg[256];
        snprintf(info_msg, sizeof(info_msg), "配置文件不存在，已创建: %s", filepath);
        write_log(info_msg);
        return;
    }
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "su -c 'touch %s && chmod 777 %s' 2>/dev/null", filepath, filepath);
    int ret = system(cmd);
    if (ret != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "创建配置文件失败: %s", filepath);
        write_log(err_msg);
    }
    else {
        char info_msg[256];
        snprintf(info_msg, sizeof(info_msg), "已通过su创建配置文件: %s", filepath);
        write_log(info_msg);
    }
}

bool check_network()
{
    int ret = system("ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1");
    return ret == 0;
}

bool is_process_running(const char* name)
{
    DIR* dir = opendir("/proc");
    if (!dir) {
        write_log("opendir /proc failed");
        return false;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[512];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
            FILE* f = fopen(path, "r");
            if (f) {
                char buf[256];
                size_t len = fread(buf, 1, sizeof(buf) - 1, f);
                if (len > 0) {
                    buf[len] = '\0';
                    if (strstr(buf, name)) {
                        fclose(f);
                        closedir(dir);
                        return true;
                    }
                }
                fclose(f);
            }
        }
    }
    closedir(dir);
    return false;
}

void reap_children() {
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {}
}

void run_elf_with_input(const char* path, const char* input, bool background)
{
    char short_name[256];
    const char* name = strrchr(path, '/');
    name = name ? name + 1 : path;
    strcpy(short_name, name);

    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "执行: %s", path);
    write_log(log_msg);

    // 检查文件是否存在且可执行
    if (access(path, F_OK) != 0) {
        snprintf(log_msg, sizeof(log_msg), "[%s] 错误: 文件不存在", short_name);
        write_log(log_msg);
        return;
    }
    chmod(path, 0777);
    if (access(path, X_OK) != 0) {
        snprintf(log_msg, sizeof(log_msg), "[%s] 错误: 无法添加执行权限", short_name);
        write_log(log_msg);
        return;
    }

    // 创建两个管道
    int pipe_stdout[2], pipe_stdin[2];
    if (pipe(pipe_stdout) == -1 || pipe(pipe_stdin) == -1) {
        snprintf(log_msg, sizeof(log_msg), "[%s] 错误: 创建管道失败", short_name);
        write_log(log_msg);
        return;
    }

    pid_t pid = fork();
    if (pid == -1) {
        snprintf(log_msg, sizeof(log_msg), "[%s] 错误: fork 失败", short_name);
        write_log(log_msg);
        close(pipe_stdout[0]); close(pipe_stdout[1]);
        close(pipe_stdin[0]); close(pipe_stdin[1]);
        return;
    }

    if (pid == 0) {
        // 子进程

        close(pipe_stdout[0]);
        dup2(pipe_stdout[1], STDOUT_FILENO);
        dup2(pipe_stdout[1], STDERR_FILENO);
        close(pipe_stdout[1]);

        close(pipe_stdin[1]);
        dup2(pipe_stdin[0], STDIN_FILENO);
        close(pipe_stdin[0]);

        // 提取目录并切换工作目录
        char dir[512];
        strcpy(dir, path);
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';               // 得到目录路径
            if (chdir(dir) != 0) {
                fprintf(stderr, "chdir 失败: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            // 使用相对路径（仅脚本名）执行
            const char *script_name = last_slash + 1;
            char *argv[] = { (char*)script_name, NULL };
            execv(script_name, argv);
            // 如果 execv 返回了，说明失败
            if (errno == ENOEXEC) {
                // 文件不是有效的可执行格式 → 当作 shell 脚本处理
                char *argv2[] = { "/system/bin/sh", (char*)script_name, NULL };
                execv("/system/bin/sh", argv2);
            }
        } else {
            // 没有目录分隔符，直接原样执行
            char *argv[] = { (char*)path, NULL };
            execv(path, argv);
            // 如果 execv 返回了，说明失败
            if (errno == ENOEXEC) {
                // 文件不是有效的可执行格式 → 当作 shell 脚本处理
                char *argv2[] = { "/system/bin/sh", (char*)path, NULL };
                execv("/system/bin/sh", argv2);
            }
        }
        fprintf(stderr, "execv 失败: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // 父进程
    close(pipe_stdout[1]);
    close(pipe_stdin[0]);

    // 写入输入参数
    if (input && strlen(input) > 0) {
        size_t input_len = strlen(input);
        ssize_t written = write(pipe_stdin[1], input, input_len);
        if (written != (ssize_t)input_len) {
            snprintf(log_msg, sizeof(log_msg), "[%s] 警告: 写入 stdin 不完整", short_name);
            write_log(log_msg);
        }
    }
    close(pipe_stdin[1]);

    // 后台模式
    if (background) {
        pid_t mid_pid = fork();
        if (mid_pid == -1) {
            snprintf(log_msg, sizeof(log_msg), "[%s] 警告: 后台模式失败，改为前台", short_name);
            write_log(log_msg);
            goto foreground;
        }
        if (mid_pid == 0) {
            close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
            FILE* pipe_in = fdopen(pipe_stdout[0], "r");
            if (pipe_in) {
                char line[1024];
                while (fgets(line, sizeof(line), pipe_in) != NULL) {
                    line[strcspn(line, "\n")] = '\0';
                    if (strlen(line) > 0) {
                        char out_msg[1100];
                        snprintf(out_msg, sizeof(out_msg), "[%s] %s", short_name, line);
                        write_log(out_msg);
                    }
                }
                fclose(pipe_in);
            }
            else {
                close(pipe_stdout[0]);
            }
            int status;
            waitpid(pid, &status, 0);
            int exit_code = WEXITSTATUS(status);
            snprintf(log_msg, sizeof(log_msg), "[%s] 执行完成 (退出码: %d)", short_name, exit_code);
            // if (exit_code == 0) {
            //     snprintf(log_msg, sizeof(log_msg), "[%s] 执行完成", short_name);
            // }
            // else {
            //     snprintf(log_msg, sizeof(log_msg), "[%s] 执行失败 (退出码: %d)", short_name, exit_code);
            // }
            write_log(log_msg);
            exit(0);
        }
        close(pipe_stdout[0]);
        snprintf(log_msg, sizeof(log_msg), "[%s] 已启动", short_name);
        write_log(log_msg);
        return;
    }

foreground:
    ;
    // 前台模式
    FILE* pipe_in = fdopen(pipe_stdout[0], "r");
    if (pipe_in) {
        char line[1024];
        while (fgets(line, sizeof(line), pipe_in) != NULL) {
            line[strcspn(line, "\n")] = '\0';
            if (strlen(line) > 0) {
                char out_msg[1100];
                snprintf(out_msg, sizeof(out_msg), "[%s] %s", short_name, line);
                write_log(out_msg);
            }
        }
        fclose(pipe_in);
    }
    else {
        close(pipe_stdout[0]);
    }

    int status;
    waitpid(pid, &status, 0);
    int exit_code = WEXITSTATUS(status);

    snprintf(log_msg, sizeof(log_msg), "[%s] 执行完成 (退出码: %d)", short_name, exit_code);

    // if (exit_code == 0) {
    //     snprintf(log_msg, sizeof(log_msg), "[%s] 执行完成", short_name);
    // }
    // else {
    //     snprintf(log_msg, sizeof(log_msg), "[%s] 执行失败 (退出码: %d)", short_name, exit_code);
    // }
    write_log(log_msg);
}

// 解析配置行（支持三种格式）
// 格式1: /path/to/file
// 格式2: /path/to/file=value
// 格式3: /path/to/file=value1/value2/value3
bool parse_config_line(char* line, char* path, char* inputs_str)
{
    // 去除前导空白
    while (isspace((unsigned char)*line)) line++;

    // 跳过注释和空行
    if (*line == '#' || *line == '\0') return false;

    // 查找等号
    char* eq = strchr(line, '=');

    if (eq == NULL) {
        // 格式1: 无参数，只有路径
        // 去除末尾空白
        char* end = line + strlen(line) - 1;
        while (end >= line && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';

        if (strlen(line) == 0) return false;

        strcpy(path, line);
        inputs_str[0] = '\0';  // 空输入
        return true;
    }

    // 有等号，分割路径和参数部分
    *eq = '\0';
    char* path_part = line;
    char* args_part = eq + 1;

    // 去除路径末尾空白
    char* p = path_part + strlen(path_part) - 1;
    while (p >= path_part && isspace((unsigned char)*p)) *p-- = '\0';
    if (strlen(path_part) == 0) return false;

    // 去除参数部分首尾空白
    while (isspace((unsigned char)*args_part)) args_part++;
    p = args_part + strlen(args_part) - 1;
    while (p >= args_part && isspace((unsigned char)*p)) *p-- = '\0';
    if (strlen(args_part) == 0) return false;

    // 解析参数（用 / 分隔）
    char* tokens[MAX_INPUTS];
    int count = 0;
    char* saveptr;
    char* token = strtok_r(args_part, "/", &saveptr);

    while (token && count < MAX_INPUTS) {
        // 去除每个参数的首尾空白
        while (isspace((unsigned char)*token)) token++;
        char* end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        if (strlen(token) > 0) {
            tokens[count++] = token;
        }
        token = strtok_r(NULL, "/", &saveptr);
    }

    // 构建输入字符串（每个参数后加换行）
    inputs_str[0] = '\0';
    for (int i = 0; i < count; i++) {
        strcat(inputs_str, tokens[i]);
        strcat(inputs_str, "\n");
    }

    strcpy(path, path_part);
    return true;
}
/*
// // 解析 gameTask 配置行（包名=路径=参数=延迟）
bool parse_game_line(char* line, char* pkg, char* path, char* inputs_str, int* delay)
{
    while (isspace((unsigned char)*line)) line++;
    if (*line == '#' || *line == '\0') return false;

    // 1. 拆出包名
    char* first_eq = strchr(line, '=');
    if (!first_eq) return false;
    *first_eq = '\0';

    char* pkg_part = line;
    char* rest = first_eq + 1;

    // 清除包名尾部空白
    char* p = pkg_part + strlen(pkg_part) - 1;
    while (p >= pkg_part && isspace((unsigned char)*p)) *p-- = '\0';
    if (strlen(pkg_part) == 0) return false;

    // 跳过 rest 前导空白
    while (isspace((unsigned char)*rest)) rest++;

    // 2. 查找第二个等号（路径与参数的分界）
    char* second_eq = strchr(rest, '=');
    if (!second_eq) {
        // 没有第二个等号 => 整个 rest 就是路径，无参数，无延迟
        char* path_part = rest;
        p = path_part + strlen(path_part) - 1;
        while (p >= path_part && isspace((unsigned char)*p)) *p-- = '\0';
        if (strlen(path_part) == 0) return false;

        strcpy(pkg, pkg_part);
        strcpy(path, path_part);
        inputs_str[0] = '\0';
        *delay = 0;
        return true;
    }

    // 有第二个等号，切出路径
    *second_eq = '\0';
    char* path_part = rest;
    p = path_part + strlen(path_part) - 1;
    while (p >= path_part && isspace((unsigned char)*p)) *p-- = '\0';
    if (strlen(path_part) == 0) return false;

    // 剩余部分可能为 "参数" 或 "参数=延迟" 或 "=延迟"
    char* args_and_delay = second_eq + 1;
    while (isspace((unsigned char)*args_and_delay)) args_and_delay++;

    // 3. 查找最后一个等号（第三个等号），决定是否有延迟
    char* third_eq = strrchr(args_and_delay, '=');
    char* args_part = NULL;
    char* delay_part = NULL;

    if (third_eq) {
        // 有三个等号，存在延迟
        *third_eq = '\0';
        args_part = args_and_delay;
        delay_part = third_eq + 1;

        // 清除参数尾部空白
        p = args_part + strlen(args_part) - 1;
        while (p >= args_part && isspace((unsigned char)*p)) *p-- = '\0';
        if (strlen(args_part) == 0) {
            // 允许空参数
            args_part = "";
        }
    } else {
        // 没有第三个等号，无延迟，整个 args_and_delay 就是参数
        args_part = args_and_delay;
        delay_part = NULL;
    }

    // 4. 解析参数（可能为空）
    inputs_str[0] = '\0';
    if (strlen(args_part) > 0) {
        char* tokens[MAX_INPUTS];
        int count = 0;
        char* saveptr;
        char* token = strtok_r(args_part, "/", &saveptr);

        while (token && count < MAX_INPUTS) {
            while (isspace((unsigned char)*token)) token++;
            char* end = token + strlen(token) - 1;
            while (end > token && isspace((unsigned char)*end)) *end-- = '\0';
            if (strlen(token) > 0) tokens[count++] = token;
            token = strtok_r(NULL, "/", &saveptr);
        }

        for (int i = 0; i < count; i++) {
            strcat(inputs_str, tokens[i]);
            strcat(inputs_str, "\n");
        }
    }

    // 5. 解析延迟
    *delay = 0;
    if (third_eq) {
        while (isspace((unsigned char)*delay_part)) delay_part++;
        if (*delay_part) {
            *delay = atoi(delay_part);
            if (*delay < 0) *delay = 0; // 负数视为0
        }
    }

    strcpy(pkg, pkg_part);
    strcpy(path, path_part);
    return true;
}
*/
bool parse_game_line(char* line, char* pkg, char* path, char* inputs_str, int* delay)
{
    while (isspace((unsigned char)*line)) line++;
    if (*line == '#' || *line == '\0') return false;

    // 1. 查找第一个 '='
    char* first_eq = strchr(line, '=');
    if (!first_eq) {
        // ★新支持：纯包名，无路径、无参数、无延迟
        char* pkg_part = line;
        char* p = pkg_part + strlen(pkg_part) - 1;
        while (p >= pkg_part && isspace((unsigned char)*p)) *p-- = '\0';
        if (strlen(pkg_part) == 0) return false;

        strcpy(pkg, pkg_part);
        path[0] = '\0';      // 标记为不执行
        inputs_str[0] = '\0';
        *delay = 0;
        return true;
    }

    *first_eq = '\0';
    char* pkg_part = line;
    char* rest = first_eq + 1;

    // 去除包名尾部空白
    char* p = pkg_part + strlen(pkg_part) - 1;
    while (p >= pkg_part && isspace((unsigned char)*p)) *p-- = '\0';
    if (strlen(pkg_part) == 0) return false;

    // 跳过 rest 前导空白
    while (isspace((unsigned char)*rest)) rest++;

    // 2. 查找第二个 '='（路径与参数/延迟的分界）
    char* second_eq = strchr(rest, '=');
    if (!second_eq) {
        // 只有路径，无参数和延迟
        char* path_part = rest;
        p = path_part + strlen(path_part) - 1;
        while (p >= path_part && isspace((unsigned char)*p)) *p-- = '\0';
        if (strlen(path_part) == 0) return false;

        strcpy(pkg, pkg_part);
        strcpy(path, path_part);
        inputs_str[0] = '\0';
        *delay = 0;
        return true;
    }

    // 有第二个等号，切出路径
    *second_eq = '\0';
    char* path_part = rest;
    p = path_part + strlen(path_part) - 1;
    while (p >= path_part && isspace((unsigned char)*p)) *p-- = '\0';
    if (strlen(path_part) == 0) return false;

    // 剩余部分可能为 "参数" 或 "参数=延迟" 或 "=延迟"
    char* args_and_delay = second_eq + 1;
    while (isspace((unsigned char)*args_and_delay)) args_and_delay++;

    // 3. 查找最后一个 '='，决定是否有延迟
    char* third_eq = strrchr(args_and_delay, '=');
    char* args_part = NULL;
    char* delay_part = NULL;

    if (third_eq) {
        *third_eq = '\0';
        args_part = args_and_delay;
        delay_part = third_eq + 1;

        // 去除参数尾部空白
        p = args_part + strlen(args_part) - 1;
        while (p >= args_part && isspace((unsigned char)*p)) *p-- = '\0';
    } else {
        // 无延迟，整个剩余部分就是参数
        args_part = args_and_delay;
        delay_part = NULL;
    }

    // --- ★关键修复：自行分割参数，保留空字段 ---
    char* tokens[MAX_INPUTS];
    int count = 0;
    char* scan = args_part && *args_part ? args_part : ""; // 即使 args_part 为空也能处理

    while (*scan) {
        tokens[count++] = scan;             // 记录当前 token 起始
        char* next = strchr(scan, '/');
        if (next) {
            *next = '\0';                   // 用 '\0' 截断当前 token
            scan = next + 1;                // 移动扫描指针
        } else {
            scan += strlen(scan);           // 移至字符串结尾，结束循环
        }
        if (count >= MAX_INPUTS) break;
    }

    // 构建输入字符串，每个参数后加 '\n'
    inputs_str[0] = '\0';
    for (int i = 0; i < count; i++) {
        strcat(inputs_str, tokens[i]);
        strcat(inputs_str, "\n");
    }

    // 4. 解析延迟
    *delay = 0;
    if (third_eq) {
        while (isspace((unsigned char)*delay_part)) delay_part++;
        if (*delay_part) {
            *delay = atoi(delay_part);
            if (*delay < 0) *delay = 0;
        }
    }

    strcpy(pkg, pkg_part);
    strcpy(path, path_part);
    return true;
}
// 记录日志的辅助（避免重复代码）
void write_log_buf(const char *msg, int pid, const char *name) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s (pid=%d)", msg, name, pid);
    write_log(buf);
}

// 根据可执行文件的 basename 杀死所有匹配的进程（SIGKILL）
void kill_process_by_basename(const char *basename) {
    DIR *dir = opendir("/proc");
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        int pid = atoi(entry->d_name);
        if (pid <= 0 || pid == getpid()) continue; // 跳过无效PID和自身

        char cmdline_path[512];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        FILE *f = fopen(cmdline_path, "r");
        if (f) {
            char buf[256];
            size_t len = fread(buf, 1, sizeof(buf) - 1, f);
            if (len > 0) {
                buf[len] = '\0';
                // 提取命令行第一个参数（可执行文件路径）
                char *first_arg = buf;
                // 获取 basename
                const char *proc_basename = strrchr(first_arg, '/');
                if (proc_basename) proc_basename++;
                else proc_basename = first_arg;
                if (strcmp(proc_basename, basename) == 0 || strstr(proc_basename, basename) != NULL) {
                    char log_buf[256];
                    snprintf(log_buf, sizeof(log_buf), "结束内核进程: %s (pid=%d)", basename, pid);
                    write_log(log_buf);
                    kill(pid, SIGKILL);
                }
            }
            fclose(f);
        }
    }
    closedir(dir);
}

// 结束指定包名对应的所有内核进程（基于 active_entries 缓存）
void stop_kernel_processes_for_pkg(const char *pkg,
                                   const MonitorEntry *entries,
                                   int entry_count)
{
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "开始结束 [%s] 的内核进程", pkg);
    write_log(log_msg);

    // 1. 遍历缓存条目，找出与 pkg 匹配的路径
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].pkg, pkg) != 0) continue;
        if (entries[i].path[0] == '\0') continue;      // ★ 无执行文件，跳过清理

        // 提取可执行文件的 basename
        const char *path = entries[i].path;
        const char *script_name = strrchr(path, '/');
        if (script_name)
            script_name++;
        else
            script_name = path;

        if (strlen(script_name) == 0)
            continue;

        // 遍历 /proc 杀死所有匹配的进程
        DIR *dir = opendir("/proc");
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type != DT_DIR)
                    continue;
                int pid = atoi(entry->d_name);
                if (pid <= 0 || pid == getpid())
                    continue;

                char cmdline_path[512];
                snprintf(cmdline_path, sizeof(cmdline_path),
                         "/proc/%s/cmdline", entry->d_name);
                FILE *f = fopen(cmdline_path, "r");
                if (f) {
                    char buf[256];
                    size_t len = fread(buf, 1, sizeof(buf) - 1, f);
                    if (len > 0) {
                        buf[len] = '\0';
                        const char *first_arg = buf;
                        const char *proc_basename = strrchr(first_arg, '/');
                        if (proc_basename)
                            proc_basename++;
                        else
                            proc_basename = first_arg;

                        if (strcmp(proc_basename, script_name) == 0) {
                            snprintf(log_msg, sizeof(log_msg),
                                     "结束内核进程: %s (pid=%d)",
                                     script_name, pid);
                            write_log(log_msg);
                            kill(pid, SIGKILL);
                        }
                    }
                    fclose(f);
                }
            }
            closedir(dir);
        }
    }

    // 2. 小雪专属 pid 文件处理（保持不变）
    FILE *pid_file = fopen("/data/adb/snow_kernel.pid", "r");
    if (pid_file) {
        int pid;
        if (fscanf(pid_file, "%d", &pid) == 1 && pid > 0) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg),
                     "结束小雪内核进程 (pid=%d)", pid);
            write_log(log_msg);
            kill(pid, SIGKILL);
        }
        fclose(pid_file);
        remove("/data/adb/snow_kernel.pid");
    }

    write_log("所有内核进程结束操作完成");
}
// 加载 runDev 配置并执行
void load_and_execute_dev()
{
    FILE* fp = fopen(DEV_CONFIG, "r");
    if (!fp) {
        write_log("无法打开 runDev 配置文件");
        return;
    }

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;

        char path[512] = { 0 };
        char inputs[1024] = { 0 };

        if (parse_config_line(line, path, inputs)) {
            run_elf_with_input(path, inputs, true);
        }
    }
    fclose(fp);
}

// 获取包名的上次状态
bool get_pkg_last_state(const char* pkg, bool* out_state)
{
    for (int i = 0; i < g_pkg_state_count; i++) {
        if (strcmp(g_pkg_states[i].pkg, pkg) == 0) {
            *out_state = g_pkg_states[i].last_state;
            return true;
        }
    }
    if (g_pkg_state_count < MAX_PKG_STATES) {
        strcpy(g_pkg_states[g_pkg_state_count].pkg, pkg);
        g_pkg_states[g_pkg_state_count].last_state = false;
        *out_state = false;
        g_pkg_state_count++;
        return true;
    }
    return false;
}

// 更新包名的上次状态
void set_pkg_last_state(const char* pkg, bool state)
{
    for (int i = 0; i < g_pkg_state_count; i++) {
        if (strcmp(g_pkg_states[i].pkg, pkg) == 0) {
            g_pkg_states[i].last_state = state;
            return;
        }
    }
    if (g_pkg_state_count < MAX_PKG_STATES) {
        strcpy(g_pkg_states[g_pkg_state_count].pkg, pkg);
        g_pkg_states[g_pkg_state_count].last_state = state;
        g_pkg_state_count++;
    }
}

// 动态监控游戏进程
void run_game_monitor()
{
    write_log("进入游戏监控循环");

    MonitorEntry active_entries[MAX_MONITOR_ENTRIES];
    int active_entry_count = 0;
    bool game_running = false;
    char pkg_now[256] = {0};

    while (1) {
        if (!game_running) {
            MonitorEntry entries[MAX_MONITOR_ENTRIES];
            int entry_count = 0;
            FILE* fp = fopen(TASK_CONFIG, "r");
            if (!fp) {
                write_log("无法打开 gameTask 配置文件");
                reap_children();
                sleep(2);
                continue;
            }

            char line[LINE_MAX];
            while (fgets(line, sizeof(line), fp) && entry_count < MAX_MONITOR_ENTRIES) {
                line[strcspn(line, "\n")] = '\0';
                if (strlen(line) == 0) continue;

                char pkg[256] = { 0 };
                char path[512] = { 0 };
                char inputs[1024] = { 0 };
                int delay = 0;

                if (parse_game_line(line, pkg, path, inputs, &delay)) {
                    strcpy(entries[entry_count].pkg, pkg);
                    strcpy(entries[entry_count].path, path);
                    strcpy(entries[entry_count].inputs, inputs);
                    entries[entry_count].delay_seconds = delay;   // 记录延迟
                    entry_count++;
                }
            }
            fclose(fp);

            if (entry_count == 0) {
                reap_children();
                sleep(2);
                continue;
            }

            char* pkgs[MAX_PKG_STATES];
            int pkg_count = 0;
            for (int i = 0; i < entry_count; i++) {
                bool found = false;
                for (int j = 0; j < pkg_count; j++) {
                    if (strcmp(pkgs[j], entries[i].pkg) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found && pkg_count < MAX_PKG_STATES) {
                    pkgs[pkg_count] = entries[i].pkg;
                    pkg_count++;
                }
            }

            bool any_started = false;
            for (int p = 0; p < pkg_count; p++) {
                const char* pkg = pkgs[p];
                bool now = is_process_running(pkg);
                bool last = false;
                if (get_pkg_last_state(pkg, &last)) {
                    if (!last && now) {
                        char log_msg[256];
                        snprintf(log_msg, sizeof(log_msg), "检测到游戏启动: %s", pkg);
                        write_log(log_msg);
                        for (int i = 0; i < entry_count; i++) {
                            if (strcmp(entries[i].pkg, pkg) == 0) {
                                if (entries[i].path[0] == '\0') continue;   // ★ 纯监控，无执行
                                if (entries[i].delay_seconds > 0) {
                                    // 延迟执行：fork 一个子进程负责 sleep
                                    pid_t delay_pid = fork();
                                    if (delay_pid == 0) {
                                        // 子进程 1：等待指定秒数
                                        sleep(entries[i].delay_seconds);
                                        // 二次 fork，让实际执行进程成为孤儿，不阻塞父进程
                                        pid_t inner = fork();
                                        if (inner == 0) {
                                            // 子进程 2：真正执行 ELF
                                            run_elf_with_input(entries[i].path, entries[i].inputs, true);
                                            if (entries[i].inputs[0] != '\0') {
                                                char cmd[1024];
                                                snprintf(cmd, sizeof(cmd), "输入参数:%s", entries[i].inputs);
                                                write_log(cmd);
                                            }else write_log("无输入参数");
                                            _exit(0);
                                        }
                                        // 子进程 1 等待 inner 结束（run_elf_with_input 后台模式会立即返回）
                                        waitpid(inner, NULL, 0);
                                        _exit(0);
                                    }
                                    // 父进程不等待 delay_pid，由 reap_children 后续回收
                                } else {
                                    // 无延迟，直接立即执行
                                    run_elf_with_input(entries[i].path, entries[i].inputs, true);
                                    if (entries[i].inputs[0] != '\0') {
                                        char cmd[1024];
                                        snprintf(cmd, sizeof(cmd), "输入参数:%s", entries[i].inputs);
                                        write_log(cmd);
                                    }else write_log("无输入参数");
                                }
                            }
                        }
                        strncpy(pkg_now, pkgs[p], sizeof(pkg_now) - 1);
                        any_started = true;
                    }
                    if (last != now) {
                        set_pkg_last_state(pkg, now);
                    }
                }
                else {
                    set_pkg_last_state(pkg, now);
                }
            }

            if (any_started) {
                active_entry_count = entry_count;
                for (int i = 0; i < entry_count; i++) {
                    active_entries[i] = entries[i];
                }
                game_running = true;
                reap_children();
                sleep(3);
                clear_telegram_verification_files();
                FILE* f = fopen("/data/adb/runELFConfig/isjiahao", "r");
                if (f) {
                    fclose(f);
                    write_log("游戏已启动，等待嘉豪执行");
                    reap_children();
                    sleep(7);
                    char cmd[1024];
                    char tmp[256];
                    snprintf(cmd, sizeof(cmd),
                        "chmod 777 /data/adb/jhjm; printf 'y' | /data/adb/jhjm >> %s 2>&1 &",
                        LOG_FILE);

                    int res = system(cmd);
                    snprintf(tmp, sizeof(tmp), "[DONE] /data/adb/jhjm 退出码: %d", res);
                    write_log(tmp);
                    // system("printf 'y' | /data/adb/jhjm &");
                }
                write_log("游戏已启动，进入等待退出模式");
            }
            else {
                reap_children();
                sleep(2);
            }
        }
        else {
                if (!is_process_running(pkg_now)) {
                    char log_msg[256];
                    snprintf(log_msg, sizeof(log_msg), "首次启动的游戏 [%s] 已退出，恢复检测", pkg_now);
                    write_log(log_msg);

                    // 将首次启动包名的状态设为 false
                    set_pkg_last_state(pkg_now, false);
                    game_running = false;

                    write_log("收到退出信号，开始清理...");
                    stop_kernel_processes_for_pkg(pkg_now, active_entries, active_entry_count);
                    write_telegram_verification_files();

                    FILE* f = fopen("/data/adb/runELFConfig/iscleanano", "r");
                    if (f) {
                        fclose(f);
                        write_log("检测到iscleanano文件, 开始清理...");
                        clear_dfm_ano_files();
                        write_log("清理完成\n");
                    }
                    reap_children();
                    sleep(1);
                }
                else {
                    reap_children();
                    sleep(2);
                }
            /*
            char pkgs[MAX_PKG_STATES][256];
            int pkg_count = 0;
            for (int i = 0; i < active_entry_count; i++) {
                bool found = false;
                for (int j = 0; j < pkg_count; j++) {
                    if (strcmp(pkgs[j], active_entries[i].pkg) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found && pkg_count < MAX_PKG_STATES) {
                    strcpy(pkgs[pkg_count], active_entries[i].pkg);
                    pkg_count++;
                }
            }

            bool any_running = false;
            for (int p = 0; p < pkg_count; p++) {
                if (is_process_running(pkgs[p])) {
                    any_running = true;
                    break;
                }
            }

            if (!any_running) {
                write_log("所有监控游戏已退出，恢复检测");
                for (int p = 0; p < pkg_count; p++) {
                    set_pkg_last_state(pkgs[p], false);
                }
                game_running = false;
                write_log("收到退出信号，开始清理...");
                stop_kernel_processes_for_pkg(pkg_now, active_entries, active_entry_count);
                write_telegram_verification_files();
                FILE* f = fopen("/data/adb/runELFConfig/iscleanano", "r");
                if (f) {
                    fclose(f);
                    clear_dfm_ano_files();
                }
                reap_children();
                sleep(1);
            }
            else {
                reap_children();
                sleep(2);
            }
            */
        }
    }
}

void run_dev_elf()
{
    write_log("开始执行 Dev 程序");
    load_and_execute_dev();
    // write_log("Dev 程序执行完毕");
}

int main()
{
    // 清空日志
    FILE* clr = fopen(LOG_FILE, "w");
    if (clr) fclose(clr);

    ensure_config_file(DEV_CONFIG);
    ensure_config_file(TASK_CONFIG);
    write_log("监控程序启动，等待网络...");

    while (!check_network()) {
        sleep(3);
    }
    write_log("网络已就绪，等待3秒，开始刷入驱动");
    sleep(1);
    write_log("正在创建过验证文件(上游戏自动清理，下游戏自动恢复) [林羽, 小雪 黑雪, 牛逼哥, XF, 宇宙, 橘子, 六花]");
    write_telegram_verification_files();
    sleep(2);
    run_dev_elf();
    run_game_monitor();

    return 0;
}