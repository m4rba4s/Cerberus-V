// SPDX-License-Identifier: Apache-2.0
// Landlock LSM Integration for Cerberus-V
// APT-Grade Filesystem Access Control

#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
        const struct landlock_ruleset_attr *const attr,
        const size_t size, const __u32 flags)
{
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
        const enum landlock_rule_type rule_type,
        const void *const rule_attr, const __u32 flags)
{
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
            rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
        const __u32 flags)
{
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

// Cerberus-V specific filesystem paths
static const char *CERBERUS_PATHS[] = {
    "/var/log/cerberus",
    "/sys/fs/bpf",
    "/run/vpp",
    "/etc/cerberus",
    "/opt/cerberus"
};

// Initialize Landlock LSM for Cerberus-V
int cerberus_landlock_init(void) {
    int abi_version;
    int ruleset_fd;
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                            LANDLOCK_ACCESS_FS_WRITE_FILE |
                            LANDLOCK_ACCESS_FS_READ_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_MAKE_CHAR |
                            LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_MAKE_REG |
                            LANDLOCK_ACCESS_FS_MAKE_SOCK |
                            LANDLOCK_ACCESS_FS_MAKE_FIFO |
                            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                            LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    // Check Landlock ABI version
    abi_version = landlock_create_ruleset(NULL, 0,
            LANDLOCK_CREATE_RULESET_VERSION);
    if (abi_version < 0) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Landlock not supported by kernel\n");
            return -1;
        }
        if (errno == EOPNOTSUPP) {
            fprintf(stderr, "Landlock not supported by kernel configuration\n");
            return -1;
        }
        fprintf(stderr, "Failed to get Landlock ABI version: %s\n", strerror(errno));
        return -1;
    }

    // Create ruleset
    ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "Failed to create Landlock ruleset: %s\n", strerror(errno));
        return -1;
    }

    // Add rules for Cerberus-V paths
    for (size_t i = 0; i < sizeof(CERBERUS_PATHS) / sizeof(CERBERUS_PATHS[0]); i++) {
        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR,
            .parent_fd = open(CERBERUS_PATHS[i], O_PATH | O_CLOEXEC),
        };

        if (path_beneath.parent_fd < 0) {
            fprintf(stderr, "Failed to open %s: %s\n", CERBERUS_PATHS[i], strerror(errno));
            continue;
        }

        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                &path_beneath, 0)) {
            fprintf(stderr, "Failed to add Landlock rule for %s: %s\n", 
                    CERBERUS_PATHS[i], strerror(errno));
            close(path_beneath.parent_fd);
            continue;
        }

        close(path_beneath.parent_fd);
    }

    // Set no new privileges
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        fprintf(stderr, "Failed to set no new privileges: %s\n", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    // Apply Landlock restrictions
    if (landlock_restrict_self(ruleset_fd, 0)) {
        fprintf(stderr, "Failed to apply Landlock restrictions: %s\n", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    close(ruleset_fd);
    return 0;
}

// Test Landlock functionality
int test_landlock(void) {
    printf("Testing Landlock LSM integration...\n");
    
    if (cerberus_landlock_init() == 0) {
        printf("✅ Landlock LSM successfully applied\n");
        printf("Filesystem access restricted to Cerberus-V paths\n");
        return 0;
    } else {
        printf("❌ Landlock LSM initialization failed\n");
        return -1;
    }
}

#ifdef TEST_LANDLOCK
int main(void) {
    return test_landlock();
}
#endif 