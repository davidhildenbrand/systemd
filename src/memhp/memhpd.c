/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-table.h"
#include "proc-cmdline.h"
#include "fd-util.h"
#include "fileio.h"
#include "env-file.h"
#include "virt.h"
#include "sd-device.h"
#include "device-util.h"
#include "device-private.h"

typedef enum BlockState {
        BLOCK_STATE_OFFLINE = 0,
        BLOCK_STATE_ONLINE,
        BLOCK_STATE_ONLINE_KERNEL,
        BLOCK_STATE_ONLINE_MOVABLE,
        _BLOCK_STATE_MAX,
        _BLOCK_STATE_INVALID = -1,
} BlockState;

static const char* const block_state_table[_BLOCK_STATE_MAX] = {
        [BLOCK_STATE_OFFLINE] = "offline",
        [BLOCK_STATE_ONLINE] = "online",
        [BLOCK_STATE_ONLINE_KERNEL] = "online_kernel",
        [BLOCK_STATE_ONLINE_MOVABLE] = "online_movable",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(block_state, BlockState);

static bool auto_online_block_state_supported;
BlockState target_state;
sd_device_monitor *device_monitor;
static sd_event *event;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-memhpd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Memory Hotplug Configuration Daemon.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --list             List all known memory block states\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_LIST,
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                { "list",          no_argument,       NULL, ARG_LIST          },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hq", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_LIST:
                        DUMP_STRING_TABLE(block_state, int, _BLOCK_STATE_MAX);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.",
                                       program_invocation_short_name);

        return 1;
}

static BlockState memhp_get_auto_online_block_state(void) {
        const char *auto_path = "/sys/devices/system/memory/auto_online_blocks";
        _cleanup_free_ char *buf = NULL;
        BlockState state;
        int r;

        assert(auto_online_block_state_supported);

        r = read_one_line_file(auto_path, &buf);
        if (r < 0)
                return _BLOCK_STATE_INVALID;

        state = block_state_from_string(buf);
        if (state < 0) {
                log_warning("Unknown target memory block state is currently configured: %s", buf);
                return _BLOCK_STATE_INVALID;
        }
        return state;
}

static int memhp_set_auto_online_block_state(BlockState state)
{
        const char *auto_path = "/sys/devices/system/memory/auto_online_blocks";

        assert(auto_online_block_state_supported);

        return write_string_file(auto_path, block_state_to_string(state),
                                 WRITE_STRING_FILE_DISABLE_BUFFER);
}

static void memhp_process_memory_block_device(sd_device *d, BlockState state) {
        const char *sysfs, *old_state;
        int r;

        assert(state > 0 && state != BLOCK_STATE_OFFLINE);

        r = sd_device_get_syspath(d, &sysfs);
        if (r < 0) {
                log_error_errno(r, "Failed to acquire sysfs path of device: %m");
                return;
        }

        r = sd_device_get_sysattr_value(d, "state", &old_state);
        if (r == -ENOENT)
                return;
        if (r < 0) {
                log_error_errno(r, "Failed to acquire 'state' device property, ignoring: %m");
                return;
        }

        if (streq(old_state, "offline")) {
                log_debug("Onlining: %s", sysfs);
                r = sd_device_set_sysattr_value(d, "state", "online");
                if (r < 0) {
                        log_error_errno(r, "Failed to online: %m");
                        return;
                }
        }
}

static int memhp_device_monitor_event(sd_device_monitor *monitor, sd_device *d, void *userdata) {
        DeviceAction action;
        int r;

        r = device_get_action(d, &action);
        if (r < 0) {
                log_error_errno(r, "Failed to get udev action: %m");
                return 0;
        }

        if (action != DEVICE_ACTION_ADD)
                return 0;

        memhp_process_memory_block_device(d, target_state);
        return 0;
}

static int memhp_watch_devices(void) {
        int r;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_device_monitor_new(&device_monitor);
        if (r < 0)
                return log_error_errno(-r, "Failed to allocate device monitor: %m");

        /* TODO: do we need sd_device_monitor_set_receive_buffer_size * */

        r = sd_device_monitor_filter_add_match_subsystem_devtype(device_monitor, "memory", NULL);
        if (r < 0)
                return log_error_errno(-r, "Failed to configure device monitor match: %m");

        r = sd_device_monitor_attach_event(device_monitor, event);
        if (r < 0)
                return log_error_errno(-r, "Failed to attach device monitor to event loop: %m");

        r = sd_device_monitor_start(device_monitor, memhp_device_monitor_event, NULL);
        if (r < 0)
                return log_error_errno(-r, "Failed to start device monitor: %m");

        return 0;
}

static int memhp_enumerate_devices(BlockState state) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "memory", true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d)
                memhp_process_memory_block_device(d, state);
        return 0;
}

static int memhp_set_target_block_state(BlockState state) {
        BlockState old_state;
        int r = 0;

        log_info("Setting target memory block state to: %s", block_state_to_string(state));
        target_state = state;

        if (auto_online_block_state_supported) {
                old_state = memhp_get_auto_online_block_state();
        } else if (state == BLOCK_STATE_OFFLINE) {
                /*
                 * Without kernel support and when wanting to keep memory
                 * offline, there really isn't anything to do for use.
                 */
                return 0;
        }

        if (old_state == state) {
                log_debug("Target memory block state already matches: %s", block_state_to_string(r));
                return 0;
        } else if (auto_online_block_state_supported) {
                /*
                 * Setting should monly fail for older kernels which don't
                 * support "online_movable" or "online_kernel".
                 */
                r = memhp_set_auto_online_block_state(state);
                if (r) {
                        if (state != BLOCK_STATE_ONLINE_MOVABLE &&
                            state != BLOCK_STATE_ONLINE_KERNEL) {
                                return log_error_errno(-r, "Setting auto online block state failed: %m");
                        }
                }
        }

        if (state == BLOCK_STATE_OFFLINE) {
                return 0;
        }

        /*
         * In case we failed to configure behavior in the kernel, default
         * to "offline" (just in case anything was configured) and handle it via
         * udev events.
         */
        if (r) {
                if (old_state != BLOCK_STATE_OFFLINE) {
                        r = memhp_set_auto_online_block_state(BLOCK_STATE_OFFLINE);
                        if (r) {
                                return log_error_errno(-r, "Setting auto online block state failed: %m");
                        }
                }
                memhp_watch_devices();
        } else if (!auto_online_block_state_supported) {
                memhp_watch_devices();
        }

        /* Process any devices that are already there. */
        if (old_state == BLOCK_STATE_OFFLINE || old_state < 0)
                memhp_enumerate_devices(state);
        return 0;
}

#if defined(__i386__) || defined(__x86_64__)
static bool memhp_is_rhv(void) {
        _cleanup_free_ char *product_family  = NULL;
        int r;

        r = read_one_line_file("/sys/devices/virtual/dmi/id/product_family", &product_family);
        if (r < 0)
                return false;
        return streq(product_family, "RHV");
}
#endif

static BlockState memhp_auto_detect_target_block_state(void) {
        int r;

        r = detect_vm();
        if (r < 0)
                return log_error_errno(-r, "Could not detect virtualization");

#if defined(__s390__) || defined(__s390x__)
        /*
         * On LPAR and under z/VM we can have standby memory which is to
         * be onlined by the user manually on demand. Under KVM, we might
         * have other hot(un)plug mechanisms in the future (e.g., virito-mem).
         */
        if (r != VIRTUALIZATION_KVM)
                return BLOCK_STATE_OFFLINE;
#elif defined(__powerpc__) || defined(__powerpc64__)
        /*
         * Memory added via dlpar/"dynamic memory" in the kernel is onlined
         * automatically, even when set onlining behavior is configured
         * "offline". The semantics correspond to "online" in that case. While
         * some drivers (Nvidia CUDA) require hotplugged memory to remain
         * offline or to be onlined movable, we expect manual configuration for
         * these special cases.
         */
        return BLOCK_STATE_ONLINE;
#endif

        if (r == VIRTUALIZATION_NONE) {
                /*
                 * On enterprise servers that support memory hotplug, users
                 * assume hotplugged memory can get hotunplugged again.
                 */
                return BLOCK_STATE_ONLINE_MOVABLE;
        }
#if defined(__i386__) || defined(__x86_64__)
        /*
         * RHV users on x86_64 expect hotplugged DIMMs to VMs to be
         * hotunpluggable again. RHV takes care of avoiding zone imbalances.
         */
        if (memhp_is_rhv())
                return BLOCK_STATE_ONLINE_MOVABLE;
#endif
        /*
         * Many VMs rely on ballooning to work as expected - which is often
         * incompatible with ZONE_MOVABLE. Environments where the MOVABLE
         * zone is safe should configure this explicitly.
         */
        return BLOCK_STATE_ONLINE;
}

static int memhp_check_system(void) {
        const char *auto_path = "/sys/devices/system/memory/auto_online_blocks";
        const char *sysfs_path = "/sys/devices/system/memory/";
        _cleanup_fclose_ FILE *config_file = NULL;
        _cleanup_free_ char *c = NULL;
        int r;

        r = proc_cmdline_get_key("memhp_default_state", 0, &c);
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'memhp_default_state' is configured via kernel cmdline");

        if (access(sysfs_path, F_OK) < 0) {
                log_info("Kernel does not support memory hotplug");
                return -ENODEV;
        }

        if (access(auto_path, F_OK) < 0) {
                log_info("Auto online support missing in the kernel");
        } else {
                auto_online_block_state_supported = true;

                if (access(auto_path, R_OK|W_OK) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                               "Missing access permissions for file: %s", auto_path);
        }

        /*
         * The user might either have already configured it or the kernel
         * defaults to !OFFLINE (e.g., CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE).
         *
         * Let's warn in that case.
         */
        if (auto_online_block_state_supported) {
                r = memhp_get_auto_online_block_state();
                if (r < 0)
                        log_warning("Could not read configured target memory block state");
                if (r != BLOCK_STATE_OFFLINE)
                        log_warning("Target memory block state is already configured to: %s",
                                    block_state_to_string(r));
        }
        return 0;
}

static int memhp_run(void)
{
        int r;

        /*
         * In case we can handle it fully in the kernel, there is nothing
         * to do for us.
         */
        if (!device_monitor) {
                log_info("No event loop required, going to sleep.");
                pause();
                return 0;
        }

        while (true) {
                r = sd_event_get_state(event);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        return 0;

                log_debug("Running event loop");
                r = sd_event_run(event, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *conf_block_state = NULL;
        BlockState state;
        int r;

        log_setup_cli();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_env_file(NULL, "/etc/memhpd.conf", "TARGET_BLOCK_STATE", &conf_block_state);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/memhp.conf: %m");

        r = memhp_check_system();
        if (r == -ENODEV)
                return 0;
        else if (r)
                return r;

        if (conf_block_state) {
                log_debug("Using target memory block state for hotplugged memory from config file");
                state = block_state_from_string(conf_block_state);
                if (state < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown target block state: %s",
                                               conf_block_state);
        } else {
                log_debug("Auto detecting target memory block state for hotplugged memory");
                state = memhp_auto_detect_target_block_state();
        }

        r = memhp_set_target_block_state(state);
        if (r)
                return r;

        return memhp_run();
}

DEFINE_MAIN_FUNCTION(run);
