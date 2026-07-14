/*
 * pam_pqkerberos.c  —  PAM module for PQ-Kerberos authentication
 *
 * Connects to the PQ-Kerberos PAMAuthDaemon on 127.0.0.1:7777.
 * Every authentication attempt triggers a full post-quantum Kerberos
 * exchange visible in the SystemDaemon terminal window.
 *
 * WIRE PROTOCOL:
 *   Module → Daemon : "username:password\n"
 *   Daemon → Module : "OK:principal@REALM\n"   or   "FAIL:reason\n"
 *
 * COMPILE:
 *   gcc -fPIC -shared -o pam_pqkerberos.so pam_pqkerberos.c -lpam
 *
 * INSTALL:
 *   sudo cp pam_pqkerberos.so /lib/x86_64-linux-gnu/security/
 *
 * CONFIGURE  /etc/pam.d/pqkerberos :
 *   auth    required    pam_pqkerberos.so
 *   account required    pam_permit.so
 *
 * TEST:
 *   sudo pamtester pqkerberos alice authenticate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* ── Configuration ─────────────────────────────────────────────────────── */
#define DAEMON_HOST  "127.0.0.1"
#define DAEMON_PORT  7777
#define TIMEOUT_SEC  20        /* generous — PQ keygen takes time first boot */
#define BUFSIZE      512

/* ── Internal: send username:password, read OK/FAIL ───────────────────── */
static int pqk_authenticate_via_daemon(pam_handle_t *pamh,
                                        const char   *username,
                                        const char   *password,
                                        char         *result_buf,
                                        size_t        result_size)
{
    int fd;
    struct sockaddr_in addr;
    struct timeval tv;
    char request[BUFSIZE];
    ssize_t n;

    /* Create TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR,
            "pam_pqkerberos: socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Socket timeout so a dead daemon doesn't hang login */
    tv.tv_sec  = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Connect to PAMAuthDaemon */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(DAEMON_PORT);
    addr.sin_addr.s_addr = inet_addr(DAEMON_HOST);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        pam_syslog(pamh, LOG_ERR,
            "pam_pqkerberos: cannot connect to %s:%d (%s). "
            "Is the PQ-Kerberos daemon running?",
            DAEMON_HOST, DAEMON_PORT, strerror(errno));
        close(fd);
        return -1;
    }

    /* Send "username:password\n" */
    snprintf(request, sizeof(request), "%s:%s\n", username, password);
    if (send(fd, request, strlen(request), 0) < 0) {
        pam_syslog(pamh, LOG_ERR,
            "pam_pqkerberos: send() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Read daemon response */
    memset(result_buf, 0, result_size);
    n = recv(fd, result_buf, result_size - 1, 0);
    close(fd);

    if (n <= 0) {
        pam_syslog(pamh, LOG_ERR,
            "pam_pqkerberos: recv() failed or daemon closed early: %s",
            strerror(errno));
        return -1;
    }

    /* Strip trailing newline */
    char *nl = strchr(result_buf, '\n');
    if (nl) *nl = '\0';

    return 0;
}

/* ── PAM auth entry point ──────────────────────────────────────────────── */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    const char *username = NULL;
    const char *password = NULL;
    char result[BUFSIZE];
    int rc;

    /* 1. Get username */
    rc = pam_get_user(pamh, &username, "PQ-Kerberos Username: ");
    if (rc != PAM_SUCCESS || !username) {
        pam_syslog(pamh, LOG_WARNING,
            "pam_pqkerberos: could not get username (rc=%d)", rc);
        return PAM_USER_UNKNOWN;
    }

    /* 2. Get password (prompts user if not already cached) */
    rc = pam_get_authtok(pamh, PAM_AUTHTOK, &password,
                          "PQ-Kerberos Password: ");
    if (rc != PAM_SUCCESS || !password) {
        pam_syslog(pamh, LOG_WARNING,
            "pam_pqkerberos: could not get password for '%s' (rc=%d)",
            username, rc);
        return PAM_AUTH_ERR;
    }

    pam_syslog(pamh, LOG_INFO,
        "pam_pqkerberos: authentication attempt for '%s'", username);

    /* 3. Hand off to PAMAuthDaemon */
    if (pqk_authenticate_via_daemon(pamh, username, password,
                                     result, sizeof(result)) != 0) {
        pam_syslog(pamh, LOG_ERR,
            "pam_pqkerberos: daemon unavailable for '%s'", username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* 4. Interpret response */
    if (strncmp(result, "OK:", 3) == 0) {
        const char *principal = result + 3;
        pam_syslog(pamh, LOG_NOTICE,
            "pam_pqkerberos: SUCCESS for '%s' — principal: %s",
            username, principal);
        /* Store principal so pam_get_item(PAM_RUSER) works downstream */
        pam_set_item(pamh, PAM_RUSER, principal);
        return PAM_SUCCESS;
    }

    /* FAIL path */
    const char *reason = (strncmp(result, "FAIL:", 5) == 0)
                         ? result + 5 : result;
    pam_syslog(pamh, LOG_WARNING,
        "pam_pqkerberos: FAILURE for '%s': %s", username, reason);

    /* Small delay to slow down brute-force — same as pam_unix */
    sleep(2);
    return PAM_AUTH_ERR;
}

/* ── Required PAM stubs ────────────────────────────────────────────────── */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    /* Password changes not supported — handled by system auth */
    return PAM_SERVICE_ERR;
}
