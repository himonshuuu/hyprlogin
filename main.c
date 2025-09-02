#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <grp.h>

static void disable_echo(void) {
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &t) == 0) {
        t.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    }
}

static void enable_echo(void) {
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &t) == 0) {
        t.c_lflag |= ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    }
}

struct conv_data {
    char *username;
    char *password;
};

static int pam_conv_fn(int num_msg, const struct pam_message **msg,
                      struct pam_response **resp, void *appdata_ptr) {
    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    struct pam_response *aresp = calloc(num_msg, sizeof(struct pam_response));
    if (!aresp) {
        return PAM_CONV_ERR;
    }

    struct conv_data *cd = (struct conv_data *)appdata_ptr;
    
    for (int i = 0; i < num_msg; i++) {
        const struct pam_message *m = msg[i];
        if (!m) {
            continue;
        }

        switch (m->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                if (!cd->password) {
                    char buf[512] = {0};
                    
                    if (m->msg && *m->msg) {
                        fprintf(stdout, "%s", m->msg);
                        fflush(stdout);
                    }
                    
                    disable_echo();
                    if (!fgets(buf, sizeof(buf), stdin)) {
                        enable_echo();
                        free(aresp);
                        return PAM_CONV_ERR;
                    }
                    enable_echo();
                    
                    size_t len = strlen(buf);
                    if (len && buf[len-1] == '\n') {
                        buf[len-1] = '\0';
                    }
                    cd->password = strdup(buf);
                }
                aresp[i].resp = strdup(cd->password);
                aresp[i].resp_retcode = 0;
                break;

            case PAM_PROMPT_ECHO_ON:
                if (!cd->username) {
                    char buf[256] = {0};
                    
                    if (m->msg && *m->msg) {
                        fprintf(stdout, "%s", m->msg);
                        fflush(stdout);
                    }
                    
                    if (!fgets(buf, sizeof(buf), stdin)) {
                        free(aresp);
                        return PAM_CONV_ERR;
                    }
                    
                    size_t len = strlen(buf);
                    if (len && buf[len-1] == '\n') {
                        buf[len-1] = '\0';
                    }
                    cd->username = strdup(buf);
                }
                aresp[i].resp = strdup(cd->username);
                aresp[i].resp_retcode = 0;
                break;

            case PAM_TEXT_INFO:
                if (m->msg) {
                    fprintf(stdout, "%s\n", m->msg);
                }
                aresp[i].resp = NULL;
                aresp[i].resp_retcode = 0;
                break;

            case PAM_ERROR_MSG:
                if (m->msg) {
                    fprintf(stderr, "%s\n", m->msg);
                }
                aresp[i].resp = NULL;
                aresp[i].resp_retcode = 0;
                break;

            default:
                aresp[i].resp = NULL;
                aresp[i].resp_retcode = 0;
                break;
        }
    }
    *resp = aresp;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    struct conv_data cd = {0};

    // check if running interactively
    if (isatty(STDIN_FILENO)) {
        printf("Username: ");
        fflush(stdout);
        
        char username[256] = {0};
        if (!fgets(username, sizeof(username), stdin)) {
            return 1;
        }

        size_t len = strlen(username);
        if (len && username[len-1] == '\n') {
            username[len-1] = '\0';
        }

        if (strlen(username) == 0) {
            fprintf(stderr, "empty username\n");
            return 1;
        }

        cd.username = strdup(username);
    } else {
        fprintf(stderr, "stdin is not a tty\n");
        return 1;
    }

    // initialize PAM
    struct pam_conv conv = {
        .conv = pam_conv_fn,
        .appdata_ptr = &cd
    };
    
    pam_handle_t *pamh = NULL;
    const char *service = "hyprlogin";
    
    int ret = pam_start(service, cd.username, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_start: %s\n", pam_strerror(pamh, ret));
        return 1;
    }

    // authenticate user
    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 1;
    }

    // check account validity
    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "Account not available: %s\n", pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 1;
    }

    pam_setcred(pamh, PAM_ESTABLISH_CRED);

    ret = pam_open_session(pamh, 0);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_open_session: %s\n", pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 1;
    }

    // get user info
    struct passwd *pw = getpwnam(cd.username);
    if (!pw) {
        fprintf(stderr, "user not found\n");
        pam_close_session(pamh, 0);
        pam_end(pamh, 0);
        return 1;
    }

    // set up environment
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", pw->pw_shell, 1);
    setenv("XDG_SESSION_TYPE", "wayland", 1);
    setenv("XDG_CURRENT_DESKTOP", "Hyprland", 1);

    // change to home directory
    if (chdir(pw->pw_dir) != 0) {
        /* ignore failure */
    }

    // set user/group permissions
    if (setgid(pw->pw_gid) != 0) {
        perror("setgid");
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        perror("initgroups"); 
    }
    if (setuid(pw->pw_uid) != 0) {
        perror("setuid");
    }

    // execute shell
    execlp("bash", "bash", (char *)NULL);

    // only reached on exec failure
    fprintf(stderr, "failed to exec bash: %s\n", strerror(errno));

    pam_close_session(pamh, 0);
    pam_end(pamh, 0);

    return 1;
}