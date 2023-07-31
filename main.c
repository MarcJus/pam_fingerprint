#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <errno.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv ){
	ssize_t ret;
	int tty_fd;
	const char *tty_name;

	ret = pam_get_item(pamh, PAM_TTY, (const void **)&tty_name);

	if(tty_name == NULL){
		tty_name = ttyname(STDOUT_FILENO);
		if(tty_name == NULL){
			pam_syslog(pamh, LOG_ALERT, "Could not get tty name");
			tty_name = "/dev/tty";
		}
	}

	pam_syslog(pamh, LOG_DEBUG, "tty: %s", tty_name);

	tty_fd = open(tty_name, O_RDWR);
	if(tty_fd < 0){
		pam_syslog(pamh, LOG_ERR, "Could not open tty: %s", strerror(errno));
		return PAM_ABORT;
	}

	return PAM_ABORT;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_SUCCESS;
}
