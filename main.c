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
	int fingerprint_fd;
	const char *tty_name;
	uint8_t *fingerprint_buffer;

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
		ret = PAM_ABORT;
		goto exit;
	}

	ret = dup2(tty_fd, STDOUT_FILENO);
	if(tty_fd < 0){
		pam_syslog(pamh, LOG_ERR, "Error duplicating stdout: %s", strerror(errno));
		ret = PAM_ABORT;
		goto exit;
	}

	ret = dup2(tty_fd, STDERR_FILENO);
	if(tty_fd < 0){
		pam_syslog(pamh, LOG_ERR, "Error duplicating stderr: %s", strerror(errno));
		ret = PAM_ABORT;
		goto exit;
	}

	fingerprint_fd = open("/dev/fingerprint", O_RDONLY);
	if(fingerprint_fd < 0){
		perror("Could not open fingerprint");
		ret = PAM_ABORT;
		goto exit;
	}

	fingerprint_buffer = malloc(64);
	if(fingerprint_buffer == NULL){
		pam_syslog(pamh, LOG_ERR, "Could not allocate buffer for data");
		ret = PAM_ABORT;
		goto exit_close;
	}
    
	printf("Waiting for fingerprint...\n");
	ret = read(fingerprint_fd, fingerprint_buffer, 64);
	if(ret < 0){
		perror("Could not read data from reader");
		free(fingerprint_buffer);
		close(fingerprint_fd);
		ret = PAM_ABORT;
		goto exit_free;
	} else {
		switch(fingerprint_buffer[1]){ // the byte where the most important data is stored
			case 0xfd: // failure
				fprintf(stderr, "Fingerprint not recognized!\n");
				pam_syslog(pamh, LOG_ERR, "Fingerprint not recognized!\n");
				ret = PAM_ABORT;
				break;

			case 0x01:
				ret = PAM_SUCCESS;
				break;

			default:
				ret = PAM_ABORT;
				break;
		}
	}

exit_free:
	free(fingerprint_buffer);
exit_close:
	close(fingerprint_fd);
exit:
	return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_SUCCESS;
}
