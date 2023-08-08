#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>

struct fingerprint_thread_arguments {
	pam_handle_t *pamh;

	pid_t parent_id;
};
typedef struct fingerprint_thread_arguments ft_args_t;

void *fingerprint_thread_function(void *args){
	ft_args_t ft_args;
	int fingerprint_fd, ret;
	ssize_t bytes_read;
	uint8_t *fingerprint_buffer;

	ft_args = *((ft_args_t*)args);

	fingerprint_fd = open("/dev/fingerprint", O_RDONLY);
	if(fingerprint_fd < 0){
		pam_syslog(ft_args.pamh, LOG_ERR, "Could not open fingerprint reader: %s", strerror(errno));
		return NULL;
	}

	fingerprint_buffer = malloc(64);
	if(fingerprint_buffer == NULL){
		pam_syslog(ft_args.pamh, LOG_ERR, "Memory error! Abort");
	}

	bytes_read = read(fingerprint_fd, fingerprint_buffer, 64);
	if(fingerprint_fd < 0){
		pam_syslog(ft_args.pamh, LOG_ERR, "Error reading data from reader: %s", strerror(errno));
		return NULL;
	}

	return NULL;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv ){
	ssize_t ret;
	int fingerprint_fd;
	uint8_t *fingerprint_buffer;
	pthread_t fingerprint_thread;
	pid_t pid;
	ft_args_t *ft_arguments;

	ft_arguments = malloc(sizeof(ft_args_t));
	if(ft_arguments == NULL){
		pam_syslog(pamh, LOG_ERR, "Memory error! Abort");
		ret = PAM_ABORT;
		goto exit;
	}

	pid = getpid();
	ft_arguments->parent_id = pid;
	ft_arguments->pamh = pamh;

	pthread_create(&fingerprint_thread, NULL, fingerprint_thread_function, (void *)ft_arguments);

	fingerprint_fd = open("/dev/fingerprint", O_RDONLY);
	if(fingerprint_fd < 0){
		pam_syslog(pamh, LOG_ERR, "Error opening fingerprint reader: %s", strerror(errno));
		ret = PAM_ABORT;
		goto exit;
	}

	fingerprint_buffer = malloc(64);
	if(fingerprint_buffer == NULL){
		pam_syslog(pamh, LOG_ERR, "Could not allocate buffer for data");
		ret = PAM_ABORT;
		goto exit_close;
	}
    
	ret = read(fingerprint_fd, fingerprint_buffer, 64);
	if(ret < 0){
		pam_syslog(pamh, LOG_ERR, "Could not read data from reader: %s", strerror(errno));
		free(fingerprint_buffer);
		close(fingerprint_fd);
		ret = PAM_ABORT;
		goto exit_free;
	} else {
		switch(fingerprint_buffer[1]){ // the byte where the most important data is stored
			case 0xfd: // failure
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
