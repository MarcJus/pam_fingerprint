build: main.c
	gcc -fPIC -fno-stack-protector -c main.c -lpam -lpam_misc
	sudo -S ld -x --shared -o /usr/lib/x86_64-linux-gnu/security/fingerprint.so /home/marc/CLionProjects/pam_fingerprint/main.o /usr/lib/x86_64-linux-gnu/libpam_misc.so

run:
	pamtester -v sudo marc authenticate
