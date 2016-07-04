/*
 * tunproxy.c --- small demo program for tunneling over UDP with tun/tap
 *
 * Copyright (C) 2003  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
//pki part

#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include <openssl/rsa.h> 
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//pipe and fork part
#include <sys/wait.h>

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define BUFFER_LENGTH 1500
// length for hmac sha256
#define OUTPUT_LENGTH 32


//pki client part
#define CCERTF "client.crt"
#define CKEYF "client.key"
#define CCACERT "ca.crt"

//pki server part
/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define SCERTF  HOME "server.crt"
#define SKEYF  HOME  "server.key"
#define SCACERT HOME "ca.crt"

#define ClientCN "PKILabClient.com"
#define ServerCN "PKILabServer.com"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

unsigned char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";
void generateRandKey(char* key_iv)
{
  srand(time(0));
  int i=0;
  for(i=0;i<16;i++)
  {
    key_iv[i] = rand()%254+1;
  }
}
void generateRandIV(char* key_iv)
{
  srand(time(0));
  int i=0;
  for(i=0;i<16;i++)
  {
    key_iv[i+16] = rand()%254+1;
  }
}
void usage()
{
	fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");
	exit(0);
}

void menuOp(pid_t cpid, char* key_iv)
{
   int i=0;
   char inCh;
   printf("\n-----------------\n");
   printf(" a> change key\n");
   printf(" b> change IV\n");
   printf(" c> exit\n");
   printf("-----------------\n");
   scanf("%c",&inCh);getchar();
   if(inCh == 'a')
   {
	printf("   1> generate random key\n");
	printf("   2> user input key\n");
	scanf("%c",&inCh);getchar();
	if(inCh == '1')
	{
	  generateRandKey(key_iv);
	}
	else if(inCh == '2')
	{
	  for(i=0;i<16;i++)//should be change late to support key with size > 16
	  {
		scanf("%c",&inCh);
		if(inCh == '\n'){break;}
		key_iv[i] = inCh;
	  }
	}
	else{kill(cpid,SIGKILL);exit(0);}
   }
   else if(inCh == 'b')
   {
	printf("   1> generate random IV\n");
	printf("   2> user input IV\n");
	scanf("%c",&inCh);getchar();
	if(inCh == '1')
	{
	  generateRandIV(key_iv);
	}
	else if(inCh == '2')
	{
	  for(i=0;i<16;i++)
	  {
		scanf("%c",&inCh);
		if(inCh == '\n'){break;}
		key_iv[i+16] = inCh;
	  }
	}
	else{kill(cpid,SIGKILL);exit(0);}
   }
   else if(inCh == 'c'){kill(cpid,SIGKILL);exit(0);}
   else{kill(cpid,SIGKILL);exit(0);}
}

int do_crypt(char* keyiv, unsigned char *inbuf, int inlen,unsigned  char *outbuf, int *outlen, int do_encrypt)
{
	int i;
	int tmplen;
	// Bogus key and IV: we'd normally set these from another source.
	unsigned char key[16];
	unsigned char iv[16];
for(i=0;i<16;i++)
{
	key[i] = keyiv[i];
}
for(i=0;i<16;i++)
{
	iv[i] = keyiv[i+16];
}

	// Don't set key or IV because we will modify the parameters
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
	// We finished modifying parameters so now we can set key and IV
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

	// outlen is passed by reference
	if(!EVP_CipherUpdate(&ctx, outbuf, outlen, inbuf, inlen))
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	if(!EVP_CipherFinal_ex(&ctx, outbuf + *outlen, &tmplen))
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	*outlen += tmplen;

	EVP_CIPHER_CTX_cleanup(&ctx);
	return 1;
}

// print hash value in hex
print(unsigned char *md, int md_len)
{
	int i;
	for(i = 0; i < md_len; i++)
	{
		printf("%02x", md[i]);
	}
	printf("\n");
}

//pki client
void doPKIClient(pid_t cpid, int* pipefd,char* newkeyiv,int port, int PORT, char* ip)//(int argc, char* argv[])
{
  int i;
  int err;
  int sd;
  struct sockaddr_in sa;
  SSL_CTX* ctx;//create a context for one or more ssl session
  SSL*     ssl;//hold ssl connection structure
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;

  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);

  CHK_SSL(err);


  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  SSL_CTX_load_verify_locations(ctx,CCACERT,NULL);//load cert, location for ca

  if (SSL_CTX_use_certificate_file(ctx, CCERTF, SSL_FILETYPE_PEM) <= 0) {//load the fisrt cert from file to ctx
	  ERR_print_errors_fp(stderr);
	  exit(-2);
  }
  
  if (SSL_CTX_use_PrivateKey_file(ctx, CKEYF, SSL_FILETYPE_PEM) <= 0) {//load private key for use with ssl
	  ERR_print_errors_fp(stderr);
	  exit(-3);
  }

  if (!SSL_CTX_check_private_key(ctx)) {//check private key with cert
	  printf("Private key does not match the certificate public keyn");
	  exit(-4);
  }
  
  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr (ip);   /* Server IP */
  sa.sin_port        = htons     (port);          /* Server Port number */
  
  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, sd);//assign a socket to ssl
//start ssl session with remote server
  err = SSL_connect (ssl);                     CHK_SSL(err);
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */

  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printf ("Server certificate:\n");

//blx verifying the common name

char commonName[512];
X509_NAME *name=X509_get_subject_name (server_cert);
X509_NAME_get_text_by_NID(name,NID_commonName,commonName,512);
//printf("%s\n",commonName);
if(strcmp(commonName,ServerCN)!=0)
{
printf("wrong CN\n");
exit(-1);
}
printf("right CN\n");

  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);

  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  X509_free (server_cert);
  
  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  //generate rand iv and key as initial
  generateRandKey(newkeyiv);
  generateRandIV(newkeyiv);

  err = SSL_write (ssl, newkeyiv, 32);  CHK_SSL(err);//write new key and iv to server
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);//read reply from server
  buf[err] = '\0';
  //if(err == 0){continue;}
  //printf ("Got %d chars:'%s'\n", err, buf);
  printf ("%s\n", buf);
  write(pipefd[1], newkeyiv, 32);


  //not the first time, user decide
while(1){
  menuOp(cpid,newkeyiv);

  err = SSL_write (ssl, newkeyiv, 32);  CHK_SSL(err);//write new key and iv to server
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);//read reply from server
  buf[err] = '\0';
  //if(err == 0){continue;}
  //printf ("Got %d chars:'%s'\n", err, buf);
  printf ("%s\n", buf);
  write(pipefd[1], newkeyiv, 32);
}
  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

//pki server
void doPKIServer(pid_t cpid, int* pipefd,char* newkeyiv, int port, int PORT, char* ip)//(int argc, char* argv[])
{
  int i;
  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;
  
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,SCACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, SCERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, SKEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (PORT);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  printf ("Connection from %lx, port %x\n",
	  (long unsigned int)sa_cli.sin_addr.s_addr, sa_cli.sin_port);
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  if (client_cert != NULL) {
    printf ("Client certificate:\n");


//blx verify the common name
char commonName[512];
X509_NAME *name=X509_get_subject_name (client_cert);
X509_NAME_get_text_by_NID(name,NID_commonName,commonName,512);
//printf("%s\n",commonName);
if(strcmp(commonName,ClientCN)!=0)
{
printf("wrong CN\n");
exit(-1);
}
printf("right CN\n");
  
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    X509_free (client_cert);
  } else
    printf ("Client does not have certificate.\n");

  /* DATA EXCHANGE - Receive message and send reply. */
while(1){//key read new key and iv
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
  if(err ==0){continue;}
  buf[err] = '\0';
  //printf ("Got %d chars:'%s'\n", err, buf);

  for(i=0;i<32;i++)
  {
	newkeyiv[i] = buf[i];
  }
  write(pipefd[1], newkeyiv, 32);//write the new key and iv to tunnel process
  err = SSL_write (ssl, "server recieved new key or iv.", strlen("server recieved new key or iv."));  CHK_SSL(err);//write reply to client
}
  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

int main(int argc, char *argv[])
{
/*
//test
char testki[32];
print(testki,32);
menuOp(testki);
print(testki,32);
menuOp(testki);
print(testki,32);
*/

//select mode from argv, and decide the port and ip and if client or server
	int port, PORT;
	char c, *p, *ip;
	int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;
	while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
		switch (c) {
		case 'h':
			usage();
		case 'd':
			DEBUG++;
			break;
		case 's':
			MODE = 1;
			PORT = atoi(optarg);
			break;
		case 'c':
			MODE = 2;
			p = memchr(optarg,':',16);
			if (!p) ERROR("invalid argument : [%s]\n",optarg);
			*p = 0;
			ip = optarg;
			port = atoi(p+1);
			PORT = 0;
			break;
		case 'e':
			TUNMODE = IFF_TAP;
			break;
		default:
			usage();
		}
	}
	if (MODE == 0) usage();

///////////////////////////tunnel communicate part begin////////////////////////////////////
	struct sockaddr_in sin, sout, from;
	struct ifreq ifr;
	int fd, s, fromlen, soutlen, l, outl;
	
	/* Allow enough space in output buffer for additional block */
	unsigned char buf[BUFFER_LENGTH + OUTPUT_LENGTH], encryptedbuf[BUFFER_LENGTH + OUTPUT_LENGTH + EVP_MAX_BLOCK_LENGTH];
	unsigned char digest[OUTPUT_LENGTH];
	fd_set fdset;

	if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TUNMODE;
	strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
	printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
	
	s = socket(PF_INET, SOCK_DGRAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(PORT);
	if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");

	fromlen = sizeof(from);

	if (MODE == 1) {
		while(1) {
			l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (l < 0) PERROR("recvfrom");
			if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
				break;
//			printf("Bad magic word from %s:%i\n", 
//			       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
		} 
		l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
		if (l < 0) PERROR("sendto");
	} else {
		from.sin_family = AF_INET;
		from.sin_port = htons(port);
		inet_aton(ip, &from.sin_addr);
		l =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
		if (l < 0) PERROR("sendto");
		l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
		if (l < 0) PERROR("recvfrom");
		if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
			ERROR("Bad magic word for peer\n");
	}
///////////////////////////tunnel create part end////////////////////////////////////

char newkeyiv[32];
char keyiv[32];// = {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1};

//pipe and fork prepare
    int pipefd[2];
    pid_t cpid;

    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    cpid = fork();
    if (cpid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

//pki part
    if (cpid > 0) {            // Parent writes argv[1] to pipe
        close(pipefd[0]);          // Close unused read end    

        //pki
	if(MODE == 1)
	{doPKIServer(cpid,pipefd,newkeyiv,port, PORT, ip);}
	else if(MODE == 2)
	{doPKIClient(cpid,pipefd,newkeyiv,port, PORT, ip);}

	//exit
        wait(NULL);                // Wait for child
	kill(cpid,SIGKILL);
    }

//tunnel part
    else {    // Child reads from pipe
        close(pipefd[1]);          // Close unused write end
	fcntl(pipefd[0],F_SETFL,O_NONBLOCK);//set unblock pipe read

///////////////////////////tunnel communicate part begin////////////////////////////////////
	int num;
        
	int i;
	char key[16];
		while (1) {
		num=read(pipefd[0], keyiv, 32);//read key and iv from pki process
		if(num==32){//if read new key and iv, print it
			printf("new key and iv:\n");
			print(keyiv,32);
		}
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
		if (FD_ISSET(fd, &fdset)) {
			if (DEBUG) write(1,">", 1);
			l = read(fd, buf, BUFFER_LENGTH);
			if (l < 0) PERROR("read");
			// encrypt here
			do_crypt(keyiv, buf, l, encryptedbuf, &outl, 1);
			// hmac
for(i=0;i<16;i++)
{
	key[i] = keyiv[i];
}
			strncpy(digest, HMAC(EVP_sha256(), key, 16, (unsigned char *)encryptedbuf, outl, NULL, NULL), OUTPUT_LENGTH);
			// add on hmac
			strncpy(encryptedbuf + outl, digest, OUTPUT_LENGTH);
			outl += OUTPUT_LENGTH;
			if (sendto(s, encryptedbuf, outl, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
		} else {
			if (DEBUG) write(1,"<", 1);
			l = recvfrom(s, encryptedbuf, sizeof(encryptedbuf), 0, (struct sockaddr *)&sout, &soutlen);
			// get hmac
			l -= OUTPUT_LENGTH;
			strncpy(digest, encryptedbuf + l, OUTPUT_LENGTH);
for(i=0;i<16;i++)
{
	key[i] = keyiv[i];
}
			if (strncmp(digest, HMAC(EVP_sha256(), key, 16, (unsigned char *)encryptedbuf, l, NULL, NULL), OUTPUT_LENGTH))
			{
				continue;
			}
			// decrypt here
			do_crypt(keyiv, encryptedbuf, l, buf, &outl, 0);
			if (write(fd, buf, outl) < 0) PERROR("write");
		}
	}
///////////////////////////tunnel communicate part end////////////////////////////////////

	//exit
        _exit(EXIT_SUCCESS);
    }
}
