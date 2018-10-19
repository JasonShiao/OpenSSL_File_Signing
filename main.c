
#include <stdlib.h>
#include <stdio.h>

#include <winsock2.h>
#include <windows.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include <assert.h>


int main()
{

	// Parse existing certificate
	char *path = "C:\\Users\\9518\\Documents\\Training_3\\OpenSSL_File_Signing\\OpenSSL_File_Signing\\openssl\\www.example.com.cert.pem";
	FILE *fp = NULL;
	fopen_s(&fp, path, "r");
	if (!fp) {
		fprintf(stderr, "unable to open: %s\n", path);
		return EXIT_FAILURE;
	}

	X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!cert) {
		fprintf(stderr, "unable to parse certificate in: %s\n", path);
		fclose(fp);
		return EXIT_FAILURE;
	}

	// any additional processing would go here..

	char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

	printf("%s\n", subj);
	printf("%s\n", issuer);

	X509_free(cert);
	fclose(fp);


	/*********************************************************************/
	/*                            Signing Message                        */
	/*********************************************************************/

	/* Generate key */
	EVP_PKEY * pkey;
	pkey = EVP_PKEY_new();

	RSA * rsa;
	rsa = RSA_generate_key(
		2048,   /* number of bits for the key - 2048 is a sensible value */
		RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
		NULL,   /* callback - can be NULL if we aren't displaying progress */
		NULL    /* callback argument - not needed in this case */
	);
	EVP_PKEY_assign_RSA(pkey, rsa);

	/* Sign the text */
	EVP_MD_CTX *mdctx = NULL;
	int ret = 0;
	char *msg = "Test Message";

	unsigned char **sig = malloc(sizeof(unsigned char*));
	*sig = NULL;
	
	size_t slen;

	/* Create the Message Digest Context */
	if (!(mdctx = EVP_MD_CTX_create())) goto err;

	/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) goto err;

	/* Call update with the message */
	if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) goto err;

	/* Finalise the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	* signature. Length is returned in slen */
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) goto err;
	/* Allocate memory for the signature based on size in slen */
	if (!(*sig = OPENSSL_malloc(sizeof(unsigned char) * slen))) goto err;
	/* Obtain the signature */
	if (1 != EVP_DigestSignFinal(mdctx, *sig, &slen)) goto err;

	/* Success */
	FILE *fp2;
	fopen_s(&fp2, "signature.sha256", "w");

	fwrite(*sig, 1, slen, fp2);

	fclose(fp2);

	/*********************************************************************/
	/*                       Signature Verification                      */
	/*********************************************************************/

	/* Initialize `key` with a public key */
	if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) goto err;

	/* Initialize `key` with a public key */
	if (1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg))) goto err;

	if (1 == EVP_DigestVerifyFinal(mdctx, *sig, slen))
	{
		/* Success */
		printf("Signature verification success!\n");
	}
	else
	{
		/* Failure */
		printf("Signature verification failed!\n");
	}


err:
	if (ret != 1)
	{
		/* Do some error handling */
	}

	/* Clean up */
	if (*sig && !ret) OPENSSL_free(*sig);
	if (mdctx) EVP_MD_CTX_destroy(mdctx);




	system("pause");
	
	return 0;
}