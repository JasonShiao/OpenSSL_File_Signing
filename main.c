
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

int add_ext(X509 *CA_cert, X509 *new_cert, int nid, char *value);
X509* CreateCertificate(X509_REQ* csr, X509 *CA_cert, EVP_PKEY *CA_pkey);

int main()
{

	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	// Parse an existing certificate
	/*char *path = "C:\\Users\\9518\\Documents\\Training_3\\OpenSSL_File_Signing\\OpenSSL_File_Signing\\openssl\\www.example.com.cert.pem";
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
	fclose(fp);*/


	/**********************************************************************/
	/*                       Create a CA certificate                      */
	/**********************************************************************/

	EVP_PKEY * CA_pkey;
	CA_pkey = EVP_PKEY_new();

	RSA * CA_rsa;
	CA_rsa = RSA_generate_key(
		4096,   /* number of bits for the key - 2048 is a sensible value */
		RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
		NULL,   /* callback - can be NULL if we aren't displaying progress */
		NULL    /* callback argument - not needed in this case */
	);
	EVP_PKEY_assign_RSA(CA_pkey, CA_rsa);


	X509 * CA_cert;
	CA_cert = X509_new();

	ASN1_INTEGER_set(X509_get_serialNumber(CA_cert), 1);

	/* Set serial number */
	ASN1_INTEGER_set(X509_get_serialNumber(CA_cert), 1);
	
	/* Set start and expire date */
	X509_gmtime_adj(X509_get_notBefore(CA_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(CA_cert), 31536000L); // in number of seconds
	
	/* Set public key */
	X509_set_pubkey(CA_cert, CA_pkey);
	
	/* Set subject information */
	X509_NAME * CA_name;
	CA_name = X509_get_subject_name(CA_cert);
	
	/* Set country code(．C・), organization('O') and common name('CN') */
	X509_NAME_add_entry_by_txt(CA_name, "C", MBSTRING_ASC,
								(unsigned char *)"TW", -1, -1, 0);
	X509_NAME_add_entry_by_txt(CA_name, "O", MBSTRING_ASC,
								(unsigned char *)"UIC Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_txt(CA_name, "CN", MBSTRING_ASC,
								(unsigned char *)"jasonshiao.com", -1, -1, 0);
	/* Set issuer name:
		self-signed: issuer name is equal to subject name */
	X509_set_issuer_name(CA_cert, CA_name); // if it's not self-signed, the name should be acquired from issuer certificate

	/* Add various extensions: standard extensions */
	add_ext(CA_cert, CA_cert, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(CA_cert, CA_cert, NID_key_usage, "critical,keyCertSign,cRLSign");
	add_ext(CA_cert, CA_cert, NID_subject_key_identifier, "hash");

	/* CA self-signs the certificate */
	if (!X509_sign(CA_cert, CA_pkey, EVP_sha256()))
		return 1;


	/* Output/Write the certificate into a .pem file or directly print with stderr */
	FILE *CA_cert_fp;
	fopen_s(&CA_cert_fp, "CA.crt.pem", "w");
	PEM_write_X509(CA_cert_fp, CA_cert);
	fclose(CA_cert_fp);


	/* Output pkey file */
	FILE *CA_pkey_fp;
	fopen_s(&CA_pkey_fp, "CA.key", "w");

	PEM_write_PrivateKey(
		CA_pkey_fp,		/* write the key to the file we've opened */
		CA_pkey,    /* key struct in the program */
		NULL,		/* cipher for encrypting the key on disk */
		NULL,		/* passphrase for the key encryption on disk */
		-1,			/* length of the passphrase string */
		NULL,		/* callback for requesting a password */
		NULL		/* data to pass to the callback */
	);

	fclose(CA_pkey_fp);


	/**********************************************************************/
	/*                         Create a certificate                       */
	/**********************************************************************/

#ifdef SIGN_DIRECTLY
	/* Get issuer name from CA cert */

	

	EVP_PKEY * endpoint_pkey;
	endpoint_pkey = EVP_PKEY_new();

	RSA * endpoint_rsa;
	endpoint_rsa = RSA_generate_key(
		4096,   /* number of bits for the key - 2048 is a sensible value */
		RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
		NULL,   /* callback - can be NULL if we aren't displaying progress */
		NULL    /* callback argument - not needed in this case */
	);
	EVP_PKEY_assign_RSA(endpoint_pkey, endpoint_rsa);


	X509 * endpoint_cert;
	endpoint_cert = X509_new();

	ASN1_INTEGER_set(X509_get_serialNumber(endpoint_cert), 1);

	/* Set serial number */
	ASN1_INTEGER_set(X509_get_serialNumber(endpoint_cert), 1);

	/* Set start and expire date */
	X509_gmtime_adj(X509_get_notBefore(endpoint_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(endpoint_cert), 31536000L); // in number of seconds

	/* Set public key */
	X509_set_pubkey(endpoint_cert, endpoint_pkey);

	/* Set subject information */
	X509_NAME * endpoint_name;
	endpoint_name = X509_get_subject_name(endpoint_cert);

	/* Set country code(．C・), organization('O') and common name('CN') */
	X509_NAME_add_entry_by_txt(endpoint_name, "C", MBSTRING_ASC,
		(unsigned char *)"TW", -1, -1, 0);
	X509_NAME_add_entry_by_txt(endpoint_name, "O", MBSTRING_ASC,
		(unsigned char *)"UIC Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_txt(endpoint_name, "CN", MBSTRING_ASC,
		(unsigned char *)"pc.jasonshiao.com", -1, -1, 0);
	/* Set issuer name:
	self-signed: issuer name is equal to subject name */
	X509_set_issuer_name(endpoint_cert, CA_name); // if it's not self-signed, the name should be acquired from issuer certificate

	/* Add various extensions: standard extensions */
	add_ext(CA_cert, endpoint_cert, NID_basic_constraints, "critical,CA:FALSE");
	add_ext(CA_cert, endpoint_cert, NID_subject_key_identifier, "hash");

	/* CA signs the certificate for endpoint */
	if (!X509_sign(endpoint_cert, CA_pkey, EVP_sha256()))
		return 1;

	/* Write the certificate into a .pem file or directly print with stderr */
	FILE *endpoint_cert_fp;
	fopen_s(&endpoint_cert_fp, "endpoint.crt.pem", "w");
	PEM_write_X509(endpoint_cert_fp, endpoint_cert);
	fclose(endpoint_cert_fp);


	/* Output pkey file */
	FILE *endpoint_pkey_fp;
	fopen_s(&endpoint_pkey_fp, "endpoint.key", "w");

	PEM_write_PrivateKey(
		endpoint_pkey_fp,		/* write the key to the file we've opened */
		endpoint_pkey,    /* key struct in the program */
		NULL,		/* cipher for encrypting the key on disk */
		NULL,		/* passphrase for the key encryption on disk */
		-1,			/* length of the passphrase string */
		NULL,		/* callback for requesting a password */
		NULL		/* data to pass to the callback */
	);

	fclose(endpoint_pkey_fp);
#else
	/**********************************************************************/
	/*                           Create a CSR                             */
	/**********************************************************************/

	EVP_PKEY * endpoint_pkey;
	endpoint_pkey = EVP_PKEY_new();

	RSA * endpoint_rsa;
	endpoint_rsa = RSA_generate_key(
		4096,   /* number of bits for the key - 2048 is a sensible value */
		RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
		NULL,   /* callback - can be NULL if we aren't displaying progress */
		NULL    /* callback argument - not needed in this case */
	);
	EVP_PKEY_assign_RSA(endpoint_pkey, endpoint_rsa);


	// 2. set version of x509 req
	int nVersion = 0; // must be 0?
	X509_REQ *endpoint_cert_req = X509_REQ_new();
	int ret = X509_REQ_set_version(endpoint_cert_req, nVersion);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	// 3. set subject of x509 req
	X509_NAME * endpoint_name;
	endpoint_name = X509_REQ_get_subject_name(endpoint_cert_req);

	ret = X509_NAME_add_entry_by_txt(endpoint_name, "C", MBSTRING_ASC, "TW", -1, -1, 0);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	ret = X509_NAME_add_entry_by_txt(endpoint_name, "ST", MBSTRING_ASC, "Taiwan", -1, -1, 0);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	ret = X509_NAME_add_entry_by_txt(endpoint_name, "L", MBSTRING_ASC, "Taipei", -1, -1, 0);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	ret = X509_NAME_add_entry_by_txt(endpoint_name, "O", MBSTRING_ASC, "UIC", -1, -1, 0);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	ret = X509_NAME_add_entry_by_txt(endpoint_name, "CN", MBSTRING_ASC, "pc.jasonshiao.com", -1, -1, 0);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}


	// 4. set public key of x509 req
	ret = X509_REQ_set_pubkey(endpoint_cert_req, endpoint_pkey);
	if (ret != 1) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	// 5. Endpoint signs the CSR 
	ret = X509_REQ_sign(endpoint_cert_req, endpoint_pkey, EVP_sha256());    // return x509_req->signature->length
	if (ret <= 0) {
		X509_REQ_free(endpoint_cert_req);
		EVP_PKEY_free(endpoint_pkey);
	}

	/* Write the CSR into a .pem file or directly print with stderr */
	FILE *endpoint_csr_fp;
	fopen_s(&endpoint_csr_fp, "endpoint.csr.pem", "w");
	PEM_write_X509_REQ(endpoint_csr_fp, endpoint_cert_req);
	fclose(endpoint_csr_fp);


	/* Output pkey file */
	FILE *endpoint_pkey_fp;
	fopen_s(&endpoint_pkey_fp, "endpoint.key", "w");

	PEM_write_PrivateKey(
		endpoint_pkey_fp,		/* write the key to the file we've opened */
		endpoint_pkey,    /* key struct in the program */
		NULL,		/* cipher for encrypting the key on disk */
		NULL,		/* passphrase for the key encryption on disk */
		-1,			/* length of the passphrase string */
		NULL,		/* callback for requesting a password */
		NULL		/* data to pass to the callback */
	);

	fclose(endpoint_pkey_fp);

	/**********************************************************************/
	/*               Sign a certificate based on the CSR                  */
	/**********************************************************************/
	X509 * endpoint_cert;
	endpoint_cert = X509_new();
	
	endpoint_cert = CreateCertificate(endpoint_cert_req, CA_cert, CA_pkey);
	/* Write the certificate into a .pem file or directly print with stderr */
	FILE *endpoint_cert_fp;
	fopen_s(&endpoint_cert_fp, "endpoint.crt.pem", "w");
	PEM_write_X509(endpoint_cert_fp, endpoint_cert);
	fclose(endpoint_cert_fp);


#endif


	/*********************************************************************/
	/*                            Signing Message                        */
	/*********************************************************************/

	/* Read private key from endpoint.key */
	EVP_PKEY * signing_pkey;
	signing_pkey = EVP_PKEY_new();

	FILE* key_fp;
	fopen_s(&key_fp, "endpoint.key", "r");
	PEM_read_PrivateKey(key_fp, &signing_pkey, NULL, NULL);
	fclose(key_fp);



	/* Sign the text */
	EVP_MD_CTX *mdctx = NULL;
	ret = 0;
	char *msg = "Test Message";

	unsigned char *sig = NULL;
	
	size_t slen;

	/* Create the Message Digest Context */
	if (!(mdctx = EVP_MD_CTX_create())) goto err;

	/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, signing_pkey))
	{
		printf("Private key set error\n");
		goto err;
	}

	/* Call update with the message */
	if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) goto err;

	/* Finalise the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the signature. 
		Length is returned in slen */
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) goto err;
	/* Allocate memory for the signature based on size in slen */
	if (!(sig = OPENSSL_malloc(sizeof(unsigned char) * slen))) goto err;
	/* Obtain the signature */
	if (1 != EVP_DigestSignFinal(mdctx, sig, &slen)) goto err;

	/* Success */
	FILE *fp2;
	fopen_s(&fp2, "text.sha256.signature", "w");

	fwrite(sig, 1, slen, fp2);

	fclose(fp2);





	/*********************************************************************/
	/*                       Signature Verification                      */
	/*********************************************************************/

	const char cert_filestr[] = "endpoint.crt.pem";

	EVP_PKEY *endpoint_pubkey;
	endpoint_pubkey = EVP_PKEY_new();

	/* Read public key from endpoint certificate */
	/*certbio = BIO_new(BIO_s_file());
	ret = BIO_read_filename(certbio, cert_filestr);
	if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		printf("Error loading cert into memory\n");
	}

	if ((endpoint_pubkey = X509_get_pubkey(cert)) == NULL)
		printf("Error getting public key from certificate");*/

	FILE *cert_fp;
	fopen_s(&cert_fp, cert_filestr, "r");
	endpoint_pubkey = PEM_read_PUBKEY(cert_fp, &endpoint_pubkey, NULL, NULL);
	fclose(cert_fp);


	/* Initialize the Hash function and the public key */
	if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, endpoint_pubkey))
	{
		printf("Public key init error\n");
		goto err;
	}
	/* Input the message */
	if (1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg)))
	{
		printf("message input error\n");
		goto err;
	}
	/* Verify operation */
	if (1 == EVP_DigestVerifyFinal(mdctx, sig, slen))
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
	if (sig && !ret) OPENSSL_free(sig);
	if (mdctx) EVP_MD_CTX_destroy(mdctx);



	system("pause");
	
	return 0;
}



int add_ext(X509 *CA_cert, X509 *new_cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);

	/* Issuer and subject certs: both the target since it is self signed,
	* no request and no CRL
	*/
	X509V3_set_ctx(&ctx, CA_cert, new_cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(new_cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}


X509* CreateCertificate(X509_REQ* csr, X509 *CA_cert, EVP_PKEY *CA_pkey)
{

	X509 *m_req_reply;
	m_req_reply = X509_new();

	X509_NAME *subject = NULL;
	EVP_PKEY *pkey = NULL;
	int serial_num = 2;
	int validity_time_in_seconds = 31536000L;

	/* Set serial number */
	ASN1_INTEGER_set(X509_get_serialNumber(m_req_reply), serial_num);
	/* Set validity Date */
	X509_gmtime_adj(X509_get_notBefore(m_req_reply), 0);
	X509_gmtime_adj(X509_get_notAfter(m_req_reply), validity_time_in_seconds);

	/* Extract the public key from CSR and set to the certificate */
	pkey = X509_REQ_get_pubkey(csr);
	X509_set_pubkey(m_req_reply, pkey);

	/* Get CA name from CA_cert and set to the certificate as issuer */
	X509_NAME *issuerSubject = X509_get_subject_name(CA_cert);
	X509_set_issuer_name(m_req_reply, issuerSubject);

	/* Get the subject name of CSR and set to the certificate as subject */
	subject = X509_REQ_get_subject_name(csr);
	X509_set_subject_name(m_req_reply, subject);

	if (X509_sign(m_req_reply, CA_pkey, EVP_sha256()))
		printf("client cert ok\n");
	else
		printf("client cert error\n");

	return m_req_reply;
}
