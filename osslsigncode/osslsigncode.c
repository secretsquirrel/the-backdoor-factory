/*
   OpenSSL based Authenticode signing for PE/MSI/Java CAB files.

	 Copyright (C) 2005-2015 Per Allansson <pallansson@gmail.com>


   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   In addition, as a special exception, the copyright holders give
   permission to link the code of portions of this program with the
   OpenSSL library under certain conditions as described in each
   individual source file, and distribute linked combinations
   including the two.
   You must obey the GNU General Public License in all respects
   for all of the code used other than OpenSSL.  If you modify
   file(s) with this exception, you may extend this exception to your
   version of the file(s), but you are not obligated to do so.  If you
   do not wish to do so, delete this exception statement from your
   version.  If you delete this exception statement from all source
   files in the program, then also delete it here.
*/

static const char *rcsid = "$Id: osslsigncode.c,v 1.7.1 2014/07/11 14:14:14 mfive Exp $";

/*
   Implemented with good help from:

   * Peter Gutmann's analysis of Authenticode:

	  http://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt

   * MS CAB SDK documentation

	  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncabsdk/html/cabdl.asp

   * MS PE/COFF documentation

	  http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

   * MS Windows Authenticode PE Signature Format

	  http://msdn.microsoft.com/en-US/windows/hardware/gg463183

	  (Although the part of how the actual checksumming is done is not
	  how it is done inside Windows. The end result is however the same
	  on all "normal" PE files.)

   * tail -c, tcpdump, mimencode & openssl asn1parse :)

*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_WINDOWS_H
#define NOCRYPT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef unsigned char u_char;
#endif

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef _WIN32
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#endif

#ifdef WITH_GSF
#include <gsf/gsf-infile-msole.h>
#include <gsf/gsf-infile.h>
#include <gsf/gsf-input-stdio.h>
#include <gsf/gsf-outfile-msole.h>
#include <gsf/gsf-outfile.h>
#include <gsf/gsf-output-stdio.h>
#include <gsf/gsf-utils.h>
#endif

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#ifdef ENABLE_CURL
#ifdef __CYGWIN__
#ifndef SOCKET
#define SOCKET UINT_PTR
#endif
#endif
#include <curl/curl.h>

#define MAX_TS_SERVERS 256

#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#if defined (HAVE_TERMIOS_H) || defined (HAVE_GETPASS)
#define PROVIDE_ASKPASS 1
#endif

/* MS Authenticode object ids */
#define SPC_INDIRECT_DATA_OBJID	 "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID	 "1.3.6.1.4.1.311.2.1.12"
#define SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID "1.3.6.1.4.1.311.2.1.21"
#define SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID "1.3.6.1.4.1.311.2.1.22"
#define SPC_MS_JAVA_SOMETHING	 "1.3.6.1.4.1.311.15.1"
#define SPC_PE_IMAGE_DATA_OBJID	 "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID		 "1.3.6.1.4.1.311.2.1.25"
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_SIPINFO_OBJID		 "1.3.6.1.4.1.311.2.1.30"

#define SPC_PE_IMAGE_PAGE_HASHES_V1 "1.3.6.1.4.1.311.2.3.1" /* Page hash using SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2 "1.3.6.1.4.1.311.2.3.2" /* Page hash using SHA256 */

#define SPC_NESTED_SIGNATURE_OBJID  "1.3.6.1.4.1.311.2.4.1"

#define SPC_RFC3161_OBJID "1.3.6.1.4.1.311.3.3.1"

/* 1.3.6.1.4.1.311.4... MS Crypto 2.0 stuff... */


#define WIN_CERT_REVISION_2             0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002


/*
  ASN.1 definitions (more or less from official MS Authenticode docs)
*/

typedef struct {
	int type;
	union {
		ASN1_BMPSTRING *unicode;
		ASN1_IA5STRING *ascii;
	} value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING , 0),
	ASN1_IMP_OPT(SpcString, value.ascii,   ASN1_IA5STRING,	1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)


typedef struct {
	ASN1_OCTET_STRING *classId;
	ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)


typedef struct {
	int type;
	union {
		ASN1_IA5STRING *url;
		SpcSerializedObject *moniker;
		SpcString *file;
	} value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url,	 ASN1_IA5STRING,	  0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file,	 SpcString,			  2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)


typedef struct {
	SpcString *programName;
	SpcLink	  *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)


typedef struct {
	ASN1_OBJECT *type;
	ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)


typedef struct {
	ASN1_OBJECT *algorithm;
	ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)


typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)


typedef struct {
	SpcAttributeTypeAndOptionalValue *data;
	DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)


typedef struct {
	ASN1_BIT_STRING* flags;
	SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData)

ASN1_SEQUENCE(SpcPeImageData) = {
	ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
	ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)


typedef struct {
	ASN1_INTEGER *a;
	ASN1_OCTET_STRING *string;
	ASN1_INTEGER *b;
	ASN1_INTEGER *c;
	ASN1_INTEGER *d;
	ASN1_INTEGER *e;
	ASN1_INTEGER *f;
} SpcSipInfo;

DECLARE_ASN1_FUNCTIONS(SpcSipInfo)

ASN1_SEQUENCE(SpcSipInfo) = {
	ASN1_SIMPLE(SpcSipInfo, a, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, string, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSipInfo, b, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, c, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, d, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, e, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, f, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SpcSipInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSipInfo)


#ifdef ENABLE_CURL

typedef struct {
	ASN1_OBJECT *type;
	ASN1_OCTET_STRING *signature;
} TimeStampRequestBlob;

DECLARE_ASN1_FUNCTIONS(TimeStampRequestBlob)

ASN1_SEQUENCE(TimeStampRequestBlob) = {
	ASN1_SIMPLE(TimeStampRequestBlob, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TimeStampRequestBlob, signature, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(TimeStampRequestBlob)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequestBlob)



typedef struct {
	ASN1_OBJECT *type;
	TimeStampRequestBlob *blob;
} TimeStampRequest;

DECLARE_ASN1_FUNCTIONS(TimeStampRequest)

ASN1_SEQUENCE(TimeStampRequest) = {
	ASN1_SIMPLE(TimeStampRequest, type, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampRequest, blob, TimeStampRequestBlob)
} ASN1_SEQUENCE_END(TimeStampRequest)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequest)


/* RFC3161 Time stamping */

typedef struct {
	ASN1_INTEGER *status;
	STACK_OF(ASN1_UTF8STRING) *statusString;
	ASN1_BIT_STRING *failInfo;
} PKIStatusInfo;

DECLARE_ASN1_FUNCTIONS(PKIStatusInfo)

ASN1_SEQUENCE(PKIStatusInfo) = {
	ASN1_SIMPLE(PKIStatusInfo, status, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(PKIStatusInfo, statusString, ASN1_UTF8STRING),
	ASN1_OPT(PKIStatusInfo, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PKIStatusInfo)

IMPLEMENT_ASN1_FUNCTIONS(PKIStatusInfo)


typedef struct {
	PKIStatusInfo *status;
	PKCS7 *token;
} TimeStampResp;

DECLARE_ASN1_FUNCTIONS(TimeStampResp)

ASN1_SEQUENCE(TimeStampResp) = {
	ASN1_SIMPLE(TimeStampResp, status, PKIStatusInfo),
	ASN1_OPT(TimeStampResp, token, PKCS7)
} ASN1_SEQUENCE_END(TimeStampResp)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampResp)

typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = {
	ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

typedef struct {
	ASN1_INTEGER *version;
	MessageImprint *messageImprint;
	ASN1_OBJECT *reqPolicy;
	ASN1_INTEGER *nonce;
	ASN1_BOOLEAN *certReq;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampReq;

DECLARE_ASN1_FUNCTIONS(TimeStampReq)

ASN1_SEQUENCE(TimeStampReq) = {
	ASN1_SIMPLE(TimeStampReq, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, messageImprint, MessageImprint),
	ASN1_OPT   (TimeStampReq, reqPolicy, ASN1_OBJECT),
	ASN1_OPT   (TimeStampReq, nonce, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, certReq, ASN1_BOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampReq, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampReq)

#endif /* ENABLE_CURL */


static SpcSpOpusInfo* createOpus(const char *desc, const char *url)
{
	SpcSpOpusInfo *info = SpcSpOpusInfo_new();

	if (desc) {
		info->programName = SpcString_new();
		info->programName->type = 1;
		info->programName->value.ascii = M_ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->programName->value.ascii,
						(const unsigned char*)desc, strlen(desc));
	}

	if (url) {
		info->moreInfo = SpcLink_new();
		info->moreInfo->type = 0;
		info->moreInfo->value.url = M_ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->moreInfo->value.url,
						(const unsigned char*)url, strlen(url));
	}

	return info;
}

static unsigned int asn1_simple_hdr_len(const unsigned char *p, unsigned int len) {
	if (len <= 2 || p[0] > 0x31)
		return 0;
	return (p[1]&0x80) ? (2 + (p[1]&0x7f)) : 2;
}

static void tohex(const unsigned char *v, unsigned char *b, int len)
{
	int i;
	for(i=0; i<len; i++)
		sprintf((char*)b+i*2, "%02X", v[i]);
	b[i*2] = 0x00;
}

static int add_unauthenticated_blob(PKCS7 *sig)
{
	u_char *p = NULL;
	int len = 1024+4;
	char prefix[] = "\x0c\x82\x04\x00---BEGIN_BLOB---";  // Length data for ASN1 attribute plus prefix
	char postfix[] = "---END_BLOB---";

	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sig->d.sign->signer_info, 0);

	p = OPENSSL_malloc(len);
	memset(p, 0, len);
	memcpy(p, prefix, sizeof(prefix));
	memcpy(p+len-sizeof(postfix), postfix, sizeof(postfix));

	ASN1_STRING *astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);

	int nid = OBJ_create("1.3.6.1.4.1.42921.1.2.1",
						 "unauthenticatedData",
						 "unauthenticatedData");

	PKCS7_add_attribute (si, nid, V_ASN1_SEQUENCE, astr);

	OPENSSL_free(p);

	return 0;
}


static int g_verbose = 0;

#ifdef ENABLE_CURL

static int blob_has_nl = 0;
static size_t curl_write( void *ptr, size_t sz, size_t nmemb, void *stream)
{
	if (sz*nmemb > 0 && !blob_has_nl) {
		if (memchr(ptr, '\n', sz*nmemb))
			blob_has_nl = 1;
	}
	return BIO_write((BIO*)stream, ptr, sz*nmemb);
}

static void print_timestamp_error(const char *url, long http_code)
{
    if (http_code != -1) {
        fprintf(stderr, "Failed to convert timestamp reply from %s; "
                "HTTP status %ld\n", url, http_code);
    } else {
        fprintf(stderr, "Failed to convert timestamp reply from %s; "
                "no HTTP status available", url);
    }

    ERR_print_errors_fp(stderr);
}

/*
  A timestamp request looks like this:

  POST <someurl> HTTP/1.1
  Content-Type: application/octet-stream
  Content-Length: ...
  Accept: application/octet-stream
  User-Agent: Transport
  Host: ...
  Cache-Control: no-cache

  <base64encoded blob>


  .. and the blob has the following ASN1 structure:

  0:d=0	 hl=4 l= 291 cons: SEQUENCE
  4:d=1	 hl=2 l=  10 prim:	OBJECT			  :1.3.6.1.4.1.311.3.2.1
  16:d=1  hl=4 l= 275 cons:	 SEQUENCE
  20:d=2  hl=2 l=	9 prim:	  OBJECT			:pkcs7-data
  31:d=2  hl=4 l= 260 cons:	  cont [ 0 ]
  35:d=3  hl=4 l= 256 prim:	   OCTET STRING
  <signature>



  .. and it returns a base64 encoded PKCS#7 structure.

*/

static int add_timestamp(PKCS7 *sig, char *url, char *proxy, int rfc3161, const EVP_MD *md, int verbose, int noverifypeer)
{
	CURL *curl;
	struct curl_slist *slist = NULL;
	CURLcode c;
	BIO *bout, *bin, *b64;
	u_char *p = NULL;
	int len = 0;
	PKCS7_SIGNER_INFO *si =
		sk_PKCS7_SIGNER_INFO_value
		(sig->d.sign->signer_info, 0);

	if (!url) return -1;

	curl = curl_easy_init();

	if (proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
		if (!strncmp("http:", proxy, 5))
			curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
		if (!strncmp("socks:", proxy, 6))
			curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
/*	  curl_easy_setopt(curl, CURLOPT_VERBOSE, 42);	*/

	if (noverifypeer)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);

	if (rfc3161) {
		slist = curl_slist_append(slist, "Content-Type: application/timestamp-query");
		slist = curl_slist_append(slist, "Accept: application/timestamp-reply");
	} else {
		slist = curl_slist_append(slist, "Content-Type: application/octet-stream");
		slist = curl_slist_append(slist, "Accept: application/octet-stream");
	}
	slist = curl_slist_append(slist, "User-Agent: Transport");
	slist = curl_slist_append(slist, "Cache-Control: no-cache");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

	if (rfc3161) {
		unsigned char mdbuf[EVP_MAX_MD_SIZE];
		EVP_MD_CTX mdctx;

		EVP_MD_CTX_init(&mdctx);
		EVP_DigestInit(&mdctx, md);
		EVP_DigestUpdate(&mdctx, si->enc_digest->data, si->enc_digest->length);
		EVP_DigestFinal(&mdctx, mdbuf, NULL);

		TimeStampReq *req = TimeStampReq_new();
		ASN1_INTEGER_set(req->version, 1);
		req->messageImprint->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(md));
		req->messageImprint->digestAlgorithm->parameters = ASN1_TYPE_new();
		req->messageImprint->digestAlgorithm->parameters->type = V_ASN1_NULL;
		M_ASN1_OCTET_STRING_set(req->messageImprint->digest, mdbuf, EVP_MD_size(md));
		req->certReq = (void*)0x1;

		len = i2d_TimeStampReq(req, NULL);
		p = OPENSSL_malloc(len);
		len = i2d_TimeStampReq(req, &p);
		p -= len;

		TimeStampReq_free(req);
	} else {
		TimeStampRequest *req = TimeStampRequest_new();
		req->type = OBJ_txt2obj(SPC_TIME_STAMP_REQUEST_OBJID, 1);
		req->blob->type = OBJ_nid2obj(NID_pkcs7_data);
		req->blob->signature = si->enc_digest;

		len = i2d_TimeStampRequest(req, NULL);
		p = OPENSSL_malloc(len);
		len = i2d_TimeStampRequest(req, &p);
		p -= len;

		req->blob->signature = NULL;
		TimeStampRequest_free(req);
	}

	bout = BIO_new(BIO_s_mem());
	if (!rfc3161) {
		b64 = BIO_new(BIO_f_base64());
		bout = BIO_push(b64, bout);
	}
	BIO_write(bout, p, len);
	(void)BIO_flush(bout);
	OPENSSL_free(p);
	p = NULL;

	len = BIO_get_mem_data(bout, &p);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)p);

	bin = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(bin, 0);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, bin);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);

	c = curl_easy_perform(curl);

	curl_slist_free_all(slist);
	BIO_free_all(bout);

	if (c) {
		BIO_free_all(bin);
		if (verbose)
			fprintf(stderr, "CURL failure: %s\n", curl_easy_strerror(c));
	} else {
		(void)BIO_flush(bin);

		long http_code = -1;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		/*
		 * At this point we could also look at the response body (and perhaps
		 * log it if we fail to decode the response):
		 *
		 *     char *resp_body = NULL;
		 *     long resp_body_len = BIO_get_mem_data(bin, &resp_body);
		 */

		if (rfc3161) {
			TimeStampResp *reply;
			(void)BIO_flush(bin);
			reply = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TimeStampResp), bin, NULL);
			BIO_free_all(bin);
			if (!reply) {
				if (verbose)
					print_timestamp_error(url, http_code);
				return -1;
			}
			if (ASN1_INTEGER_get(reply->status->status) != 0) {
				if (verbose)
					fprintf(stderr, "Timestamping failed: %ld\n", ASN1_INTEGER_get(reply->status->status));
				TimeStampResp_free(reply);
				return -1;
			}

			if (((len = i2d_PKCS7(reply->token, NULL)) <= 0) ||
				(p = OPENSSL_malloc(len)) == NULL) {
				if (verbose) {
					fprintf(stderr, "Failed to convert pkcs7: %d\n", len);
					ERR_print_errors_fp(stderr);
				}
				TimeStampResp_free(reply);
				return -1;
			}
			len = i2d_PKCS7(reply->token, &p);
			p -= len;
			TimeStampResp_free(reply);

			STACK_OF(X509_ATTRIBUTE) *attrs = sk_X509_ATTRIBUTE_new_null();
			attrs = X509at_add1_attr_by_txt
				(&attrs, SPC_RFC3161_OBJID, V_ASN1_SET, p, len);
			OPENSSL_free(p);
			PKCS7_set_attributes(si, attrs);
			sk_X509_ATTRIBUTE_pop_free(attrs, X509_ATTRIBUTE_free);
		} else {
			int i;
			PKCS7 *p7;
			PKCS7_SIGNER_INFO *info;
			ASN1_STRING *astr;
			BIO* b64_bin;
			b64 = BIO_new(BIO_f_base64());
			if (!blob_has_nl)
				BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
			b64_bin = BIO_push(b64, bin);
			p7 = d2i_PKCS7_bio(b64_bin, NULL);
			if (p7 == NULL) {
				BIO_free_all(b64_bin);
				if (verbose)
					print_timestamp_error(url, http_code);
				return -1;
			}
			BIO_free_all(b64_bin);

			for(i = sk_X509_num(p7->d.sign->cert)-1; i>=0; i--)
				PKCS7_add_certificate(sig, sk_X509_value(p7->d.sign->cert, i));

			info = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
			if (((len = i2d_PKCS7_SIGNER_INFO(info, NULL)) <= 0) ||
				(p = OPENSSL_malloc(len)) == NULL) {
				if (verbose) {
					fprintf(stderr, "Failed to convert signer info: %d\n", len);
					ERR_print_errors_fp(stderr);
				}
				PKCS7_free(p7);
				return -1;
			}
			len = i2d_PKCS7_SIGNER_INFO(info, &p);
			p -= len;
			astr = ASN1_STRING_new();
			ASN1_STRING_set(astr, p, len);
			OPENSSL_free(p);
			PKCS7_add_attribute
				(si, NID_pkcs9_countersignature,
				 V_ASN1_SEQUENCE, astr);

			PKCS7_free(p7);
		}
	}

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return (int)c;
}

static int add_timestamp_authenticode(PKCS7 *sig, char **url, int nurls, char *proxy, int noverifypeer)
{
	int i;
	for (i=0; i<nurls; i++) {
		int res = add_timestamp(sig, url[i], proxy, 0, NULL, g_verbose || nurls == 1, noverifypeer);
		if (!res) return 0;
	}
	return -1;
}

static int add_timestamp_rfc3161(PKCS7 *sig, char **url, int nurls, char *proxy, const EVP_MD *md, int noverifypeer)
{
	int i;
	for (i=0; i<nurls; i++) {
		int res = add_timestamp(sig, url[i], proxy, 1, md, g_verbose || nurls == 1, noverifypeer);
		if (!res) return 0;
	}
	return -1;
}

#endif /* ENABLE_CURL */

#ifdef WITH_GSF
static int gsf_initialized = 0;
#endif

static void cleanup_lib_state(void)
{
#ifdef WITH_GSF
	if (gsf_initialized)
		gsf_shutdown();
#endif
	OBJ_cleanup();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    EVP_cleanup();
	CONF_modules_free();
    CRYPTO_cleanup_all_ex_data();
#if OPENSSL_VERSION_NUMBER > 0x10000000
	ERR_remove_thread_state(NULL);
#endif
    ERR_free_strings();
}

static void usage(const char *argv0)
{
	fprintf(stderr,
			"Usage: %s\n\n\t[ --version | -v ]\n\n"
			"\t[ sign ]\n"
			"\t\t( -certs <certfile> -key <keyfile> | -pkcs12 <pkcs12file> |\n"
			"\t\t  -pkcs11engine <engine> -pkcs11module <module> -certs <certfile> -key <pkcs11 key id>)\n"
			"\t\t[ -pass <password> ] "
#ifdef PROVIDE_ASKPASS
			"[ -askpass ]"
#endif
			"[ -readpass <file> ]\n"
			"\t\t[ -ac <crosscertfile> ]\n"
			"\t\t[ -h {md5,sha1,sha2(56),sha384,sha512} ]\n"
			"\t\t[ -n <desc> ] [ -i <url> ] [ -jp <level> ] [ -comm ]\n"
			"\t\t[ -ph ]\n"
#ifdef ENABLE_CURL
			"\t\t[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n"
			"\t\t[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n"
#endif
			"\t\t[ -addUnauthenticatedBlob ]\n\n"
			"\t\t[ -nest ]\n\n"
			"\t\t[ -verbose ]\n\n"
			"\t\tMSI specific:\n"
			"\t\t[ -add-msi-dse ]\n\n"
			"\t\t[ -in ] <infile> [-out ] <outfile>\n\n"
			"\textract-signature [ -pem ] [ -in ] <infile> [ -out ] <outfile>\n\n"
			"\tremove-signature [ -in ] <infile> [ -out ] <outfile>\n\n"
			"\tattach-signature [ -sigin ] <sigfile> [ -in ] <infile> [ -out ] <outfile>\n\n"
			"\tverify [ -in ] <infile>\n"
			"\t\t[ -require-leaf-hash {md5,sha1,sha2(56),sha384,sha512}:XXXXXXXXXXXX... ]\n\n"
			"\tadd [-addUnauthenticatedBlob] [ -in ] <infile> [ -out ] <outfile>\n"
#ifdef ENABLE_CURL
			"\t\t[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n"
			"\t\t[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n"
#endif
			"\n"
			"",
			argv0);
	cleanup_lib_state();
	exit(-1);
}

#define DO_EXIT_0(x)	{ fputs(x, stderr); goto err_cleanup; }
#define DO_EXIT_1(x, y) { fprintf(stderr, x, y); goto err_cleanup; }
#define DO_EXIT_2(x, y, z) { fprintf(stderr, x, y, z); goto err_cleanup; }

#define GET_UINT16_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8))

#define GET_UINT32_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8) |	\
						  (((u_char*)(p))[2]<<16) | (((u_char*)(p))[3]<<24))

#define PUT_UINT16_LE(i,p)						\
	((u_char*)(p))[0] = (i) & 0xff;				\
	((u_char*)(p))[1] = ((i)>>8) & 0xff

#define PUT_UINT32_LE(i,p)						\
	((u_char*)(p))[0] = (i) & 0xff;				\
	((u_char*)(p))[1] = ((i)>>8) & 0xff;		\
	((u_char*)(p))[2] = ((i)>>16) & 0xff;		\
	((u_char*)(p))[3] = ((i)>>24) & 0xff


typedef enum {
	FILE_TYPE_CAB,
	FILE_TYPE_PE,
	FILE_TYPE_MSI,
} file_type_t;

typedef enum {
	CMD_SIGN,
	CMD_EXTRACT,
	CMD_REMOVE,
	CMD_VERIFY,
	CMD_ADD,
	CMD_ATTACH,
} cmd_type_t;


static SpcLink *get_obsolete_link(void)
{
	static const unsigned char obsolete[] = {
		0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
		0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
		0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e
	};
	SpcLink *link = SpcLink_new();
	link->type = 2;
	link->value.file = SpcString_new();
	link->value.file->type = 0;
	link->value.file->value.unicode = ASN1_BMPSTRING_new();
	ASN1_STRING_set(link->value.file->value.unicode, obsolete, sizeof(obsolete));
	return link;
}

static const unsigned char classid_page_hash[] = {
	0xA6, 0xB5, 0x86, 0xD5, 0xB4, 0xA1, 0x24, 0x66,
	0xAE, 0x05, 0xA2, 0x17, 0xDA, 0x8E, 0x60, 0xD6
};

static unsigned char *calc_page_hash(char *indata, unsigned int peheader, int pe32plus,
									 unsigned int sigpos, int phtype, unsigned int *phlen);

DECLARE_STACK_OF(ASN1_OCTET_STRING)
#ifndef sk_ASN1_OCTET_STRING_new_null
#define sk_ASN1_OCTET_STRING_new_null() SKM_sk_new_null(ASN1_OCTET_STRING)
#define sk_ASN1_OCTET_STRING_free(st) SKM_sk_free(ASN1_OCTET_STRING, (st))
#define sk_ASN1_OCTET_STRING_push(st, val) SKM_sk_push(ASN1_OCTET_STRING, (st), (val))
#define i2d_ASN1_SET_OF_ASN1_OCTET_STRING(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(ASN1_OCTET_STRING, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#endif

DECLARE_STACK_OF(SpcAttributeTypeAndOptionalValue)
#ifndef sk_SpcAttributeTypeAndOptionalValue_new_null
#define sk_SpcAttributeTypeAndOptionalValue_new_null() SKM_sk_new_null(SpcAttributeTypeAndOptionalValue)
#define sk_SpcAttributeTypeAndOptionalValue_free(st) SKM_sk_free(SpcAttributeTypeAndOptionalValue, (st))
#define sk_SpcAttributeTypeAndOptionalValue_push(st, val) SKM_sk_push(SpcAttributeTypeAndOptionalValue, (st), (val))
#define i2d_SpcAttributeTypeAndOptionalValue(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(SpcAttributeTypeAndOptionalValue, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#endif

static SpcLink *get_page_hash_link(int phtype, char *indata, unsigned int peheader, int pe32plus, unsigned int sigpos)
{
	unsigned int phlen;
	unsigned char *ph = calc_page_hash(indata, peheader, pe32plus, sigpos, phtype, &phlen);
	if (!ph) {
		fprintf(stderr, "Failed to calculate page hash\n");
		exit(-1);
	}

	ASN1_OCTET_STRING *ostr = M_ASN1_OCTET_STRING_new();
	M_ASN1_OCTET_STRING_set(ostr, ph, phlen);
	free(ph);

	STACK_OF(ASN1_OCTET_STRING) *oset = sk_ASN1_OCTET_STRING_new_null();
	sk_ASN1_OCTET_STRING_push(oset, ostr);
	unsigned char *p, *tmp;
	unsigned int l;
	l = i2d_ASN1_SET_OF_ASN1_OCTET_STRING(oset, NULL, i2d_ASN1_OCTET_STRING,
										  V_ASN1_SET, V_ASN1_UNIVERSAL, IS_SET);
	tmp = p = OPENSSL_malloc(l);
	i2d_ASN1_SET_OF_ASN1_OCTET_STRING(oset, &tmp, i2d_ASN1_OCTET_STRING,
									  V_ASN1_SET, V_ASN1_UNIVERSAL, IS_SET);
	ASN1_OCTET_STRING_free(ostr);
	sk_ASN1_OCTET_STRING_free(oset);

	SpcAttributeTypeAndOptionalValue *aval = SpcAttributeTypeAndOptionalValue_new();
	aval->type = OBJ_txt2obj((phtype == NID_sha1) ? SPC_PE_IMAGE_PAGE_HASHES_V1 : SPC_PE_IMAGE_PAGE_HASHES_V2, 1);
	aval->value = ASN1_TYPE_new();
	aval->value->type = V_ASN1_SET;
	aval->value->value.set = ASN1_STRING_new();
	ASN1_STRING_set(aval->value->value.set, p, l);
	OPENSSL_free(p);

	STACK_OF(SpcAttributeTypeAndOptionalValue) *aset = sk_SpcAttributeTypeAndOptionalValue_new_null();
	sk_SpcAttributeTypeAndOptionalValue_push(aset, aval);
	l = i2d_SpcAttributeTypeAndOptionalValue(aset, NULL, i2d_SpcAttributeTypeAndOptionalValue,
											 V_ASN1_SET, V_ASN1_UNIVERSAL, IS_SET);
	tmp = p = OPENSSL_malloc(l);
	l = i2d_SpcAttributeTypeAndOptionalValue(aset, &tmp, i2d_SpcAttributeTypeAndOptionalValue,
											 V_ASN1_SET, V_ASN1_UNIVERSAL, IS_SET);
	sk_SpcAttributeTypeAndOptionalValue_free(aset);
	SpcAttributeTypeAndOptionalValue_free(aval);

	SpcSerializedObject *so = SpcSerializedObject_new();
	M_ASN1_OCTET_STRING_set(so->classId, classid_page_hash, sizeof(classid_page_hash));
	M_ASN1_OCTET_STRING_set(so->serializedData, p, l);
	OPENSSL_free(p);

	SpcLink *link = SpcLink_new();
	link->type = 1;
	link->value.moniker = so;
	return link;
}

static void get_indirect_data_blob(u_char **blob, int *len, const EVP_MD *md, file_type_t type,
								   int pagehash, char *indata, unsigned int peheader, int pe32plus,
								   unsigned int sigpos)
{
	static const unsigned char msistr[] = {
		0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
	};

	u_char *p;
	int hashlen, l;
	void *hash;
	ASN1_OBJECT *dtype;
	SpcIndirectDataContent *idc = SpcIndirectDataContent_new();
	idc->data->value = ASN1_TYPE_new();
	idc->data->value->type = V_ASN1_SEQUENCE;
	idc->data->value->value.sequence = ASN1_STRING_new();
	if (type == FILE_TYPE_CAB) {
		SpcLink *link = get_obsolete_link();
		l = i2d_SpcLink(link, NULL);
		p = OPENSSL_malloc(l);
		i2d_SpcLink(link, &p);
		p -= l;
		dtype = OBJ_txt2obj(SPC_CAB_DATA_OBJID, 1);
		SpcLink_free(link);
	} else if (type == FILE_TYPE_PE) {
		SpcPeImageData *pid = SpcPeImageData_new();
		ASN1_BIT_STRING_set(pid->flags, (unsigned char*)"0", 0);
		if (pagehash) {
			int phtype = NID_sha1;
			if (EVP_MD_size(md) > EVP_MD_size(EVP_sha1()))
				phtype = NID_sha256;
			pid->file = get_page_hash_link(phtype, indata, peheader, pe32plus, sigpos);
		} else {
			pid->file = get_obsolete_link();
		}
		l = i2d_SpcPeImageData(pid, NULL);
		p = OPENSSL_malloc(l);
		i2d_SpcPeImageData(pid, &p);
		p -= l;
		dtype = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1);
		SpcPeImageData_free(pid);
	} else if (type == FILE_TYPE_MSI) {
		SpcSipInfo *si = SpcSipInfo_new();
		ASN1_INTEGER_set(si->a, 1);
		ASN1_INTEGER_set(si->b, 0);
		ASN1_INTEGER_set(si->c, 0);
		ASN1_INTEGER_set(si->d, 0);
		ASN1_INTEGER_set(si->e, 0);
		ASN1_INTEGER_set(si->f, 0);
		M_ASN1_OCTET_STRING_set(si->string, msistr, sizeof(msistr));
		l = i2d_SpcSipInfo(si, NULL);
		p = OPENSSL_malloc(l);
		i2d_SpcSipInfo(si, &p);
		p -= l;
		dtype = OBJ_txt2obj(SPC_SIPINFO_OBJID, 1);
		SpcSipInfo_free(si);
	} else {
		fprintf(stderr, "Unexpected file type: %d\n", type);
		exit(1);
	}

	idc->data->type = dtype;
	idc->data->value->value.sequence->data = p;
	idc->data->value->value.sequence->length = l;
	idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(md));
	idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
	idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

	hashlen = EVP_MD_size(md);
	hash = OPENSSL_malloc(hashlen);
	memset(hash, 0, hashlen);
	M_ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashlen);
	OPENSSL_free(hash);

	*len  = i2d_SpcIndirectDataContent(idc, NULL);
	*blob = OPENSSL_malloc(*len);
	p = *blob;
	i2d_SpcIndirectDataContent(idc, &p);
	SpcIndirectDataContent_free(idc);
}

static unsigned int calc_pe_checksum(BIO *bio, unsigned int peheader)
{
	unsigned int checkSum = 0;
	unsigned short val;
	unsigned int size = 0;
	unsigned short *buf;
	int nread;

	/* recalc checksum. */
	buf = (unsigned short*)malloc(sizeof(unsigned short)*32768);

	(void)BIO_seek(bio, 0);
	while ((nread = BIO_read(bio, buf, sizeof(unsigned short)*32768)) > 0) {
		int i;
		for (i = 0; i < nread / 2; i++) {
			val = buf[i];
			if (size == peheader + 88 || size == peheader + 90)
				val = 0;
			checkSum += val;
			checkSum = 0xffff & (checkSum + (checkSum >> 0x10));
			size += 2;
		}
	}

	free(buf);

	checkSum = 0xffff & (checkSum + (checkSum >> 0x10));
	checkSum += size;

	return checkSum;
}

static void recalc_pe_checksum(BIO *bio, unsigned int peheader)
{
	unsigned int checkSum = calc_pe_checksum(bio, peheader);
	char buf[4];

	/* write back checksum. */
	(void)BIO_seek(bio, peheader + 88);
	PUT_UINT32_LE(checkSum, buf);
	BIO_write(bio, buf, 4);
}

static unsigned char nib2val(unsigned char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}

	printf("Illegal hex value: '%x'\n", c);
	return 0;
}

static int verify_leaf_hash(X509 *leaf, const char *leafhash) {
	char *lhdup = NULL;
	char *orig = NULL;
	char *mdid = NULL;
	char *hash = NULL;
	int ret = 0;

	lhdup = strdup(leafhash);
	orig = lhdup;
	mdid = lhdup;
	while (lhdup != NULL && *lhdup != '\0') {
		if (*lhdup == ':') {
			*lhdup = '\0';
			++lhdup;
			hash = lhdup;
			break;
		}
		++lhdup;
	}
	lhdup = orig;

	if (hash == NULL) {
		printf("Unable to parse -require-leaf-hash parameter: %s\n\n", orig);
		ret = 1;
		goto out;
	}

	const EVP_MD *md = EVP_get_digestbyname(mdid);
	if (md == NULL) {
		printf("Unable to lookup digest by name '%s'\n", mdid);
		ret = 1;
		goto out;
	}

	unsigned long sz = EVP_MD_size(md);
	unsigned long actual = strlen(hash);
	if (actual%2 != 0) {
		printf("Hash length mismatch: length is uneven.\n");
		ret = 1;
		goto out;
	}
	actual /= 2;
	if (actual != sz) {
		printf("Hash length mismatch: '%s' digest must be %lu bytes long (got %lu bytes)\n", mdid, sz, actual);
		ret = 1;
		goto out;
	}

	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
	int i = 0, j = 0;
	while (i < sz*2) {
		unsigned char x;
		x = nib2val(hash[i+1]);
		x |= nib2val(hash[i]) << 4;
		mdbuf[j] = x;
		i += 2;
		j += 1;
	}

	unsigned long certlen = i2d_X509(leaf, NULL);
	unsigned char *certbuf = malloc(certlen);
	unsigned char *tmp = certbuf;
	i2d_X509(leaf, &tmp);

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, certbuf, certlen);
	EVP_DigestFinal_ex(ctx, cmdbuf, NULL);
	EVP_MD_CTX_destroy(ctx);

	free(certbuf);

	if (memcmp(mdbuf, cmdbuf, EVP_MD_size(md))) {
		ret = 1;
		goto out;
	}

out:
	free(lhdup);
	return ret;
}

// pkcs7_get_nested_signature exctracts a nested signature from p7.
// The caller is responsible for freeing the returned object.
//
// If has_sig is provided, it will be set to either 1 if there is a
// SPC_NESTED_SIGNATURE attribute in p7 at all or 0 if not.
// This allows has_sig to be used to distinguish two possible scenarios
// when the functon returns NULL: if has_sig is 1, it means d2i_PKCS7
// failed to decode the nested signature. However, if has_sig is 0, it
// simply means the given p7 does not have a nested signature.
static PKCS7 *pkcs7_get_nested_signature(PKCS7 *p7, int *has_sig) {
	PKCS7 *ret = NULL;
	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	ASN1_TYPE *nestedSignature = PKCS7_get_attribute(si, OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID));
	if (nestedSignature) {
		ASN1_STRING *astr = nestedSignature->value.sequence;
		const unsigned char *p = astr->data;
		ret = d2i_PKCS7(NULL, &p, astr->length);
	}
	if (has_sig)
		*has_sig = (nestedSignature != NULL);
	return ret;
}

// pkcs7_set_nested_signature adds the p7nest signature to p7
// as a nested signature (SPC_NESTED_SIGNATURE).
static int pkcs7_set_nested_signature(PKCS7 *p7, PKCS7 *p7nest) {
	u_char *p = NULL;
	int len = 0;

	if (((len = i2d_PKCS7(p7nest, NULL)) <= 0) ||
		(p = OPENSSL_malloc(len)) == NULL)
		return 0;

	i2d_PKCS7(p7nest, &p);
	p -= len;
	ASN1_STRING *astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);
	OPENSSL_free(p);

	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (PKCS7_add_attribute(si, OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID), V_ASN1_SEQUENCE, astr) == 0)
		return 0;

	return 1;
}

#ifdef WITH_GSF
static gint msi_base64_decode(gint x)
{
	if (x < 10)
		return x + '0';
	if (x < (10 + 26))
		return x - 10 + 'A';
	if (x < (10 + 26 + 26))
		return x - 10 - 26 + 'a';
	if (x == (10 + 26 + 26))
		return '.';
	return 1;
}

static void msi_decode(const guint8 *in, gchar *out)
{
	guint count = 0;
	guint8 *q = (guint8 *)out;

	/* utf-8 encoding of 0x4840 */
	if (in[0] == 0xe4 && in[1] == 0xa1 && in[2] == 0x80)
		in += 3;

	while (*in) {
		guint8 ch = *in;
		if ((ch == 0xe3 && in[1] >= 0xa0) || (ch == 0xe4 && in[1] < 0xa0)) {
			*q++ = msi_base64_decode(in[2] & 0x7f);
			*q++ = msi_base64_decode(in[1] ^ 0xa0);
			in += 3;
			count += 2;
			continue;
		}
		if (ch == 0xe4 && in[1] == 0xa0) {
			*q++ = msi_base64_decode(in[2] & 0x7f);
			in += 3;
			count++;
			continue;
		}
		*q++ = *in++;
		if (ch >= 0xc1)
			*q++ = *in++;
		if (ch >= 0xe0)
			*q++ = *in++;
		if (ch >= 0xf0)
			*q++ = *in++;
		count++;
	}
	*q = 0;
}

/*
 * Sorry if this code looks a bit silly, but that seems
 * to be the best solution so far...
 */
static gint msi_cmp(gpointer a, gpointer b)
{
	glong anc = 0, bnc = 0;
	gchar *pa = (gchar*)g_utf8_to_utf16(a, -1, NULL, &anc, NULL);
	gchar *pb = (gchar*)g_utf8_to_utf16(b, -1, NULL, &bnc, NULL);
	gint diff;

	diff = memcmp(pa, pb, MIN(2*anc, 2*bnc));
	/* apparently the longer wins */
	if (diff == 0)
		return 2*anc > 2*bnc ? 1 : -1;
	g_free(pa);
	g_free(pb);

	return diff;
}

/*
 * msi_sorted_infile_children returns a sorted list of all
 * of the children of the given infile. The children are
 * sorted according to the msi_cmp.
 *
 * The returned list must be freed with g_slist_free.
 */
static GSList *msi_sorted_infile_children(GsfInfile *infile)
{
	GSList *sorted = NULL;
	gchar decoded[0x40];
	int i;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const guint8 *name = (const guint8*)gsf_input_name(child);
		msi_decode(name, decoded);

		if (!g_strcmp0(decoded, "\05DigitalSignature"))
			continue;
		if (!g_strcmp0(decoded, "\05MsiDigitalSignatureEx"))
			continue;
 
		sorted = g_slist_insert_sorted(sorted, (gpointer)name, (GCompareFunc)msi_cmp);
	}

	return sorted;
}

/*
 * msi_prehash_utf16_name converts an UTF-8 representation of
 * an MSI filename to its on-disk UTF-16 representation and
 * writes it to the hash BIO.  It is used when calculating the
 * pre-hash used for MsiDigitalSignatureEx signatures in MSI files.
 */
static gboolean msi_prehash_utf16_name(gchar *name, BIO *hash)
{
	glong chars_written = 0;

	gchar *u16name = (gchar*)g_utf8_to_utf16(name, -1, NULL, &chars_written, NULL);
	if (u16name == NULL) {
		return FALSE;
	}

	BIO_write(hash, u16name, 2*chars_written);

	g_free(u16name);

	return TRUE;
}

/*
 * msi_prehash calculates the pre-hash used for 'MsiDigitalSignatureEx'
 * signatures in MSI files.  The pre-hash hashes only metadata (file names,
 * file sizes, creation times and modification times), whereas the basic
 * 'DigitalSignature' MSI signature only hashes file content.
 *
 * The hash is written to the hash BIO.
 */
static gboolean msi_prehash(GsfInfile *infile, gchar *dirname, BIO *hash)
{
	GSList *sorted = NULL;
	guint8 classid[16];
	guint8 zeroes[8];

	memset(&zeroes, 0, sizeof(zeroes));

	gsf_infile_msole_get_class_id(GSF_INFILE_MSOLE(infile), classid);

	if (dirname != NULL) {
		if (!msi_prehash_utf16_name(dirname, hash))
			return FALSE;
	}

	BIO_write(hash, classid, sizeof(classid));
	BIO_write(hash, zeroes, 4);

	if (dirname != NULL) {
		/*
		 * Creation time and modification time for the root directory.
		 * These are always zero. The ctime and mtime of the actual
		 * file itself takes precedence.
		 */ 
		BIO_write(hash, zeroes, 8); // ctime as Windows FILETIME.
		BIO_write(hash, zeroes, 8); // mtime as Windows FILETIME.
	}

	sorted = msi_sorted_infile_children(infile);

	for (; sorted; sorted = sorted->next) {
		gchar *name = (gchar*)sorted->data;
		GsfInput *child =  gsf_infile_child_by_name(infile, name);
		if (child == NULL)
			continue;

		gboolean is_dir = GSF_IS_INFILE(child) && gsf_infile_num_children(GSF_INFILE(child)) > 0;
		if (is_dir) {
			if (!msi_prehash(GSF_INFILE(child), name, hash))
				return FALSE;
		} else {
			if (!msi_prehash_utf16_name(name, hash))
				return FALSE;

			/*
			 * File size.
			 */
			gsf_off_t size = gsf_input_remaining(child);
			guint32 sizebuf = GUINT32_TO_LE((guint32)size);
			BIO_write(hash, &sizebuf, sizeof(sizebuf));

			/*
			 * Reserved - must be 0. Corresponds to
			 * offset 0x7c..0x7f in the CDFv2 file.
			 */
			BIO_write(hash, zeroes, 4);

			/*
			 * Creation time and modification time
			 * as Windows FILETIMEs. We keep them
			 * zeroed, because libgsf doesn't seem
			 * to support outputting them.
			 */
			BIO_write(hash, zeroes, 8); // ctime as a Windows FILETIME
			BIO_write(hash, zeroes, 8); // mtime as a Windows FILETIME
		}
	}

	g_slist_free(sorted);

	return TRUE;
}

/**
 * msi_handle_dir performs a direct copy of the input MSI file in infile to a new
 * output file in outfile.  While copying, it also writes all file content to the
 * hash BIO in order to calculate a 'basic' hash that can be used for an MSI
 * 'DigitalSignature' hash.
 *
 * msi_handle_dir is hierarchy aware: if any subdirectories are found, they will be
 * visited, copied and hashed as well.
 */
static gboolean msi_handle_dir(GsfInfile *infile, GsfOutfile *outole, BIO *hash)
{
	guint8 classid[16];
	GSList *sorted = NULL;

	gsf_infile_msole_get_class_id(GSF_INFILE_MSOLE(infile), classid);
	if (outole != NULL)
		gsf_outfile_msole_set_class_id(GSF_OUTFILE_MSOLE(outole), classid);

	sorted = msi_sorted_infile_children(infile);

	for (; sorted; sorted = sorted->next) {
		gchar *name = (gchar*)sorted->data;
		GsfInput *child =  gsf_infile_child_by_name(infile, name);
		if (child == NULL)
			continue;

		gboolean is_dir = GSF_IS_INFILE(child) && gsf_infile_num_children(GSF_INFILE(child)) > 0;
		GsfOutput *outchild = NULL;
		if (outole != NULL)
			outchild = gsf_outfile_new_child(outole, name, is_dir);
		if (is_dir) {
			if (!msi_handle_dir(GSF_INFILE(child), GSF_OUTFILE(outchild), hash)) {
				return FALSE;
			}
		} else {
			while (gsf_input_remaining(child) > 0) {
				gsf_off_t size = MIN(gsf_input_remaining(child), 4096);
				guint8 const *data = gsf_input_read(child, size, NULL);
				BIO_write(hash, data, size);
				if (outchild != NULL && !gsf_output_write(outchild, size, data)) {
					return FALSE;
				}
			}
		}

		if (outchild != NULL) {
			gsf_output_close(outchild);
			g_object_unref(outchild);
		}
	}

	BIO_write(hash, classid, sizeof(classid));

	g_slist_free(sorted);

	return TRUE;
}

/*
 * msi_verify_pkcs7 is a helper function for msi_verify_file.
 * It exists to make it easier to implement verification of nested signatures.
 */
static int msi_verify_pkcs7(PKCS7 *p7, GsfInfile *infile, unsigned char *exdata, unsigned int exlen, char *leafhash, int allownest) {
	int i = 0;
	int ret = 0;
	X509_STORE *store = NULL;
	int mdtype = -1;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
#ifdef GSF_CAN_READ_MSI_METADATA
	unsigned char cexmdbuf[EVP_MAX_MD_SIZE];
#endif
	unsigned char hexbuf[EVP_MAX_MD_SIZE*2+1];
	BIO *bio = NULL;

	ASN1_OBJECT *indir_objid = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	if (p7 && PKCS7_type_is_signed(p7) && !OBJ_cmp(p7->d.sign->contents->type, indir_objid) && p7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE) {
		ASN1_STRING *astr = p7->d.sign->contents->d.other->value.sequence;
		const unsigned char *p = astr->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, astr->length);
		if (idc) {
			if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
				mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
				memcpy(mdbuf, idc->messageDigest->digest->data, idc->messageDigest->digest->length);
			}
			SpcIndirectDataContent_free(idc);
		}
		ASN1_OBJECT_free(indir_objid);
	}

	if (mdtype == -1) {
		printf("Failed to extract current message digest\n\n");
		ret = 1;
		goto out;
	}

	if (p7 == NULL) {
		printf("Failed to read PKCS7 signature from DigitalSignature section\n\n");
		ret = 1;
		goto out;
	}

	printf("Message digest algorithm         : %s\n", OBJ_nid2sn(mdtype));

	const EVP_MD *md = EVP_get_digestbynid(mdtype);
	BIO *hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, md);
	BIO_push(hash, BIO_new(BIO_s_null()));

	if (exdata) {
		/*
		 * Until libgsf can read more MSI metadata, we can't
		 * really verify them by plowing through the file.
		 * Verifying files signed by osslsigncode itself works,
		 * though!
		 *
		 * For now, the compromise is to use the hash given
		 * by the file, which is equivalent to verifying a
		 * non-MsiDigitalSignatureEx signature from a security
		 * pespective, because we'll only be calculating the
		 * file content hashes ourselves.
		 */
#ifdef GSF_CAN_READ_MSI_METADATA
		BIO *prehash = BIO_new(BIO_f_md());
		BIO_set_md(prehash, md);
		BIO_push(prehash, BIO_new(BIO_s_null()));

		if (!msi_prehash(infile, NULL, prehash)) {
			ret = 1;
			goto out;
		}

		BIO_gets(prehash, (char*)cexmdbuf, EVP_MAX_MD_SIZE);
		BIO_write(hash, (char*)cexmdbuf, EVP_MD_size(md));
#else
		BIO_write(hash, (char *)exdata, EVP_MD_size(md));
#endif
	}

	if (!msi_handle_dir(infile, NULL, hash)) {
		ret = 1;
		goto out;
	}

	BIO_gets(hash, (char*)cmdbuf, EVP_MAX_MD_SIZE);
	tohex(cmdbuf, hexbuf, EVP_MD_size(md));
	int mdok = !memcmp(mdbuf, cmdbuf, EVP_MD_size(md));
	if (!mdok) ret = 1;
	printf("Calculated DigitalSignature      : %s", hexbuf);
	if (mdok) {
		printf("\n");
	} else {
		tohex(mdbuf, hexbuf, EVP_MD_size(md));
		printf("    MISMATCH!!! FILE HAS %s\n", hexbuf);
	}

#ifdef GSF_CAN_READ_MSI_METADATA
	if (exdata) {
		tohex(cexmdbuf, hexbuf, EVP_MD_size(md));
		int exok = !memcmp(exdata, cexmdbuf, MIN(EVP_MD_size(md), exlen));
		if (!exok) ret = 1;
		printf("Calculated MsiDigitalSignatureEx : %s", hexbuf);
		if (exok) {
			printf("\n");
		} else {
			tohex(exdata, hexbuf, EVP_MD_size(md));
			printf("    MISMATCH!!! FILE HAS %s\n", hexbuf);
		}
	}
#endif

	printf("\n");

	int seqhdrlen = asn1_simple_hdr_len(p7->d.sign->contents->d.other->value.sequence->data,
										p7->d.sign->contents->d.other->value.sequence->length);
	bio = BIO_new_mem_buf(p7->d.sign->contents->d.other->value.sequence->data + seqhdrlen,
						  p7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);
	store = X509_STORE_new();
	int verok = PKCS7_verify(p7, p7->d.sign->cert, store, bio, NULL, PKCS7_NOVERIFY);
	BIO_free(bio);
	/* XXX: add more checks here (attributes, timestamp, etc) */
	printf("Signature verification: %s\n\n", verok ? "ok" : "failed");
	if (!verok) {
		ERR_print_errors_fp(stdout);
		ret = 1;
	}

	int leafok = 0;
	STACK_OF(X509) *signers = PKCS7_get0_signers(p7, NULL, 0);
	printf("Number of signers: %d\n", sk_X509_num(signers));
	for (i=0; i<sk_X509_num(signers); i++) {
		X509 *cert = sk_X509_value(signers, i);
		char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		printf("\tSigner #%d:\n\t\tSubject : %s\n\t\tIssuer  : %s\n", i, subject, issuer);
		OPENSSL_free(subject);
		OPENSSL_free(issuer);

		if (leafhash != NULL && leafok == 0) {
			leafok = verify_leaf_hash(cert, leafhash) == 0;
		}
	}
	sk_X509_free(signers);

	printf("\nNumber of certificates: %d\n", sk_X509_num(p7->d.sign->cert));
	for (i=0; i<sk_X509_num(p7->d.sign->cert); i++) {
		X509 *cert = sk_X509_value(p7->d.sign->cert, i);
		char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		printf("\tCert #%d:\n\t\tSubject : %s\n\t\tIssuer  : %s\n", i, subject, issuer);
		OPENSSL_free(subject);
		OPENSSL_free(issuer);
    }

	printf("\n");

	if (leafhash != NULL) {
		printf("Leaf hash match: %s\n\n", leafok ? "ok" : "failed");
		if (!leafok)
			ret = 1;
	}

	if (allownest) {
		int has_sig = 0;
		PKCS7 *p7nest = pkcs7_get_nested_signature(p7, &has_sig);
		if (p7nest) {
			printf("\n");
			int nest_ret = msi_verify_pkcs7(p7nest, infile, exdata, exlen, leafhash, 0);
			if (ret == 0)
				ret = nest_ret;
			PKCS7_free(p7nest);
		} else if (!p7nest && has_sig) {
			printf("\nFailed to decode nested signature!\n");
			ret = 1;
		} else
			printf("\n");
	} else
		printf("\n");

out:
	if (store)
		X509_STORE_free(store);

	return ret;
}

/*
 * msi_verify_file checks whether or not the signature of infile is valid.
 */
static int msi_verify_file(GsfInfile *infile, char *leafhash) {
	GsfInput *sig = NULL;
	GsfInput *exsig = NULL;
	unsigned char *exdata = NULL;
	unsigned char *indata = NULL;
	gchar decoded[0x40];
	int i, ret = 0;
	PKCS7 *p7 = NULL;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const guint8 *name = (const guint8*)gsf_input_name(child);
		msi_decode(name, decoded);
		if (!g_strcmp0(decoded, "\05DigitalSignature"))
			sig = child;
		if (!g_strcmp0(decoded, "\05MsiDigitalSignatureEx"))
			exsig = child;
	}
	if (sig == NULL) {
		printf("MSI file has no signature\n\n");
		ret = 1;
		goto out;
	}

	unsigned long inlen = (unsigned long) gsf_input_remaining(sig);
	indata = malloc(inlen);
	if (gsf_input_read(sig, inlen, indata) == NULL) {
		ret = 1;
		goto out;
	}

	unsigned long exlen = 0;
	if (exsig != NULL) {
		exlen = (unsigned long) gsf_input_remaining(exsig);
		exdata = malloc(exlen);
		if (gsf_input_read(exsig, exlen, exdata) == NULL) {
			ret = 1;
			goto out;
		}
	}

	const unsigned char *blob = (unsigned char *)indata;
	p7 = d2i_PKCS7(NULL, &blob, inlen);

	ret = msi_verify_pkcs7(p7, infile, exdata, exlen, leafhash, 1);

out:
	free(indata);
	free(exdata);

	if (p7)
		PKCS7_free(p7);

	return ret;
}

static int msi_extract_dse(GsfInfile *infile, unsigned char **dsebuf, unsigned long *dselen, int *has_dse) {
	GsfInput *exsig = NULL;
	gchar decoded[0x40];
	u_char *buf = NULL;
	gsf_off_t size = 0;
	int i, ret = 0;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const guint8 *name = (const guint8*)gsf_input_name(child);
		msi_decode(name, decoded);
		if (!g_strcmp0(decoded, "\05MsiDigitalSignatureEx"))
			exsig = child;
	}
	if (exsig == NULL) {
		ret = 1;
		goto out;
	}

	if (has_dse != NULL) {
		*has_dse = 1;
	}

	size = gsf_input_remaining(exsig);

	if (dselen != NULL) {
		*dselen = (unsigned long) size;
	}

	if (dsebuf != NULL) {
		buf = malloc(size);
		if (gsf_input_read(exsig, size, buf) == NULL) {
			ret = 1;
			goto out;
		}
		*dsebuf = (unsigned char *) buf;
	}

out:
	return ret;
}

/*
 * msi_extract_signature_to_file extracts the MSI DigitalSignaure from infile
 * to a file at the path given by outfile.
 */
static int msi_extract_signature_to_file(GsfInfile *infile, char *outfile) {
	unsigned char hexbuf[EVP_MAX_MD_SIZE*2+1];
	GsfInput *sig = NULL;
	GsfInput *exsig = NULL;
	unsigned char *exdata = NULL;
	unsigned long exlen = 0;
	BIO *outdata = NULL;
	gchar decoded[0x40];
	int i, ret = 0;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const guint8 *name = (const guint8*)gsf_input_name(child);
		msi_decode(name, decoded);
		if (!g_strcmp0(decoded, "\05DigitalSignature"))
			sig = child;
		if (!g_strcmp0(decoded, "\05MsiDigitalSignatureEx"))
			exsig = child;
	}
	if (sig == NULL) {
		printf("MSI file has no signature\n\n");
		ret = 1;
		goto out;
	}

	/* Create outdata file */
	outdata = BIO_new_file(outfile, "w+b");
	if (outdata == NULL) {
		printf("Unable to open %s\n\n", outfile);
		ret = 1;
		goto out;
	}

	while (gsf_input_remaining(sig) > 0) {
		gsf_off_t size = MIN(gsf_input_remaining(sig), 4096);
		guint8 const *data = gsf_input_read(sig, size, NULL);
		BIO_write(outdata, data, size);
	}

	if (exsig != NULL) {
		exlen = (unsigned long) gsf_input_remaining(exsig);
		if (exlen > EVP_MAX_MD_SIZE) {
			printf("MsiDigitalSignatureEx is larger than EVP_MAX_MD_SIZE. Aborting...\n\n");
			ret = 1;
			goto out;
		}

		exdata = malloc(exlen);
		if (gsf_input_read(exsig, exlen, exdata) == NULL) {
			printf("Unable to read MsiDigitalSignatureEx\n\n");
			ret = 1;
			goto out;
		}

		tohex(exdata, hexbuf, exlen);
		printf("Note: MSI includes a MsiDigitalSignatureEx section.\n");
		printf("MsiDigitalSignatureEx pre-hash: %s\n\n", hexbuf);
	}

out:
	free(exdata);
	if (outdata)
		BIO_free_all(outdata);

	return ret;
}

static PKCS7 *msi_extract_signature_to_pkcs7(GsfInfile *infile) {
	GsfInput *sig = NULL;
	gchar decoded[0x40];
	PKCS7 *p7 = NULL;
	u_char *buf = NULL;
	gsf_off_t size = 0;
	int i = 0;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const guint8 *name = (const guint8*)gsf_input_name(child);
		msi_decode(name, decoded);
		if (!g_strcmp0(decoded, "\05DigitalSignature"))
			sig = child;
	}
	if (sig == NULL) {
		goto out;
	}

	size = gsf_input_remaining(sig);
	buf = malloc(size);
	if (gsf_input_read(sig, size, buf) == NULL) {
		goto out;
	}

	const unsigned char *p7buf = buf;
	p7 = d2i_PKCS7(NULL, &p7buf, size);

out:
	free(buf);
	return p7;
}

#endif

static void calc_pe_digest(BIO *bio, const EVP_MD *md, unsigned char *mdbuf,
						   unsigned int peheader, int pe32plus, unsigned int fileend)
{
	static unsigned char bfb[16*1024*1024];
	EVP_MD_CTX mdctx;

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit(&mdctx, md);

	memset(mdbuf, 0, EVP_MAX_MD_SIZE);

	(void)BIO_seek(bio, 0);
	BIO_read(bio, bfb, peheader + 88);
	EVP_DigestUpdate(&mdctx, bfb, peheader + 88);
	BIO_read(bio, bfb, 4);
	BIO_read(bio, bfb, 60+pe32plus*16);
	EVP_DigestUpdate(&mdctx, bfb, 60+pe32plus*16);
	BIO_read(bio, bfb, 8);

	unsigned int n = peheader + 88 + 4 + 60+pe32plus*16 + 8;
	while (n < fileend) {
		int want = fileend - n;
		if (want > sizeof(bfb))
			want = sizeof(bfb);
		int l = BIO_read(bio, bfb, want);
		if (l <= 0)
			break;
		EVP_DigestUpdate(&mdctx, bfb, l);
		n += l;
	}

	EVP_DigestFinal(&mdctx, mdbuf, NULL);
}


static void	extract_page_hash (SpcAttributeTypeAndOptionalValue *obj,
							   unsigned char **ph, unsigned int *phlen, int *phtype)
{
	*phlen = 0;

	const unsigned char *blob = obj->value->value.sequence->data;
	SpcPeImageData *id = d2i_SpcPeImageData(NULL, &blob, obj->value->value.sequence->length);
	if (id == NULL)
		return;

	if (id->file->type != 1) {
		SpcPeImageData_free(id);
		return;
	}

	SpcSerializedObject *so = id->file->value.moniker;
	if (so->classId->length != sizeof(classid_page_hash) ||
		memcmp(so->classId->data, classid_page_hash, sizeof (classid_page_hash))) {
		SpcPeImageData_free(id);
		return;
	}

	/* skip ASN.1 SET hdr */
	unsigned int l = asn1_simple_hdr_len(so->serializedData->data, so->serializedData->length);
	blob = so->serializedData->data + l;
	obj = d2i_SpcAttributeTypeAndOptionalValue(NULL, &blob, so->serializedData->length - l);
	SpcPeImageData_free(id);
	if (!obj)
		return;

	char buf[128];
	*phtype = 0;
	buf[0] = 0x00;
	OBJ_obj2txt(buf, sizeof(buf), obj->type, 1);
	if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V1)) {
		*phtype = NID_sha1;
	} else if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V2)) {
		*phtype = NID_sha256;
	} else {
		SpcAttributeTypeAndOptionalValue_free(obj);
		return;
	}

	/* Skip ASN.1 SET hdr */
	unsigned int l2 = asn1_simple_hdr_len(obj->value->value.sequence->data, obj->value->value.sequence->length);
	/* Skip ASN.1 OCTET STRING hdr */
	l =  asn1_simple_hdr_len(obj->value->value.sequence->data + l2, obj->value->value.sequence->length - l2);
	l += l2;
	*phlen = obj->value->value.sequence->length - l;
	*ph = malloc(*phlen);
	memcpy(*ph, obj->value->value.sequence->data + l, *phlen);
	SpcAttributeTypeAndOptionalValue_free(obj);
}

static unsigned char *calc_page_hash(char *indata, unsigned int peheader, int pe32plus,
									 unsigned int sigpos, int phtype, unsigned int *rphlen)
{
	unsigned short nsections = GET_UINT16_LE(indata + peheader + 6);
	unsigned int pagesize = GET_UINT32_LE(indata + peheader + 56);
	unsigned int hdrsize = GET_UINT32_LE(indata + peheader + 84);
	const EVP_MD *md = EVP_get_digestbynid(phtype);
	int pphlen = 4 + EVP_MD_size(md);
	int phlen = pphlen * (3 + nsections + sigpos / pagesize);
	unsigned char *res = malloc(phlen);
	unsigned char *zeroes = calloc(pagesize, 1);
	EVP_MD_CTX mdctx;

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit(&mdctx, md);
	EVP_DigestUpdate(&mdctx, indata, peheader + 88);
	EVP_DigestUpdate(&mdctx, indata + peheader + 92, 60 + pe32plus*16);
	EVP_DigestUpdate(&mdctx, indata + peheader + 160 + pe32plus*16, hdrsize - (peheader + 160 + pe32plus*16));
	EVP_DigestUpdate(&mdctx, zeroes, pagesize - hdrsize);
	memset(res, 0, 4);
	EVP_DigestFinal(&mdctx, res + 4, NULL);

	unsigned short sizeofopthdr = GET_UINT16_LE(indata + peheader + 20);
	char *sections = indata + peheader + 24 + sizeofopthdr;
	int i, pi = 1;
	unsigned int lastpos = 0;
	for (i=0; i<nsections; i++) {
		unsigned int rs = GET_UINT32_LE(sections + 16);
		unsigned int ro = GET_UINT32_LE(sections + 20);
		unsigned int l;
		for (l=0; l < rs; l+=pagesize, pi++) {
			PUT_UINT32_LE(ro + l, res + pi*pphlen);
			EVP_DigestInit(&mdctx, md);
			if (rs - l < pagesize) {
				EVP_DigestUpdate(&mdctx, indata + ro + l, rs - l);
				EVP_DigestUpdate(&mdctx, zeroes, pagesize - (rs - l));
			} else {
				EVP_DigestUpdate(&mdctx, indata + ro + l, pagesize);
			}
			EVP_DigestFinal(&mdctx, res + pi*pphlen + 4, NULL);
		}
		lastpos = ro + rs;
		sections += 40;
	}
	PUT_UINT32_LE(lastpos, res + pi*pphlen);
	memset(res + pi*pphlen + 4, 0, EVP_MD_size(md));
	pi++;
	free(zeroes);
	*rphlen = pi*pphlen;
	return res;
}

static int verify_pe_pkcs7(PKCS7 *p7, char *indata, unsigned int peheader, int pe32plus,
						   unsigned int sigpos, unsigned int siglen, char *leafhash,
						   int allownest)
{
	int ret = 0;
	int mdtype = -1, phtype = -1;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
	unsigned char hexbuf[EVP_MAX_MD_SIZE*2+1];
	unsigned char *ph = NULL;
	unsigned int phlen = 0;
	BIO *bio = NULL;

	ASN1_OBJECT *indir_objid = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	if (PKCS7_type_is_signed(p7) &&
		!OBJ_cmp(p7->d.sign->contents->type, indir_objid) &&
		p7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE) {
		ASN1_STRING *astr = p7->d.sign->contents->d.other->value.sequence;
		const unsigned char *p = astr->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, astr->length);
		if (idc) {
			extract_page_hash (idc->data, &ph, &phlen, &phtype);
			if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
				mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
				memcpy(mdbuf, idc->messageDigest->digest->data, idc->messageDigest->digest->length);
			}
			SpcIndirectDataContent_free(idc);
		}
	}
	ASN1_OBJECT_free(indir_objid);

	if (mdtype == -1) {
		printf("Failed to extract current message digest\n\n");
		return -1;
	}

	printf("Message digest algorithm  : %s\n", OBJ_nid2sn(mdtype));

	const EVP_MD *md = EVP_get_digestbynid(mdtype);
	tohex(mdbuf, hexbuf, EVP_MD_size(md));
	printf("Current message digest    : %s\n", hexbuf);

	bio = BIO_new_mem_buf(indata, sigpos + siglen);
	calc_pe_digest(bio, md, cmdbuf, peheader, pe32plus, sigpos);
	BIO_free(bio);
	tohex(cmdbuf, hexbuf, EVP_MD_size(md));
	int mdok = !memcmp(mdbuf, cmdbuf, EVP_MD_size(md));
	if (!mdok) ret = 1;
	printf("Calculated message digest : %s%s\n\n", hexbuf, mdok?"":"    MISMATCH!!!");

	if (phlen > 0) {
		printf("Page hash algorithm  : %s\n", OBJ_nid2sn(phtype));
		tohex(ph, hexbuf, (phlen < 32) ? phlen : 32);
		printf("Page hash            : %s ...\n", hexbuf);
		unsigned int cphlen = 0;
		unsigned char *cph = calc_page_hash(indata, peheader, pe32plus, sigpos, phtype, &cphlen);
		tohex(cph, hexbuf, (cphlen < 32) ? cphlen : 32);
		printf("Calculated page hash : %s ...%s\n\n", hexbuf,
			   ((phlen != cphlen) || memcmp(ph, cph, phlen)) ? "    MISMATCH!!!":"");
		free(ph);
		free(cph);
	}

	int seqhdrlen = asn1_simple_hdr_len(p7->d.sign->contents->d.other->value.sequence->data,
										p7->d.sign->contents->d.other->value.sequence->length);
	bio = BIO_new_mem_buf(p7->d.sign->contents->d.other->value.sequence->data + seqhdrlen,
						  p7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);
	X509_STORE *store = X509_STORE_new();
	int verok = PKCS7_verify(p7, p7->d.sign->cert, store, bio, NULL, PKCS7_NOVERIFY);
	BIO_free(bio);
	/* XXX: add more checks here (attributes, timestamp, etc) */
	printf("Signature verification: %s\n\n", verok ? "ok" : "failed");
	if (!verok) {
		ERR_print_errors_fp(stdout);
		ret = 1;
	}

	int i;
	int leafok = 0;
	STACK_OF(X509) *signers = PKCS7_get0_signers(p7, NULL, 0);
	printf("Number of signers: %d\n", sk_X509_num(signers));
	for (i=0; i<sk_X509_num(signers); i++) {
		X509 *cert = sk_X509_value(signers, i);
		char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		BIGNUM *serialbn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
		char *serial = BN_bn2hex(serialbn);
		if (i > 0)
			printf("\t------------------\n");
		printf("\tSigner #%d:\n\t\tSubject: %s\n\t\tIssuer : %s\n\t\tSerial : %s\n",
			   i, subject, issuer, serial);
		OPENSSL_free(subject);
		OPENSSL_free(issuer);
		OPENSSL_free(serial);
		BN_free(serialbn);

		if (leafhash != NULL && leafok == 0) {
			leafok = verify_leaf_hash(cert, leafhash) == 0;
		}
	}
	sk_X509_free(signers);

	printf("\nNumber of certificates: %d\n", sk_X509_num(p7->d.sign->cert));
	for (i=0; i<sk_X509_num(p7->d.sign->cert); i++) {
		X509 *cert = sk_X509_value(p7->d.sign->cert, i);
		char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		BIGNUM *serialbn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
		char *serial = BN_bn2hex(serialbn);
		if (i > 0)
			printf("\t------------------\n");
		printf("\tCert #%d:\n\t\tSubject: %s\n\t\tIssuer : %s\n\t\tSerial : %s\n",
			   i, subject, issuer, serial);
		OPENSSL_free(subject);
		OPENSSL_free(issuer);
		OPENSSL_free(serial);
		BN_free(serialbn);
	}

	if (leafhash != NULL) {
		printf("\nLeaf hash match: %s\n", leafok ? "ok" : "failed");
		if (!leafok)
			ret = 1;
	}

	if (allownest) {
		int has_sig = 0;
		PKCS7 *p7nest = pkcs7_get_nested_signature(p7, &has_sig);
		if (p7nest) {
			printf("\n");
			int nest_ret = verify_pe_pkcs7(p7nest, indata, peheader, pe32plus, sigpos, siglen, leafhash, 0);
			if (ret == 0)
				ret = nest_ret;
			PKCS7_free(p7nest);
		} else if (!p7nest && has_sig) {
			printf("\nFailed to decode nested signature!\n");
			ret = 1;
		} else
			printf("\n");
	} else
		printf("\n");

	X509_STORE_free(store);

	return ret;
}

static int verify_pe_file(char *indata, unsigned int peheader, int pe32plus,
						  unsigned int sigpos, unsigned int siglen, char *leafhash)
{
	int ret = 0;
	unsigned int pe_checksum = GET_UINT32_LE(indata + peheader + 88);
	printf("Current PE checksum   : %08X\n", pe_checksum);

	BIO *bio = BIO_new_mem_buf(indata, sigpos + siglen);
	unsigned int real_pe_checksum = calc_pe_checksum(bio, peheader);
	BIO_free(bio);
	if (pe_checksum && pe_checksum != real_pe_checksum)
		ret = 1;
	printf("Calculated PE checksum: %08X%s\n\n", real_pe_checksum,
		   ret ? "     MISMATCH!!!!" : "");
	if (siglen == 0) {
		printf("No signature found.\n\n");
		return ret;
	}

	unsigned int pos = 0;
	PKCS7 *p7 = NULL;

	while (pos < siglen) {
		unsigned int l = GET_UINT32_LE(indata + sigpos + pos);
		unsigned short certrev  = GET_UINT16_LE(indata + sigpos + pos + 4);
		unsigned short certtype = GET_UINT16_LE(indata + sigpos + pos + 6);
		if (certrev == WIN_CERT_REVISION_2 && certtype == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
			const unsigned char *blob = (unsigned char*)indata + sigpos + pos + 8;
			p7 = d2i_PKCS7(NULL, &blob, l - 8);
		}
		if (l%8)
			l += (8 - l%8);
		pos += l;
	}

	if (p7 == NULL) {
		printf("Failed to extract PKCS7 data\n\n");
		return -1;
	}

	ret = verify_pe_pkcs7(p7, indata, peheader, pe32plus, sigpos, siglen, leafhash, 1);
	PKCS7_free(p7);
	return ret;
}

// extract_existing_pe_pkcs7 retreives a decoded PKCS7 struct corresponding to the
// existing signature of the PE file.
static PKCS7 *extract_existing_pe_pkcs7(char *indata, unsigned int peheader, int pe32plus,
									   unsigned int sigpos, unsigned int siglen)
{
	unsigned int pos = 0;
	PKCS7 *p7 = NULL;

	while (pos < siglen) {
		unsigned int l = GET_UINT32_LE(indata + sigpos + pos);
		unsigned short certrev  = GET_UINT16_LE(indata + sigpos + pos + 4);
		unsigned short certtype = GET_UINT16_LE(indata + sigpos + pos + 6);
		if (certrev == WIN_CERT_REVISION_2 && certtype == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
			const unsigned char *blob = (unsigned char*)indata + sigpos + pos + 8;
			p7 = d2i_PKCS7(NULL, &blob, l - 8);
		}
		if (l%8)
			l += (8 - l%8);
		pos += l;
	}

	return p7;
}

static STACK_OF(X509) *PEM_read_certs_with_pass(BIO *bin, char *certpass)
{
	STACK_OF(X509) *certs = sk_X509_new_null();
	X509 *x509;
	(void)BIO_seek(bin, 0);
	while((x509 = PEM_read_bio_X509(bin, NULL, NULL, certpass)))
		sk_X509_push(certs, x509);
	if (!sk_X509_num(certs)) {
		sk_X509_free(certs);
		return NULL;
	}
	return certs;
}

static STACK_OF(X509) *PEM_read_certs(BIO *bin, char *certpass)
{
	STACK_OF(X509) *certs = PEM_read_certs_with_pass(bin, certpass);
	if (!certs)
		certs = PEM_read_certs_with_pass(bin, NULL);
	return certs;
}


static off_t get_file_size(const char *infile)
{
	int ret;
#ifdef _WIN32
	struct _stat st;
	ret = _stat(infile, &st);
#else
	struct stat st;
	ret = stat(infile, &st);
#endif
	if (ret)
	{
		fprintf(stderr, "Failed to open file: %s\n", infile);
		return 0;
	}

	if (st.st_size < 4) {
		fprintf(stderr, "Unrecognized file type - file is too short: %s\n", infile);
		return 0;
	}
	return st.st_size;
}

static char* map_file(const char *infile, const off_t size)
{
	char *indata = NULL;
#ifdef WIN32
	HANDLE fh, fm;
	fh = CreateFile(infile, GENERIC_READ, FILE_SHARE_READ , NULL, OPEN_EXISTING, 0, NULL);
	if (fh == INVALID_HANDLE_VALUE)
		return NULL;
	fm = CreateFileMapping(fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (fm == NULL)
		return NULL;
	indata = MapViewOfFile(fm, FILE_MAP_READ, 0, 0, 0);
#else
	int fd = open(infile, O_RDONLY);
	if (fd < 0)
		return NULL;
	indata = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (indata == MAP_FAILED)
		return NULL;
#endif
	return indata;
}

#ifdef PROVIDE_ASKPASS
char *getpassword(const char *prompt)
{
#ifdef HAVE_TERMIOS_H
	struct termios ofl, nfl;
    char *p, passbuf[1024];

    fputs(prompt, stdout);

    tcgetattr(fileno(stdin), &ofl);
    nfl = ofl;
    nfl.c_lflag &= ~ECHO;
    nfl.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nfl) != 0) {
	    fprintf(stderr, "Failed to set terminal attributes\n");
		return NULL;
    }

    p = fgets(passbuf, sizeof(passbuf), stdin);

    if (tcsetattr(fileno(stdin), TCSANOW, &ofl) != 0)
	    fprintf(stderr, "Failed to restore terminal attributes\n");

	if (!p) {
	    fprintf(stderr, "Failed to read password\n");
		return NULL;
    }

	passbuf[strlen(passbuf)-1] = 0x00;
	char *pass = strdup(passbuf);
	memset(passbuf, 0, sizeof(passbuf));
	return pass;
#else
	return getpass(prompt);
#endif
}
#endif

int main(int argc, char **argv)
{
	BIO *btmp, *sigbio, *hash, *outdata;
	PKCS12 *p12;
	PKCS7 *p7 = NULL, *cursig = NULL, *outsig = NULL, *sig, *p7x = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *certs = NULL, *xcerts = NULL;
	EVP_PKEY *pkey = NULL;
	PKCS7_SIGNER_INFO *si;
	ASN1_STRING *astr;
	const EVP_MD *md;

	const char *argv0 = argv[0];
	static char buf[64*1024];
	char *xcertfile, *certfile, *keyfile, *pvkfile, *pkcs12file, *infile, *outfile, *sigfile, *desc, *url, *indata, *insigdata, *outdataverify;
	char *p11engine, *p11module;
	char *pass = NULL, *readpass = NULL;
	int output_pkcs7 = 0;
	int askpass = 0;
	char *leafhash = NULL;
#ifdef ENABLE_CURL
	char *turl[MAX_TS_SERVERS], *proxy = NULL, *tsurl[MAX_TS_SERVERS];
	int noverifypeer = 0;
#endif
	int nest = 0;
	int add_msi_dse = 0;
	int nturl = 0, ntsurl = 0;
	int addBlob = 0;
	u_char *p = NULL;
	int ret = 0, i, len = 0, jp = -1, pe32plus = 0, comm = 0, pagehash = 0;
	unsigned int tmp, peheader = 0, padlen = 0;
	off_t filesize, fileend, sigfilesize, sigfileend, outdatasize;
	file_type_t type;
	cmd_type_t cmd = CMD_SIGN;
	char *failarg = NULL;

	static u_char purpose_ind[] = {
		0x30, 0x0c,
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15
	};

	static u_char purpose_comm[] = {
		0x30, 0x0c,
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x16
	};

	static u_char msi_signature[] = {
		0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
	};

#ifdef WITH_GSF
	GsfOutfile *outole = NULL;
	GsfOutput *sink = NULL;
	u_char *p_msiex = NULL;
	int len_msiex = 0;
#endif

	xcertfile = certfile = keyfile = pvkfile = pkcs12file = p11module = p11engine = infile = outfile = sigfile = desc = url = NULL;
	hash = outdata = NULL;

	/* Set up OpenSSL */
	ERR_load_crypto_strings();
	OPENSSL_add_all_algorithms_conf();

	/* create some MS Authenticode OIDS we need later on */
	if (!OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL) ||
		!OBJ_create(SPC_MS_JAVA_SOMETHING, NULL, NULL) ||
		!OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL) ||
		!OBJ_create(SPC_NESTED_SIGNATURE_OBJID, NULL, NULL))
		DO_EXIT_0("Failed to add objects\n");

	md = EVP_sha1();

	if (argc > 1) {
		if (!strcmp(argv[1], "sign")) {
			cmd = CMD_SIGN;
			argv++;
			argc--;
		} else if (!strcmp(argv[1], "extract-signature")) {
			cmd = CMD_EXTRACT;
			argv++;
			argc--;
		} else if (!strcmp(argv[1], "attach-signature")) {
			cmd = CMD_ATTACH;
			argv++;
                        argc--;
		} else if (!strcmp(argv[1], "remove-signature")) {
			cmd = CMD_REMOVE;
			argv++;
			argc--;
		} else if (!strcmp(argv[1], "verify")) {
			cmd = CMD_VERIFY;
			argv++;
			argc--;
		} else if (!strcmp(argv[1], "add")) {
			cmd = CMD_ADD;
			argv++;
			argc--;
		}
	}

	for (argc--,argv++; argc >= 1; argc--,argv++) {
		if (!strcmp(*argv, "-in")) {
			if (--argc < 1) usage(argv0);
			infile = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) usage(argv0);
			outfile = *(++argv);
		} else if (!strcmp(*argv, "-sigin")) {
			if (--argc < 1) usage(argv0);
			sigfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && (!strcmp(*argv, "-spc") || !strcmp(*argv, "-certs"))) {
			if (--argc < 1) usage(argv0);
			certfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-ac")) {
			if (--argc < 1) usage(argv0);
			xcertfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-key")) {
			if (--argc < 1) usage(argv0);
			keyfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs12")) {
			if (--argc < 1) usage(argv0);
			pkcs12file = *(++argv);
		} else if ((cmd == CMD_EXTRACT) && !strcmp(*argv, "-pem")) {
			output_pkcs7 = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11engine")) {
			if (--argc < 1) usage(argv0);
			p11engine = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11module")) {
			if (--argc < 1) usage(argv0);
			p11module = *(++argv); 
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pass")) {
			if (askpass || readpass) usage(argv0);
			if (--argc < 1) usage(argv0);
			pass = strdup(*(++argv));
			memset(*argv, 0, strlen(*argv));
#ifdef PROVIDE_ASKPASS
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-askpass")) {
			if (pass || readpass) usage(argv0);
			askpass = 1;
#endif
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-readpass")) {
			if (askpass || pass) usage(argv0);
			if (--argc < 1) usage(argv0);
			readpass = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-comm")) {
			comm = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-ph")) {
			pagehash = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-n")) {
			if (--argc < 1) usage(argv0);
			desc = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-h")) {
			if (--argc < 1) usage(argv0);
			++argv;
			if (!strcmp(*argv, "md5")) {
				md = EVP_md5();
			} else if (!strcmp(*argv, "sha1")) {
				md = EVP_sha1();
			} else if (!strcmp(*argv, "sha2") || !strcmp(*argv, "sha256")) {
				md = EVP_sha256();
			} else if (!strcmp(*argv, "sha384")) {
				md = EVP_sha384();
			} else if (!strcmp(*argv, "sha512")) {
				md = EVP_sha512();
			} else {
				usage(argv0);
			}
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-i")) {
			if (--argc < 1) usage(argv0);
			url = *(++argv);
#ifdef ENABLE_CURL
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-t")) {
			if (--argc < 1) usage(argv0);
			turl[nturl++] = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-ts")) {
			if (--argc < 1) usage(argv0);
			tsurl[ntsurl++] = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-p")) {
			if (--argc < 1) usage(argv0);
			proxy = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-noverifypeer")) {
			noverifypeer = 1;
#endif
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-addUnauthenticatedBlob")) {
			addBlob = 1;
		} else if ((cmd == CMD_SIGN || cmd == CMD_ATTACH) && !strcmp(*argv, "-nest")) {
			nest = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-verbose")) {
			g_verbose = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-add-msi-dse")) {
			add_msi_dse = 1;
		} else if ((cmd == CMD_VERIFY) && !strcmp(*argv, "-require-leaf-hash")) {
			if (--argc < 1) usage(argv0);
			leafhash = (*++argv);
		} else if (!strcmp(*argv, "-v") || !strcmp(*argv, "--version")) {
			printf(PACKAGE_STRING ", using:\n\t%s\n\t%s\n",
				   SSLeay_version(SSLEAY_VERSION),
#ifdef ENABLE_CURL
				   curl_version()
#else
				   "no libcurl available"
#endif
			   );
			printf(
#ifdef WITH_GSF
				   "\tlibgsf %d.%d.%d\n",
				   libgsf_major_version,
				   libgsf_minor_version,
				   libgsf_micro_version
#else
				   "\tno libgsf available\n"
#endif
				);
			printf("\nPlease send bug-reports to "
				   PACKAGE_BUGREPORT
				   "\n\n");

		} else if (!strcmp(*argv, "-jp")) {
			char *ap;
			if (--argc < 1) usage(argv0);
			ap = *(++argv);
			for (i=0; ap[i]; i++) ap[i] = tolower((int)ap[i]);
			if (!strcmp(ap, "low")) {
				jp = 0;
			} else if (!strcmp(ap, "medium")) {
				jp = 1;
			} else if (!strcmp(ap, "high")) {
				jp = 2;
			}
			if (jp != 0) usage(argv0); /* XXX */
		} else {
			failarg = *argv;
			break;
		}
	}

	if (!infile && argc > 0) {
		infile = *(argv++);
		argc--;
	}

	if (cmd != CMD_VERIFY && (!outfile && argc > 0)) {
		if (!strcmp(*argv, "-out")) {
			argv++;
			argc--;
		}
		if (argc > 0) {
			outfile = *(argv++);
			argc--;
		}
	}

	if (argc > 0 || (nturl && ntsurl) || !infile ||
		(cmd != CMD_VERIFY && !outfile) ||
		(cmd == CMD_SIGN && !((certfile && keyfile) || pkcs12file || (p11engine && p11module)))) {
		if (failarg)
			fprintf(stderr, "Unknown option: %s\n", failarg);
		usage(argv0);
	}

	if (readpass) {
		char passbuf[4096];
		int passfd = open(readpass, O_RDONLY);
		if (passfd < 0)
			DO_EXIT_1("Failed to open password file: %s\n", readpass);
		int passlen = read(passfd, passbuf, sizeof(passbuf)-1);
		close(passfd);
		if (passlen <= 0)
			DO_EXIT_1("Failed to read password from file: %s\n", readpass);
		passbuf[passlen] = 0x00;
		pass = strdup(passbuf);
		memset(passbuf, 0, sizeof(passbuf));
#ifdef PROVIDE_ASKPASS
	} else if (askpass) {
		pass = getpassword("Password: ");
#endif
	}

	if (cmd == CMD_SIGN) {
		/* Read certificate and key */
		if (keyfile && !p11engine && (btmp = BIO_new_file(keyfile, "rb")) != NULL) {
			unsigned char magic[4];
			unsigned char pvkhdr[4] = { 0x1e, 0xf1, 0xb5, 0xb0 };
			magic[0] = 0x00;
			BIO_read(btmp, magic, 4);
			if (!memcmp(magic, pvkhdr, 4)) {
				pvkfile = keyfile;
				keyfile = NULL;
			}
			BIO_free(btmp);
		}

		if (pkcs12file != NULL) {
			if ((btmp = BIO_new_file(pkcs12file, "rb")) == NULL ||
				(p12 = d2i_PKCS12_bio(btmp, NULL)) == NULL)
				DO_EXIT_1("Failed to read PKCS#12 file: %s\n", pkcs12file);
			BIO_free(btmp);
			if (!PKCS12_parse(p12, pass ? pass : "", &pkey, &cert, &certs))
				DO_EXIT_1("Failed to parse PKCS#12 file: %s (Wrong password?)\n", pkcs12file);
			PKCS12_free(p12);
		} else if (pvkfile != NULL) {
#if OPENSSL_VERSION_NUMBER > 0x10000000
			if ((btmp = BIO_new_file(certfile, "rb")) == NULL ||
				((p7 = d2i_PKCS7_bio(btmp, NULL)) == NULL &&
				 (certs = PEM_read_certs(btmp, "")) == NULL))
				DO_EXIT_1("Failed to read certificate file: %s\n", certfile);
			BIO_free(btmp);
			if ((btmp = BIO_new_file(pvkfile, "rb")) == NULL ||
				( (pkey = b2i_PVK_bio(btmp, NULL, pass ? pass : "")) == NULL &&
				  (BIO_seek(btmp, 0) == 0) &&
				  (pkey = b2i_PVK_bio(btmp, NULL, NULL)) == NULL))
				DO_EXIT_1("Failed to read PVK file: %s\n", pvkfile);
			BIO_free(btmp);
#else
			DO_EXIT_1("Can not read keys from PVK files, must compile against a newer version of OpenSSL: %s\n", pvkfile);
#endif
		} else if (p11engine != NULL && p11module != NULL) {
			const int CMD_MANDATORY = 0;
			ENGINE_load_dynamic();
			ENGINE * dyn = ENGINE_by_id( "dynamic" );
			if ( ! dyn )
				DO_EXIT_0( "Failed to load 'dynamic' engine");
			if ( 1 != ENGINE_ctrl_cmd_string( dyn, "SO_PATH", p11engine, CMD_MANDATORY ) )
				DO_EXIT_1( "Failed to set dyn SO_PATH to '%s'", p11engine);

			if ( 1 != ENGINE_ctrl_cmd_string( dyn, "ID", "pkcs11", CMD_MANDATORY ) )
				DO_EXIT_0( "Failed to set dyn ID to 'pkcs11'" );

			if ( 1 != ENGINE_ctrl_cmd( dyn, "LIST_ADD", 1, NULL, NULL, CMD_MANDATORY ) )
				DO_EXIT_0( "Failed to set dyn LIST_ADD to '1'" );

			if ( 1 != ENGINE_ctrl_cmd( dyn, "LOAD", 1, NULL, NULL, CMD_MANDATORY ) )
				DO_EXIT_0( "Failed to set dyn LOAD to '1'" );

			ENGINE * pkcs11 = ENGINE_by_id( "pkcs11" );
			if ( ! pkcs11 )
				DO_EXIT_0( "Failed to find and load pkcs11 engine" );

			if ( 1 != ENGINE_ctrl_cmd_string( pkcs11, "MODULE_PATH", p11module, CMD_MANDATORY ) )
				DO_EXIT_1( "Failed to set pkcs11 engine MODULE_PATH to '%s'", p11module );
		
			if (pass != NULL) {
				if ( 1 != ENGINE_ctrl_cmd_string( pkcs11, "PIN", pass, CMD_MANDATORY ) )
					DO_EXIT_0( "Failed to set pkcs11 PIN" );
			}

			if ( 1 != ENGINE_init( pkcs11 ) )
				DO_EXIT_0( "Failed to initialized pkcs11 engine" );

			pkey = ENGINE_load_private_key( pkcs11, keyfile, NULL, NULL );
			if (pkey == NULL)
				DO_EXIT_1("Failed to load private key %s", keyfile);
			if ((btmp = BIO_new_file(certfile, "rb")) == NULL ||
				((p7 = d2i_PKCS7_bio(btmp, NULL)) == NULL &&
				 (certs = PEM_read_certs(btmp, "")) == NULL))
				DO_EXIT_1("Failed to read certificate file: %s\n", certfile);
			BIO_free(btmp);
		} else {
			if ((btmp = BIO_new_file(certfile, "rb")) == NULL ||
				((p7 = d2i_PKCS7_bio(btmp, NULL)) == NULL &&
				 (certs = PEM_read_certs(btmp, "")) == NULL))
				DO_EXIT_1("Failed to read certificate file: %s\n", certfile);
			BIO_free(btmp);
			if ((btmp = BIO_new_file(keyfile, "rb")) == NULL ||
				( (pkey = d2i_PrivateKey_bio(btmp, NULL)) == NULL &&
				  (BIO_seek(btmp, 0) == 0) &&
				  (pkey = PEM_read_bio_PrivateKey(btmp, NULL, NULL, pass ? pass : "")) == NULL &&
				  (BIO_seek(btmp, 0) == 0) &&
				  (pkey = PEM_read_bio_PrivateKey(btmp, NULL, NULL, NULL)) == NULL))
				DO_EXIT_1("Failed to read private key file: %s (Wrong password?)\n", keyfile);
			BIO_free(btmp);
		}

		if (xcertfile) {
			if ((btmp = BIO_new_file(xcertfile, "rb")) == NULL ||
				((p7x = d2i_PKCS7_bio(btmp, NULL)) == NULL &&
				 (xcerts = PEM_read_certs(btmp, "")) == NULL))
				DO_EXIT_1("Failed to read cross certificate file: %s\n", xcertfile);
			BIO_free(btmp);
		}

		if (pass) {
			memset (pass, 0, strlen(pass));
			pass = NULL;
	    }
	}

	if (certs == NULL && p7 != NULL)
		certs = p7->d.sign->cert;

	/* Check if indata is cab or pe */
	filesize = get_file_size(infile);
	if (filesize == 0)
		goto err_cleanup;

	indata = map_file(infile, filesize);
	if (indata == NULL)
		DO_EXIT_1("Failed to open file: %s\n", infile);

	fileend = filesize;

	if (!memcmp(indata, "MSCF", 4)) {
		type = FILE_TYPE_CAB;
	} else if (!memcmp(indata, "MZ", 2)) {
		type = FILE_TYPE_PE;
	} else if (!memcmp(indata, msi_signature, sizeof(msi_signature))) {
		type = FILE_TYPE_MSI;
#ifdef WITH_GSF
		gsf_init();
		gsf_initialized = 1;
#endif
	} else {
		DO_EXIT_1("Unrecognized file type: %s\n", infile);
	}

	if (cmd != CMD_SIGN && !(type == FILE_TYPE_PE || type == FILE_TYPE_MSI))
		DO_EXIT_1("Command is not supported for non-PE/non-MSI files: %s\n", infile);

	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, md);

	if (type == FILE_TYPE_CAB) {
		if (filesize < 44)
			DO_EXIT_1("Corrupt cab file - too short: %s\n", infile);
		if (indata[0x1e] != 0x00 || indata[0x1f] != 0x00)
			DO_EXIT_0("Cannot sign cab files with flag bits set!\n"); /* XXX */
	} else if (type == FILE_TYPE_PE) {
		if (filesize < 64)
			DO_EXIT_1("Corrupt DOS file - too short: %s\n", infile);
		peheader = GET_UINT32_LE(indata+60);
		if (filesize < peheader + 160)
			DO_EXIT_1("Corrupt PE file - too short: %s\n", infile);
		if (memcmp(indata+peheader, "PE\0\0", 4))
			DO_EXIT_1("Unrecognized DOS file type: %s\n", infile);
	} else if (type == FILE_TYPE_MSI) {
#ifdef WITH_GSF
		GsfInput *src;
		GsfInfile *ole;

		BIO_push(hash, BIO_new(BIO_s_null()));

		src = gsf_input_stdio_new(infile, NULL);
		if (!src)
			DO_EXIT_1("Error opening file %s", infile);
		ole = gsf_infile_msole_new(src, NULL);

		if (cmd == CMD_EXTRACT) {
			if(output_pkcs7) {
				sig = msi_extract_signature_to_pkcs7(ole);
				if (!sig)
					DO_EXIT_0("Unable to extract existing signature.");
				outdata = BIO_new_file(outfile, "w+b");
				if (outdata == NULL)
					DO_EXIT_1("Unable to open %s\n\n", outfile);
				ret = !PEM_write_bio_PKCS7(outdata, sig);
				BIO_free_all(outdata);
			}
			else
				ret = msi_extract_signature_to_file(ole, outfile);
			goto skip_signing;
		} else if (cmd == CMD_VERIFY) {
			ret = msi_verify_file(ole, leafhash);
			goto skip_signing;
		} else if (cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH) {
				if (nest || cmd == CMD_ADD) {
				// Perform a sanity check for the MsiDigitalSignatureEx section.
				// If the file we're attempting to sign has an MsiDigitalSignatureEx
				// section, we can't add a nested signature of a different MD type
				// without breaking the initial signature.
				{
					unsigned long dselen = 0;
					int has_dse = 0;
					if (msi_extract_dse(ole, NULL, &dselen, &has_dse) != 0 && has_dse) {
						DO_EXIT_0("Unable to extract MsiDigitalSigantureEx section.\n");
					}
					if (has_dse) {
						int mdlen = EVP_MD_size(md);
						if (dselen != (unsigned long)mdlen) {
							DO_EXIT_0("Unable to add nested signature with a different MD type (-h parameter) "
							          "than what exists in the MSI file already. This is due to the presence of "
							          "MsiDigitalSigantureEx (-add-msi-dse parameter).\n");
						}
					}
				}

				cursig = msi_extract_signature_to_pkcs7(ole);
				if (cursig == NULL) {
					DO_EXIT_0("Unable to extract existing signature in -nest mode");
				}
				if (cmd == CMD_ADD) {
					sig = cursig;
				}
			}
		}

		sink = gsf_output_stdio_new(outfile, NULL);
		if (!sink)
			DO_EXIT_1("Error opening output file %s", outfile);
		outole = gsf_outfile_msole_new(sink);

		/*
		 * MsiDigitalSignatureEx is an enhanced signature type that
		 * can be used when signing MSI files.  In addition to
		 * file content, it also hashes some file metadata, specifically
		 * file names, file sizes, creation times and modification times.
		 *
		 * The file content hashing part stays the same, so the
		 * msi_handle_dir() function can be used across both variants.
		 *
		 * When an MsiDigitalSigntaureEx section is present in an MSI file,
		 * the meaning of the DigitalSignature section changes:  Instead
		 * of being merely a file content hash (as what is output by the
		 * msi_handle_dir() function), it is now hashes both content
		 * and metadata.
		 *
		 * Here is how it works:
		 *
		 * First, a "pre-hash" is calculated. This is the "metadata" hash.
		 * It iterates over the files in the MSI in the same order as the
		 * file content hashing method would - but it only processes the
		 * metadata.
		 * 
		 * Once the pre-hash is calculated, a new hash is created for
		 * calculating the hash of the file content.  The output of the
		 * pre-hash is added as the first element of the file content hash.  
		 *
		 * After the pre-hash is written, what follows is the "regular"
		 * stream of data that would normally be written when performing
		 * file content hashing.
		 *
		 * The output of this hash, which combines both metadata and file
		 * content, is what will be output in signed form to the
		 * DigitalSignature section when in 'MsiDigitalSignatureEx' mode.
		 *
		 * As mentioned previously, this new mode of operation is signalled
		 * by the presence of a 'MsiDigitalSignatureEx' section in the MSI
		 * file.  This section must come after the 'DigitalSignature'
		 * section, and its content must be the output of the pre-hash
		 * ("metadata") hash.
		 */
		if (add_msi_dse) {
			BIO *prehash = BIO_new(BIO_f_md());
			BIO_set_md(prehash, md);
			BIO_push(prehash, BIO_new(BIO_s_null()));

			if (!msi_prehash(ole, NULL, prehash))
				DO_EXIT_0("unable to calculate MSI pre-hash ('metadata') hash.\n");

			p_msiex = malloc(EVP_MAX_MD_SIZE);
			len_msiex = BIO_gets(prehash, (char*)p_msiex, EVP_MAX_MD_SIZE);

			BIO_write(hash, p_msiex, len_msiex);
		}

		if (!msi_handle_dir(ole, outole, hash)) {
			DO_EXIT_0("unable to msi_handle_dir()\n");
		}

		if (cmd == CMD_REMOVE) {
			gsf_output_close(GSF_OUTPUT(outole));
			g_object_unref(sink);
		}
#else
		DO_EXIT_1("libgsf is not available, msi support is disabled: %s\n", infile);
#endif
	}

	if (type == FILE_TYPE_CAB || type == FILE_TYPE_PE) {
		if (cmd != CMD_VERIFY) {
			/* Create outdata file */
			outdata = BIO_new_file(outfile, "w+b");
			if (outdata == NULL)
				DO_EXIT_1("Failed to create file: %s\n", outfile);
			BIO_push(hash, outdata);
		}
	}

	if (type == FILE_TYPE_CAB) {
		unsigned short nfolders;

		u_char cabsigned[] = {
			0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
			0xde, 0xad, 0xbe, 0xef, /* size of cab file */
			0xde, 0xad, 0xbe, 0xef, /* size of asn1 blob */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		BIO_write(hash, indata, 4);
		BIO_write(outdata, indata+4, 4);

		tmp = GET_UINT32_LE(indata+8) + 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(hash, buf, 4);

		BIO_write(hash, indata+12, 4);

		tmp = GET_UINT32_LE(indata+16) + 24;
		PUT_UINT32_LE(tmp, buf+4);
		BIO_write(hash, buf+4, 4);

		memcpy(buf+4, indata+20, 14);
		buf[4+10] = 0x04; /* RESERVE_PRESENT */

		BIO_write(hash, buf+4, 14);
		BIO_write(outdata, indata+34, 2);

		memcpy(cabsigned+8, buf, 4);
		BIO_write(outdata, cabsigned, 20);
		BIO_write(hash, cabsigned+20, 4); /* ??? or possibly the previous 4 bytes instead? */

		nfolders = indata[26] | (indata[27] << 8);
		for (i = 36; nfolders; nfolders--, i+=8) {
			tmp = GET_UINT32_LE(indata+i);
			tmp += 24;
			PUT_UINT32_LE(tmp, buf);
			BIO_write(hash, buf, 4);
			BIO_write(hash, indata+i+4, 4);
		}

		/* Write what's left */
		BIO_write(hash, indata+i, filesize-i);
	} else if (type == FILE_TYPE_PE) {
		unsigned int sigpos, siglen, nrvas;
		unsigned short magic;

		if (jp >= 0)
			fprintf(stderr, "Warning: -jp option is only valid "
					"for CAB files.\n");

		magic = GET_UINT16_LE(indata + peheader + 24);
		if (magic == 0x20b) {
			pe32plus = 1;
		} else if (magic == 0x10b) {
			pe32plus = 0;
		} else {
			DO_EXIT_2("Corrupt PE file - found unknown magic %x: %s\n", magic, infile);
		}

		nrvas = GET_UINT32_LE(indata + peheader + 116 + pe32plus*16);
		if (nrvas < 5)
			DO_EXIT_1("Can not handle PE files without certificate table resource: %s\n", infile);

		sigpos = GET_UINT32_LE(indata + peheader + 152 + pe32plus*16);
		siglen = GET_UINT32_LE(indata + peheader + 152 + pe32plus*16 + 4);

		/* Since fix for MS Bulletin MS12-024 we can really assume
		   that signature should be last part of file */
		if (sigpos > 0 && sigpos + siglen != filesize)
			DO_EXIT_1("Corrupt PE file - current signature not at end of file: %s\n", infile);

		if ((cmd == CMD_REMOVE || cmd == CMD_EXTRACT) && sigpos == 0)
			DO_EXIT_1("PE file does not have any signature: %s\n", infile);

		if (cmd == CMD_EXTRACT) {
			/* A lil' bit of ugliness. Reset stream, write signature and skip forward */
			(void)BIO_reset(outdata);
			if(output_pkcs7) {
				sig = extract_existing_pe_pkcs7(indata, peheader, pe32plus, sigpos ? sigpos : fileend, siglen);
				if (!sig)
					DO_EXIT_0("Unable to extract existing signature.");
				PEM_write_bio_PKCS7(outdata, sig);
			}
			else
				BIO_write(outdata, indata + sigpos, siglen);
			goto skip_signing;
		}

		if ((cmd == CMD_SIGN && nest) || (cmd == CMD_ATTACH && nest) || cmd == CMD_ADD) {
			cursig = extract_existing_pe_pkcs7(indata, peheader, pe32plus, sigpos ? sigpos : fileend, siglen);
			if (cursig == NULL) {
				DO_EXIT_0("Unable to extract existing signature in -nest mode");
			}
			if (cmd == CMD_ADD) {
				sig = cursig;
			}
		}

		if (cmd == CMD_VERIFY) {
			ret = verify_pe_file(indata, peheader, pe32plus, sigpos ? sigpos : fileend, siglen, leafhash);
			goto skip_signing;
		}

		if (sigpos > 0) {
			/* Strip current signature */
			fileend = sigpos;
		}

		BIO_write(hash, indata, peheader + 88);
		i = peheader + 88;
		memset(buf, 0, 4);
		BIO_write(outdata, buf, 4); /* zero out checksum */
		i += 4;
		BIO_write(hash, indata + i, 60+pe32plus*16);
		i += 60+pe32plus*16;
		memset(buf, 0, 8);
		BIO_write(outdata, buf, 8); /* zero out sigtable offset + pos */
		i += 8;

		BIO_write(hash, indata + i, fileend - i);

		/* pad (with 0's) pe file to 8 byte boundary */
		len = 8 - fileend % 8;
		if (len > 0 && len != 8) {
			memset(buf, 0, len);
			BIO_write(hash, buf, len);
			fileend += len;
		}
	}

	if (cmd == CMD_ADD)
		goto add_only;

	if(cmd == CMD_ATTACH)
	{
		const char pemhdr[] = "-----BEGIN PKCS7-----";
		sigfilesize = get_file_size(sigfile);
		if(!sigfilesize)
			goto err_cleanup;
		insigdata = map_file(sigfile, sigfilesize);
		if (insigdata == NULL)
			DO_EXIT_1("Failed to open file: %s\n", infile);

		if (sigfilesize >= sizeof(pemhdr) && !memcmp(insigdata, pemhdr, sizeof(pemhdr)-1))
		{
			sigbio = BIO_new_mem_buf(insigdata, sigfilesize);
			sig = PEM_read_bio_PKCS7(sigbio, NULL, NULL, NULL);
			BIO_free_all(sigbio);
		}
		else {
			if (type == FILE_TYPE_PE) {
				sig = extract_existing_pe_pkcs7(insigdata, peheader, pe32plus, 0, sigfilesize);
			}
			else if (type == FILE_TYPE_MSI) {
#ifdef WITH_GSF
				const unsigned char *p = (unsigned char*)insigdata;
				sig = d2i_PKCS7(NULL, &p, sigfilesize);
#else
	                        DO_EXIT_1("libgsf is not available, msi support is disabled: %s\n", infile);
#endif
			}
		}
		if (!sig)
			DO_EXIT_0("No valid signature found.");
		goto add_only;
	}

	if (cmd != CMD_SIGN)
		goto skip_signing;

	sig = PKCS7_new();
	PKCS7_set_type(sig, NID_pkcs7_signed);

	si = NULL;
	if (cert != NULL)
		si = PKCS7_add_signature(sig, cert, pkey, md);
	if (si == NULL) {
		for (i=0; i<sk_X509_num(certs); i++) {
			X509 *signcert = sk_X509_value(certs, i);
			/* X509_print_fp(stdout, signcert); */
			si = PKCS7_add_signature(sig, signcert, pkey, md);
			if (si != NULL) break;
		}
	}
	EVP_PKEY_free(pkey);
	pkey = NULL;

	if (si == NULL)
		DO_EXIT_0("Signing failed(PKCS7_add_signature)\n");

	PKCS7_add_signed_attribute
		(si, NID_pkcs9_contentType,
		 V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1));

	if (type == FILE_TYPE_CAB && jp >= 0) {
		const u_char *attrs = NULL;
		static const u_char java_attrs_low[] = {
			0x30, 0x06, 0x03, 0x02, 0x00, 0x01, 0x30, 0x00
		};

		switch (jp) {
			case 0:
				attrs = java_attrs_low;
				len = sizeof(java_attrs_low);
				break;
			case 1:
				/* XXX */
			case 2:
				/* XXX */
			default:
				break;
		}

		if (attrs) {
			astr = ASN1_STRING_new();
			ASN1_STRING_set(astr, attrs, len);
			PKCS7_add_signed_attribute
				(si, OBJ_txt2nid(SPC_MS_JAVA_SOMETHING),
				 V_ASN1_SEQUENCE, astr);
		}
	}

	astr = ASN1_STRING_new();
	if (comm) {
		ASN1_STRING_set(astr, purpose_comm, sizeof(purpose_comm));
	} else {
		ASN1_STRING_set(astr, purpose_ind, sizeof(purpose_ind));
	}
	PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_STATEMENT_TYPE_OBJID),
							   V_ASN1_SEQUENCE, astr);

	if (desc || url) {
		SpcSpOpusInfo *opus = createOpus(desc, url);
		if ((len = i2d_SpcSpOpusInfo(opus, NULL)) <= 0 ||
			(p = OPENSSL_malloc(len)) == NULL)
			DO_EXIT_0("Couldn't allocate memory for opus info\n");
		i2d_SpcSpOpusInfo(opus, &p);
		p -= len;
		astr = ASN1_STRING_new();
		ASN1_STRING_set(astr, p, len);
		OPENSSL_free(p);

		PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_SP_OPUS_INFO_OBJID),
								   V_ASN1_SEQUENCE, astr);

		SpcSpOpusInfo_free(opus);
	}

	PKCS7_content_new(sig, NID_pkcs7_data);

	if (cert != NULL) {
		PKCS7_add_certificate(sig, cert);
		X509_free(cert);
		cert = NULL;
	}
	if (xcerts) {
		for(i = sk_X509_num(xcerts)-1; i>=0; i--)
			PKCS7_add_certificate(sig, sk_X509_value(xcerts, i));
	}
	for(i = sk_X509_num(certs)-1; i>=0; i--)
		PKCS7_add_certificate(sig, sk_X509_value(certs, i));

	if (p7 == NULL || certs != p7->d.sign->cert) {
		sk_X509_free(certs);
		certs = NULL;
	}
	if (p7) {
		PKCS7_free(p7);
		p7 = NULL;
	}
	if (xcerts) {
		sk_X509_free(xcerts);
		xcerts = NULL;
	}
	if (p7x) {
		PKCS7_free(p7x);
		p7x = NULL;
	}

	get_indirect_data_blob(&p, &len, md, type, pagehash, indata, peheader, pe32plus, fileend);
	len -= EVP_MD_size(md);
	memcpy(buf, p, len);
	OPENSSL_free(p);
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen = BIO_gets(hash, (char*)mdbuf, EVP_MAX_MD_SIZE);
	memcpy(buf+len, mdbuf, mdlen);
	int seqhdrlen = asn1_simple_hdr_len((unsigned char*)buf, len);

	if ((sigbio = PKCS7_dataInit(sig, NULL)) == NULL)
		DO_EXIT_0("Signing failed(PKCS7_dataInit)\n");
	BIO_write(sigbio, buf+seqhdrlen, len-seqhdrlen+mdlen);
	(void)BIO_flush(sigbio);

	if (!PKCS7_dataFinal(sig, sigbio))
		DO_EXIT_0("Signing failed(PKCS7_dataFinal)\n");
	BIO_free_all(sigbio);

	/* replace the data part with the MS Authenticode
	   spcIndirectDataContext blob */
	PKCS7 *td7 = PKCS7_new();
	td7->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	td7->d.other = ASN1_TYPE_new();
	td7->d.other->type = V_ASN1_SEQUENCE;
	td7->d.other->value.sequence = ASN1_STRING_new();
	ASN1_STRING_set(td7->d.other->value.sequence, buf, len+mdlen);
	PKCS7_set_content(sig, td7);

add_only:

#ifdef ENABLE_CURL
	/* add counter-signature/timestamp */
	if (nturl && add_timestamp_authenticode(sig, turl, nturl, proxy, noverifypeer))
		DO_EXIT_0("authenticode timestamping failed\n");
	if (ntsurl && add_timestamp_rfc3161(sig, tsurl, ntsurl, proxy, md, noverifypeer))
		DO_EXIT_0("RFC 3161 timestamping failed\n");
#endif

	if (addBlob && add_unauthenticated_blob(sig))
		DO_EXIT_0("Adding unauthenticated blob failed\n");


#if 0
	if (!PEM_write_PKCS7(stdout, sig))
		DO_EXIT_0("PKCS7 output failed\n");
#endif

	if (nest) {
		if (cursig == NULL) {
			DO_EXIT_0("no 'cursig' was extracted. this points to a bug in the code. aborting...\n")
		}
		if (pkcs7_set_nested_signature(cursig, sig) == 0)
			DO_EXIT_0("unable to append the nested signature to the current signature\n");
		outsig = cursig;
	} else {
		outsig = sig;
	}

	/* Append signature to outfile */
	if (((len = i2d_PKCS7(outsig, NULL)) <= 0) ||
		(p = OPENSSL_malloc(len)) == NULL)
		DO_EXIT_1("i2d_PKCS - memory allocation failed: %d\n", len);
	i2d_PKCS7(outsig, &p);
	p -= len;
	padlen = (8 - len%8) % 8;

	if (type == FILE_TYPE_PE) {
		PUT_UINT32_LE(len+8+padlen, buf);
		PUT_UINT16_LE(WIN_CERT_REVISION_2, buf + 4);
		PUT_UINT16_LE(WIN_CERT_TYPE_PKCS_SIGNED_DATA, buf + 6);
		BIO_write(outdata, buf, 8);
	}

	if (type == FILE_TYPE_PE || type == FILE_TYPE_CAB) {
		BIO_write(outdata, p, len);

		/* pad (with 0's) asn1 blob to 8 byte boundary */
		if (padlen > 0) {
			memset(p, 0, padlen);
			BIO_write(outdata, p, padlen);
		}
#ifdef WITH_GSF
	} else if (type == FILE_TYPE_MSI) {
		/* Only output signatures if we're signing. */
		if (cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH) {
			GsfOutput *child = gsf_outfile_new_child(outole, "\05DigitalSignature", FALSE);
			if (!gsf_output_write(child, len, p))
				DO_EXIT_1("Failed to write MSI 'DigitalSignature' signature to %s", infile);
			gsf_output_close(child);

			if (p_msiex != NULL) {
				child = gsf_outfile_new_child(outole, "\05MsiDigitalSignatureEx", FALSE);
				if (!gsf_output_write(child, len_msiex, p_msiex)) {
					DO_EXIT_1("Failed to write MSI 'MsiDigitalSignatureEx' signature to %s", infile);
				}
				gsf_output_close(child);
			}

			gsf_output_close(GSF_OUTPUT(outole));
			g_object_unref(sink);
		}
#endif
	}

	PKCS7_free(sig);
	OPENSSL_free(p);

skip_signing:

	if (type == FILE_TYPE_PE) {
		if (cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH) {
			/* Update signature position and size */
			(void)BIO_seek(outdata, peheader+152+pe32plus*16);
			PUT_UINT32_LE(fileend, buf); /* Previous file end = signature table start */
			BIO_write(outdata, buf, 4);
			PUT_UINT32_LE(len+8+padlen, buf);
			BIO_write(outdata, buf, 4);
		}
		if (cmd == CMD_SIGN || cmd == CMD_REMOVE || cmd == CMD_ADD || cmd == CMD_ATTACH)
			recalc_pe_checksum(outdata, peheader);
	} else if (type == FILE_TYPE_CAB) {
		(void)BIO_seek(outdata, 0x30);
		PUT_UINT32_LE(len+padlen, buf);
		BIO_write(outdata, buf, 4);
	}

	BIO_free_all(hash);
	hash = outdata = NULL;

	if (cmd == CMD_ATTACH) {
		if (type == FILE_TYPE_PE) {
			outdatasize = get_file_size(outfile);
			if (!outdatasize)
				DO_EXIT_0("Error verifying result.\n");
			outdataverify = map_file(outfile, outdatasize);
			if (!outdataverify)
				DO_EXIT_0("Error verifying result.\n");
			int sigpos = GET_UINT32_LE(outdataverify + peheader + 152 + pe32plus*16);
			int siglen = GET_UINT32_LE(outdataverify + peheader + 152 + pe32plus*16 + 4);
			ret = verify_pe_file(outdataverify, peheader, pe32plus, sigpos, siglen, leafhash);
			if (ret) {
				DO_EXIT_0("Signature mismatch.\n");
			}
		}
		else if (type == FILE_TYPE_MSI)
		{
#ifdef WITH_GSF
			GsfInput *src;
			GsfInfile *ole;

			src = gsf_input_stdio_new(outfile, NULL);
			if (!src)
				DO_EXIT_1("Error opening file %s", outfile);
			ole = gsf_infile_msole_new(src, NULL);
			g_object_unref(src);
			ret = msi_verify_file(ole, leafhash);
			g_object_unref(ole);
			if (ret) {
				DO_EXIT_0("Signature mismatch.\n");
			}
#else
			DO_EXIT_1("libgsf is not available, msi support is disabled: %s\n", infile);
#endif
		}
		else
		{
			DO_EXIT_1("Unknown input type for file: %s\n", infile);
		}
		printf("Signature successfully attached.\n");
	}
        else
		printf(ret ? "Failed\n" : "Succeeded\n");
	cleanup_lib_state();

	return ret;

err_cleanup:
	if (pass) {
		memset (pass, 0, strlen(pass));
		pass = NULL;
	}
	ERR_print_errors_fp(stderr);
	if (certs && (p7 == NULL || certs != p7->d.sign->cert))
		sk_X509_free(certs);
	if (p7)
		PKCS7_free(p7);
	if (p7x)
		PKCS7_free(p7x);
	if (xcerts)
		sk_X509_free(xcerts);
	if (cert)
		X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (hash)
		BIO_free_all(hash);
	if (outfile)
		unlink(outfile);
	fprintf(stderr, "\nFailed\n");
	cleanup_lib_state();
	return -1;
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 :
*/
