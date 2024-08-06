#include <stdlib.h>
#include <sys/stat.h>

#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/pkcs12.h>
#include <openssl/pem.h>

// /* An object used to store the ASN1 data fields that will be signed */
// typedef struct MySignInfoObject_st
// {
//     ASN1_INTEGER *version;
//     X509_ALGOR sig_alg;
// } MySignInfoObject;

// DECLARE_ASN1_FUNCTIONS(MySignInfoObject)
// /*
// * A higher level object containing the ASN1 fields, signature alg and
// * output signature.
// */
// typedef struct MyObject_st
// {
//     MySignInfoObject info;
//     X509_ALGOR sig_alg;
//     ASN1_BIT_STRING *signature;
// } MyObject;

// DECLARE_ASN1_FUNCTIONS(MyObject)

// /* The ASN1 definition of MySignInfoObject */
// ASN1_SEQUENCE_cb(MySignInfoObject, NULL) = {
//     ASN1_SIMPLE(MySignInfoObject, version, ASN1_INTEGER),
//     ASN1_EMBED(MySignInfoObject, sig_alg, X509_ALGOR)
// } ASN1_SEQUENCE_END_cb(MySignInfoObject, MySignInfoObject)

// /* new, free, d2i & i2d functions for MySignInfoObject */
// IMPLEMENT_ASN1_FUNCTIONS(MySignInfoObject)

// /* The ASN1 definition of MyObject */
// ASN1_SEQUENCE_cb(MyObject, NULL) = {
//     ASN1_EMBED(MyObject, info, MySignInfoObject),
//     ASN1_EMBED(MyObject, sig_alg, X509_ALGOR),
//     ASN1_SIMPLE(MyObject, signature, ASN1_BIT_STRING)
// } ASN1_SEQUENCE_END_cb(MyObject, MyObject)

// /* new, free, d2i & i2d functions for MyObject */
// IMPLEMENT_ASN1_FUNCTIONS(MyObject)

// const char *rsa_private_key = "-----BEGIN PRIVATE KEY-----\n" \
// "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCxNzEszuHXupeu\n" \
// "MQih9TTUwlSSx5sjSFtBzxPmZRxNagsVXOUBO60H9TiqfMO4N/Gu6PeRwIUqRtSg\n" \
// "uenLmYWWmQuN5K/X2uFFuSJbIVY41q5ZjG1Yp00nJEigXn75bGRMj9WCAZOdws/U\n" \
// "ydp3XZOogGMPXdslvTpujj4I1IO6hhW5wSuagvQwFJxvglEXcqMVoz+HxNorFMxt\n" \
// "yq9H0fiZdsypH8CrLQ/DljaC6zmbNRV7sYiajRh5HX44RpCq0gw0tyJqFsnbK9H7\n" \
// "v1C0ce6VQSquaQuXU7xyKACGP7B9/v5fR5ecUJby1jB4XTpc0T/8tedomTXY8oQR\n" \
// "FMl7f/jRAgMBAAECggEABQbewzmfGGJ3mP5VE1sEQ6C7i2pUET0lMYmxM9Dca6m9\n" \
// "ZL681DsgHmCrWdKuLpSPq3l6RE0kud1GfMSpSBgzvODcfgrlngbcawDkY5dffb9B\n" \
// "NNMR6vjb7GdQFBR6H5MeiTlvQf/PcyMqiAutwcMKxDXYGYB9DeX/OVGZmuCEWA8X\n" \
// "gJVKTRSaEVlZX7UwSW4y3r2YKbuSprZsd4KXapleIDnphh2e0G1EDtkJ7p+GM+vW\n" \
// "sPpszX5eIgmI4zo/BHhqgEu+6I3qYAPq/tDT0wAF2x1E1NoPMxzWHBV3+p6lrno0\n" \
// "e/1L+Sdwtu1tupaeqUP8A/A9jISDzhGo+YfSTvFN7QKBgQDnbV70jeYTvvYmSEMQ\n" \
// "0XHLQFxIdwNVBnK+c+v73CZzGWHbURCAfHbLsgYCLQu4WQrBjiIumeG6B9W82FEe\n" \
// "7bJoDJPtz1Gjf6LUKURFWGQUnqZ959Y5hDCrbdErepF7RI4s8NTTb1iOPMgc5ZiO\n" \
// "gw/2FQJ/vQfvYNGSYQeG2C3bbwKBgQDECD8dhawBFeYKC1o+H2DI1MzUuyM9ftJd\n" \
// "lKVsnLlUiDOMZlyDynL/ViD3YI0t4i1F6CxejuYVifnSnwLEraP7pC3H6UnF1V3j\n" \
// "JLeMR0f79Vj+1VLHcpBgWRaDgpMJsPy8MpNFSLqiV9e6nH9enKlJ6mt0PCcOwTAW\n" \
// "BDg/XY5PvwKBgFejcVwHCGPd4vUoVE1gI0mm+8ttVlOyd21sFKdx/RWFPSuCjU86\n" \
// "0vncVq4oRNHw1kPqAUPIflSmduhmuoGN3gvNB4/8/Jt/0Der0PC5wlyUn9P6IYPy\n" \
// "bUPd+GIQrlsR4Q1fvhi7h7uFhPp8b8M4GqlD14hsGz8pWPOnzuPfpa39AoGAdeu8\n" \
// "A8dIK7L/mSUxGNOJReX0fTdBQJnMc6yaQhaYyYfQ8nEUz9Z1jLFDzWtQIby/nSDH\n" \
// "p+3v7B7+n7s1UBhf31zoiSwFS7NI8f1BSGoMnDz/VvP+AqogvUR57YwbZSYJMjB+\n" \
// "NJxGYKfUxpWjbMdycltIXjhdClwdz/Cj4UIm/EMCgYAsjhxJ5gosgO3F4gGvmGx2\n" \
// "sck7LxNJqfZoDYEmd4Sm1tndpvcVRQSVoWQ5UuICrCftMMR2Kn725/5neSYzcIOD\n" \
// "kj2gLWgH/xs/mYW+euTgdvhKiupgqTb82NRF/WDpPAmbEGQZIGdw+UL9x8vRcNwg\n" \
// "rKjjml++r2SkZPn/K+H4NQ==\n" \
// "-----END PRIVATE KEY-----";

// EVP_PKEY *read_pkey_from_memory(const char *pkey_buf, int buf_len){
//     EVP_PKEY *pkey = NULL;
//     BIO *bufio;

//     bufio = BIO_new_mem_buf((void*)pkey_buf, buf_len);
//     pkey = PEM_read_bio_PrivateKey(bufio, NULL, NULL, NULL);
//     if (!pkey){
//         fprintf(stderr, "%s:%d: PEM_read_PrivateKey...FAILED\n", __FILE__, __LINE__);
//         goto err;
//     }

//     fprintf(stderr, "%s:%d: PEM_read_PrivateKey...SUCCESS\n", __FILE__, __LINE__);
// err:
//     BIO_free(bufio);
    
//     return pkey;
// }

// static EVP_PKEY *pkey = NULL;
// static EVP_MD_CTX *vctx = NULL;


int FuzzerInitialize(int *argc, char ***argv)
{
    // char* tmp = "700101000000Z";
    // ASN1_TIME t1 = {.data = (unsigned char*)tmp, .length = strlen(tmp), .type = V_ASN1_UTCTIME, .flags = 0};
    // tmp = "380119031407Z";
    // ASN1_TIME t2 = {.data = (unsigned char*)tmp, .length = strlen(tmp), .type = V_ASN1_UTCTIME, .flags = 0};
    // tmp = "9912310000-0000";
    // ASN1_TIME t3 = {.data = (unsigned char*)tmp, .length = strlen(tmp), .type = V_ASN1_UTCTIME, .flags = 0};
    // tmp = "19700101000000Z";
    // ASN1_TIME t4 = {.data = (unsigned char*)tmp, .length = strlen(tmp), .type = V_ASN1_UTCTIME, .flags = 0};
    // tmp = "20371231235959Z";
    // ASN1_TIME tBad2 = {.data = (unsigned char*)tmp, .length = strlen(tmp), .type = V_ASN1_UTCTIME, .flags = 0};


    // ASN1_TIME init[] = {t1, t2, t3, t4, tBad2};

    // for (int i = 0; i < sizeof(init) / sizeof(init[0]); i++) {
    //     char name[100] = "/home/user/Documents/opensslAll/my/openssl/fuzz/corpora/asn1_time_to_generalizedtime/init";
    //     sprintf(name + strlen("/home/user/Documents/opensslAll/my/openssl/fuzz/corpora/asn1_time_to_generalizedtime/init"), "%d", i);
    //     FILE* f = fopen(name, "wb");
    //     if (!f) printf("suka, pizdez\n");
    //     unsigned char *p = NULL;
    //     int ret = i2d_ASN1_TIME(init + i, &p);
    //     if (ret <= 0) printf("suka, pizdez 1\n");
    //     fwrite(p, sizeof(p[0]), ret, f);
    //     fclose(f);
    // }

    // ASN1_TIME* init[5];
    // for (int i = 0; i < 5; i++) {
    //     char name[100] = "/home/user/Documents/opensslAll/my/openssl/fuzz/corpora/asn1_time_to_generalizedtime/init";
    //     sprintf(name + strlen("/home/user/Documents/opensslAll/my/openssl/fuzz/corpora/asn1_time_to_generalizedtime/init"), "%d", i);
    //     FILE* f = fopen(name,"rb");
    //     if (!f) printf("suka, pizdez\n");
    //     unsigned char buf[100];
    //     size_t s = fread(buf, 1, 100, f);
    //     if (!s) printf("suka, pizdez 1\n");
    //     unsigned char* pbuf = &buf;
    //     init[i] = d2i_ASN1_TIME(NULL, &pbuf, s);
    //     if (!init[i]) printf("suka, pizdez 1\n");
    //     fclose(f);
    // }




    // pkey = read_pkey_from_memory(rsa_private_key, strlen(rsa_private_key));
    // if (!pkey){
    //     return 1;
    // }

    // vctx = EVP_MD_CTX_new();
    // if (vctx == NULL
    //     || !EVP_DigestVerifyInit_ex(vctx, NULL, OSSL_DIGEST_NAME_SHA3_512, NULL, NULL, pkey, NULL)){
    //     return 1;
    // }

    return 0;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len){
    // int ret = 0;
    // const unsigned char *p = NULL;
    // MyObject *loaded_obj = NULL;
    // const ASN1_ITEM *it = ASN1_ITEM_rptr(MySignInfoObject);

    // p = buf;
    // loaded_obj = d2i_MyObject(NULL, &p, len);
    // if (loaded_obj == NULL){
    //     return 1;
    // }

    // ret = ASN1_item_verify_ctx(it, &loaded_obj->sig_alg, loaded_obj->signature,
    //                             &loaded_obj->info, vctx);

    // MyObject_free(loaded_obj);
    ASN1_TIME* it = d2i_ASN1_TIME(NULL, (const unsigned char **)&buf, len);

    ASN1_TIME* genTime = ASN1_TIME_to_generalizedtime(it, NULL);
    ASN1_TIME_free(genTime);
    ASN1_TIME_free(it);
    return 0;
}

void FuzzerCleanup(void){
}