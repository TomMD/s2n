/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "tls/s2n_kem.h"
#include "tests/unit/s2n_nist_kats.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

/*
 * These values are taken from BIKE which currently uses the most memory. These may need to be raised when new PQ KEMS
 * are added.
 */
#define MAX_PRIVATE_KEY_LENGTH  4670
#define MAX_PUBLIC_KEY_LENGTH  2542
#define MAX_CIPHERTEXT_LENGTH 2542
#define MAX_SHARED_SECRET_LENGTH 32
#define MAX_SEED_LENGTH 48
uint8_t kat_entropy_buff[MAX_SEED_LENGTH] = {0};
struct s2n_blob kat_entropy_blob = {.size = 48, .data = kat_entropy_buff};

int kat_entropy(struct s2n_blob *blob)
{
    eq_check(blob->size, kat_entropy_blob.size);
    blob->data = kat_entropy_blob.data;
    return 0;
}

int s2n_test_kem_with_kat(const struct s2n_kem *kem, const char *kat_file_name)
{
    notnull_check(kem);
    lte_check(kem->public_key_length, MAX_PUBLIC_KEY_LENGTH);
    lte_check(kem->private_key_length, MAX_PRIVATE_KEY_LENGTH);
    lte_check(kem->ciphertext_length, MAX_CIPHERTEXT_LENGTH);
    lte_check(kem->shared_secret_key_length, MAX_SHARED_SECRET_LENGTH);

    FILE *kat_file = fopen(kat_file_name, "r");
    notnull_check(kat_file);

    int count = 0;

    /* Client side variables */
    uint8_t ct[MAX_CIPHERTEXT_LENGTH];
    uint8_t client_shared_secret[MAX_SHARED_SECRET_LENGTH];

    /* Server side variables */
    uint8_t pk[MAX_PUBLIC_KEY_LENGTH];
    uint8_t sk[MAX_PRIVATE_KEY_LENGTH];
    uint8_t server_shared_secret[MAX_SHARED_SECRET_LENGTH];

    /* Known answer variables */
    uint8_t pk_answer[MAX_PUBLIC_KEY_LENGTH];
    uint8_t sk_answer[MAX_PRIVATE_KEY_LENGTH];
    uint8_t ct_answer[MAX_CIPHERTEXT_LENGTH];
    uint8_t ss_answer[MAX_SHARED_SECRET_LENGTH];

    s2n_stack_blob(persoanlization_string, 48, 48);

    for (uint32_t i = 0; i < NUM_OF_KATS; i++) {
        /* Verify test index */
        GUARD(FindMarker(kat_file, "count = "));
        gt_check(fscanf(kat_file, "%d", &count), 0);
        eq_check(count, i);

        /* Set the NIST rng to the same state the response file was created with */
        GUARD(ReadHex(kat_file, kat_entropy_blob.data, 48, "seed = "));
        struct s2n_drbg kat_drbg = {.entropy_generator = kat_entropy};
        GUARD(s2n_drbg_instantiate(&kat_drbg, &persoanlization_string, S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR));
        GUARD(s2n_set_private_drbg_for_test(kat_drbg));

        /* Generate the public/private key pair */
        GUARD(kem->generate_keypair(pk, sk));

        /* Create a shared secret and use the public key to encrypt it */
        GUARD(kem->encapsulate(ct, client_shared_secret, pk));

        /* Use the private key to decrypt the ct to get the shared secret */
        GUARD(kem->decapsulate(server_shared_secret, ct, sk));

        /* Read the KAT values */
        GUARD(ReadHex(kat_file, pk_answer, kem->public_key_length, "pk = "));
        GUARD(ReadHex(kat_file, sk_answer, kem->private_key_length, "sk = "));
        GUARD(ReadHex(kat_file, ct_answer, kem->ciphertext_length, "ct = "));
        GUARD(ReadHex(kat_file, ss_answer, kem->shared_secret_key_length, "ss = "));

        /* Test the client and server got the same value */
        eq_check(memcmp( client_shared_secret, server_shared_secret, kem->shared_secret_key_length ), 0);

        /* Compare the KAT values */
        eq_check(memcmp(pk_answer, pk, kem->shared_secret_key_length), 0);
        eq_check(memcmp(sk_answer, sk, kem->shared_secret_key_length), 0);
        eq_check(memcmp(ct_answer, ct, kem->shared_secret_key_length), 0);
        eq_check(memcmp(ss_answer, server_shared_secret, kem->shared_secret_key_length ), 0);
    }
    fclose(kat_file);

    return 0;
}
