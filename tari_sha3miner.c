/******************************************************************************
filename    tari_sha3miner.c
author      Blue, The Tari Developer Community
git-hub     
GCC         gcc -Werror (-O0 or -Ofast) -Wall -Wextra -ansi tari_sha3miner.c -lssl
            -lcrypto -o tari_sha3miner
Brief Description:
  C port of Tari's Sha3 miner.
******************************************************************************/
#include <stdio.h>
#include <openssl/evp.h>

/* Define 64 bit unsigned integer */
typedef unsigned long long int u64;

/* Define 8 bit unsigned integer */
typedef unsigned char u8;

/* Define 32 bit unsigned integer */
typedef unsigned long int u32;

/* Define Difficulty */
typedef unsigned long long int Difficulty;

/* Define ProofOfWork */
struct proofofwork
{
  u64 pow_algo;
  u64 accumulated_monero_difficulty;
  u64 accumulated_blake_difficulty;
  char pow_data;
  u64 target_difficulty;
};
typedef struct proofofwork ProofOfWork;

/* Define BlockHeader */
struct blockheader
{
  u64 nonce;
  u32 version;
  u64 height;
  char prev_hash;
  u64 timestamp;
  char output_mr;
  char range_proof_mr;
  char kernel_mr;
  char total_kernel_offset;
  ProofOfWork pow;
};
typedef struct blockheader BlockHeader;

/* Memory representation of u32 as a byte array in little-endian */
void u32_ByteArrayLE(u32 x, u8 *byteArray)
{

  byteArray[0] = x;
  byteArray[1] = x>>8;
  byteArray[2] = x>>16;
  byteArray[3] = x>>24;
}

/* Memory representation of u64 as a byte array in little-endian */
void u64_ByteArrayLE(u64 x, u8 *byteArray)
{

  byteArray[0] = x;
  byteArray[1] = x>>8;
  byteArray[2] = x>>16;
  byteArray[3] = x>>24;

  byteArray[4] = x>>32;
  byteArray[5] = x>>40;
  byteArray[6] = x>>48;
  byteArray[7] = x>>56;
}

/* Convert from byte array to u64 */
void ByteArrayLE_u64(u8 *byteArray, u64 *x)
{
  *x = (u64)byteArray[0] | ((u64)byteArray[1]<<8) | ((u64)byteArray[2]<<16) | ((u64)byteArray[3]<<24)
  | ((u64)byteArray[4]<<32) | ((u64)byteArray[5]<<40) | ((u64)byteArray[6]<<48) | ((u64)byteArray[7]<<56);
}

/* Sha3 hasher */
void sha3_hash(BlockHeader const *header, u8 * digest)
{
  EVP_MD_CTX *ctx;
  ctx = EVP_MD_CTX_new();
  EVP_DigestInit(ctx, EVP_sha3_256());

  u8 byteArray_u32[3];
  u8 byteArray_u64[7];
  unsigned int shalength;

  u32_ByteArrayLE(header->version, byteArray_u32);
  EVP_DigestUpdate(ctx, byteArray_u32, sizeof(byteArray_u32) / sizeof(byteArray_u32[0]));

  u64_ByteArrayLE(header->height, byteArray_u64);
  EVP_DigestUpdate(ctx, byteArray_u64, sizeof(byteArray_u64) / sizeof(byteArray_u64[0]));

  EVP_DigestUpdate(ctx, &header->prev_hash, sizeof(header->prev_hash));

  u64_ByteArrayLE(header->timestamp, byteArray_u64);
  EVP_DigestUpdate(ctx, byteArray_u64, sizeof(byteArray_u64) / sizeof(byteArray_u64[0]));

  EVP_DigestUpdate(ctx, &header->output_mr, sizeof(header->output_mr));

  EVP_DigestUpdate(ctx, &header->range_proof_mr, sizeof(header->range_proof_mr));

  EVP_DigestUpdate(ctx, &header->kernel_mr, sizeof(header->kernel_mr));

  EVP_DigestUpdate(ctx, &header->total_kernel_offset, sizeof(header->total_kernel_offset));

  u64_ByteArrayLE(header->nonce, byteArray_u64);
  EVP_DigestUpdate(ctx, byteArray_u64, sizeof(byteArray_u64) / sizeof(byteArray_u64[0]));

  EVP_DigestUpdate(ctx, &header->pow, sizeof(header->pow));

  EVP_DigestFinal(ctx, digest, &shalength);

  EVP_MD_CTX_free(ctx);
}

/* Sha3 difficulty */
Difficulty sha3_difficulty_with_hash(BlockHeader const *header)
{
  u8 hash[7];
  u64 scalar;
  const u64 MAX_TARGET = (u64)-1;
  
  sha3_hash(header, hash);
  ByteArrayLE_u64(hash, &scalar);
  /* Rust functions have the ability to return multiple values, pretty cool! */
  /* We won't be using that here for now */
  return MAX_TARGET / scalar;
}

/* Sha3 difficulty helper function */
Difficulty sha3_difficulty(BlockHeader const *header)
{
  return sha3_difficulty_with_hash(header);
}

/* Sha3 miner */
u64 mine_sha3(Difficulty target_difficulty, BlockHeader *header)
{
  /* Starts the nonce at 0 */
  header->nonce = 0;
  
  /* We're mining over here! */

  /* Iterates until a header hash is found that meets desired target block */
  while(sha3_difficulty(header) < target_difficulty)
  {
    header->nonce += 1;
  }

  /* Return nonce*/
  return header->nonce;
}

/* Start */
int main(void)
{
  BlockHeader *header = {0};
  ProofOfWork pow = {0};
  
  pow.pow_algo = 1;
  pow.accumulated_monero_difficulty = 2;
  pow.accumulated_blake_difficulty = 3;
  pow.pow_data = 4;
  pow.target_difficulty = 5;

  header->nonce = 10;
  header->version = 2;
  header->height = 3;
  header->prev_hash = 4;
  header->timestamp = 5;
  header->output_mr = 6;
  header->range_proof_mr = 7;
  header->kernel_mr = 8;
  header->total_kernel_offset = 9;
  header->pow = pow;
  
  printf("%I64d", mine_sha3(5, header));
  
  
  /* Returns successfully to OS */
  return 0;
}