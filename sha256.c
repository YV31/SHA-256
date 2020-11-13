#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

// Functions
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define ROTL(x, n) ((x << n) | (x >> (32 - n)))
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))
#define USIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define USIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define NUM_OF_BLOCKS(x) (((x + 511) - ((x + 511) % 512)) / 512)

// Constants
const uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t bytes_to_32bits(uint8_t *bytes, uint start)
{
  uint32_t val = 0;
  for (uint i = start; i < start + 4; i++) {
    val |= (bytes[i] & 0xff) << 8 * (3 - i);
  }
  return val;
}

uint32_t *compression_sha256(uint8_t *block, uint32_t *hash)
{
  // Schedule {{{
  uint32_t w[64];

  // Clear schedule
  for (uint i = 0; i < 64; i++) {
    w[i] = 0L;
  }

  // Add chunk
  for (uint i = 0; i < 16; i++) {
    w[i] = bytes_to_32bits(block, i * 4);
  }

  // Extend schedule
  for (uint i = 16; i < 64; i++) {
    w[i] = w[i - 16] + SIG0(w[i - 15]) + w[i - 7] + SIG1(w[i - 2]);
  }

  // }}}

  // Compression {{{
  
  // Initialized working variables
  uint32_t a = hash[0];
  uint32_t b = hash[1];
  uint32_t c = hash[2];
  uint32_t d = hash[3];
  uint32_t e = hash[4];
  uint32_t f = hash[5];
  uint32_t g = hash[6];
  uint32_t h = hash[7];
  
  // Compression function loop
  for (uint i = 0; i < 64; i++) {
    uint32_t t1 = h + USIG1(e) + CH(e, f, g) + K[i] + w[i];
    uint32_t t2 = USIG0(a) + MAJ(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  
  // Compute hash values
  hash[0] += a;
  hash[1] += b;
  hash[2] += c;
  hash[3] += d;
  hash[4] += e;
  hash[5] += f;
  hash[6] += g;
  hash[7] += h;

  // }}}
  
  return hash;
}

uint8_t **preprocessing_sha256(char *message)
{
  // Message Info {{{

  size_t message_len = strlen(message);
  uint64_t message_len_bits = message_len * 8;
  size_t num_of_blocks = NUM_OF_BLOCKS(message_len_bits + 64 + 8);

  // }}}

  // Padding {{{

  uint8_t M[64 * num_of_blocks];

  // Clear Message buffer
  for (size_t i = 0; i < 64 * num_of_blocks; i++) {
    M[i] = 0;
  }

  // Append message
  strcat((char *) M, message);

  // Append one bit
  M[message_len] = 0x80;

  // Add message length in bits
  for (size_t i = 0; i < 8; i++) {
    M[(64 * num_of_blocks - 1) - i] = ((0xff << i * 8) & message_len_bits) >> i * 8;
  }

  // }}}

  // Parsing {{{

  uint8_t **blocks = (uint8_t **) malloc(10 * sizeof(uint8_t *));

  assert(blocks != NULL);

  for (size_t i = 0; i < num_of_blocks; i++) {
    blocks[i] = (uint8_t *) malloc(64 * sizeof(uint8_t));
  }

  for (size_t i = 0; i < num_of_blocks; i++) {
    for (size_t j = i * 64; j < (i + 1) * 64; j++) {
      blocks[i][j - (i * 64)] = M[j];
    }
  }

  // }}}
  
  return blocks;
}

uint32_t *sha256(char *message)
{
  uint32_t H[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };

  uint32_t *hash = H;

  size_t num_of_blocks = NUM_OF_BLOCKS((strlen(message) * 8) + 64 + 8);

  uint8_t **blocks = preprocessing_sha256(message);

  for (size_t i = 0; i < num_of_blocks; i++) {
    hash = compression_sha256(blocks[i], hash);
  }

  // Free blocks
  for (size_t i = 0; i < num_of_blocks; i++) {
    free(blocks[i]);
  }
  free(blocks);

  return hash;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    printf("\033[38;5;9mERROR:\033[0m Ilegal number of arguments.\n");
    return -1;
  }

  uint32_t* hash = sha256(argv[1]);

  printf("%x%x%x%x%x%x%x%x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
}
