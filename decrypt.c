#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#define BUFSZ (24*4096)

static uint32_t key[4];

struct block_header_t {
    uint16_t flags;
    uint8_t checksum;
    uint8_t magic;
    uint32_t target_address;
    uint32_t byte_count;
    uint32_t argument;
    uint8_t raw[16];
};

uint16_t get_le16(uint8_t *buf)
{
    return buf[0] + (buf[1] << 8);
}

uint32_t get_le32(uint8_t *buf)
{
    return buf[0] + (buf[1] << 8) + (buf[2] << 16) + (buf[3] << 24);
}

uint32_t get_be32(uint8_t *buf)
{
    return buf[3] + (buf[2] << 8) + (buf[1] << 16) + (buf[0] << 24);
}

int read_block_header(FILE* fd, struct block_header_t *bh)
{
    int count;

    count = fread(bh->raw, 1, 16, fd);
    
    bh->flags = get_le16(&bh->raw[0]);
    
    bh->checksum = bh->raw[2];
    bh->magic = bh->raw[3];
    
    bh->target_address = get_le32(&bh->raw[4]);
    bh->byte_count = get_le32(&bh->raw[8]);
    bh->argument = get_le32(&bh->raw[12]);

    return count;
}

int write_block_header(FILE* fd, struct block_header_t *bh)
{
    uint32_t tmp32;
    uint16_t tmp16;

    tmp16 = htole16(bh->flags);
    fwrite(&tmp16, 2, 1, fd);
    
    fwrite(&bh->checksum, 1, 1, fd);
    fwrite(&bh->magic, 1, 1, fd);

    tmp32 = htole32(bh->target_address);
    fwrite(&tmp32, 4, 1, fd);
    tmp32 = htole32(bh->byte_count);
    fwrite(&tmp32, 4, 1, fd);
    tmp32 = htole32(bh->argument);
    fwrite(&tmp32, 4, 1, fd);
}

int check_block_header(struct block_header_t *bh)
{
    int i;
    uint8_t chksum=0;
    
    if (bh->magic != 0xad)
        return -1;

    for (i=0; i<16; i++)
        chksum ^= bh->raw[i];

    if (chksum != 0)
        return -1;
    
    return 0;
}

void decipher (uint8_t num_cycles, uint32_t v[2], uint32_t const k[4])
{
    uint8_t i;
    const uint32_t delta = 0x9E3779B9;
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t sum = delta * num_cycles;
    
    for (i=0; i < num_cycles; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

void decrypt(uint8_t *buffer, int n)
{
    int i;
    
    for (i=0; i+24<=n; i+=24) {
        decipher(32, (uint32_t*)&buffer[i], key);
    }
}

uint8_t nibble(char c)
{
    if ((c >= '0') && (c <= '9'))
        return c-'0';

    if ((c >= 'A') && (c <= 'F'))
        return c-'A'+10;

    if ((c >= 'a') && (c <= 'f'))
        return c-'a'+10;
    
    return 0;
}

int read_key(char* keystr)
{
    int i;
    uint8_t keybytes[16];
    
    if (strlen(keystr) != 32)
        return -1;

    for (i=0; i<16; i++) {
        keybytes[i] = (nibble(keystr[i*2]) << 4) + nibble(keystr[i*2+1]);
    }

    key[0] = get_be32(&keybytes[0]);
    key[1] = get_be32(&keybytes[4]);
    key[2] = get_be32(&keybytes[8]);
    key[3] = get_be32(&keybytes[12]);

    return 0;
}

int main(int argc, char** argv)
{
    FILE *ldr_in, *ldr_out;
    struct block_header_t bh;

    uint8_t buf[BUFSZ];
    
    int i, remaining;
    int count=0;
    int iscallback=0;

    if (argc != 4) {
        printf("Usage: decrypt [key] [input] [output]\n");
        exit(1);
    }

    if (read_key(argv[1]) != 0) {
        printf("Could not read key.\n");
        exit(1);
    }

    ldr_in = fopen(argv[2], "rb");
    if (ldr_in == NULL) {
        printf("Could not open input file '%s'\n", argv[2]);
    }
    ldr_out = fopen(argv[3], "wb");
    if (ldr_out == NULL) {
        printf("Could not open output file '%s'\n", argv[3]);
    }

    while (!feof(ldr_in)) {
        // check, copy and modify block header
        if (read_block_header(ldr_in, &bh) != 16)
            continue;

        count += 1;

        if (check_block_header(&bh) != 0) {
            printf("invalid block header found.\n");
            break;
        }
        
        if ((bh.flags & 0x100) != 0) {
            write_block_header(ldr_out, &bh);
            continue;
        }

        if ((bh.flags & 0x2400) == 0x2400) {
            bh.flags &= ~(0x2400);
            bh.checksum ^= 0x24;
            iscallback=1;
        } else
            iscallback=0;

        write_block_header(ldr_out, &bh);

        if (bh.byte_count == 0)
            continue;

        // copy and decrypt block content
        remaining = bh.byte_count;
        
        while (remaining > BUFSZ) {
            fread(buf, BUFSZ, 1, ldr_in);
            if (iscallback)
                decrypt(buf, BUFSZ);
            remaining -= BUFSZ;
            fwrite(buf, BUFSZ, 1, ldr_out);
        }
        
        fread(buf, remaining, 1, ldr_in);
        if (iscallback)
            decrypt(buf, remaining);
        fwrite(buf, remaining, 1, ldr_out);
    }

    fclose(ldr_in);
    fclose(ldr_out);

    return 0;
}
