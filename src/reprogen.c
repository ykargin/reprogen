#define _GNU_SOURCE

// Constants for PRNG
#define PRNG_MULTIPLIER 0x5DEECE66D
#define PRNG_INCREMENT 11
#define PRNG_MASK 0xFFFFFFFF0000
#define PRNG_MAX 0x1FFFFFFFFFFFF

// File content type identifiers
#define CONTENT_UNIFORM 0
#define CONTENT_PATTERN 1
#define CONTENT_CHAOS 2
#define CONTENT_SEGMENTS 3
#define CONTENT_ASCII 4
#define CONTENT_MIXED 5

// Default buffer size: 4KB chunk
#define DEFAULT_CHUNK_SIZE 4096

// Utility macros
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

/* Global constants */

// Magic marker for blocks
const char BLOCK_SIGNATURE[4] = { 0xc0, 0xff, 0xee, 0x10 };

// Character set for filenames and hex content
const char CHARSET[64] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_";

// CRC-64 lookup table for seed generation
const unsigned long long CRC_LOOKUP[256] = {
    0x0000000000000000, 0x42F0E1EBA9EA3693, 0x85E1C3D753D46D26,
    0xC711223CFA3E5BB5, 0x493366450E42ECDF, 0x0BC387AEA7A8DA4C,
    0xCCD2A5925D9681F9, 0x8E224479F47CB76A, 0x9266CC8A1C85D9BE,
    0xD0962D61B56FEF2D, 0x17870F5D4F51B498, 0x5577EEB6E6BB820B,
    0xDB55AACF12C73561, 0x99A54B24BB2D03F2, 0x5EB4691841135847,
    0x1C4488F3E8F96ED4, 0x663D78FF90E185EF, 0x24CD9914390BB37C,
    0xE3DCBB28C335E8C9, 0xA12C5AC36ADFDE5A, 0x2F0E1EBA9EA36930,
    0x6DFEFF5137495FA3, 0xAAEFDD6DCD770416, 0xE81F3C86649D3285,
    0xF45BB4758C645C51, 0xB6AB559E258E6AC2, 0x71BA77A2DFB03177,
    0x334A9649765A07E4, 0xBD68D2308226B08E, 0xFF9833DB2BCC861D,
    0x388911E7D1F2DDA8, 0x7A79F00C7818EB3B, 0xCC7AF1FF21C30BDE,
    0x8E8A101488293D4D, 0x499B3228721766F8, 0x0B6BD3C3DBFD506B,
    0x854997BA2F81E701, 0xC7B97651866BD192, 0x00A8546D7C558A27,
    0x4258B586D5BFBCB4, 0x5E1C3D753D46D260, 0x1CECDC9E94ACE4F3,
    0xDBFDFEA26E92BF46, 0x990D1F49C77889D5, 0x172F5B3033043EBF,
    0x55DFBADB9AEE082C, 0x92CE98E760D05399, 0xD03E790CC93A650A,
    0xAA478900B1228E31, 0xE8B768EB18C8B8A2, 0x2FA64AD7E2F6E317,
    0x6D56AB3C4B1CD584, 0xE374EF45BF6062EE, 0xA1840EAE168A547D,
    0x66952C92ECB40FC8, 0x2465CD79455E395B, 0x3821458AADA7578F,
    0x7AD1A461044D611C, 0xBDC0865DFE733AA9, 0xFF3067B657990C3A,
    0x711223CFA3E5BB50, 0x33E2C2240A0F8DC3, 0xF4F3E018F031D676,
    0xB60301F359DBE0E5, 0xDA050215EA6C212F, 0x98F5E3FE438617BC,
    0x5FE4C1C2B9B84C09, 0x1D14202910527A9A, 0x93366450E42ECDF0,
    0xD1C685BB4DC4FB63, 0x16D7A787B7FAA0D6, 0x5427466C1E109645,
    0x4863CE9FF6E9F891, 0x0A932F745F03CE02, 0xCD820D48A53D95B7,
    0x8F72ECA30CD7A324, 0x0150A8DAF8AB144E, 0x43A04931514122DD,
    0x84B16B0DAB7F7968, 0xC6418AE602954FFB, 0xBC387AEA7A8DA4C0,
    0xFEC89B01D3679253, 0x39D9B93D2959C9E6, 0x7B2958D680B3FF75,
    0xF50B1CAF74CF481F, 0xB7FBFD44DD257E8C, 0x70EADF78271B2539,
    0x321A3E938EF113AA, 0x2E5EB66066087D7E, 0x6CAE578BCFE24BED,
    0xABBF75B735DC1058, 0xE94F945C9C3626CB, 0x676DD025684A91A1,
    0x259D31CEC1A0A732, 0xE28C13F23B9EFC87, 0xA07CF2199274CA14,
    0x167FF3EACBAF2AF1, 0x548F120162451C62, 0x939E303D987B47D7,
    0xD16ED1D631917144, 0x5F4C95AFC5EDC62E, 0x1DBC74446C07F0BD,
    0xDAAD56789639AB08, 0x985DB7933FD39D9B, 0x84193F60D72AF34F,
    0xC6E9DE8B7EC0C5DC, 0x01F8FCB784FE9E69, 0x43081D5C2D14A8FA,
    0xCD2A5925D9681F90, 0x8FDAB8CE70822903, 0x48CB9AF28ABC72B6,
    0x0A3B7B1923564425, 0x70428B155B4EAF1E, 0x32B26AFEF2A4998D,
    0xF5A348C2089AC238, 0xB753A929A170F4AB, 0x3971ED50550C43C1,
    0x7B810CBBFCE67552, 0xBC902E8706D82EE7, 0xFE60CF6CAF321874,
    0xE224479F47CB76A0, 0xA0D4A674EE214033, 0x67C58448141F1B86,
    0x253565A3BDF52D15, 0xAB1721DA49899A7F, 0xE9E7C031E063ACEC,
    0x2EF6E20D1A5DF759, 0x6C0603E6B3B7C1CA, 0xF6FAE5C07D3274CD,
    0xB40A042BD4D8425E, 0x731B26172EE619EB, 0x31EBC7FC870C2F78,
    0xBFC9838573709812, 0xFD39626EDA9AAE81, 0x3A28405220A4F534,
    0x78D8A1B9894EC3A7, 0x649C294A61B7AD73, 0x266CC8A1C85D9BE0,
    0xE17DEA9D3263C055, 0xA38D0B769B89F6C6, 0x2DAF4F0F6FF541AC,
    0x6F5FAEE4C61F773F, 0xA84E8CD83C212C8A, 0xEABE6D3395CB1A19,
    0x90C79D3FEDD3F122, 0xD2377CD44439C7B1, 0x15265EE8BE079C04,
    0x57D6BF0317EDAA97, 0xD9F4FB7AE3911DFD, 0x9B041A914A7B2B6E,
    0x5C1538ADB04570DB, 0x1EE5D94619AF4648, 0x02A151B5F156289C,
    0x4051B05E58BC1E0F, 0x87409262A28245BA, 0xC5B073890B687329,
    0x4B9237F0FF14C443, 0x0962D61B56FEF2D0, 0xCE73F427ACC0A965,
    0x8C8315CC052A9FF6, 0x3A80143F5CF17F13, 0x7870F5D4F51B4980,
    0xBF61D7E80F251235, 0xFD913603A6CF24A6, 0x73B3727A52B393CC,
    0x31439391FB59A55F, 0xF652B1AD0167FEEA, 0xB4A25046A88DC879,
    0xA8E6D8B54074A6AD, 0xEA16395EE99E903E, 0x2D071B6213A0CB8B,
    0x6FF7FA89BA4AFD18, 0xE1D5BEF04E364A72, 0xA3255F1BE7DC7CE1,
    0x64347D271DE22754, 0x26C49CCCB40811C7, 0x5CBD6CC0CC10FAFC,
    0x1E4D8D2B65FACC6F, 0xD95CAF179FC497DA, 0x9BAC4EFC362EA149,
    0x158E0A85C2521623, 0x577EEB6E6BB820B0, 0x906FC95291867B05,
    0xD29F28B9386C4D96, 0xCEDBA04AD0952342, 0x8C2B41A1797F15D1,
    0x4B3A639D83414E64, 0x09CA82762AAB78F7, 0x87E8C60FDED7CF9D,
    0xC51827E4773DF90E, 0x020905D88D03A2BB, 0x40F9E43324E99428,
    0x2CFFE7D5975E55E2, 0x6E0F063E3EB46371, 0xA91E2402C48A38C4,
    0xEBEEC5E96D600E57, 0x65CC8190991CB93D, 0x273C607B30F68FAE,
    0xE02D4247CAC8D41B, 0xA2DDA3AC6322E288, 0xBE992B5F8BDB8C5C,
    0xFC69CAB42231BACF, 0x3B78E888D80FE17A, 0x7988096371E5D7E9,
    0xF7AA4D1A85996083, 0xB55AACF12C735610, 0x724B8ECDD64D0DA5,
    0x30BB6F267FA73B36, 0x4AC29F2A07BFD00D, 0x08327EC1AE55E69E,
    0xCF235CFD546BBD2B, 0x8DD3BD16FD818BB8, 0x03F1F96F09FD3CD2,
    0x41011884A0170A41, 0x86103AB85A2951F4, 0xC4E0DB53F3C36767,
    0xD8A453A01B3A09B3, 0x9A54B24BB2D03F20, 0x5D45907748EE6495,
    0x1FB5719CE1045206, 0x919735E51578E56C, 0xD367D40EBC92D3FF,
    0x1476F63246AC884A, 0x568617D9EF46BED9, 0xE085162AB69D5E3C,
    0xA275F7C11F7768AF, 0x6564D5FDE549331A, 0x279434164CA30589,
    0xA9B6706FB8DFB2E3, 0xEB46918411358470, 0x2C57B3B8EB0BDFC5,
    0x6EA7525342E1E956, 0x72E3DAA0AA188782, 0x30133B4B03F2B111,
    0xF7021977F9CCEAA4, 0xB5F2F89C5026DC37, 0x3BD0BCE5A45A6B5D,
    0x79205D0E0DB05DCE, 0xBE317F32F78E067B, 0xFCC19ED95E6430E8,
    0x86B86ED5267CDBD3, 0xC4488F3E8F96ED40, 0x0359AD0275A8B6F5,
    0x41A94CE9DC428066, 0xCF8B0890283E370C, 0x8D7BE97B81D4019F,
    0x4A6ACB477BEA5A2A, 0x089A2AACD2006CB9, 0x14DEA25F3AF9026D,
    0x562E43B4931334FE, 0x913F6188692D6F4B, 0xD3CF8063C0C759D8,
    0x5DEDC41A34BBEEB2, 0x1F1D25F19D51D821, 0xD80C07CD676F8394,
    0x9AFCE626CE85B507
};

/* Global variables */
static unsigned long long prng_state = 0;
static char *output_dir = NULL;
static char *buffer = NULL;
static size_t buffer_size = DEFAULT_CHUNK_SIZE;

/* Complementary Multiply With Carry RNG parameters */
#define CMWC_SIZE 4096
#define CMWC_MAX_C 809430660
struct cmwc_state {
    unsigned int q[CMWC_SIZE];
    unsigned int c;
    unsigned int idx;
};

/*
 * Simple file ID generator functions
 * These functions manage a simple LCG-based PRNG for 
 * filename generation. We use a separate PRNG stream
 * from the main content generation to ensure reproducibility.
 */

/* Initialize the filename PRNG with a seed */
void init_file_id_generator(unsigned long long seed)
{
    prng_state = seed & PRNG_MAX;
}

/* Generate a 32-bit random integer for filename generation */
unsigned int generate_file_id_part()
{
    prng_state = (prng_state * PRNG_MULTIPLIER + PRNG_INCREMENT) & PRNG_MAX;
    return (prng_state & PRNG_MASK) >> 16;
}

/* Generate a random byte for filename */
unsigned char generate_file_id_byte()
{
    return generate_file_id_part() & 0xFF;
}

/* Print detailed help information */
void print_help(int error_code)
{
    printf("ReproGen - Reproducible File Generator\n\n");
    printf("A fast utility for generating test files with reproducible content\n");
    printf("Perfect for benchmarking, testing I/O performance, or creating test datasets\n\n");
    
    printf("USAGE:\n");
    printf("  reprogen -d <directory> [OPTIONS]\n\n");
    
    printf("REQUIRED ARGUMENTS:\n");
    printf("  -d, --directory DIR   Directory where files will be created\n\n");
    
    printf("OPTIONS:\n");
    printf("  -s, --size SIZE       Size of each generated file in bytes (default: 32768)\n");
    printf("  -n, --number NUM      Number of files to generate (default: 1)\n");
    printf("  -i, --id ID           Recreate a specific file by its 12-character ID\n");
    printf("  -b, --buffer SIZE     Buffer size for I/O operations (default: 4096)\n");
    printf("  -m, --mark-blocks     Mark blocks with identifiers (for debugging)\n");
    printf("  -D, --direct          Use O_DIRECT flag for bypassing OS cache\n");
    printf("  -S, --sync            Use O_SYNC flag for synchronous writes\n");
    printf("  -h, --help            Show this help message\n\n");
    
    printf("EXAMPLES:\n");
    printf("  # Generate a single 1MB file\n");
    printf("  reprogen -d /tmp/test -s 1048576\n\n");
    
    printf("  # Generate 10 files of 4KB each\n");
    printf("  reprogen -d /tmp/test -s 4096 -n 10\n\n");
    
    printf("  # Recreate a specific file by ID\n");
    printf("  reprogen -d /tmp/test -s 1048576 -i abc123xyz456\n\n");
    
    printf("  # Use direct I/O with a large buffer for better performance\n");
    printf("  reprogen -d /tmp/test -s 104857600 -b 1048576 -D\n\n");
    
    if (error_code) {
        printf("Error status: %d\n", error_code);
    }
}

/* Generate a random file ID (12 characters) */
char *generate_file_id()
{
    char *id = malloc(13);
    if (!id)
        return NULL;
    
    for (int i = 0; i < 12; i++) {
        id[i] = CHARSET[generate_file_id_byte() & 0x3F];
    }
    id[12] = 0;
    
    return id;
}

/* Compute a seed from a file ID using CRC-64 */
unsigned long long id_to_seed(char *id)
{
    unsigned long long result = 0xffffffffffffffff;
    unsigned char idx = 0;
    
    for (int i = 0; i < 12; i++) {
        idx = (result >> 56) ^ id[i];
        result = CRC_LOOKUP[idx] ^ (result << 8);
    }
    
    return result;
}

/* Initialize the CMWC PRNG with a seed */
void init_cmwc(struct cmwc_state *state, unsigned long long seed)
{
    init_file_id_generator(seed);
    
    for (int i = 0; i < CMWC_SIZE; i++)
        state->q[i] = generate_file_id_part();
    
    do {
        state->c = generate_file_id_part();
    } while (state->c >= CMWC_MAX_C);
    
    state->idx = CMWC_SIZE - 1;
}

/* Generate a random number using CMWC algorithm */
unsigned int next_random(struct cmwc_state *state)
{
    const unsigned long long a = 18782;
    const unsigned int m = 0xfffffffe;
    unsigned long long t;
    unsigned int x;
    
    state->idx = (state->idx + 1) & (CMWC_SIZE - 1);
    t = a * state->q[state->idx] + state->c;
    state->c = t >> 32;
    x = t + state->c;
    
    if (x < state->c) {
        x++;
        state->c++;
    }
    
    return state->q[state->idx] = m - x;
}

/* Generate a random byte using CMWC */
unsigned char next_byte(struct cmwc_state *state)
{
    return next_random(state) & 0xFF;
}

/* Content generators for different file types */

/* Fill buffer with a single repeating byte */
char *generate_uniform(struct cmwc_state *state)
{
    unsigned char value = next_byte(state);
    
    for (size_t i = 0; i < buffer_size; i++) {
        buffer[i] = value;
    }
    
    return buffer;
}

/* Generate an arithmetic sequence pattern */
char *generate_pattern(struct cmwc_state *state)
{
    unsigned char value = next_byte(state);
    unsigned char step = next_byte(state);
    
    for (size_t i = 0; i < buffer_size; i++) {
        buffer[i] = value;
        value += step;
    }
    
    return buffer;
}

/* Generate random bytes (high entropy) */
char *generate_chaos(struct cmwc_state *state)
{
    unsigned int random_value = next_random(state);
    
    for (size_t i = 0; i < buffer_size; i++) {
        if (!(i & 3)) // Every 4 bytes
            random_value = next_random(state);
        
        buffer[i] = random_value & 0xFF;
        random_value >>= 8;
    }
    
    return buffer;
}

/* Generate runs of repeated bytes */
char *generate_segments(struct cmwc_state *state)
{
    size_t remaining = buffer_size;
    unsigned char value;
    unsigned char run_length;
    size_t offset = 0;
    
    while (remaining > 0) {
        value = next_byte(state);
        run_length = MAX(1, next_byte(state));
        
        if (run_length > remaining)
            run_length = remaining;
        
        for (size_t i = 0; i < run_length; i++) {
            buffer[offset++] = value;
        }
        
        remaining -= run_length;
    }
    
    return buffer;
}

/* Generate ASCII hex characters */
char *generate_ascii(struct cmwc_state *state)
{
    unsigned int random_value = next_random(state);
    
    for (size_t i = 0; i < buffer_size; i++) {
        if (!(i & 1)) // Every 2 bytes
            random_value = next_random(state);
        
        buffer[i] = CHARSET[random_value & 0x0F];
        random_value >>= 4;
    }
    
    return buffer;
}

/* Generate a mix of all types based on random selection */
char *generate_mixed(struct cmwc_state *state)
{
    switch (next_random(state) % 5) {
    case CONTENT_UNIFORM:
        return generate_uniform(state);
    case CONTENT_PATTERN:
        return generate_pattern(state);
    case CONTENT_CHAOS:
        return generate_chaos(state);
    case CONTENT_SEGMENTS:
        return generate_segments(state);
    case CONTENT_ASCII:
        return generate_ascii(state);
    }
    
    // Should never reach here, but just in case
    return generate_chaos(state);
}

/* Function pointer table for content generators */
char *(*content_generators[6])(struct cmwc_state *) = {
    generate_uniform, 
    generate_pattern, 
    generate_chaos,
    generate_segments, 
    generate_ascii, 
    generate_mixed
};

/* Core file generation function */
int create_file(long long file_size, char *id, int mark_blocks, int io_flags)
{
    unsigned long long id_seed;
    unsigned int content_seed;
    struct cmwc_state cmwc;
    int content_type;
    int result;
    int chunk_size;
    int fd;
    char *base_id = NULL;
    char *block_marker = NULL;
    size_t marker_size;
    char *file_path = NULL;
    FILE *output_file;
    
    /* Generate or use the provided file ID */
    base_id = id ? id : generate_file_id();
    
    /* Derive content seed from the ID */
    content_seed = id_to_seed(base_id);
    id_seed = prng_state; /* Save the ID generator state */
    
    /* Initialize the content generator */
    init_cmwc(&cmwc, content_seed);
    content_type = content_seed % 6;
    
    /* Prepare the output file path */
    file_path = malloc(strlen(output_dir) + strlen(base_id) + 2);
    if (!file_path)
        return 1;
        
    /* Prepare block marker if requested */
    if (mark_blocks) {
        marker_size = strlen(base_id) + 8;
        block_marker = malloc(marker_size);
        if (!block_marker) {
            free(file_path);
            return 1;
        }
        
        /* Format: [MAGIC][ID][MAGIC] */
        memcpy(block_marker, BLOCK_SIGNATURE, sizeof(BLOCK_SIGNATURE));
        memcpy(block_marker + sizeof(BLOCK_SIGNATURE), base_id, strlen(base_id));
        memcpy(block_marker + marker_size - sizeof(BLOCK_SIGNATURE),
               BLOCK_SIGNATURE, sizeof(BLOCK_SIGNATURE));
    }
    
    /* Construct the full file path */
    sprintf(file_path, "%s/%s", output_dir, base_id);
    
    /* Open the output file with the appropriate flags */
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | io_flags, 0644);
    if (fd < 0) {
        if (block_marker)
            free(block_marker);
        free(file_path);
        return 1;
    }
    
    output_file = fdopen(fd, "w");
    if (!output_file) {
        close(fd);
        if (block_marker)
            free(block_marker);
        free(file_path);
        return 1;
    }
    
    /* Generate and write data in chunks */
    while (file_size > 0) {
        chunk_size = MIN(file_size, buffer_size);
        
        /* Generate content for this chunk */
        (*content_generators[content_type])(&cmwc);
        
        /* Add block marker if requested */
        if (block_marker)
            memcpy(buffer, block_marker, marker_size);
        
        /* Write the chunk to the file */
        result = fwrite(buffer, 1, chunk_size, output_file);
        if (result != chunk_size) {
            fclose(output_file);
            if (block_marker)
                free(block_marker);
            free(file_path);
            return 1;
        }
        
        file_size -= chunk_size;
    }
    
    /* Clean up and restore state */
    fclose(output_file);
    free(file_path);
    
    /* Restore the ID generator state */
    init_file_id_generator(id_seed);
    
    /* Clean up allocated memory */
    if (!id)
        free(base_id);
    if (block_marker)
        free(block_marker);
    
    return 0;
}

/* Parse command line arguments and run the program */
int main(int argc, char **argv)
{
    long long file_size = 32768;
    long long file_count = 1;
    char *reproduce_id = NULL;
    int mark_blocks = 0;
    int io_flags = 0;
    int opt;
    int option_index = 0;
    
    /* Define long options */
    static struct option long_options[] = {
        {"directory", required_argument, 0, 'd'},
        {"size",      required_argument, 0, 's'},
        {"number",    required_argument, 0, 'n'},
        {"id",        required_argument, 0, 'i'},
        {"buffer",    required_argument, 0, 'b'},
        {"mark-blocks", no_argument,    0, 'm'},
        {"direct",    no_argument,      0, 'D'},
        {"sync",      no_argument,      0, 'S'},
        {"help",      no_argument,      0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Parse command-line options */
    while ((opt = getopt_long(argc, argv, "d:s:n:i:b:mDSh", 
                              long_options, &option_index)) != -1) {
        switch (opt) {
        case 'd':
            output_dir = optarg;
            break;
        case 's':
            file_size = atoll(optarg);
            break;
        case 'n':
            file_count = atoll(optarg);
            break;
        case 'i':
            reproduce_id = optarg;
            break;
        case 'b':
            buffer_size = atoll(optarg);
            break;
        case 'm':
            mark_blocks = 1;
            break;
        case 'D':
            io_flags |= O_DIRECT;
            break;
        case 'S':
            io_flags |= O_SYNC;
            break;
        case 'h':
            print_help(0);
            return 0;
        default:
            print_help(1);
            return 1;
        }
    }
    
    /* Validate required parameters */
    if (!output_dir) {
        fprintf(stderr, "Error: Output directory (--directory) is required\n");
        print_help(2);
        return 2;
    }
    
    if (file_size < 1) {
        fprintf(stderr, "Error: File size must be at least 1 byte\n");
        print_help(3);
        return 3;
    }
    
    if (buffer_size < 1) {
        fprintf(stderr, "Error: Buffer size must be at least 1 byte\n");
        print_help(4);
        return 4;
    }
    
    if (file_count < 1 && !reproduce_id) {
        fprintf(stderr, "Error: Number of files must be at least 1\n");
        print_help(5);
        return 5;
    }
    
    if (file_size % buffer_size != 0) {
        fprintf(stderr, "Error: File size must be a multiple of buffer size\n");
        print_help(6);
        return 6;
    }
    
    /* Initialize the random generator with current time as seed */
    init_file_id_generator((unsigned long long)time(NULL));
    
    /* Allocate buffer for data generation */
    buffer = malloc(buffer_size);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate buffer memory\n");
        return 7;
    }
    
    /* Execute in appropriate mode */
    if (reproduce_id) {
        /* Reproduce mode - generate a specific file by ID */
        file_count = 1;
        if (create_file(file_size, reproduce_id, mark_blocks, io_flags)) {
            fprintf(stderr, "Error: Failed to create file with ID %s\n", reproduce_id);
            free(buffer);
            return 8;
        }
    } else {
        /* Bulk generation mode - create multiple files */
        for (int i = 0; i < file_count; i++) {
            if (create_file(file_size, NULL, mark_blocks, io_flags)) {
                fprintf(stderr, "Error: Failed to create file %d of %lld\n", 
                        i + 1, file_count);
                free(buffer);
                return 9;
            }
        }
    }
    
    /* Clean up and exit */
    free(buffer);
    return 0;
}