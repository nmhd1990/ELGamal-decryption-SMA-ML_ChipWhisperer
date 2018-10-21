

#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bigint.h"

#define BIGINT_CEIL(x) ((((x) + sizeof(bigint_word_t) - 1) / sizeof(bigint_word_t)) *  sizeof(bigint_word_t))
#define BIGINT_OFF(x) ((sizeof(bigint_word_t) - (x) % sizeof(bigint_word_t)) % sizeof(bigint_word_t))

/**********************************************************************************************
   ELGAMAL PUBLIC KEY #0
**********************************************************************************************/

/* Prime_Number_Modulus: */
const uint8_t modulus[] PROGMEM = {
0xff, 0xf1 
};

/* Ciphertext */
const uint8_t encrypted_x[] PROGMEM = {
0xa1, 0x08 
};
/**********************************************************************************************/
const uint8_t hexdigit_tab_lc_P[] PROGMEM = {
'0','1','2','3',
'4','5','6','7',
'8','9','a','b',
'c','d','e','f'
};


typedef struct {
	bigint_t modulus;
} elgamal_publickey_t;

typedef struct {
	bigint_t ciphertext;
} elgamal_ciphertext_t;

elgamal_publickey_t pub_key;
elgamal_ciphertext_t cipher;

#define ENCRYPTED encrypted_x
#define MODULUS modulus
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif




/* The following helper functions copied from the ELGamal tests in avr-crypto-lib */
uint8_t load_bigint_from_os(bigint_t* a, PGM_VOID_P os, uint16_t length_B){
	a->length_B = BIGINT_CEIL(length_B) / sizeof(bigint_word_t);
	a->wordv = malloc(BIGINT_CEIL(length_B));
	if(!a->wordv){
        putch('F');
        while(1);
		return 1;
	}
	memset(a->wordv, 0, sizeof(bigint_word_t));
	memcpy_P((uint8_t*)a->wordv + BIGINT_OFF(length_B), os, length_B);
	a->info = 0;
	bigint_changeendianess(a);
	bigint_adjust(a);
	return 0;
}



void load_key(uint8_t use_fake)
{
    if (use_fake){
        /* This "Fake" data loads part of a different private key. You could also set a few bytes
           of the private key to 0 for example, although you need to ensure you don't put invalid
           data. Play around with the real_dec() version first. */
         load_bigint_from_os(&pub_key.modulus, MODULUS, sizeof(MODULUS));
         load_bigint_from_os(&(cipher.ciphertext), ENCRYPTED, sizeof(ENCRYPTED));


    } else {
        /* This is the "real" pub data */
        load_bigint_from_os(&pub_key.modulus, MODULUS, sizeof(MODULUS));
        load_bigint_from_os(&(cipher.ciphertext), ENCRYPTED, sizeof(ENCRYPTED));

    }
}




/* Perform a real ELGAMAL decryption, be aware this is VERY SLOW on AVR/XMEGA. At 7.37MHz using the default
   1024 byte key it takes about 687 seconds (over 10 mins). */
uint8_t real_dec(uint8_t * pt)
{
    /* Load encrypted message */

        load_bigint_from_os(&(cipher.ciphertext), ENCRYPTED, sizeof(ENCRYPTED));

    return 0;
}

/* Performs PART of a ELGAMAL decryption by using ****Montgomery Exponentiation Algorithm**** which uses only 16 bytes of keying material, where the "key" is
   actually the 16-byte input plaintext (sent with 'p' command). This is used to give you an easier
   target to perform SPA on rather than the full (very slow) ELGAMAL algorithm. */
uint8_t get_pt(uint8_t * pt)
{
	uint8_t flag = 0;
    const bigint_t* r = &(pub_key.modulus);
    const bigint_t* a = &(cipher.ciphertext);
    bigint_t R0, base, R1;
	bigint_word_t t, base_b[MAX(a->length_B,r->length_B)], R0_b[r->length_B*2], R1_b[r->length_B*2];
	uint16_t i;
	uint8_t j;
	R0.wordv = R0_b;
	R1.wordv = R1_b;
	base.wordv = base_b;
	bigint_copy(&base, a);
	bigint_reduce(&base, r);
	R0.wordv[0]=1;
	R0.length_B=1;
	R0.info = 0;
	bigint_adjust(&R0);
    R1.wordv[0]=1;
	R1.length_B=1;
	R1.info = 0;
	bigint_adjust(&R1);

/* R0 <-- c mod p */
    bigint_mul_u(&R0, &R0, &base);
	bigint_reduce(&R0, r);

/* R1 <-- R0* R0 mod p */
	bigint_square(&R1, &R0);
	bigint_reduce(&R1, r);
	
    trigger_high();
	
	for(i = 0; i < 16; i++) {
    
		//t = exp->wordv[i - 1];
        t = pt[i];
		for(j=8; j > 0; --j){
			if(!flag){
				if(t & (1<<(8-1))){
					flag = 1;
                    t<<=1;
                     j--;
				}
			}
			if(flag){
				if(t & (1<<(8-1))){
		        bigint_mul_u(&R0, &R0, &R1);
				bigint_reduce(&R0, r);

				bigint_square(&R1, &R1);
			    bigint_reduce(&R1, r);
				}
                else {
		        bigint_mul_u(&R1, &R0, &R1);
				bigint_reduce(&R1, r);
 
				bigint_square(&R0, &R0);
			    bigint_reduce(&R0, r);
				}
			}
			t<<=1;
		}
	}

    trigger_low();

    return 0;
}


int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Load all the keys etc */

    load_key(0);

	simpleserial_init();
    simpleserial_addcmd('t', 0,  real_dec);
    simpleserial_addcmd('p', 16, get_pt);
    while(1)
    simpleserial_get();
}
	
