
/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         FROG by TechApro International S.A.                          */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */

/* Timing data for FROG (frog.c)

Core timing without I/O endian conversion:

128 bit key:
Key Setup: 1416182 cycles
Encrypt:      2417 cycles =    10.6 mbits/sec
Decrypt:      2227 cycles =    11.5 mbits/sec
Mean:         2322 cycles =    11.0 mbits/sec

192 bit key:
Key Setup: 1422837 cycles
Encrypt:      2433 cycles =    10.5 mbits/sec
Decrypt:      2255 cycles =    11.4 mbits/sec
Mean:         2344 cycles =    10.9 mbits/sec

256 bit key:
Key Setup: 1423613 cycles
Encrypt:      2440 cycles =    10.5 mbits/sec
Decrypt:      2240 cycles =    11.4 mbits/sec
Mean:         2340 cycles =    10.9 mbits/sec

Full timing with I/O endian conversion:

128 bit key:
Key Setup: 1402261 cycles
Encrypt:      2467 cycles =    10.4 mbits/sec
Decrypt:      2287 cycles =    11.2 mbits/sec
Mean:         2377 cycles =    10.8 mbits/sec

192 bit key:
Key Setup: 1420286 cycles
Encrypt:      2389 cycles =    10.7 mbits/sec
Decrypt:      2260 cycles =    11.3 mbits/sec
Mean:         2325 cycles =    11.0 mbits/sec

256 bit key:
Key Setup: 1421665 cycles
Encrypt:      2450 cycles =    10.4 mbits/sec
Decrypt:      2250 cycles =    11.4 mbits/sec
Mean:         2350 cycles =    10.9 mbits/sec

*/
#define _CRT_SECURE_NO_WARNINGS
#define BLOCK_SWAP

#ifdef CORE_TIME
#  undef BLOCK_SWAP
#endif

#include "std_defs.h"

static char *alg_name[] = { "frog", "frog.c", "frog" };

char **cipher_name()
{
    return alg_name;
}

const unsigned int  ik_len = 2304;

u1byte  seed[256] =
{
    113,  21, 232,  18, 113,  92,  63, 157, 124, 193, 166, 197, 126,  56, 229, 229, 
    156, 162,  54,  17, 230,  89, 189,  87, 169,   0,  81, 204,   8,  70, 203, 225, 
    160,  59, 167, 189, 100, 157,  84,  11,   7, 130,  29,  51,  32,  45, 135, 237, 
    139,  33,  17, 221,  24,  50,  89,  74,  21, 205, 191, 242,  84,  53,   3, 230, 

    231, 118,  15,  15, 107,   4,  21,  34,   3, 156,  57,  66,  93, 255, 191,   3, 
     85, 135, 205, 200, 185, 204,  52,  37,  35,  24,  68, 185, 201,  10, 224, 234, 
      7, 120, 201, 115, 216, 103,  57, 255,  93, 110,  42, 249,  68,  14,  29,  55, 
    128,  84,  37, 152, 221, 137,  39,  11, 252,  50, 144,  35, 178, 190,  43, 162, 

    103, 249, 109,   8, 235,  33, 158, 111, 252, 205, 169,  54,  10,  20, 221, 201, 
    178, 224,  89, 184, 182,  65, 201,  10,  60,   6, 191, 174,  79,  98,  26, 160, 
    252,  51,  63,  79,   6, 102, 123, 173,  49,   3, 110, 233,  90, 158, 228, 210, 
    209, 237,  30,  95,  28, 179, 204, 220,  72, 163,  77, 166, 192,  98, 165,  25, 

    145, 162,  91, 212,  41, 230, 110,   6, 107, 187, 127,  38,  82,  98,  30,  67, 
    225,  80, 208, 134,  60, 250, 153,  87, 148,  60,  66, 165,  72,  29, 165,  82, 
    211, 207,   0, 177, 206,  13,   6,  14,  92, 248,  60, 201, 132,  95,  35, 215, 
    118, 177, 121, 180,  27,  83, 131,  26,  39,  46,  12,   0,   0,   0,   0,   0
};

typedef struct  
{   u1byte  k_xbu[16];
    u1byte  k_spu[256];
    u1byte  k_bpu[16];
} k_str;

typedef struct
{   k_str   f_key[8];
    u1byte  i_key[8][256];
} key_str;

key_str loc_key;
key_str sim_key;
key_str *lkp;

u1byte test[16];

// top is 1 greater than that used in FROG specification
// this routine makes a permutation containing 'top' values

void make_perm(u1byte *ip, u4byte top)
{   u1byte  ua[260];
    u4byte  i, j, ie, ne;

    for(i = 0; i < top; ++i)
        ua[i] = (u1byte)i;

    ie = 0; ne = top;

    for(i = 0; i < top - 1; ++i)
    {
        ie = (ie + ip[i]) % ne;

        ip[i] = ua[ie]; ne--;

        for(j = ie; j < ne; ++j)

            ua[j] = ua[j + 1];
    }

    ip[top - 1] = ua[0];
};

void make_ikey(key_str *kp)
{   u4byte  i, j, k, ix, ll;
    u1byte  ua[16];
        
    for(i = 0; i < 8; ++i)
    {
        make_perm(kp->f_key[i].k_spu, 256);

        for(j = 0; j < 256; ++j)

            kp->i_key[i][kp->f_key[i].k_spu[j]] = (u1byte)j;

        make_perm(kp->f_key[i].k_bpu, 16);

        for(j = 0; j < 16; ++j)

            ua[j] = 0;

        for(j = ix = 0; j < 15; ++j)
        {
            if(!kp->f_key[i].k_bpu[ix])
            {
                k = ix;

                do
                {
                    k = (k + 1) & 15;
                }
                while
                    (ua[k]);

                kp->f_key[i].k_bpu[ix] = (u1byte)k; ll = k;

                while(kp->f_key[i].k_bpu[ll] != k)
                
                    ll = kp->f_key[i].k_bpu[ll];

                kp->f_key[i].k_bpu[ll] = 0;
            }

            ua[ix] = 1; ix = kp->f_key[i].k_bpu[ix];
        }

        for(j = 0; j < 16; ++j)

            if(kp->f_key[i].k_bpu[j] == ((j + 1) & 15))

                kp->f_key[i].k_bpu[j] = (u1byte)((j + 2) & 15);
    }
}

/* initialise the key schedule from the user supplied key   */

void enc(const u4byte in_blk[4], u4byte out_blk[4]);

u4byte *set_key(const u4byte in_key[], const u4byte key_len)
{   u4byte  i, j, k;
    u1byte  kb[32];

    get_key(kb, key_len);

    for(i = j = k = 0; i < ik_len; ++i)
    {
        ((u1byte*)(sim_key.f_key))[i] = seed[j] ^ kb[k];

        j = (j < 250 ? j + 1 : 0);

        k  = (k < (key_len / 8) - 1 ? k + 1 : 0);
    }

    make_ikey(&sim_key); lkp = &sim_key;

    kb[0] ^= (key_len / 8); 

    for(i = 0; i < ik_len / 16; ++i)
    {
        enc((u4byte*)kb, (u4byte*)kb);

        for(j = 0; j < 16; ++j)

            ((u1byte*)(loc_key.f_key))[16 * i + j] = kb[j];
    }

    make_ikey(&loc_key);

    lkp = &loc_key;

    return (u4byte*)&loc_key;
};

#define f_rnd(j)                    \
    k = pp[j];                      \
    blk[j] = sp[blk[j] ^ xp[j]];    \
    blk[(j + 1) & 15] ^= blk[j];    \
    blk[k] ^= blk[j]

#define b_rnd(j)                    \
    ct = blk[j];                    \
    blk[pp[j]] ^= blk[j];           \
    blk[(j + 1) & 15] ^= blk[j];    \
    blk[j] = sp[ct] ^ xp[j]

void enc(const u4byte in_blk[4], u4byte out_blk[4])
{   u4byte  i, k;
    u1byte  blk[16], *xp, *sp, *pp;
    
    *(u4byte*)(blk +  0) = in_blk[0]; *(u4byte*)(blk +  4) = in_blk[1];
    *(u4byte*)(blk +  8) = in_blk[2]; *(u4byte*)(blk + 12) = in_blk[3];
    
    for(i = 0; i < 8; ++i)
    {
        xp = lkp->f_key[i].k_xbu;
        sp = lkp->f_key[i].k_spu;
        pp = lkp->f_key[i].k_bpu;

        f_rnd( 0); f_rnd( 1); f_rnd( 2); f_rnd( 3);
        f_rnd( 4); f_rnd( 5); f_rnd( 6); f_rnd( 7);
        f_rnd( 8); f_rnd( 9); f_rnd(10); f_rnd(11);
        f_rnd(12); f_rnd(13); f_rnd(14); f_rnd(15);
    }

    out_blk[0] = *(u4byte*)(blk +  0); out_blk[1] = *(u4byte*)(blk +  4);
    out_blk[2] = *(u4byte*)(blk +  8); out_blk[3] = *(u4byte*)(blk + 12);
};

/* encrypt a block of text  */

void encrypt(const u4byte in_blk[4], u4byte out_blk[4])
{   u4byte  i, k;
    u1byte  blk[16], *xp, *sp, *pp;
    
    get_block(blk);
    
    for(i = 0; i < 8; ++i)
    {
        xp = lkp->f_key[i].k_xbu;
        sp = lkp->f_key[i].k_spu;
        pp = lkp->f_key[i].k_bpu;

        f_rnd( 0); f_rnd( 1); f_rnd( 2); f_rnd( 3);
        f_rnd( 4); f_rnd( 5); f_rnd( 6); f_rnd( 7);
        f_rnd( 8); f_rnd( 9); f_rnd(10); f_rnd(11);
        f_rnd(12); f_rnd(13); f_rnd(14); f_rnd(15);
    }

    put_block(blk);

    for (int j = 0; j < 16; j++) {
        test[j] = blk[j];
    }
};

/* decrypt a block of text  */

void decrypt(const u4byte in_blk[4], u4byte out_blk[4])
{   s4byte  i;
    u1byte  blk[16], ct, *xp, *sp, *pp;
    
    get_block(blk);
    
    for(i = 7; i >= 0; --i)
    {
        xp = lkp->f_key[i].k_xbu;
        sp = lkp->i_key[i];
        pp = lkp->f_key[i].k_bpu;

        b_rnd(15); b_rnd(14); b_rnd(13); b_rnd(12);
        b_rnd(11); b_rnd(10); b_rnd( 9); b_rnd( 8);
        b_rnd( 7); b_rnd( 6); b_rnd( 5); b_rnd( 4);
        b_rnd( 3); b_rnd( 2); b_rnd( 1); b_rnd( 0);
    }

    put_block(blk);
};

int utf_strlen(char *source)
{
    int a = 0;
    int res = 0;

    while (source[a++])
        if ((source[a - 1] >= 'A' && source[a - 1] <= 'Z') || (source[a - 1] >= 'a' && source[a - 1] <= 'z') || source[a - 1] == ' '
            || source[a - 1] == ',' || source[a - 1] == '.' || source[a - 1] == '!' || source[a - 1] == '?' || source[a - 1] == ':')
            res++;

    return res;
}

char text_filter(char* in, char* out, int str_len)
{
    int i = 0;
    int j = 0;
    //strcpy(out, "");
    while (in[i] != 0)
    {
        if ((in[i] >= 'A' && in[i] <= 'Z') || (in[i] >= 'a' && in[i] <= 'z') || in[i] == ' '
            || in[i] == ',' || in[i] == '.' || in[i] == '!' || in[i] == '?' || in[i] == ':' || i < strlen(in)) 
        {
            i++;
        }
        else
        {
            for (j = i; j < str_len; j++)
                in[j] = in[j+1];
        }
    }
    sprintf(out, "%.*s", str_len, in);
    strcat(out, "\0");

    printf("Full text after filter is: \"%s\" \n\n\n", out);
}

int check_char(char in)
{
    if ((in >= 'A' && in <= 'Z') || (in >= 'a' && in <= 'z') || in == ' '
        || in == ',' || in == '.' || in == '!' || in == '?' || in == ':')
    {
        return 1;
    }
    else 
    {
        return 0;
    }
}


//Primer - pobaytovoe 4tenie nevozmojno, nujno konvertirovat stroki d massiv iz integer'ov

//char decrypt_full(char* in, char* out)
//{
//    int i = 1;
//    int j = 1;
//    int d;
//    char* buffer_part[4];
//    char* buffer_temp[4];
//
//    strcpy(buffer_temp, "");
//    strcpy(buffer_part, "");
//    //strcat(buffer_temp, "\0");
//    //strcat(buffer_part, "\0");
//    //strcat(buffer_full, "\0");
//
//    for (; i < strlen(in) / 4; i +=4)
//    {
//        //sprintf(buffer_part, "%.16s", buffer_full);
//        //for (; j < 5; j++)
//        //{
//
//        //strcat(buffer_part[j], "%c", buffer_full[j]);
//
//            buffer_part[0] = in[i - 1];
//
//            buffer_part[1] = in[i];
//
//            buffer_part[2] = in[i + 1];
//
//            buffer_part[3] = in[i + 2];
//
//        //}
//        //strcat(buffer_part, "\0");
//        decrypt(buffer_part, buffer_temp);
//        strcpy(out, buffer_temp);
//
//        printf("%s", out);
//
//        /*while (buffer_part[j] != '\0')
//        {
//            printf("%c", buffer_part[j]);
//            j++;
//        }*/
//
//    }
//
//    //strcat(out, "\0");
//}

char decrypt_full(char* in, char* out)
{
    //int d = utf_strlen(in) - 1;
    char* buffer_full[128];
    char* buffer_part[128];
    char* buffer_temp[16];
    char* buffer_out[16];

    strcpy(buffer_temp, "");
    strcpy(buffer_part, "");
    strcpy(buffer_full, "");
    //strcat(buffer_full, "\0");

    strcpy(buffer_part, in);

    for (int i = 0; i < 28; i += 4)
    {

        //printf("\t\t(text 16 chars)\t %.16s \n\n", buffer_part);
        ////////////////////memmove(buffer_part, buffer_part + 4, strlen(buffer_part));
        decrypt(buffer_part, buffer_temp);
        strncat(buffer_full, buffer_temp, 16);
        //printf("\t(text decrypted 16 chars)\t %.16s \n\n", buffer_temp);

        memmove(buffer_part, buffer_part + 4, strlen(buffer_part));
    }
    int d = utf_strlen(buffer_full) - 1;
    strncpy(out, buffer_full, d);
    //printf("\n\n(full)\t %s \n\n", buffer_full);
    //strncpy(out, buffer_full, d + 1);

}

char encrypt_full(char* in, char* out)
{
    //int i = 0;
    int j = 1;
    int d = utf_strlen(in) - 1;
    char* buffer_full[32];
    char* buffer_part[16];
    char* buffer_temp[16];
    char* buffer_out[16];

    //strcpy(buffer_temp, "");
    //strcpy(buffer_part, "");
    strcpy(buffer_full, "");
    //strcat(buffer_full, "\0");



    sprintf(buffer_part, in);

    for (int i = 0; i < 28; i +=4)
    {

        //printf("\t\t(text 16 chars)\t %.16s \n\n", buffer_part);
        ////////////////////memmove(buffer_part, buffer_part + 4, strlen(buffer_part));
        encrypt(buffer_part, buffer_temp);
        strncat(buffer_full, buffer_temp, 16);
        //printf("\t(text crypted 16 chars)\t %.16s \n\n", buffer_temp);

        decrypt(buffer_temp, buffer_out);

        //printf("(text decrypted 16 chars)\t %.16s \n\n", buffer_out);

        memmove(buffer_part, buffer_part + 4, strlen(buffer_part));
    }

    //strcat(buffer_full, "\0");
    //printf("(full)\t %s \n\n", buffer_full);
        /*while (buffer_part[j] != '\0')
        {
            printf("%c", buffer_part[j]);
            j++;
        }*/
    strncpy(out, buffer_full, d+1);
    //strcat(out, "\0");
    //strcat(out, "\0");
}

void main(void)
{
    
    // HOW TO USE -> Dlya ispolzovaniya programmi obyazatelno sobludyat RAZMERI MASSIVOV. Po skolku dlya pro4teniya
    // bolshogo texta ispolzuetsa sdvig po massivu (memmove), a takje (strncpy) dlya kopirovaniya massivov typa char.
    // Na 4to vliyaet input_key ya do sih por ne znau, t.k. ego izmenenie ne vliyaet na zashifrovannuu informatsiu.
    // Na dannii moment shifrovanie rabotaet v ramkah odnoi programmi...


    // ENG: For using that programm so important follows to massives of chars (char[]), because writing big numbers of symbols
    // (more that 16 chars) provides by memmove and strncpy.
    // P.S. i dont understand on that time what is set_key do, because changes of input_key != changes of crypted information.
    // on that time encrypting and decrypting working only in that program ( i dont try to separate )...

    printf("\n\nPROGRAM\n\tIS\n\t\tSTART\n");


    FILE* text_file = fopen("text.txt", "r");

    char* text_raw[16];

    fread(text_raw, sizeof(char), 48, text_file);
    fclose(text_file);

    int str_len = 0;

    str_len = utf_strlen(text_raw);

    char* text[32];
    
    text_filter(text_raw, text, str_len);

    char full_crypted_text[64];
    char full_decrypted_text[64];

    int key_check = 0;

    char* input_key[8];

    int key_len = 0;

    while (key_check == 0)
    {
        printf("Input keyword here :");
        scanf("%s", input_key);

        key_len = strlen(input_key);
        if (key_len < 4 || key_len > 15)
        {
            printf("Key is wrong, try again ! \n");
        }
        else
        {
            key_check = 1;
            set_key(input_key, key_len);
        }
    }

    //sprintf(input_key, "BBBGGGGS");
    //set_key(input_key, strlen(input_key));

    //char* text[16];
    //sprintf(text, "Simple text Simple text Simple text Simple text ");

    char* textout[16];

    printf("Your key is: \"%s\" \n\n\n", input_key);

    printf("Your text is: \"%s\" \n\n\n", text);

    printf("Crypted key (format 1:256 and 8 rings) is: \n");


    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            printf("%i ", loc_key.i_key[i][j]);
        }
        printf("\n \n");
    }

    encrypt(text, textout);

    printf("Your encrypted text is: \"%.16s\" \n", textout);

    /*for (int i = 0; i < 16; i++)
    {
        printf("%i ", test[i]);
    }*/

    printf("\n \n");

    char* text_encrypt[16];

    decrypt(textout, text_encrypt);

    int str_len2 = utf_strlen(text_encrypt);

    printf("Your decrypted text is: \n");
    
    printf("%.*s \n \n", str_len2, text_encrypt);

    strcpy(full_crypted_text, "");
    //strcat(full_crypted_text, "\0");
    //strcat(full_crypted_text, text);

    int str_len3 = utf_strlen(text);

    printf("And full encrypted text is: \n");
    encrypt_full(text, full_crypted_text);
    printf("\t\t(print out)\t %.*s \n \n \n", str_len3, full_crypted_text);

    printf("And full decrypted text is: \n");
    decrypt_full(full_crypted_text, full_decrypted_text);
    printf("\t\t(print out)\t %.*s \n", str_len3, full_decrypted_text);
    //char full_decrypted_text[49];
    //printf("\n\n");
    //printf("And full decrypted text is: \n");
    //decrypt_full(full_crypted_text, full_decrypted_text);
    //printf("%s \n", full_crypted_text);
    //strcpy(full_crypted_text, "\0");
    //text_filter(text, str_len2);
}