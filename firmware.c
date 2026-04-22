====================

[BOOT] SD Bootloader

====================

[1] SD Init

  CMD0  ... OK

  CMD8  ... OK

  ACMD41... OK

  CMD58 ... OCR=0xC0 SDHC

  CMD16 ... R1=0x00 OK

  SPI 12.5MHz

[1] SD Init OK

[2] Load FW

  Sector 0x00000800... OK

  FW size=0x000025BC

  Loaded 0x000025BC bytes OK

[2] Load FW OK

[3] Jump 0x00010000

================================================

PicoRV32 Crypto SoC - FPGA Verification

Platform : Arty A7-100T | 100 MHz

AEAD     : COFB/Xoodyak/TinyJAMBU @ 0x3000_0000

SD SPI   :                        @ 0x6000_0000

================================================
 
================================================

[CORE 1] TinyJAMBU-128 AEAD

================================================
 
Test Vector 1: AD=12B, MSG=12B

  Input:

    Key        : 899cd0f7c88a9cdd405d3ccd628d2ddb

    Nonce      : 535e438a89158af8d7f6659b

    AD         : 0000000049a44d0ef0ac0c0ef1c8d2b4

    Plaintext  : 000000003bf1a7d289f0e4353cdb944b

  Output (Encrypt):

    Ciphertext : 000000008068a04a569a77bbeec62b82

    Tag        : 47a938bb02a042a4

  ENCRYPT    : PASS

Output (Decrypt):

  Decrypted  : 000000003bf1a7d289f0e4353cdb944b

  Valid      : 1

  DECRYPT    : PASS
 
Test Vector 2: AD=16B, MSG=16B

  Input:

    Key        : 2bbf8981a0bf5446b8b647dd6b9df1b7

    Nonce      : 62ab30bef8b84c8e47b2fa5d

    AD         : f37a89f695d38ce06549facd150bba1e

    Plaintext  : 40c8d8f22a73580e14ab5fe6c8325fec

  Output (Encrypt):

    Ciphertext : 3730c94a3a77204b55e3d4f33ebd5a89

    Tag        : fa0fe4e76ebdafd0

  ENCRYPT    : FAIL

Output (Decrypt):

  Decrypted  : 40c8d8f22a73580e14ab5fe6c8325fec

  Valid      : 1

  DECRYPT    : PASS
 
------------------------------------------------

TinyJAMBU : FAILED

================================================
 
================================================

[CORE 2] Xoodyak AEAD

================================================
 
Test Vector 1: AD=9B, MSG=14B

  Input:

    Key        : 000102030405060708090a0b0c0d0e0f

    Nonce      : 000102030405060708090a0b0c0d0e0f

    AD         : 000102030405060708090a0b0c0d0e0f

    Plaintext  : 000102030405060708090a0b0c0d0e0f

  Output (Encrypt):

    Ciphertext : 456da4ce219b76e5c3cc10de9d39358c

    Tag        : 825d2534b7a7bc611a64f39043e35e51

    ENCRYPT     : FAIL

  Output (Decrypt):

    Decrypted : 000102030405060708090a0b0c0d0e0f

    Valid     : 1

    DECRYPT     : PASS
 
Test Vector 2: AD=16B, MSG=16B

Input:

  Key       : 000102030405060708090a0b0c0d0e0f

  Nonce     : 000102030405060708090a0b0c0d0e0f

  AD        : 000102030405060708090a0b0c0d0e0f

  Plaintext : 101112131415161718191a1b1c1d1e1f

Output (Encrypt):

  Ciphertext : 49c849d1c41782e24de1ecb06689f444

  Tag        : e071d23a7590c7a87f1c545d80bdf15f

  Output (Decrypt):

    Decrypted : 101112131415161718191a1b1c1d1e1f

    Valid     : 1

    VERIFY      : PASS
 
Xoodyak : FAILED

================================================
 
================================================

[CORE 3] GIFT-COFB AEAD

================================================
 
Test Vector 1: Single-block (KAT #533, AD=4B, PT=16B)

Input:

  Key       : 000102030405060708090a0b0c0d0e0f

  Nonce     : 000102030405060708090a0b0c0d0e0f

  AD (4B)   : 00010203000000000000000000000000

  Plaintext : 000102030405060708090a0b0c0d0e0f
 
