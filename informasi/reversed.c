for (local_c = 0; (long)local_c < (long)(file1Size - 1); local_c = local_c + 1) {
  printf("%02hhX  ",(ulong)*(byte *)((long)local_28 + (long)local_c));
}

void Decryptor(char *file1,char *file2,char *file3)

{
  long sizeFile2;
  size_t sizeFile1;
  uchar *contentFile2;
  void *local_20;
  RC4_KEY *contentFile1;
  FILE *stream;
  
  stream = fopen(file1,"rb");
  contentFile1 = (RC4_KEY *)readFile(stream,&sizeFile1);
  local_20 = calloc(sizeFile1 + 10,1);
  memset(local_20,0,sizeFile1 + 10);
  stream = fopen(file2,"rb");
  contentFile2 = (uchar *)readFile(stream,&sizeFile2);
  if (0x100 < sizeFile2) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  RC4(contentFile1,sizeFile1 - 1,contentFile2,sizeFile2);
  stream = fopen(file3,"w");
  fwrite(local_20,1,sizeFile1,stream);
  fclose(stream);
  free(local_20);
  free(contentFile1);
  free(contentFile2);
  return;
}



void RC4(RC4_KEY *key, size_t keyLen, uchar *indata, long sizeOut)

{
  int iVar1;
  uint uVar2;
  byte cache1 [256];
  byte cache2 [263];
  byte local_21;
  uint local_20;
  int outAddress;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  local_c = 0;
  local_20 = 0;
  local_10 = 0;
  for (local_14 = 0; local_14 < 0x100; local_14 = local_14 + 1) {
    cache1[local_14] = (byte)local_14;
    cache2[local_14] = indata[(long)local_14 % sizeOut];
  }
  for (local_18 = 0; local_18 < 0x100; local_18 = local_18 + 1) {
    iVar1 = (uint)cache2[local_18] + (uint)cache1[local_18] + local_c;
    uVar2 = (uint)(iVar1 >> 0x1f) >> 0x18;
    local_c = (iVar1 + uVar2 & 0xff) - uVar2;
    local_21 = cache1[local_c];
    cache1[local_c] = cache1[local_18];
    cache1[local_18] = local_21;
  }
  local_c = 0;
  for (outAddress = 0; (long)outAddress < (long)keyLen; outAddress = outAddress + 1) {
    uVar2 = (uint)(local_10 + 1 >> 0x1f) >> 0x18;
    local_10 = (local_10 + 1 + uVar2 & 0xff) - uVar2;
    uVar2 = (uint)((int)(local_c + (uint)cache1[local_10]) >> 0x1f) >> 0x18;
    local_c = (local_c + (uint)cache1[local_10] + uVar2 & 0xff) - uVar2;
    local_21 = cache1[local_c];
    cache1[local_c] = cache1[local_10];
    cache1[local_10] = local_21;
    local_20 = (uint)(byte)(cache1[local_c] + cache1[local_10]);
    *(byte *)(outAddress) =
         cache1[(int)(uint)(byte)(cache1[local_c] + cache1[local_10])] ^
         *(byte *)((long)key->data + (long)outAddress + -8);
  }
  return;
}

