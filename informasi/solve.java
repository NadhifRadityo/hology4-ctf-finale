package informasi;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;

public class solve {
    public static void main(String[] args) throws Exception {
        File keyFile = new File("chall/key");
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        File inFile = new File("chall/nilai_akhir.txt.asw");
        byte[] inFileBytes = Files.readAllBytes(inFile.toPath());
        assert(keyBytes.length >= 1032);

        // #define RC4_INT unsigned int (uint32_t) at least 4 bytes
        // key[0] = (RC4_INT) x, key[1] = (RC4_INT) y
        // key[n + 2] = RC4_INT[256]
        // size key = (256 + 2) * 4 = 1032 bytes
        // offset of key[n + 2] = 2 * sizeof(RC4_INT) = 2 * 4 = 8 bytes
        byte[] key = keyBytes;
        int keyLen = keyBytes.length - 1; // perhaps this is a mask?
        byte[] out = new byte[keyLen];
        byte[] indata = inFileBytes;
        int sizeOut = inFileBytes.length;

        byte[] cache1 = new byte[256];
        byte[] cache2 = new byte[263];
        for(int i = 0; i < 0x100; i++) {
            cache1[i] = (byte) i;
            cache2[i] = indata[i % sizeOut];
        }
        int c = 0;
        for(int i = 0; i < 0x100; i++) {
            int a = cache2[i] + cache1[i] + c;
            int b = (a >> 0x1f) >> 0x18;
            c = (a + b & 0xff) - b;
            byte temp = cache1[c];
            cache1[c] = cache1[i];
            cache1[i] = temp;
        }
        c = 0;
        int d = 0;
        for(int i = 0; i < keyLen; i++) {
            int a = (d + 1 >> 0x1f) >> 0x18;
            d = (d + 1 + a & 0xff) - a;
            a = ((c + cache1[d]) >> 0x1f) >> 0x18;
            c = (c + cache1[d] + a & 0xff) - a;
            byte temp = cache1[c];
            cache1[c] = cache1[d];
            cache1[d] = temp;
            out[i] = (byte) (cache1[(cache1[c] + cache1[d])] ^ key[8 + i - 8]);
        }

        File outputFile = new File("out");
        try(FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(out);
        }
    }
}