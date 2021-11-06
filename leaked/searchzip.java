package leaked;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class searchzip {
    public static void main(String[] args) throws Exception {
        File glob = new File("memory.dmp");
        FileInputStream globFis = new FileInputStream(glob);

        byte[] temp = new byte[1048576];
        ByteArrayInputStream bais = new ByteArrayInputStream(temp);
        
        int read;
        long position = 0x6F353;
        globFis.skip(position);
        while((read = globFis.read(temp)) != -1) {
            int offset = searchZip(temp, read);
            if(offset == -1) {
                position += read;
                continue;
            }
            if(offset != 0) {
                int rewind = read - offset;
                System.out.println("Making the header at the start, at: " + (position + offset) + " rewinding: " + rewind);
                globFis.skip(-rewind);
                position += read - rewind;
                continue;
            }
            System.out.println("Detected zip at position: " + (position + offset));

            ZipInputStream zipis = new ZipInputStream(bais);
            ZipEntry zipEntry;
            try {
                while((zipEntry = zipis.getNextEntry()) != null) {
                    File outFile = new File("outzip/" + zipEntry.getName());
                    outFile.getParentFile().mkdirs();
                    System.out.println(zipEntry.getName());
                    extractZip(zipis, outFile);
                    zipis.closeEntry();
                }
            } catch(Throwable e) {
                // e.printStackTrace();
            }

            int residue = bais.available();
            globFis.skip(-residue);
            position += read - residue;
            bais.reset();
        }
    }
    public static int searchZip(byte[] bytes, int length) throws IOException {
        int seq = 0;
        int i = 0;
        for(; i < length && seq != 4; i++) {
            if(seq == 0 && bytes[i] == (byte) 0x50) { seq++; continue; }
            if(seq == 1 && bytes[i] == (byte) 0x4b) { seq++; continue; }
            if(seq == 2 && bytes[i] == (byte) 0x03) { seq++; continue; }
            if(seq == 3 && bytes[i] == (byte) 0x04) { seq++; continue; }
            seq = 0;
        }

        if(seq == 0) return -1;
        return i - seq;
    }
    public static void extractZip(ZipInputStream zipis, File outFile) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(outFile);
        int len;
        byte[] content = new byte[1024];
        while((len = zipis.read(content)) > 0) {
            fileOutputStream.write(content, 0, len);
        }
        fileOutputStream.close();
    }
}
