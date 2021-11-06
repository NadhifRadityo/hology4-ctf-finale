package leaked;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.lang.reflect.Field;
import java.util.zip.CRC32;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class searchgzip {
    public static void main(String[] args) throws Exception {
        File glob = new File("memory.dmp");
        FileInputStream globFis = new FileInputStream(glob);

        byte[] temp = new byte[1048576];
        ByteArrayInputStream bais = new ByteArrayInputStream(temp);
        // byte[] temp2 = new byte[65535];
        int gzipLength = 1048576;
        int gzipCounter = 0;
        
        int read;
        long position = 0x6F353;
        globFis.skip(position);
        while((read = globFis.read(temp)) != -1) {
            int offset = searchGzip(temp, read);
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
            System.out.println("Detected gzip at position: " + (position + offset));

            // GZIPInputStream gzipis = new GZIPInputStream(bais);
            // Inflater inf = getInflater(gzipis);
            // byte[] buf = getBuf(gzipis);
            // int len = getLen(gzipis);
            // CRC32 crc = getCrc(gzipis);
            // int i = 0;
            // for(; i < temp2.length; i++) {
            //     if(isValid(bais, inf, buf, len, crc))
            //         break;
            //     gzipis.read(temp2, i, 1);
            // }

            FileOutputStream fos = new FileOutputStream("outgzip/result" + (gzipCounter++));
            // fos.write(temp2, 0, i);
            fos.write(temp, 0, Math.min(read, gzipLength));
            fos.flush();
            fos.close();

            // int residue = bais.available();
            // globFis.skip(-residue);
            // position += read - residue;
            // bais.reset();
            int residue = read - gzipLength;
            globFis.skip(-residue);
            position += read - residue;
        }
    }
    public static int searchGzip(byte[] bytes, int length) throws IOException {
        int seq = 0;
        int i = 0;
        for(; i < length && seq != 3; i++) {
            if(seq == 0 && bytes[i] == (byte) 0x1f) { seq++; continue; }
            if(seq == 1 && bytes[i] == (byte) 0x8b) { seq++; continue; }
            if(seq == 2 && bytes[i] == (byte) 0x08) { seq++; continue; }
            seq = 0;
        }

        if(seq == 0) return -1;
        return i - seq;
    }
    
    public static boolean isValid(InputStream ori, Inflater inf, byte[] buf, int len, CRC32 crc) throws IOException {
        InputStream in = ori;
        int n = inf.getRemaining();
        if (n > 0) {
            in = new SequenceInputStream(
                        new ByteArrayInputStream(buf, len - n, n),
                        new FilterInputStream(in) {
                            public void close() throws IOException { }
                        });
        }
        // Uses left-to-right evaluation order
        if ((readUInt(in) != crc.getValue()) ||
            // rfc1952; ISIZE is the input size modulo 2^32
            (readUInt(in) != (inf.getBytesWritten() & 0xffffffffL)))
            return false;
        return true;
    }

    // public static final Field FIELD_InflaterInputStream_inf;
    // public static final Field FIELD_InflaterInputStream_buf;
    // public static final Field FIELD_InflaterInputStream_len;
    // public static final Field FIELD_GZIPInputStream_crc;
    // static {
    //     try {
    //         FIELD_InflaterInputStream_inf = InflaterInputStream.class.getDeclaredField("inf");
    //         FIELD_InflaterInputStream_buf = InflaterInputStream.class.getDeclaredField("buf");
    //         FIELD_InflaterInputStream_len = InflaterInputStream.class.getDeclaredField("len");
    //         FIELD_GZIPInputStream_crc = GZIPInputStream.class.getDeclaredField("crc");
    //         FIELD_InflaterInputStream_inf.setAccessible(true);
    //         FIELD_InflaterInputStream_buf.setAccessible(true);
    //         FIELD_InflaterInputStream_len.setAccessible(true);
    //         FIELD_GZIPInputStream_crc.setAccessible(true);
    //     } catch(Exception e) {
    //         throw new Error(e);
    //     }
    // }

    // public static Inflater getInflater(InflaterInputStream gzipis) throws Exception {
    //     return (Inflater) FIELD_InflaterInputStream_inf.get(gzipis);
    // }
    // public static byte[] getBuf(InflaterInputStream gzipis) throws Exception {
    //     return (byte[]) FIELD_InflaterInputStream_buf.get(gzipis);
    // }
    // public static int getLen(InflaterInputStream gzipis) throws Exception {
    //     return (int) FIELD_InflaterInputStream_len.get(gzipis);
    // }
    // public static CRC32 getCrc(GZIPInputStream gzipis) throws Exception {
    //     return (CRC32) FIELD_GZIPInputStream_crc.get(gzipis);
    // }

    /*
     * Reads unsigned integer in Intel byte order.
     */
    private static long readUInt(InputStream in) throws IOException {
        long s = readUShort(in);
        return ((long)readUShort(in) << 16) | s;
    }

    /*
     * Reads unsigned short in Intel byte order.
     */
    private static int readUShort(InputStream in) throws IOException {
        int b = readUByte(in);
        return (readUByte(in) << 8) | b;
    }

    /*
     * Reads unsigned byte.
     */
    private static int readUByte(InputStream in) throws IOException {
        int b = in.read();
        if (b == -1) {
            throw new EOFException();
        }
        if (b < -1 || b > 255) {
            // Report on this.in, not argument in; see read{Header, Trailer}.
            throw new IOException(".read() returned value out of range -1..255: " + b);
        }
        return b;
    }
}
