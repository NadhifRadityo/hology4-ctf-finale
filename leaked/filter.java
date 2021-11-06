package leaked;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class filter {
    public static void main(String[] args) throws Exception {
        // https://en.wikipedia.org/wiki/System.map
        File functionHeadersFile = new File("boot/System.map-5.4.0-89-generic");
        String functionHeadersString = new String(Files.readAllBytes(functionHeadersFile.toPath()));
        Pattern pattern = Pattern.compile("^([a-zA-Z0-9]+)\\s*([a-zA-Z])\\s*([a-zA-Z0-9_\\.]+)$", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(functionHeadersString);

        File filteredFunctionsFile = new File("filtered");
        FileWriter writer = new FileWriter(filteredFunctionsFile);

        // int minLength = "email:password_toolsyangdipelajari_namafileyangdidownload_isifile".length();
        int minLength = 0;
        long lastAddress = 0;
        String lastType = null;
        String lastFunction = null;
        while(matcher.find()) {
            long address = Long.parseUnsignedLong(matcher.group(1), 16);
            String type = matcher.group(2);
            String function = matcher.group(3);

            long length = address - lastAddress;
            // "jangan abaikan proses"
            boolean adressIsUserSpace = true;
            boolean lastAdressIsUserSpace = true;
            // boolean adressIsUserSpace = Long.compareUnsigned(address, 0xffffffff00000000L) >= 0;
            // boolean lastAdressIsUserSpace = Long.compareUnsigned(lastAddress, 0xffffffff00000000L) >= 0;
            // boolean adressIsUserSpace = Long.compareUnsigned(address, 0xffffffff81000000L) >= 0;
            // boolean lastAdressIsUserSpace = Long.compareUnsigned(lastAddress, 0xffffffff81000000L) >= 0;
            // boolean adressIsUserSpace = Long.compareUnsigned(address, 0xffffffff82000000L) >= 0;
            // boolean lastAdressIsUserSpace = Long.compareUnsigned(lastAddress, 0xffffffff82000000L) >= 0;
            if(adressIsUserSpace && lastAdressIsUserSpace && length >= minLength) {
                String filtered = String.format("%016x %08x %s %s\n", lastAddress, length, lastType, lastFunction);
                System.out.print(filtered);
                writer.write(filtered);
                writer.flush();
            }

            lastAddress = address;
            lastType = type;
            lastFunction = function;
        }
        writer.close();
    }
}
