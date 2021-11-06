package leaked;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class search {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static void main(String[] args) throws Exception {
        File functionHeadersFile = new File("filtered");
        String functionHeadersString = new String(Files.readAllBytes(functionHeadersFile.toPath()));
        Pattern pattern = Pattern.compile("^([a-zA-Z0-9]+)\\s*([a-zA-Z0-9]+)\\s*([a-zA-Z])\\s*([a-zA-Z0-9_\\.]+)$", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(functionHeadersString);

        Pattern emailMatch = Pattern.compile("[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]+", Pattern.CASE_INSENSITIVE);

        File glob = new File("memory.dmp");
        FileInputStream globFis = new FileInputStream(glob);
        byte[] temp = new byte[65536];
        List<String> views = new ArrayList<>(4);
        String emptyAlign = new String(new char[8 + 1 + 8 + 1 + 1 + 64 + 1 + 1]).replace("\0", " ");

        System.out.println("Length: " + glob.length());
        long lastAddress = 0;
        while(matcher.find()) {
            // ffffffff 81a49330
            long address = Long.parseLong(matcher.group(1).substring(8), 16);
            long length = Long.parseLong(matcher.group(2), 16);
            String type = matcher.group(3);
            String function = matcher.group(4);
            if(length > Integer.MAX_VALUE) {
                System.err.println("Length too large, function: " + function + ", length: " + length);
                continue;
            }

            long skip = address - lastAddress;
            globFis.skip(skip);
            lastAddress = address;
            // System.out.println("Skipping: " + skip);

            while(temp.length < length)
                temp = new byte[temp.length * 2];
            int read = globFis.read(temp, 0, (int) length);
            if(read != length) {
                System.err.println("Read length is not matching with targeted length, function: " + 
                        function + ", length: " + length + ", read: " + read);
            }

            String test = new String(temp, 0, read);
            Matcher emailMatcher = emailMatch.matcher(test);
            while(emailMatcher.find()) {
                String email = emailMatcher.group(0);
                if(!email.contains("gmail") && !email.contains("yahoo")) continue;
                // if(email.contains("ubuntu") || email.contains("debian") || email.contains("android"))
                //     continue;
                // if(email.contains("png") || email.contains("dev@") || email.contains("lists."))
                //     continue;
                view(test, email, 20, views);
            }
            // view(test, "txt", 40, views);
            // view(test, "user", 40, views);
            view(test, "hology", 40, views);
            // view(test, "password", 40, views);
            // view(test, "flag", 40, views);
            // view(test, "gmail", 40, views);
            view(test, "Flag", 40, views);
            if(views.size() == 0)
                continue;

            System.out.print(String.format("%08x %08x %s %64s %s\n", address, length, type, function, views.get(0)));
            for(int i = 1; i < views.size(); i++)
                System.out.println(emptyAlign + views.get(i));
            views.clear();
            // File out = new File(String.format("out/%08x_%s", address, function));
            // if(!out.exists() && !out.createNewFile())
            //     throw new Error("cannot write to file " + out.getPath());
            // try(FileOutputStream fos = new FileOutputStream(out)) {
            //     fos.write(temp, 0, read);
            //     fos.flush();
            // }
        }
    }
    public static void view(String test, String what, int range, List<String> views) {
        int firstAtChar = test.indexOf(what);
        while(firstAtChar != -1) {
            int beforeFirstAtChar = firstAtChar;
            int afterFirstAtChar = firstAtChar + what.length();
            int startView = Math.max(0, beforeFirstAtChar - range);
            int endView = Math.min(test.length(), afterFirstAtChar + range);
            String view = escapeNonAscii(test.substring(startView, beforeFirstAtChar)) + 
                    ANSI_YELLOW + test.substring(beforeFirstAtChar, afterFirstAtChar) + ANSI_RESET +
                    escapeNonAscii(test.substring(afterFirstAtChar, endView));
            views.add(view);
            firstAtChar = test.indexOf(what, firstAtChar + 1);
        }
    }
    public static String escapeNonAscii(String txt) {
        return txt.replaceAll("[^\\p{InBasic_Latin}]|[\\s\\033]", ".");
    }
    public static void skipUnsigned(InputStream is, long skip) throws IOException {
        if(skip >= 0) {
            is.skip(skip);
            return;
        }
        while(skip < 0) {
            skip -= Long.MAX_VALUE;
            is.skip(Long.MAX_VALUE);
        }
        is.skip(skip);
    }
}
