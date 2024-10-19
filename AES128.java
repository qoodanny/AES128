import java.util.*; 
import java.io.*;
public class AES128{
    public static void main (String[] args){
        try{
            byte[] txt = new byte[16];
            byte[] key = new byte[16];
            byte[] cipher = new byte[16];
            byte[] newTxt = new byte[16];
            Scanner reader = new Scanner(new File(args[0]));
            for(int i = 0; i < 16; i++){
                String temp = reader.next();
                txt[i] = hexToByte(temp);
            }

            reader = new Scanner(new File(args[1]));
            for(int i = 0; i < 16; i++){
                String temp = reader.next();
                key[i] = hexToByte(temp);
            }

            cipher = AES128_Encrypt.encrypt(txt, key);
            newTxt = AES128_Decrypt.decrypt(cipher, key);
            System.out.println("End of Processing\n");
        }
        catch(IOException e){
            System.out.println("File in AES Not Working "+ e.getMessage());
        }
        catch(Exception e2){
            System.out.println(e2.getMessage());
        }
    } 

    //Translate a string into a byte
    public static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }
    
    //Translate char into integer
    private static int toDigit(char hexChar) { //helper of hexToByte
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
              "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }
}