import java.util.*; 
import java.io.*;
import java.nio.ByteBuffer;

class AES128_Encrypt{
    static byte[] encrypt(byte[] txt, byte[] key){
        int[][] keys = new int[11][4];
        keys = keyExpansionEncrypt(key);

        printEncrypt(txt, key, keys);
        
        byte[] cipher = new byte[16];
        for(int i = 0; i < 16; i++){
            cipher[i] = (byte) (txt[i] ^ key[i]);
        }

        byte[][] state = new byte[4][4];
        state = putState(cipher);

        for(int r = 1; r < 11; r++){
            state = subState(state);
            state = shiftRows(state);
            if(r <= 9){
                state = mixColumns(state);
                printStateAfterMixCol(state, r);
            }
            state = stateXorKey(state, keys[r]);
        }
        printCipher(state);
        cipher = stateToArray(state);
        return cipher;
    }

    static int[][] keyExpansionEncrypt(byte[] key){
        int[][] keys = new int[11][4];
        final int[] constant = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};
        
        for(int i = 0; i < 4; i++){
            int temp = 0;
            for(int j = 0+i*4; j < 4+i*4; j++){
                temp = (temp << 8)+(key[j] & 0xFF); //Masking the required part
            }
            keys[0][i]= temp;
        }

        for(int i = 1; i < 11; i++){
            int shift = Integer.rotateLeft(keys[i-1][3], 8);
            byte[] shiftArray = ByteBuffer.allocate(4).putInt(shift).rewind().array();
            for(int j = 0; j < 4; j++){
                shiftArray[j] = subBytes(shiftArray[j]);
            }
            int newShift = ByteBuffer.allocate(4).put(shiftArray).rewind().getInt();
            keys[i][0] = keys[i-1][0] ^ constant[i-1] ^ newShift;
            keys[i][1] = keys[i-1][1] ^ keys[i][0];
            keys[i][2] = keys[i-1][2] ^ keys[i][1];
            keys[i][3] = keys[i-1][3] ^ keys[i][2];
        }
        return keys;
    }

    static byte subBytes(byte value){
        try{
            byte ans;
            int x, y, count; //calculate move how many times in sbox
            String hex, xhex, yhex;
            Scanner reader = new Scanner(new File(""));

            hex = byteToHex(value);
            xhex = String.valueOf(hex.charAt(0));
            yhex = String.valueOf(hex.charAt(1));
            x = Integer.parseInt(xhex, 16);
            y = Integer.parseInt(yhex, 16);
            count = 16 * x + y + 1;

            String newHex = "";
            for(int i = 0; i < count; i++){
                newHex = reader.next();
            }
            ans = AES128.hexToByte (newHex);
            return ans;
        }
        catch(IOException e){
            System.out.println("File in Encryption Not Working "+ e.getMessage());
            return (byte)-1;
        }
        catch(Exception e2){
            System.out.println(e2.getMessage());
            return (byte)-1;
        }
    }

    static byte[][] subState(byte[][] state){
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[i][j] = subBytes(state[i][j]);
            }
        }
        return state;
    }

    static void printEncrypt(byte[] txt, byte[] key, int[][] keys){
        String plaintext = "Plaintext\n";
        String keytext = "Key\n";
        String keySchedule = "Key Schedule:\n";

        for(int i = 0; i < 16; i++){
            plaintext = plaintext.concat(byteToHex(txt[i]));
        }
        System.out.println(plaintext);

        for(int i = 0; i < 16; i++){
            keytext = keytext.concat(byteToHex(key[i]));
        }
        System.out.println(keytext);

        for(int i = 0; i < 11; i++){
            for(int j = 0; j < 4; j++){
                keySchedule = keySchedule.concat(toFormatHexString(keys[i][j]));
                if(j != 3)
                    keySchedule = keySchedule.concat(",");
            }
            keySchedule = keySchedule.concat("\n");
        }
        System.out.println(keySchedule);
        System.out.println();
        System.out.println("ENCRYPTION PROCESS");
        System.out.println("------------------");
        System.out.println("Plain Text:");
        System.out.println(toFormatByteArrayString(txt));
        System.out.println();
    }

    //Translate a byte into a hexadecimal string
    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    //Put a 1D Array into 2D Array
    public static byte[][] putState(byte[] array){
        byte[][] state = new byte[4][4]; //state[row][col]
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[j][i] = array[j+i*4];
            }
        }
        return state;
    }

    //Put 2D Array into 1D Array
    public static byte[] stateToArray(byte[][] state){
        byte[] array = new byte[16];
        int count = 0;
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                array[count++] = state[j][i];
            }
        }
        return array;
    }

    static byte[][] shiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            state[i] = leftRotate(state[i], i);
        }
        return state;
    }

    //Helper Method of shiftRows
    private static byte[] leftRotate(byte[] row, int times){
        if (times % 4 == 0) {
            return row;
        }
        while (times > 0) {
            byte temp = row[0];
            for (int i = 0; i < 3; i++) {
                row[i] = row[i + 1];
            }
            row[3] = temp;
            times--;
        }
        return row;
    }

    static byte[][] mixColumns(byte[][] state){
        for(int j = 0; j < 4; j++){ //run every col in state
            byte[] colInState = new byte[4];

            for(int i = 0; i < 4; i++){ //run every element in a col
                colInState[i] = state[i][j];
            }

            byte[] newCol = new byte[4];
            newCol = colOperation(colInState);

            for(int k = 0; k < 4; k++){ 
                state[k][j] = newCol[k];
            }
        }
        return state;
    }

    //Helper of colOperation, a, is the element in state and b must be 01 or 02 or 03
    private static byte multiplyBytes(byte a, byte b){
        if(b == (byte)1)
            return a;
        if(b == (byte)2){
            int value = a;
            byte c, d;

            c = (byte)(a << 1);
            if(value < 0){ //bit shifted out is 1
                d = (byte)(c ^ 27); //where {1b} is 27 in base 10
                return d;
            }
            else
                return c;
        }
        if(b == (byte)3){
            int value = a;
            byte c, d;

            c = (byte)(a << 1);
            if(a < 0)
                d = (byte)(c ^ 27); 
            else 
                d = c;

            d = (byte)(d ^ a);
            return d;
        }
        System.out.println("b value in multiplyBytes Error");
        return (byte) -1;
    }

    //Helper of mixColumns
    private static byte[] colOperation(byte[] colInState){
        byte[] newCol = new byte[4];
        newCol[0] = (byte)(multiplyBytes(colInState[0],(byte)2) ^ multiplyBytes(colInState[1], (byte)3) ^ multiplyBytes(colInState[2], (byte)1) ^ multiplyBytes(colInState[3], (byte)1));
        newCol[1] = (byte)(multiplyBytes(colInState[0],(byte)1) ^ multiplyBytes(colInState[1], (byte)2) ^ multiplyBytes(colInState[2], (byte)3) ^ multiplyBytes(colInState[3], (byte)1));
        newCol[2] = (byte)(multiplyBytes(colInState[0],(byte)1) ^ multiplyBytes(colInState[1], (byte)1) ^ multiplyBytes(colInState[2], (byte)2) ^ multiplyBytes(colInState[3], (byte)3));
        newCol[3] = (byte)(multiplyBytes(colInState[0],(byte)3) ^ multiplyBytes(colInState[1], (byte)1) ^ multiplyBytes(colInState[2], (byte)1) ^ multiplyBytes(colInState[3], (byte)2));
        return newCol;
    }

    static void printStateAfterMixCol(byte[][] state, int r){
        System.out.println("State after call "+ r +" to MixColumns()");
        System.out.println("-------------------------------------");
        String words = "";
        for(int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                words = words.concat(byteToHex(state[j][i]));
                words = words.concat("  ");
            }
            words = words.concat("   ");
        }
        System.out.println(words);
        System.out.println();
    }

    static byte[][] stateXorKey(byte[][] state, int[] keySchedule){
        String message = "", key = "";

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                message = message.concat(byteToHex(state[j][i]));
            }
        }

        for(int i = 0; i < 4; i++){
            key = key.concat(toFormatHexString(keySchedule[i]));
        }

        byte[] byteMessage = new byte[16];
        byte[] byteKey = new byte[16];
        byte[] addRound = new byte[16];
        byteMessage = decodeHexString(message);
        byteKey = decodeHexString(key);

        for(int i = 0; i < 16; i++){
            addRound[i] = (byte) (byteMessage[i] ^ byteKey[i]);
        }

        state = putState(addRound);
        return state;
    }

    //Turn hexadecimal string into a byte array
    public static byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
              "Invalid hexadecimal String supplied.");
        }
        
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = AES128.hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    //To Print a Beautiful Key Schedule
    public static String toFormatHexString(int n) {
        return String.format("%8s", Integer.toHexString(n)).replace(' ', '0');
    }

    //To Print A Beautiful Byte Array a
    public static String toFormatByteArrayString (byte[] a){
        String output = "";
        for(int i = 0; i < 16; i++){
            output = output.concat(byteToHex(a[i]));
            output = output.concat("  ");
            if(i == 3 || i == 7 || i == 11)
                output = output.concat("   ");
        }
        return output;
    }

    static void printCipher(byte[][] state){
        System.out.println("CipherText:");
        String words = "";
        for(int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                words = words.concat(byteToHex(state[j][i]));
                words = words.concat("  ");
            }
            words = words.concat("   ");
        }
        System.out.println(words);
        System.out.println();
        System.out.println();
        System.out.println();
    }
}