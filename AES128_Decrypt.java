import java.nio.*;
import java.util.*; 
import java.io.*;

public class AES128_Decrypt {
    static byte[] decrypt(byte[] cipher, byte[] key){
        
        int[][] keys = new int[11][4];
        keys = AES128_Encrypt.keyExpansionEncrypt(key);

        printDecrypt(cipher);

        byte[] txt = new byte[16];
        byte[] keyTen = new byte[16];
        keyTen = intToByteArray(keys[10]);

        for(int i = 0; i < 16; i++){
            txt[i] = (byte)(cipher[i] ^ keyTen[i]);
        }
        
        byte[][] state = new byte[4][4];
        state = AES128_Encrypt.putState(txt);
        
        for(int r = 9; r > -1; r--){
            state = invShiftRows(state);
            state = invSubState(state);
            state = AES128_Encrypt.stateXorKey(state, keys[r]);
            if(r >= 1){
                state = invMixColumns(state);
                printStateAfterinvMixCol(state, r);
            }
        }
        printPlaintext(state);
        return txt;
    }

    static void printDecrypt(byte[] cipher){
        System.out.println("DECRYPTION PROCESS");
        System.out.println("------------------");
        System.out.println("CipherText:");
        System.out.println(AES128_Encrypt.toFormatByteArrayString(cipher));
        System.out.println();
    }

    static byte[] intToByteArray(int[] array){
        ByteBuffer byteBuffer = ByteBuffer.allocate(array.length * 4);
        IntBuffer intBuffer = byteBuffer.asIntBuffer();
        intBuffer.put(array);

        byte[] value = byteBuffer.array();
        return value;
    }

    static byte[][] invShiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            state[i] = rightRotate(state[i], i);
        }
        return state;
    }

    //Helper Method of invShiftRow
    private static byte[] rightRotate(byte[] row, int times) {
        if (times % 4 == 0) {
            return row;
        }
        while (times > 0) {
            byte temp = row[3];
            for (int i = 3; i > 0; i--) {
                row[i] = row[i - 1];
            }
            row[0] = temp;
            times--;
        }
        return row;
    }

    static byte invSubBytes(byte value){
        try{
            byte ans;
            int x, y, count; //calculate move how many times in inv_sbox
            String hex, xhex, yhex;
            Scanner reader = new Scanner(new File("/Users/Danny/Documents/CS/VS/COMP 4140/A3/inv_sbox.txt"));

            hex = AES128_Encrypt.byteToHex(value);
            xhex = String.valueOf(hex.charAt(0));
            yhex = String.valueOf(hex.charAt(1));
            x = Integer.parseInt(xhex, 16);
            y = Integer.parseInt(yhex, 16);
            count = 16 * x + y + 1;

            String newHex = "";
            for(int i = 0; i < count; i++){
                newHex = reader.next();
            }
            ans = AES128.hexToByte(newHex);
            return ans;
        }
        catch(IOException e){
            System.out.println("File in Decryption Not Working "+ e.getMessage());
            return (byte)-1;
        }
        catch(Exception e2){
            System.out.println(e2.getMessage());
            return (byte)-1;
        }
    }

    static byte[][] invSubState(byte[][] state){
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[i][j] = invSubBytes(state[i][j]);
            }
        }
        return state;
    }

    static byte[][] invMixColumns(byte[][] state){
        for(int j = 0; j < 4; j++){ //run every col in state
            byte[] colInState = new byte[4];

            for(int i = 0; i < 4; i++){ //run every element in a col
                colInState[i] = state[i][j];
            }

            byte[] newCol = new byte[4];
            newCol = invColOperation(colInState);

            for(int k = 0; k < 4; k++){ 
                state[k][j] = newCol[k];
            }
        }
        return state;
    }

    //Helper of inMixColumns
    private static byte[] invColOperation(byte[] colInState){
        byte[] newCol = new byte[4];
        //{0e} = 14 in base 10, {0b} = 11, {0d} = 13, {09} = 9
        newCol[0] = (byte)(invMultiplyBytes(colInState[0],(byte)14) ^ invMultiplyBytes(colInState[1], (byte)11) ^ invMultiplyBytes(colInState[2], (byte)13) ^ invMultiplyBytes(colInState[3], (byte)9));
        newCol[1] = (byte)(invMultiplyBytes(colInState[0],(byte)9) ^ invMultiplyBytes(colInState[1], (byte)14) ^ invMultiplyBytes(colInState[2], (byte)11) ^ invMultiplyBytes(colInState[3], (byte)13));
        newCol[2] = (byte)(invMultiplyBytes(colInState[0],(byte)13) ^ invMultiplyBytes(colInState[1], (byte)9) ^ invMultiplyBytes(colInState[2], (byte)14) ^ invMultiplyBytes(colInState[3], (byte)11));
        newCol[3] = (byte)(invMultiplyBytes(colInState[0],(byte)11) ^ invMultiplyBytes(colInState[1], (byte)13) ^ invMultiplyBytes(colInState[2], (byte)9) ^ invMultiplyBytes(colInState[3], (byte)14));
        return newCol;
    }

    //Helper of invColOperation, a, is the element in state and b must be 09,11,13,14
    private static byte invMultiplyBytes(byte a, byte b){
        byte ans = 0;
        byte temp = 0;
        byte temp2 = 0;

        if(b == (byte)9){
            ans = multimultipy2(a, 3);
            ans = (byte)(ans ^ a);
            return ans;
        }
        if(b == (byte)11){
            ans = multimultipy2(a, 3);
            temp = multimultipy2(a, 1);
            ans = (byte)(ans ^ temp ^ a);
            return ans;
        }
        if(b == (byte)13){
            ans = multimultipy2(a, 3);
            temp = multimultipy2(a, 2);
            ans = (byte)(ans ^ temp ^ a);
            return ans;
        }
        if(b == (byte)14){
            ans = multimultipy2(a, 3);
            temp = multimultipy2(a, 2);
            temp2 = multimultipy2(a, 1);
            ans = (byte)(ans ^ temp ^ temp2);
            return ans;
        }
        System.out.println("b value in invMultiplyBytes Error");
        return (byte) -1;
    }

    //Helper of multimultipy2()
    private static byte multipy2(byte a){
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

    //Helper of invMultiplyBytes()
    private static byte multimultipy2(byte a, int times){
        byte ans = a;
        for (int i = 0; i < times; i++){
            ans = multipy2(ans);
        }
        return ans;
    }

    static void printStateAfterinvMixCol(byte[][] state, int r){
        int count = 10 - r;
        System.out.println("State after call "+ count +" to InvMixColumns()");
        System.out.println("----------------------------------------------");
        printState(state);
        System.out.println();
    }

    //Helper of printStateAfterinvMixCol()
    static void printState(byte[][] state){
        String words = "";
        for(int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                words = words.concat(AES128_Encrypt.byteToHex(state[j][i]));
                words = words.concat("  ");
            }
            words = words.concat("   ");
        }
        System.out.println(words);
    }

    static void printPlaintext(byte[][] state){
        System.out.println("Plaintext:");
        printState(state);
        System.out.println();
    }
}
