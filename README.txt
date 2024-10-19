//First change the directory of your sbox.txt on your computer in AES128_Encrypt.java
//In the subBytes Method, there is a line for file input need to be replaced
Scanner reader = new Scanner(new File(""));

//Then change the directory of your inv_sbox.txt on your computer in AES128_Decrypt.java
//In the invSubBytes Method, there is a line for file input need to be replaced
Scanner reader = new Scanner(new File(""));

//Compile All Class
javac AES128*.java

//Run the Program, with the file path of the plaintext.txt and key.txt document
java AES128 plaintext.txt key.txt