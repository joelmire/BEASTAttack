import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.lang.String;

public class BeastAttack {

    public static void main(String[] args) throws Exception {
    
	byte[] ciphertext=new byte[1024];
	HexBinaryAdapter adapter = new HexBinaryAdapter();
	
	for (int s = 0; s < 56; s++) {		// The plaintext is 56 blocks long.
	    
	    System.out.printf("Block Round: %d\n\n", s);
	    
	    byte[] m = {0,0,0,0,0,0,0,0};	// will store the decrypted block
	    byte[] blank = {0,0,0,0,0,0,0,0};	// will be used to generate prefixes of 0s
	
	    for (int i = 0; i < 7; i++) {	// Each block is 8 bytes long.
	        System.out.printf("Byte Round: %d\n", i);
	        
	        // Generates the appropriate length prefix of 0s.
	        byte[] prefix = Arrays.copyOfRange(blank, 0, 7 - i);
	
	        // Calls the encrypt function to establish a baseline iv value
	        int length = callEncrypt(prefix, prefix.length, ciphertext); 	
	        
	        // Store the previous block before the block in question. This previous block is either the actual IV or the previous ciphertext block.
	        byte[] ivOld = Arrays.copyOfRange(ciphertext, s, s + 8);
	        
	        // Store the block in question.
	        String blockNext = adapter.marshal(Arrays.copyOfRange(ciphertext, (s * 8) + 8, (s * 8) + 16));
	        BigInteger correctBlockNext = new BigInteger(blockNext, 16);
	        
	        for (int j = 0; j < 128; j++) {		// This loop considers each possible ASCII value.
	            
	            // Generate the prefix.
	            byte[] generatedPrefix = Arrays.copyOfRange(m,0,8);
	            generatedPrefix[7] = (byte) j;
	      
	            // Force the prefix onto the plaintext.
	            ciphertext = predict(generatedPrefix, 8, ciphertext, ivOld);
	        
	            // Store the block in question.
	            blockNext = adapter.marshal(Arrays.copyOfRange(ciphertext, 8, 16));
	            //blockNext = adapter.marshal(Arrays.copyOfRange(ciphertext, (s * 8) + 8, (s * 8) + 16));
	            BigInteger generatedBlockNext = new BigInteger(blockNext, 16);
	        
	            // Check whether the generated block matches the correct block. 
	            if (generatedBlockNext.longValue() == correctBlockNext.longValue()) {
	                // {c1,...,c8} = {c1,...,c8}'. Therefore, the ASCII value of j is the plaintext character.
	                
	                // Print out information about the match.
	                System.out.printf("match: %d\t", j);
	                for (int k = (s * 8) + 8; k < (s * 8) + 16; k++) {
	                    System.out.printf("%2x", ciphertext[k]);
	                }
	                System.out.println();
	                
	                // Update the decrypted block.
	                m[7] = (byte) (j);
	                
	                // Shift the decrypted block to the left (with wrapping).
	                byte temp = m[0];
	                for (int l = 1; l <= 7; l++) {
	                    m[l - 1] = m[l];
	                }
	                m[7] = temp;
	            }
	        }
	    }
	
	    // Print the block of plaintext.
	    System.out.println();
	    System.out.println("The block of plaintext is:");
	    System.out.println(new String(m, "US-ASCII"));
	    
	    // Remove if you want to work on decrypting the entire plaintext.
	    break;
	}
    }
    
  
    // A helper method that predicts the changing IV and adjusts the prefix block to nullify its effects before calling the encrypt function.
    static byte[] predict(byte[] prefix, int prefix_len, byte[] ciphertext, byte[] ivOld) throws IOException {
  
        HexBinaryAdapter adapter = new HexBinaryAdapter();
	long ivExpected;
	byte[] ivExpectedBytes;
	byte[] tempPrefix = new byte[10];
	
	// Call the encrypt function to establish a baseline/prior IV value.
	int length = callEncrypt(prefix, prefix_len, ciphertext);
	String iv = adapter.marshal(Arrays.copyOfRange(ciphertext, 0, 8));
	BigInteger ivPrior = new BigInteger(iv, 16);
	
	// Loop until the IV is correctly predicted.
	boolean loop = true;
	while (loop) {
	
	    // The IV is linearly related to the time. My decision to add 8 is based on observing this linear relationship.
	    // Note: System.currentTimeMillis() gives the current time.
	    ivExpected = ivPrior.longValue() + 8;
	    ivExpectedBytes = ByteBuffer.allocate(8).putLong(ivExpected).array();
	    
	    // Nullify the effects of the IV by XORing the prefix with the expected IV and the original IV used.
	    for (int i = 0; i < prefix_len; i++) {
	        tempPrefix[i] = (byte) ((prefix[i] ^ ivExpectedBytes[i]) ^ ivOld[i]);
	    }
	    
	    // Call the encrypt function with the adjusted prefix.
	    length = callEncrypt(tempPrefix, prefix_len, ciphertext);
	    
	    // Store the actual IV.
	    iv = adapter.marshal(Arrays.copyOfRange(ciphertext, 0, 8));
	    BigInteger ivActual = new BigInteger(iv, 16);
	    ivExpectedBytes = ByteBuffer.allocate(8).putLong(ivActual.longValue()).array();

	    // Check whether the prediction was correct after all.
	    if (ivExpected == ivActual.longValue()) {
	        // The prediction was correct. Break out of the loop.
	        loop = false;
	        break;
	    } else {
	        // The prediction was incorrect. Update the baseline/prior IV value and loop again.
	        ivPrior = new BigInteger(iv, 16);
	    }
	}
	
	return ciphertext;
    }
    
   
    // A helper method that prints a byte array.
    static void printByteArray(String name, byte[] array, int len) {
    	
    	System.out.print(name + ": ");
    	for(int i = 0; i < len; i++) {
            System.out.print(array[i]);
    	    System.out.print(' ');
    	}
    	System.out.println();
    }
    
    
    // A helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException {
    
	HexBinaryAdapter adapter = new HexBinaryAdapter();
	Process process;
	
	// run the external process (don't bother to catch exceptions)
	if(prefix != null) {
	    // turn prefix byte array into hex string
	    byte[] p=Arrays.copyOfRange(prefix, 0, prefix_len);
	    String PString=adapter.marshal(p);
	    process = Runtime.getRuntime().exec("./encrypt "+PString);
	} else {
	    process = Runtime.getRuntime().exec("./encrypt");
	}

	// process the resulting hex string
	String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
	byte[] c=adapter.unmarshal(CString);
	System.arraycopy(c, 0, ciphertext, 0, c.length); 
	return(c.length);
    }
}