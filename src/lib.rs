// Author: Shannon Musgrave

use std::{io, sync::{mpsc, Arc}, thread, time::Duration};
mod utility;
mod structures;

// Main function called from main.rs. Will run through complete
// encryption and decryption process.
pub fn run(){
    // Steps:
    // Get two primes each below u32max p and q.
    // multiply to get modulus N must be higher than 
    // u32max
    // get Phi (p-1)*(q-1);
    // get public exponent such that 1 < e < phi
    // and is coprime with phi
    // get private exponent which is the 
    // multiplicative inverse d * e = 1 modn
    // to encrypt c = m ^ e modn
    // to decrypt m = c ^ d modn

    // Start a loop cancelled one user is finished.
    loop{
        // Create structure to hold all encryption information.
        let mut myrsainfo = structures::RSAInfo::new();

        // Helper method to retrieve primes.
        utility::get_primes(&mut myrsainfo);
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        // Helper method to get N (modulus).
        utility::get_modulus(&mut myrsainfo);
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        // Get euler totient.
        utility::get_phi(&mut myrsainfo);
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        // Get exponent e (for encryption).
        utility::get_e(&mut myrsainfo);  
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        // Get exponent d (for decryption).
        utility::get_d(&mut myrsainfo);
        println!("");
        println!("Everything is in place to perform encryption.");
        println!("");

        println!("Type in a message that you would like to encrypt.");

        // All data is retrieved and in the structure.
        // Now get string to encrypt from user.
        let input:String = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Great, lets start the process of encryption.");

        println!("First, lets convert this to the raw bytes.");

        // Convert string to vector of bytes, rust strings are utf8.
        let rawbytes:Vec<u8> = convert_raw_bytes(&input);
        println!("");
        println!("{:?}", rawbytes);
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Now we should pad the bytes, we need to create a multiple of 8 bytes since we are performing 64 bit encryption chunks.");
        println!("We also do this to make sure the bytes are smaller, by inserting a small byte into the most significant byte.");

        // Common practice is to pad bytes, simply adding a byte of low value to most significant position.
        // every 8 bytes. Also making total array length a multiple of 8, since these will be converted to u64 integers.
        let paddedbytes:Vec<u8> = pad_the_bytes(rawbytes);
        println!("");
        println!("{:?}", paddedbytes);

        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Now we need to convert these bytes into 64bit integers, remember 8 bytes is one 64bit integer.");

        // Now to take padded vector of bytes and convert them 8 to 1 to a vector of u64 integers.
        let info:Vec<u64> = get_integers(&paddedbytes);
        println!("");
        println!("{:?}", info);
       
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("We can start encrypting these with the information above, to encrypt, it is information ^ e modulus n.");
        println!("This is the data taken to the {} power modulus {}", myrsainfo.get_e(), myrsainfo.get_n());

        // Encryption_process will encrypt each u64 integer by applying the exponent and modulus.
        let mutatedvec:Vec<u64> = encryption_process(info, myrsainfo.get_e(), myrsainfo.get_n());
        println!("");
        println!("{:?}", mutatedvec);
       
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Lets convert these encrypted integers back to bytes.");
        println!("This is our encrypted array of bytes.");
        // Converting encryption back to an array of bytes.
        let encrypted:Vec<u8> = getbytes(mutatedvec);
        println!("");
        println!("{:?}", encrypted);
       
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Now lets decrypt the information. First, we will convert back to 64bit integers.");

        // Now that bytes have been encrypted and displayed to user, now lets reverse process and decrypt.
        // Reverse steps, convert back to u64 ints.
        let encryptedintegers = get_integers(&encrypted);
        println!("");
        println!("{:?}", encryptedintegers);
        
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Now, we must decrypt the integers using the formula, cypher ^d modulus n.");
        println!("This is the data taken to the {} power modulus {}", myrsainfo.get_d(), myrsainfo.get_n());

        // Same function decrypts just using the other exponent.
        let decrypted = encryption_process(encryptedintegers, myrsainfo.get_d(), myrsainfo.get_n());
        
        println!("");
        println!("{:?}", decrypted);
        
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("Convert these decrypted integers back to the vector of bytes.");

        // Get bytes from integers.
        let getdecryptedbytes = getbytes(decrypted);
        println!("");
        println!("{:?}", getdecryptedbytes);
        
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");

        println!("We need to depad this string to get to our original string.");

        // Reverse the padding process by removing each 8th byte.
        let depadded = depad_the_bytes(getdecryptedbytes);
        println!("");
        println!("{:?}", depadded);
        
        println!("Press enter to continue.");
        _ = get_user_string();
        println!("");
        println!("-----------------------------------------------------------------");
        println!("");


        println!("Lets convert this back to text.");

        // Use utf8 function to return bytes, since it should be the original string, the string should be in 
        // well formed utf8 format. If its not we handle the error in the match statement.
        let stringresult = String::from_utf8(depadded);
        let stringres = match stringresult{
            Ok(s) => s,
            Err(_) => String::from("Error. The program was unable to retrieve the orignal string."),
        };
        println!("");
        println!("{}", stringres);

        println!("Congratulations, you have encrypted and decrypted a message using RSA assymetric encryption.");


        // Simple match for checking with user, if they type a variation of y in, process restarts.

        println!("Would you like to try again. Type Y to try again.");
       
        let s = get_user_string();

        match &s[..]{
            "Y" => {},
            "y" => {},
            "yes" => {},
            "YES" => {},
            _ => {break;}   
        }
    }

    println!("Thanks for using the RSA encryption process app.");
}

// Get bytes turns vector of u64 (8 bytes) into byte vector.
fn getbytes(input:Vec<u64>) -> Vec<u8> {
    let mut result:Vec<u8> = Vec::new();
    for i in input.into_iter(){
        let temp = i.to_le_bytes();
        for j in temp{
            result.push(j);
        }
    }

    result
}

// Main function which takes a vector of u64 and applies exponent and modulus then returns.
fn encryption_process(message:Vec<u64>, exp:u64, modulus:u64) -> Vec<u64> {

    let mut place = 0;
    let mut result:Vec<u64> = vec![0;message.len()];
    let atomicinfo = Arc::new(message);
    loop{
        let (tx,rx) = mpsc::channel::<(usize, u64)>();

        if place < atomicinfo.len(){
            let tx1 = tx.clone();
            let atom1 = atomicinfo.clone();
            thread::spawn(move ||{
                let ret = modded_exponent(atom1[place], exp, modulus);
                tx1.send((place, ret)).unwrap();
            });
            place += 1;
        }

        if place < atomicinfo.len(){
            let tx2 = tx.clone();
            let atom2 = atomicinfo.clone();
            thread::spawn(move ||{
                let ret = modded_exponent(atom2[place], exp, modulus);
                tx2.send((place, ret)).unwrap();
            });
            place += 1;
        }

        if place < atomicinfo.len(){
            let tx3 = tx.clone();
            let atom3 = atomicinfo.clone();
            thread::spawn(move ||{
                let ret = modded_exponent(atom3[place], exp, modulus);
                tx3.send((place, ret)).unwrap();
            });
            place += 1;
        }

        if place < atomicinfo.len(){
            let tx4 = tx.clone();
            let atom4 = atomicinfo.clone();
            thread::spawn(move ||{
                let ret = modded_exponent(atom4[place], exp, modulus);
                tx4.send((place, ret)).unwrap();
            });
            place += 1;
        }
        drop(tx);

        for i in rx{
           result[i.0] = i.1;
        }
        if place >= atomicinfo.len(){
            break;
        }
    }
    
    result
}

// Converts bytes into vector of u64 integers.
fn get_integers(message: &[u8]) -> Vec<u64> {
    let mut list:Vec<u64> = Vec::new();

    let len = message.len();
    let mut start = 0;
    let mut end = 8;
    loop{
        let mut eight:[u8;8] = [0;8];
        let section:Vec<&u8> = message.iter().skip(start).take(end).collect();
        for i in 0..8{
            eight[i] = *section[i];
        }
        list.push(u64::from_le_bytes(eight));
        start +=8;
        end +=8;
        if end > len{
            break;
        }
    }
    list
}

// Removes the added bytes throughout the message and those at end.
// Bytes at end are added to make vector a multiple of 8.
fn depad_the_bytes(rawbytes:Vec<u8>) -> Vec<u8>{
    let mut result:Vec<u8> = Vec::new();

    for i in 0..rawbytes.len(){
        if i == 0 || (i + 1) % 8 != 0{
            result.push(rawbytes[i]);
        }
    }

    while Some(&0) == result.last(){
        result.pop();
    }

    result
}
// Adds a byte everry 7 bytes to add randomness and keep
// integer value lower (most sig byte is rotated between 0 and 3).
// Bytes added to end to create multiple of 8. So that the message
// can be converted into array of u64 integers.
fn pad_the_bytes(rawbytes: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    for i in 0..rawbytes.len(){
       
        if i != 0 && i % 7 == 0{
            let byte:u8 = (i % 4) as u8;
            result.push(byte);
        }
        
        result.push(*rawbytes.get(i).unwrap());
    }

    while result.len() % 8 != 0{
        result.push(0);
    }

    result
}

// Convert utf8 string into vector of bytes.
fn convert_raw_bytes(input: &str) -> Vec<u8>{
    let bytes = input.as_bytes().to_vec();
    bytes
}

// Ask user for string to process.
fn get_user_string() -> String  {
    let mut input = String::new();

    std::io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_string();

    trimmed
}

// Modded exponentiation, keeps values low by applying modulus each cycle.
// Also uses logic to increase speed.
fn modded_exponent(base:u64, exp:u64, modulus:u64) -> u64{
    if base == 0u64 || exp == 0u64 || modulus == 0u64{
        panic!("Cannot perform exponents on 0.");
    }
    let  base1 = base as u128;
    let mut result = 1u128;
    let exp = exp as u128;
    let modulus = modulus as u128;
    let mut base1 = base1 % modulus;
    let mut exp = exp;

    while exp > 0{
        if exp % 2 == 1{
            result = (result * base1) % modulus;
        }
        exp = exp >> 1;
        base1 = (base1 * base1) % modulus;
    }
    let result1 = match u64::try_from(result){
        Ok(s) => s,
        Err(_) => panic!("error in exponential overflow."),
    };
    result1  

}

#[cfg(test)]
#[test]
fn test_encryption_process1(){
    let mut r = crate::structures::RSAInfo::new();
    r.set_p(50000000021);
    r.set_q(368934871);
    r.set_n(18446743557747632291);
    r.set_phi(18446743507378697400);
    r.set_e(92829719);
    r.set_d(9419014239140821679);
   
   
    assert!(r.get_n() < u64::MAX);

    let plain = vec![15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30];
    let new: Vec<u64> = encryption_process(plain.clone(), r.get_e(), r.get_n());
    let orig:Vec<u64> = encryption_process(new, r.get_d(), r.get_n());
    assert_eq!(plain, orig);

    
    let plain1 = vec![255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255];
    let new1: Vec<u64> = encryption_process(plain1.clone(), r.get_e(), r.get_n());
    let orig1:Vec<u64> = encryption_process(new1, r.get_d(), r.get_n());
    assert_eq!(plain1, orig1);
}

#[test]
fn test_encryption_process2(){
    let mut r = crate::structures::RSAInfo::new();
    r.set_p(61);
    r.set_q(53);
    r.set_n(3233);
    r.set_phi(3120);
    r.set_e(17);
    r.set_d(2753);


}


#[test]
fn test_modded_exponent(){
    let input:u64 = 500;

    let input = modded_exponent(input, 3, 27u64);

    assert_eq!(17u64, input);

}


#[test]
fn test_pad_the_bytes(){
   
    let bytes = [211,29,99,21,94,74,10,7,92,19,49,182,29,99,21,94,74,10,7,92,19,49,182,29,99,21,94,74,10,7,92,19,49,182];
    let newbytes = pad_the_bytes(bytes.to_vec());
    let newbytes1 = vec![211, 29, 99, 21, 94, 74, 10, 3, 7, 92, 19, 49, 182, 29, 99, 2, 21, 94, 74, 10, 7, 92, 19, 1, 49, 182, 29, 99, 21, 94, 74, 0, 10, 7, 92, 19, 49, 182, 0, 0];
    let reversed = depad_the_bytes(newbytes.clone());
    assert_eq!(newbytes, newbytes1);
    assert_eq!(bytes.to_vec(), reversed);

}


#[test]
fn test_getbytes(){
    let g:Vec<u64> = vec![2983,389,297,2982];
    let r = getbytes(g);
    println!("{:?}",r);
    let t:Vec<u8> = vec![167, 11, 0, 0, 0, 0, 0, 0, 133, 1, 0, 0, 0, 0, 0, 0, 41, 1, 0, 0, 0, 0, 0, 0, 166, 11, 0, 0, 0, 0, 0, 0];
    assert_eq!(r, t);
}

#[test]
fn test_convertrawbytes(){
    let s = "shannon";
    let h = convert_raw_bytes(s);
    let base = vec![115, 104, 97, 110, 110, 111, 110];
    assert_eq!(h, base);
    
}

#[test]
fn test_getintegers(){
    let m = [244,192,99,05,22,200,122,55,217,192,3,05,22,2,222,55,244,192,99,05,122,0,122,66];
    let g = get_integers(&m);
    let base:Vec<u64> = vec![3997727616149995764, 4025657410512470233, 4790141677738377460];
    assert_eq!(g, base);
}