use crate::{modded_exponent, structures::RSAInfo};
use std::{io::{self, Write}, sync::{Arc, Mutex}, thread::{self}};

const PRIME_MAX:u64 = u64::MAX / 3;

// Function that gets candidate from user, then works to get two acceptable prime.
// Primes need to be multiplied together to create an acceptable modulus. Since we are 
// doing 64 bit encryption, we need a modulus which is lower than u64::MAX. This is so there is no overflow.
pub fn get_primes(info: &mut RSAInfo) {
    println!("First, we need to get two prime numbers.");
    println!("Try to pick a location between 3 and {}.", PRIME_MAX);
    println!("Let me know where to start looking and I'll find you two.");
    print!("Enter a number:    ");
    if let Err(e) = io::stdout().flush(){
        println!("Failed to flush the buffer. Error: {e}");
    }
    let primecandidate:u64;

    let mut input:String = String::new();
    
    if let Err(_e) = io::stdin().read_line(&mut input){
        println!("Failed to get this information, I will supply a default value.");
        input = String::from("50000000000");
    }

    match input.trim().parse::<u64>(){
        Ok(s) => primecandidate = s,
        Err(_) => primecandidate = 50000000000,
    }
    let (prime1, prime2) = find_prime(primecandidate);
   
   info.set_p(prime1);
   info.set_q(prime2);
   println!("Primes {} and {} will be used.", info.get_p(), info.get_q());
}

// Multiplies to get N must be smaller than u64::MAX. 
pub fn get_modulus(info: &mut RSAInfo)  {

    let n:u64 = info.get_p() * info.get_q();
    if n > u64::MAX{
        panic!("Not allowed to have a modulus over u64::MAX.");
    }
    info.set_n(n);
    println!("Multiplying p and q (our primes) will equal {}.",info.get_n());
    println!("{} is the max u64 value, our modulus is {} which is {} less than the max.", u64::MAX, info.get_n(), u64::MAX-info.get_n());
    println!("This ensures that our encryption of 8 bytes at a time will not overflow and lose information.");
}

// Gets eulers totient, each prime minus 1 multiplied together.
pub fn get_phi(info: &mut RSAInfo) {
    let pmin1 = info.get_p() - 1;
    let qmin1 = info.get_q() - 1;
    let phi = qmin1 * pmin1;
    info.set_phi(phi);
    println!("To get the euler totient (phi), we need to multiply p-1 * q-1. That equals {}.", info.get_phi());
}

// Gets e exponent, User supplies a candidate, but function will choose a correct value.
// this exponent must be coprime with eulers totient.
pub fn get_e(info: &mut RSAInfo)  {
    println!("Our public exponent e must be coprime with our phi. Give me a place to start looking and I'll find you one.");
    let mut input:String = String::new();
    print!("Enter a number:    ");
    if let Err(e) = io::stdout().flush(){
        println!("Error reading from buffer, Error: {}", e);
    }

    if let Err(_e) = io::stdin().read_line(&mut input){
        println!("Failed to get this information, I will supply a default value.");
        input = String::from("500000000");
    }
    let number:u64;
    match input.trim().parse::<u64>(){
        Ok(s) => {
            number = s;
        },
        Err(_) => {
            println!("That's not gonna work, I'll pick you one.");
            number = u64::MAX / 2;
        },
    }
    info.set_e(get_a_coprime(number, info.get_phi()));
    
}

// Get exponent d, this exponent must be the modular inverse of eulers totient.
// must perform euclideans extended algorithm to find it.
pub fn get_d(info: &mut RSAInfo) {
    let eul= i128::try_from(info.get_phi());
    let eul = match eul{
        Ok(s) => s,
        Err(_) => panic!("cant do it."),
    };
    let e = i128::try_from(info.get_e());
    let e = match e{
        Ok(s) => s,
        Err(_) => panic!("cant do it.")
    };

    let data = extended_gcd(e, eul);
    if data.0 != 1{
        panic!("Can't get exponent d there was a problem performing extended euclidean formula.");
    }
    let val = (data.1 % eul + eul) % eul;
    info.set_d(val as u64);
    println!("D must be the multiplicative inverse: d * e = 1 mod N");
    println!("We will find this using euclideans extended algorithm.");
    println!("{} is exponent d.", val as u64);
}

// function to find both primes. What ever value user chooses, this algorithm will find one so that
// the multiplication of the two is slightly less than u64::MAX.
fn find_prime(num:u64) -> (u64, u64){
    let mid = PRIME_MAX / 2;
    let mut range = num;
   if num < 3 || num > PRIME_MAX{
        range = mid;
   }

    let mut result:(u64,u64) = (0,0);
    if range < mid{
        result.0 = find_prime_async(0, range, true);

    }else{
        result.0 = find_prime_async(range, u64::MAX, false);
    }
    if result.0 == 0{
        result.0 = find_prime_async(range, u64::MAX, false);
    }
    let start = u64::MAX / result.0;

    result.1 = find_prime_async(0, start, true);

    if result.0 == 0 || result.1 == 0{
        panic!("Cannot have primes as zero.");
    }
    if (result.0 as u128) * (result.1 as u128) > u64::MAX as u128{
        panic!("Cannot have modulus over u64 max.");
    }

    result
}

// Used by above function, this function uses multithreading to find primes quickly.
fn find_prime_async(start:u64, end:u64, go_down:bool) -> u64{

    let mut result:u64 = 0;
    let total = end - start;
    let range: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((start..=end).rev())} else {Box::new(start..=end)};
    if total < 100{
        for i in range{
            if is_prime(i){
                result = i;
                break;
            }
        }
    }else if total < 500{
        for i in range{
            if is_prime_async(i){
                result = i;
                break;
            }
        }
    }else{
        
        let chunk = total / 4;
        let section1 = start + chunk;
        let section2 = start + (chunk * 2);
        let section3 = start + (chunk * 3);
        let arc_result = Arc::new(Mutex::new(0u64));
        let mut arc_handles = vec![];

        let arc_result1 = arc_result.clone();
        let handle1 = thread::spawn(move ||{
            let range1: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((start..=section1).rev())} else {Box::new(start..=section1)};           
            for i in range1{
                if is_prime_miller_rabine(i){
                    if let Ok(mut num) = arc_result1.lock(){
                        if *num < i{
                            *num = i;
                        }
                        break;
                    }
                }
            }
        });
        arc_handles.push(handle1);

        let arc_result2 = arc_result.clone();
        let handle2 = thread::spawn(move ||{
            let range2: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((section1..=section2).rev())} else {Box::new(section1..=section2)};
            for i in range2{               
                if is_prime_miller_rabine(i){
                    if let Ok(mut num) = arc_result2.lock(){
                        if *num < i{
                            *num = i;
                        }
                        break;
                    }
                }
            }
        });
        arc_handles.push(handle2);

        let arc_result3 = arc_result.clone();
        let handle3 = thread::spawn(move ||{
            let range3: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((section2..=section3).rev())} else {Box::new(section2..=section3)};           
            for i in range3{
                if is_prime_miller_rabine(i){
                    if let Ok(mut num) = arc_result3.lock(){
                        if *num < i{
                            *num = i;
                        }
                        break;
                    }
                }
            }
        });
        arc_handles.push(handle3);


        let arc_result4 = arc_result.clone();
        let handle4 = thread::spawn(move ||{
            let range4: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((section3..=end).rev())} else {Box::new(section3..=end)};           
            for i in range4{
                if is_prime_miller_rabine(i){
                    if let Ok(mut num) = arc_result4.lock(){
                        if *num < i{
                            *num = i;
                        }
                        break;
                    }
                }
            }
        });
        arc_handles.push(handle4);
        for j in arc_handles{
            if let Err(s) =  j.join(){
                panic!("Failed to join multithread. {:?}", s);
            }
           
            let arcresult =  match arc_result.lock(){
                Ok(s) => s,
                Err(t) => panic!("Error: {:?}", t),
            };
            if *arcresult != 0{
                result = *arcresult;
                break;
            }
        }
    }
    result
}

// Most prime checking is done using Miller-Rabine algorithm, but this is 
// used to check Miller-Rabine's accuracy. Testing shows my implementation loses
// a prime about 1 in 10,000 primes. Never found a false positive,
// (Miller-Rabine says its prime but is_prime says its not.)
fn is_prime(num:u64) -> bool{
    let sqrt:u64 = (num as f32).sqrt().ceil() as u64;
    for i in 2..sqrt{
        if num % i == 0{
            return false;
        }
    }
    true
}

fn is_prime_async(num:u64) -> bool{
    if num % 2 == 0 || num % 3 == 0{
        return false;
    }
    let sqrt:u64 = (num as f32).sqrt().ceil() as u64;
    let quarter:u64 = sqrt / 4;
    let half:u64 = sqrt / 2;
    let threequarter = quarter + half;

    let isprime = Arc::new(Mutex::new(true));

    let mut handles = vec![];
    let isprime1 = isprime.clone();
    let handle1 = thread::spawn(move || {
        for j in 4..quarter{
           
            if num % j == 0{
                let l = isprime1.lock();
                let mut g = match l{
                    Ok(s) => s,
                    Err(_) => panic!("failed to spawn thread."),
                };
                *g = false;
                return;
            }
        }       
    });
    handles.push(handle1);

    let isprime2 = isprime.clone();
    let handle2 = thread::spawn(move || {
        for j in quarter..half{
           
            if num % j == 0{
                let l = isprime2.lock();
                let mut g = match l{
                    Ok(s) => s,
                    Err(_) => panic!("failed to spawn thread."),
                };
                *g = false;
                return;
            }
        }       
    });
    handles.push(handle2);

    let isprime3 = isprime.clone();
    let handle3 = thread::spawn(move || {
        for j in half..threequarter{
           
            if num % j == 0{
                let l = isprime3.lock();
                let mut g = match l{
                    Ok(s) => s,
                    Err(_) => panic!("failed to spawn thread."),
                };
                *g = false;
                return;
            }
        }       
    });
    handles.push(handle3);

    let isprime4 = isprime.clone();
    let handle4 = thread::spawn(move || {
        for j in threequarter..sqrt{
           
            if num % j == 0{
                let l = isprime4.lock();
                let mut g = match l{
                    Ok(s) => s,
                    Err(_) => panic!("failed to spawn thread."),
                };
                *g = false;
                return;
            }
        }       
    });
    handles.push(handle4);


    let mut result:bool = true;
    for h in handles{
        h.join().unwrap();
        if !(*isprime.lock().unwrap()){
            result = false;
            return result;
        }
        
    }
   result
    
}

// Miller-Rabine algorithm, sets up information and calls miller-rabine test.
pub fn is_prime_miller_rabine(num: u64) -> bool {
    let one: u64 = 1u64;
    if num <= one || num == 4 || num % 2 == 0 || num % 3 == 0{
        return false;
    }
    if num <= 3 {
        return true;
    }

    let mut d = num - one;
    while d % 2 == 0 {
        d /= 2;
    }

    for g in 0..10 {
        if miller_rabine_test(d.clone(), num, g) == false {
            return false;
        }
    }
    true
}

// Miller-Rabine test called by above function.
fn miller_rabine_test(mut d:u64, num:u64, g:u64) -> bool{
    let nextrandom = (num / 15) * (g + 1);
    let one: u64 = 1;
    let two: u64 = 2;
    let a = 2 + nextrandom;

    let mut x = modded_exponent(a, d, num);

    if x == one || x == num - one {
        return true;
    }
    while d <= (num - one) {
        if x == 0{
            return false;
        }
        x = modded_exponent(x, 2, num);

        if u64::MAX / 2 >= d{
            d *= two;
        }else{
            return false;
        }
        

        if x == one {
            return false;
        }
        if x == num - one {
            return true;
        }
    }
    false
}

// Function to find coprime value, checks supplied number
// first, then continues up, if not found, starts at 3 and continues
// up to num. If nothing found (unlikely) panics.
fn get_a_coprime(num:u64, phi: u64) -> u64{
    
    for i in num..phi{
        if is_coprime(i, phi){
            println!("{} will work as e.", i);
            return i;
        }
    }
    for j in 3..num{
        if is_coprime(j, phi){
            println!("{} will work as e.", j);
            return j;
        }
    }
    panic!("Unable to find exponent e.");
}

// Actually checks two numbers for coprime. Basically, an
// implementation of euclideans algorithm if GCD is 1 returns
// true.
fn is_coprime(e:u64, phi:u64) -> bool{
    let mut a = phi;
    let mut b = e;
    if b > a{
        return false;
    }
    loop{
        let temp = a % b;
        a = b;
        b = temp;
        if temp == 0{
            if a == 1{
                return true;
            }else{
                return false;
            }
        }

    }
}

// Exctended euclideans algorithem worked recursively.
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x, y) = extended_gcd(b, a % b);
        (g, y, x - (a / b) * y)
    }
}





#[cfg(test)]
#[test]
fn test_getmodulus(){
    let mut r = crate::structures::RSAInfo::new();
   
    r.set_p(50000000021u64);
    r.set_q(368934871u64);
    r.set_n(18446743557747632291u64);
    r.set_phi(18446743507378697400u64);
    r.set_e(927438937u64);
    r.set_d(18411267238725607273u64);

    get_modulus(&mut r);

    assert_eq!(18446743557747632291u64, r.get_n());

}

#[test]
fn test_getphi(){
    let mut r = crate::structures::RSAInfo::new();
   
    r.set_p(50000000021u64);
    r.set_q(368934871u64);
    r.set_n(18446743557747632291u64);
    r.set_phi(18446743507378697400u64);
    r.set_e(927438937u64);
    r.set_d(18411267238725607273u64);

    get_phi(&mut r);

    assert_eq!(18446743507378697400u64, r.get_phi());
}

#[test]
fn test_getd(){
    let mut r = crate::structures::RSAInfo::new();
   
    r.set_p(50000000021u64);
    r.set_q(368934871u64);
    r.set_n(18446743557747632291u64);
    r.set_phi(18446743507378697400u64);
    r.set_e(927438937u64);
    r.set_d(18411267238725607273u64);

    get_d(&mut r);

    assert_eq!(18411267238725607273u64, r.get_d());
}

#[test]
fn test_is_coprime(){
    assert_eq!(true, is_coprime(11,19));
    assert_ne!(true, is_coprime(19, 11));
}

#[test]
fn test_find_primes(){
    let returns2 = find_prime(4536527634656356);
    assert!(is_prime(returns2.0,) && is_prime(returns2.1));

    let returns3 = find_prime(3);
    assert!(is_prime(returns3.0,) && is_prime(returns3.1));
}

#[test]
fn test_is_primes(){
    let prime = 3074457345618258599u64;
    let nonprime = 29999388238928890u64;
    let g = is_prime(prime);
    let h = is_prime(nonprime);
    assert_eq!(g, true);
    assert_eq!(h, false);
}

#[test]
fn test_is_primesasync(){
    let prime = 3074457345618258599u64;
    let nonprime = 29999388238928890u64;
    let g = is_prime_async(prime);   
    let h = is_prime_async(nonprime);
    assert_eq!(g, true);
    assert_eq!(h, false);

    assert_eq!(is_prime_async(18446744073709551557u64),true);

}

#[test]
fn test_getacoprime(){
    let g = get_a_coprime(5000u64, 18446743613945430720u64);

    assert!(g == 5003u64);
}

#[test]
fn test_iscoprime(){
    assert!(is_coprime(5003u64, 18446743613945430720u64))
}



#[test]
fn test_extended_euclidean(){
    let r = crate::utility::extended_gcd(5003i128, 18446743613945430720i128);
    println!("{:?}", r);
    assert_eq!(r.0, 1);
    assert_eq!(r.1, -4457747957077758493);
    assert_eq!(r.2, 1209);

    let val = (r.1 % 18446743613945430720i128 + 18446743613945430720i128) % 18446743613945430720i128;
    assert_eq!(13988995656867672227i128, val);

}

#[test]
fn test_is_prime_miller_rabin(){
    assert_eq!(is_prime_miller_rabine(8865838643u64), is_prime_async(8865838643u64));

    assert_eq!(is_prime_miller_rabine(1537228672809129301u64),is_prime_async(1537228672809129301u64));

    assert_eq!(is_prime_miller_rabine(18446744073709551557u64),is_prime_async(18446744073709551557u64));
    
}

#[test]
fn test_isprimespeeds(){

    let now = std::time::Instant::now();
    let answer1 = is_prime_miller_rabine(1537228672809129301u64);
    let answer2 = is_prime_miller_rabine(8865838643u64);
    let el = now.elapsed();
    println!("Miller_Rabine took: {:?} seconds.", el);

    let now = std::time::Instant::now();
    let answer11 = is_prime_async(1537228672809129301u64);
    let answer22 = is_prime_async(8865838643u64);
    let el = now.elapsed();
    println!("Is_prime_async took: {:?} seconds.", el);

    let now = std::time::Instant::now();
    let answer111 = is_prime(1537228672809129301u64);
    let answer222 = is_prime(8865838643u64);
    let el = now.elapsed();
    println!("Is_prime took: {:?} seconds.", el);

    let one = !answer1 && !answer11 && !answer111;
    assert!(one);
    let two = answer2 && answer22 && answer222;
    assert!(two);

}
