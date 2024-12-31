use crate::structures::RSAInfo;
use std::io::{self, Write};

pub fn get_primes(info: &mut RSAInfo) {
    println!("First, we need to get two prime numbers.");
    println!("Try to pick a location between 1 billion and 100 billion.");
    println!("Let me know where to start looking and I'll find you two.");
    print!("Enter a number:    ");
    io::stdout().flush().unwrap();
    let primecandidate:u64;

    let mut input:String = String::new();
    
    io::stdin().read_line(&mut input).unwrap();

    match input.trim().parse::<u64>(){
        Ok(s) => primecandidate = s,
        Err(_) => primecandidate = 50000000000,
    }
    let (prime1, prime2) = find_prime(primecandidate);
   
   info.set_p(prime1);
   info.set_q(prime2);
   println!("Primes {} and {} will be used.", info.get_p(), info.get_q());
}


pub fn get_modulus(info: &mut RSAInfo)  {

    let n:u64 = info.get_p() * info.get_q();
    if n > u64::MAX{
        panic!("Not allowed to have a modulus over u64::MAX.");
    }
    info.set_n(n);
    println!("Multiplying p and q (our primes) will equal {}.",info.get_n());
    println!("{} is the max u64 value, our modulus is {} less than the max.", u64::MAX, u64::MAX-info.get_n());
    println!("This ensures that our encryption of 8 bytes at a time will not overflow and lose information.");
}

pub fn get_phi(info: &mut RSAInfo) {
    let pmin1 = info.get_p() - 1;
    let qmin1 = info.get_q() - 1;
    let phi = qmin1 * pmin1;
    info.set_phi(phi);
    println!("To get the euler totient (phi), we need to multiply p-1 * q-1. That equals {}.", info.get_phi());
}

pub fn get_e(info: &mut RSAInfo)  {
    println!("Our public exponent e must be coprime with our phi. Give me a place to start looking and I'll find you one.");
    let mut input:String = String::new();
    print!("Enter a number:    ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
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
    println!("{} is exponent d.", val as u64);
}



fn is_prime(num:u64) -> bool{
    let sqrt:u64 = (num as f32).sqrt().ceil() as u64;
    for i in 2..sqrt{
        if num % i == 0{
            return false;
        }
    }
    true
}
fn find_prime(num:u64) -> (u64, u64){
    let mid = 50000000000;
    let mut range = num;
   if num <= 1000000000 || num >= 100000000000{
        range = mid;
   }

    let mut result:(u64,u64) = (0,0);
    if range < mid{
        for i in (0..=num).rev(){
            if is_prime(i){
                result.0 = i;
                break;
            }
        }
    }else{
        for j in range..u64::MAX{
            if is_prime(j){
                result.0 = j;
                break;
            }
        }

    }
    if result.0 == 0{
        for k in range..u64::MAX{
            if is_prime(k){
                result.0 = k;
                break;
            }
        }
    }
    let start = u64::MAX / result.0;

    for l in (0..=start).rev(){
        if is_prime(l){
            result.1 = l;
            break;
        }
    }

    result
}

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
    let returns = find_prime(1_000_000_001);

    let value = (999999937u64, 18446745217u64);

    assert_eq!(returns, value);

    let returns1 = find_prime(99_999_999_999);

    let value1 = (100000000003u64, 184467427u64);

    assert_eq!(returns1, value1);

    let returns2 = find_prime(4536527634656356);

    let value2 = (50000000021u64, 368934871u64);

    assert_eq!(returns2, value2);
}

#[test]
fn test_is_primes(){
    let prime = 50000000021u64;
    let nonprime = 29999388238928890u64;

    assert_eq!(is_prime(prime), true);
    assert_eq!(is_prime(nonprime), false);
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
