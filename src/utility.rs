use crate::{modded_exponent, structures::RSAInfo};
use std::{io::{self, Write},  sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, RwLock}, thread, time::Duration};

const PRIME_MAX:u64 = u64::MAX / 3;

pub fn get_primes(info: &mut RSAInfo) {
    println!("First, we need to get two prime numbers.");
    println!("Try to pick a location between 3 and {}.", PRIME_MAX);
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

// #[cfg(debug_assertions)]
// fn print_debugging_info(print: String) {
//     println!("{}", print);
// }

fn find_prime_async(start:u64, end:u64, go_down:bool) -> u64{

    let mut result:u64 = 0;
    let total = end - start;
    let range: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((start..=end).rev())} else {Box::new(start..=end)};
    if total < 500000{
        for i in range{
            if is_prime_mr(i){
                if is_prime(i){
                    result = i;
                    break;
                }
               
            }
        }
    }else{
        
        let chunk = total / 4;
        let section1 = start + chunk;
        let section2 = start + (chunk * 2);
        let section3 = start + (chunk * 3);
        let arc_result = Arc::new(Mutex::new(0u64));
        let thread_cancel = Arc::new(RwLock::new(false));
        let mut arc_handles = vec![];

        let arc_result1 = arc_result.clone();
        let threadcancel1 = thread_cancel.clone();
        let handle1 = thread::spawn(move ||{
            //print_debugging_info(format!("thread {:?} started.", thread::current().id()));
            let range1: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((start..=section1).rev())} else {Box::new(start..=section1)};
           
            for i in range1{
                if i % 50 == 0 && *threadcancel1.read().unwrap(){
                    //print_debugging_info(format!("thread {:?} cancelled.", thread::current().id()));
                    break;
                }
                if is_prime_mr(i){
                    let mut num = arc_result1.lock().unwrap();
                    if *num == 0{
                        *num = i;
                    }
                    break;
                }
            }
        });
        arc_handles.push(handle1);

        let arc_result2 = arc_result.clone();
        let threadcancel2 = thread_cancel.clone();
        let handle2 = thread::spawn(move ||{
            //print_debugging_info(format!("thread {:?} started.", thread::current().id()));
            let range2: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((section1..=section2).rev())} else {Box::new(section1..=section2)};
           
            for i in range2{
                if i % 50 == 0 && *threadcancel2.read().unwrap(){
                    //print_debugging_info(format!("thread {:?} cancelled.", thread::current().id()));
                    break;
                }
                
                if is_prime_mr(i){
                    let mut num = arc_result2.lock().unwrap();
                    if *num == 0{
                        *num = i;
                    }
                    break;
                }
            }
        });
        arc_handles.push(handle2);

        let arc_result3 = arc_result.clone();
        let threadcancel3 = thread_cancel.clone();
        let handle3 = thread::spawn(move ||{
            //print_debugging_info(format!("thread {:?} started.", thread::current().id()));
            let range3: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((section2..=section3).rev())} else {Box::new(section2..=section3)};
           
            for i in range3{
                if i % 50 == 0 &&  *threadcancel3.read().unwrap(){
                    //print_debugging_info(format!("thread {:?} cancelled.", thread::current().id()));
                    break;
                }
                
                if is_prime_mr(i){
                    let mut num = arc_result3.lock().unwrap();
                    if *num == 0{
                        *num = i;
                    }
                    break;
                }
            }
        });
        arc_handles.push(handle3);


        let arc_result4 = arc_result.clone();
        let threadcancel4 = thread_cancel.clone();
        let handle4 = thread::spawn(move ||{
            //print_debugging_info(format!("thread {:?} started.", thread::current().id()));
            let range4: Box<dyn Iterator<Item = u64>> = if go_down {Box::new((section3..=end).rev())} else {Box::new(section3..=end)};
           
            for i in range4{
                if i % 50 == 0 && *threadcancel4.read().unwrap(){
                    //print_debugging_info(format!("thread {:?} cancelled.", thread::current().id()));
                    break;
                }
                
                if is_prime_mr(i){
                    let mut num = arc_result4.lock().unwrap();
                    if *num == 0{
                        *num = i;
                    }
                    break;
                }
            }
        });
        arc_handles.push(handle4);

        let threadcancel5 = thread_cancel.clone();
        let printhandle = thread::spawn(move|| {
            let mut i = 0;
            loop{
                if i >= 10{
                    i = 0;
                    println!("Working...");
                }
                thread::sleep(Duration::from_millis(500));
                i += 1;
                if i % 2 == 0 && *threadcancel5.read().unwrap(){
                    break;
                }

                
            }
            //println!("printmessage cancelled.");
        });
        arc_handles.push(printhandle);



        let threadcancelprint = Mutex::new(thread_cancel.clone());
        for j in arc_handles{
            let a = j.thread().id();
            j.join().unwrap();
           
            let arcresult =  arc_result.lock().unwrap();
            //print_debugging_info(format!("thread {:?} joined with main with value {}.", a, arcresult));

            if *arcresult != 0 && result == 0{
                result = *arcresult;
                let t = threadcancelprint.lock().unwrap();
                *t.write().unwrap() = true;
                //print_debugging_info(format!("Cancel issued because thread {:?} joined with main with value {}.", a, arcresult));
            }
        }
        

    }
    result
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


fn is_prime_cancellable(num:u64, cancel:Arc<RwLock<bool>>) -> bool{
    let sqrt:u64 = (num as f32).sqrt().ceil() as u64;
    for i in 2..sqrt{
       
        if i % 100 == 0 && *cancel.read().unwrap(){
            //print_debugging_info(format!("thread {:?} cancelled from is_prime_cancellable.", thread::current().id()));
            return false;
        }
        
        if num % i == 0{
            return false;
        }
    }
    true
}

pub fn is_prime_mr(num: u64) -> bool {
    let one: u64 = 1u64;
    if num <= one || num == 4 {
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
        if miller_test(d.clone(), num, g) == false {
            return false;
        }
    }
    true
}

fn miller_test(mut d:u64, num:u64, g:u64) -> bool{
    let nextrandom = (num / 15) * (g + 1);
    let one: u64 = 1;
    let two: u64 = 2;
    let a = 2 + nextrandom;

    if a == 0{
        println!("whoops.");
    }
    let mut x = modded_exponent(a, d, num);

    if x == one || x == num - one {
        return true;
    }
    while d <= (num - one) {
        if x == 0{
            println!("whoops.");
            return false;
        }
        x = modded_exponent(x, 2, num);
        d *= two;

        if x == one {
            return false;
        }
        if x == num - one {
            return true;
        }
    }
    false
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

    assert!(is_prime(returns.0,) && is_prime(returns.1));

    let returns1 = find_prime(99_999_999_999);

    assert!(is_prime(returns1.0,) && is_prime(returns1.1));

    let returns2 = find_prime(4536527634656356);

    assert!(is_prime(returns2.0,) && is_prime(returns2.1));

    let returns3 = find_prime(3);

    assert!(is_prime(returns3.0,) && is_prime(returns3.1));
}

#[test]
fn test_is_primes(){
    let prime = 3074457345618258599u64;
    let nonprime = 29999388238928890u64;

    assert_eq!(is_prime(prime), true);
    assert_eq!(is_prime(nonprime), false);

    let prime1 = 1537228672809129301u64;
    let nonprime1 = 29999388238928890u64;
    assert_eq!(is_prime(prime1), true);
    assert_eq!(is_prime(nonprime1), false);
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

    assert_eq!(is_prime_mr(3074457345618258599u64), is_prime(3074457345618258599u64));

    assert_eq!(is_prime_mr(3074457345618258590u64), is_prime(3074457345618258590u64));


    assert_eq!(is_prime_mr(8865838643u64), is_prime(8865838643u64));

    assert_eq!(is_prime_mr(1537228672809129301u64),is_prime(1537228672809129301u64));
    
}
