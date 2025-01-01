// Main structure of application, which holds all 
// needed information for encryption and decryption.
pub struct RSAInfo{
    p:u64,
    q:u64,
    n:u64,
    phi:u64,
    d:u64,
    e:u64,
}
impl RSAInfo{
    // One associated function which is used to create and initialize
    // the structure.
    pub fn new() -> RSAInfo{
        let f = RSAInfo{
            p : 0u64,
            q : 0u64,
            n : 0u64,
            phi : 0u64,
            d : 0u64,
            e : 0u64,
        };
        f
    }
    // public setter and getter methods, no logic involved but could be added later.
    
    pub fn set_p(&mut self, val:u64){
        self.p = val;
    }
    pub fn get_p(&self) -> u64{
        self.p
    }
    pub fn set_q(&mut self, val:u64){
        self.q = val;
    }
    pub fn get_q(&self) -> u64{
        self.q
    }
    pub fn set_n(&mut self, val:u64){
        self.n = val;
    }
    pub fn get_n(&self) -> u64{
        self.n
    }
    pub fn set_phi(&mut self, val:u64){
        self.phi = val;
    }
    pub fn get_phi(&self) -> u64{
        self.phi
    }
    pub fn set_d(&mut self, val:u64){
        self.d = val;
    }
    pub fn get_d(&self) -> u64{
        self.d
    }
    pub fn set_e(&mut self, val:u64){
        self.e = val;
    }
    pub fn get_e(&self) -> u64{
        self.e
    }
}

#[cfg(test)]
    #[test]
    fn teststructure(){
        let mut r = crate::structures::RSAInfo::new();
        r.set_d(1u64);
        r.set_e(2u64);
        r.set_n(3u64);
        r.set_phi(4u64);
        r.set_p(5u64);
        r.set_q(6u64);
        assert_eq!(1u64, r.get_d());
        assert_eq!(2u64, r.get_e());
        assert_eq!(3u64, r.get_n());
        assert_eq!(4u64, r.get_phi());
        assert_eq!(5u64, r.get_p());
        assert_eq!(6u64, r.get_q());
    }