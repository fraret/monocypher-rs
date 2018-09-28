//! Incremental public key signatures
//!
//! [Official documentation](https://monocypher.org/manual/advanced/sign_incr)


use ffi;
use std::mem;

/// Computes the public key of the specified secret key.
pub fn public_key(secret_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut public_key: [u8; 32] = mem::uninitialized();
        ffi::crypto_sign_public_key(public_key.as_mut_ptr(), secret_key.as_ptr());
        public_key
    }
}

/// Signs a message with secret_key.
/// The public key is optional, and will be recomputed if not provided.
/// This recomputation doubles the execution time.
pub fn sign(secret_key: [u8; 32], public_key: [u8; 32], message: &[u8]) -> [u8; 64] {
    unsafe {
        let mut signature: [u8; 64] = mem::uninitialized();
        ffi::crypto_sign(
            signature.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len() as usize,
        );

        signature
    }
}



pub struct Context(ffi::crypto_sign_ctx);

impl Context {
    #[inline]
    pub fn new(secret_key: [u8; 32], public_key: [u8; 32]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_sign_init_first_pass(&mut ctx, secret_key.as_ptr(), public_key.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            ffi::crypto_sign_update(&mut self.0, message.as_ptr(), message.len());
        }
    }

    #[inline]
    pub fn finalize(&mut self) -> [u8; 64] {
        unsafe {
            let mut signature: [u8; 64] = mem::uninitialized();
            ffi::crypto_sign_final(&mut self.0, signature.as_mut_ptr());
            signature
        }
    }

    #[inline]
    pub fn begin_second_pass(&mut self) {
        unsafe {
            ffi::crypto_sign_init_second_pass(&mut self.0);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ctx_test() {
        let secret_key = [2u8; 32];
        let public_key = public_key(secret_key);

        let mut ctx = Context::new(secret_key, public_key);

        ctx.update("test".as_bytes());
        ctx.begin_second_pass();
        ctx.update("text".as_bytes());
        let sig = ctx.finalize();

        assert_eq!(sig[0..32], [44, 38, 60, 190, 58, 69, 201, 60, 76, 129, 172, 162, 182, 226, 56,
            66, 17, 98, 172, 194, 211, 137, 201, 113, 194, 5, 128, 228, 110, 194, 35, 133]);
        assert_eq!(sig[32..63], [139, 19, 95, 177, 166, 218, 60, 129, 27, 143, 59, 210, 220, 241,
            39, 246, 186, 241, 166, 207, 76, 7, 171, 180, 209, 3, 125, 165, 133, 140, 169])

    }

    #[test]
    fn public_key_test() {
        let secret_key = [2u8; 32];
        let public_key = public_key(secret_key);

        assert_eq!(public_key, [252, 124, 239, 169, 46, 18, 111, 232, 193, 211, 67, 23, 193, 253,
            209, 14, 227, 122, 65, 105, 56, 142, 16, 128, 251, 174, 103, 79, 81, 222, 19, 48]);
    }

    #[test]
    fn sign_test() {
        let secret_key = [2u8; 32];
        let public_key = public_key(secret_key);

        let sig = sign(secret_key, public_key, "test".as_bytes());

        assert_eq!(sig[0..32], [44, 38, 60, 190, 58, 69, 201, 60, 76, 129, 172, 162, 182, 226, 56,
            66, 17, 98, 172, 194, 211, 137, 201, 113, 194, 5, 128, 228, 110, 194, 35, 133]);
        assert_eq!(sig[32..63], [159, 106, 80, 169, 167, 124, 206, 123, 9, 27, 92, 8, 60, 137, 119,
            14, 198, 42, 201, 98, 119, 215, 226, 105, 230, 193, 122, 197, 171, 87, 209])

    }


}