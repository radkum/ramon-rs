//! `fma`/`fmaf` for the linker.
//!
//! `-Z build-std=core,alloc` builds `compiler-builtins` from source, and its `libm` float
//! implementations reference the C `fma`/`fmaf`. A driver links with `/NODEFAULTLIB`, so the CRT
//! that would normally provide them is absent. The driver does no floating-point math: these
//! definitions exist only to satisfy the linker. They are not fused (`x * y + z`), which can differ
//! from a real `fma` in the last bit - irrelevant for code that is never called.
//!
//! Do not "clean this up" with `f64::mul_add`: on this target it lowers to the `llvm.fma`
//! intrinsic, i.e. a call back into `fma` itself (infinite recursion).

#[no_mangle]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    x * y + z
}

#[no_mangle]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    x * y + z
}
