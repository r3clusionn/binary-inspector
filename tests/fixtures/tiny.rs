#![no_std]
#![allow(unused)]
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
extern "C" { fn external_call(x: i32) -> i32; }
static mut COUNTER: i32 = 7;
#[no_mangle]
pub extern "C" fn add_one(x: i32) -> i32 { unsafe { COUNTER += 1; external_call(x + COUNTER) } }
#[no_mangle]
pub extern "C" fn answer() -> i32 { 42 }
