#![allow(dead_code)]
#![allow(unused_variables)]


use std::mem;

const NICE: u8 = 69;
static mut X: u8 = 55;

#[derive(Clone, Copy)]
pub struct Point {
    x: f64,
    y: f64,
}

pub fn func(p: &mut Point) {
    p.x = NICE as f64;
}

fn main() {
    let a = 5;
    unsafe {
        X = 5;
    }
    unsafe {
        println!("{} = {}", X, mem::size_of_val(&X));
    }
    let mut p1 = Point { x: 0.0, y: 0.0 };
    let mut p2 = Box::new(Point { x: 0.0, y: 0.0 });
    p1.x = 5 as f64;
    p2.x = 5 as f64;
    let mut p3 = *p2;
    println!("{}", p3.x);
    func(&mut p3);
    let var = p2.x;
    println!("{var}");
    println!("{}", p3.x);
}
