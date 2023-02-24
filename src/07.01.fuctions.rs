// functions
fn print_value(x: i32) {
    println!("value = {}", x);
}

fn increase(x: &mut i32) { // start with i32
    *x += 1;
}

fn product(x: i32, y: i32) -> i32 { // return value
    let z = x * y;
    z // no semicolons
}

pub fn demo() {
    print_value(123);

    let mut z = 1;
    increase(&mut z); // lend z
    println!("z = {}", z);

    let a = 3;
    let b = 5;
    let p = product(a, b);
    println!("{} * {} = {}", a, b, p);
}
