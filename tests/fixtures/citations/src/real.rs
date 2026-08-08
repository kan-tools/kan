// A comment that mentions fn ghost_in_comment, which is not a definition.
/// A doc comment sketching `fn doc_comment_symbol` — also not a definition.
fn string_holder() {
    let _s = "fn string_literal_symbol";
}

pub fn real_definition() {}
struct RealStruct;
const REAL_CONST: u8 = 0;

pub enum RealEnum {}
pub trait RealTrait {}
pub type RealAlias = u8;
pub mod real_mod {}
pub static REAL_STATIC: u8 = 0;
pub const fn const_fn_form() {}
macro_rules! real_macro { () => {}; }
