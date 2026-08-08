// A comment that mentions fn ghost_in_comment, which is not a definition.
/// A doc comment sketching `fn doc_comment_symbol` — also not a definition.
fn string_holder() {
    let _s = "fn string_literal_symbol";
}

pub fn real_definition() {}
struct RealStruct;
const REAL_CONST: u8 = 0;
