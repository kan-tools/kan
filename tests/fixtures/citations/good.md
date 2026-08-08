Citations that MUST resolve, so the self-test also proves the checker is not
simply failing everything.

- `src/real.rs::real_definition`
- `src/real.rs::RealStruct`
- `src/real.rs::REAL_CONST`
- `src/real.rs:7`

Every keyword branch of the definition matcher, so crippling one is a false
positive here rather than a silent narrowing (a cold review crippled six and
the self-test still passed):

- `src/real.rs::RealEnum`
- `src/real.rs::RealTrait`
- `src/real.rs::RealAlias`
- `src/real.rs::real_mod`
- `src/real.rs::real_macro!`
- `src/real.rs::REAL_STATIC`
- `src/real.rs::const_fn_form`
