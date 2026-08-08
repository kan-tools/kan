Each line below is a citation that MUST be reported. The self-test asserts
every one of them, so a checker that stops detecting any of these fails here
rather than silently passing a repository.

- ghost in a comment: `src/real.rs::ghost_in_comment`
- sketch in a doc comment: `src/real.rs::doc_comment_symbol`
- inside a string literal: `src/real.rs::string_literal_symbol`
- no such symbol at all: `src/real.rs::no_such_symbol`
- file does not exist: `src/nonexistent.rs::anything`
- positional, no such file: `src/nonexistent.rs:12`
- positional, past end: `src/short.rs:9999`
- positional, blank line: `src/short.rs:2`
