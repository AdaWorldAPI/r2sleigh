//! What a language runtime's routines do at a call, where no body proves it: models keyed by the
//! routine's name, which stays a hint the caller weighs (doc/adr-language-profile.md, item 4).

/// Whether a call to the routine named `name` re-enters its caller at the caller's entry instead of
/// returning: Go's stack growth.
///
/// cmd/internal/obj/x86/obj6.go and arm64/obj7.go `stacksplit`: the prologue's failing compare
/// calls `runtime.morestack` (`morestack_noctxt` without a closure context) and then jumps to the
/// function's start; runtime/stack.go `newstack` grows the stack and resumes after the call.
pub fn reenters_caller(name: &str) -> bool {
    let name = name.strip_prefix("sym.").unwrap_or(name);
    let name = name.strip_suffix(".abi0").unwrap_or(name);
    matches!(name, "runtime.morestack" | "runtime.morestack_noctxt")
}

#[cfg(test)]
mod tests {
    use super::reenters_caller;

    #[test]
    fn go_stack_growth_re_enters_its_caller() {
        assert!(reenters_caller("runtime.morestack_noctxt.abi0"));
        assert!(reenters_caller("sym.runtime.morestack"));
        assert!(!reenters_caller("runtime.morestackc"));
        assert!(!reenters_caller("morestack"));
    }
}
