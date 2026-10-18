# Validation scope

The public CI gate runs natively on GitHub-hosted Linux, macOS and Windows: fmt, Clippy with warnings denied, Cargo check/test/build, RustSec audit, cargo-deny and directory/history gitleaks scans. At most two matrix Jobs run concurrently. Tool/action pins are explicit; no secrets, self-hosted runners, deployment or packaging is used. The initial hosted Linux and macOS runs passed. The first hosted Windows run exposed the mock TLS delivery issue below; the corrected follow-up still needs its hosted rerun. A local Mac pass does not establish Windows execution.

The LDAP mock is an in-process verified-TLS peer with generated certificates. It covers anonymous/simple bind, read/write/schema behavior, negative TLS cases, paging/VLV, cancellation and bounded input without an external directory. Certificate tests generate inputs in memory. Native credential-store examples are opt-in and create only unique temporary synthetic entries; normal tests never access an existing credential. Runtime success does not prove credential persistence, real-GPU compatibility, high-DPI behavior, server ACLs or screen-reader acceptance.

`--smoke` opens and closes the GUI; it is a local opt-in runtime probe. Synthetic evidence examples are for local development. No real directory screenshot/gallery is included. Signing, notarization, installers, public releases and credential transfer are outside this snapshot.


## TLS mock delivery regression

The ordinary mock-server response path previously called `write_all` without flushing before awaiting another LDAP request. A TLS writer may accept plaintext while ciphertext remains buffered after socket backpressure. The incomplete LDAP frame then prevented the client from reaching its semantic 2 MiB page guard and produced a timeout instead. The mock now flushes completed replies before reading the next request; production behavior, verification, deadlines and error classification are unchanged.

The regression forces one underlying write to return Pending on the final TLS record and checks that ciphertext was retained. Complete oversized entries must still produce the strict 2 MiB budget error and leave the connection usable. Eight prescribed concurrent requests combine fragmentation and a short server delay; they are coverage cases, not retries. A truncated-frame disconnect must instead produce the exact sanitized transport error. No arbitrary socket error is accepted in place of the budget assertion.

Windows review: the check helper uses universal-newline text reads for the toolchain pin, argument-list subprocesses and NUL-delimited Git paths. Credential-harness mock expectations use platform-native Path strings. Real Linux keyring probing is guarded against execution on other systems; normal checks access no existing credential. Hosted native Windows and the post-test audit/deny steps require a successful follow-up run before being marked passed.
