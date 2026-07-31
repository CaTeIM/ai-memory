//! Per-request actor identity — who triggered an operation.
//!
//! ai-memory's data is single-tenant (no RBAC; everyone with auth sees the
//! same pages), but writes can be **attributed** to the user who made them.
//! [`ActorContext`] is the typed carrier for that identity, injected once
//! per request by the auth middleware and threaded through to the writer
//! actor so attribution lands in the same SQL transaction as the data.
//!
//! ## Resolution rungs
//!
//! 1. **Anonymous** — no `Authorization` header configured at all.
//!    `ActorContext::default()` (all fields `None`). The pre-multi-user
//!    behaviour; backward-compatible for every existing single-user setup.
//! 2. **Identified single-user (root)** — `AI_MEMORY_AUTH_TOKEN` matches
//!    `config.auth.bearer_token`. Middleware fills `user` / `email` / `name`
//!    from `[auth].root_username` / `root_email` (and optional `root_name`).
//! 3. **Identified multi-user** — bearer token matches an active
//!    `users.token_hash` row. Middleware fills the actor from the row.
//! 4. **External auth proxy** — operator runs an auth sidecar that injects
//!    pre-validated `X-Memory-Actor-*` headers; the middleware overlays
//!    them onto the rung 2/3 actor. (Scaffolding only in v1 — the `sub`
//!    and `client` fields below exist for this use case and the eventual
//!    admission webhook chain payload contract.)
//!
//! ## Why not RBAC
//!
//! ai-memory v1's data model is single-tenant by design. Attribution
//! records *who* did a write; it does not gate *whether* they could do it.
//! That keeps the engine focused on "shared memory for a household /
//! small team" without bringing in roles, groups, or per-page ACLs.
//!
//! ## Field choice
//!
//! Every field is `Option<String>` so:
//! - `Default::default()` is a valid anonymous actor (no allocation).
//! - Partial identity (e.g. agent known via hook payload, user not yet
//!   authenticated) is representable.
//! - Serialised payloads omit absent fields rather than emitting `null`
//!   noise — see the `#[serde(skip_serializing_if = "Option::is_none")]`
//!   attributes.

use serde::{Deserialize, Serialize};

/// Identity of the actor that triggered an operation.
///
/// Populated by the auth middleware. Pure data — no I/O, no resolution
/// logic lives here. Cloneable + cheap; threaded through request handlers
/// via `Extension<ActorContext>` and forwarded into the writer actor as
/// part of the write command so attribution and data land atomically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorContext {
    /// Which client triggered the write — `claude-code`, `codex`,
    /// `opencode`, `gemini-cli`, `cursor`, `cli`, `hook`, … Sourced from
    /// the MCP client info or the hook payload's `agent` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Human-readable username (e.g. `boss`, `alice`). The stable
    /// attribution key surfaced in the audit log + page frontmatter
    /// `last_modified_by`. `None` = anonymous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Optional display name (e.g. `Alice Smith`). For UIs that want to
    /// show "Last edited by Alice Smith" instead of `alice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional email. Surfaced alongside the username in the web UI +
    /// `/api/v1` responses so reviewers know who to ask about a page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Session id from the agent (when known via the hook payload).
    /// Lets per-session timelines reconstruct "what did this agent do
    /// in this session" against `audit_log` + `observations`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Reserved for the external-auth-proxy rung: the JWT `sub` claim
    /// (stable user UUID). Kept `Option<String>` so payloads to the
    /// future admission webhook chain stay forward-compatible with the
    /// shape PR #55 documents — we don't fill it from rungs 0-3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Reserved for the external-auth-proxy rung: the DCR client UUID
    /// identifying which install of an agent made the request. Same
    /// forward-compat rationale as [`Self::sub`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

/// Authorization tier the auth middleware resolved this request to.
///
/// Identity ([`ActorContext`]) carries *who* the request is from;
/// `AuthLevel` carries *what they're allowed to do*. The two are
/// distinct so a handler can guard on "must be root" without also
/// having to inspect or compare username strings against config.
///
/// Available as `Extension<AuthLevel>` on every request after the
/// auth middleware runs. In multi-user mode every `/admin/*` route
/// checks this against [`AuthLevel::Root`] and returns 403 for
/// `User` / 401 for `Anonymous`; normal DB users are allowed on the
/// MCP and read-only API surfaces where writes are attributed to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthLevel {
    /// Rung 0: no auth configured. Read-mostly setups; root-only
    /// routes refuse this tier (no root → no user management).
    Anonymous,
    /// Rung 1: authenticated as the configured root user.
    /// Allowed everywhere including user-management endpoints.
    Root,
    /// Rung 2: authenticated via the `users` table.
    /// Allowed on regular routes (write_page, query, etc.) but
    /// refused on root-only admin routes.
    User,
}

/// Coarse-grained capabilities guarded by the auth layer.
///
/// This is intentionally smaller than a role/RBAC system: ai-memory v1 is
/// single-tenant, so the policy surface is "normal read/write is allowed"
/// versus "this operational action needs root". Keeping that decision in one
/// enum prevents future handlers from open-coding subtly different checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Operational `/admin/*` routes. In multi-user mode these are root-only;
    /// in single-user/no-auth mode historical behavior is preserved.
    Admin,
    /// User lifecycle routes (`/admin/users*`). These are root-only even when
    /// multi-user mode is not fully configured.
    UserManagement,
    /// Regular read surfaces (MCP/query/API/wiki reads).
    NormalRead,
    /// Regular write surfaces that attribute to the resolved actor.
    NormalWrite,
    /// Loop-prevention admission-chain skip header.
    SkipAdmissionChain,
}

/// Authorization failure independent of any HTTP framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzError {
    /// The caller must authenticate before the capability can be used.
    AuthenticationRequired(&'static str),
    /// The caller authenticated, but the capability is root-only.
    Forbidden(&'static str),
}

impl AuthzError {
    /// Human-readable policy message for HTTP/MCP responses.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            AuthzError::AuthenticationRequired(msg) | AuthzError::Forbidden(msg) => msg,
        }
    }

    /// True when the response should be an authentication challenge (HTTP 401).
    #[must_use]
    pub fn is_authentication_required(self) -> bool {
        matches!(self, AuthzError::AuthenticationRequired(_))
    }
}

impl AuthLevel {
    /// Check whether this auth tier can use `capability`.
    ///
    /// `multi_user_enabled` is the store-backed presence of any user row:
    /// operational admin routes keep their historical bootstrap behavior until
    /// the first user is created, while user-management is always root-only.
    pub fn authorize(
        self,
        capability: Capability,
        multi_user_enabled: bool,
    ) -> Result<(), AuthzError> {
        match capability {
            Capability::NormalRead | Capability::NormalWrite => Ok(()),
            Capability::SkipAdmissionChain => match self {
                AuthLevel::User => {
                    Err(AuthzError::Forbidden("admission webhook skip is root-only"))
                }
                AuthLevel::Anonymous | AuthLevel::Root => Ok(()),
            },
            Capability::Admin if !multi_user_enabled => Ok(()),
            Capability::Admin => self.require_root(
                "admin operation requires authentication in multi-user mode",
                "admin operation is root-only in multi-user mode",
            ),
            Capability::UserManagement => self.require_root(
                "user management requires authentication",
                "user management is root-only",
            ),
        }
    }

    fn require_root(
        self,
        anonymous_message: &'static str,
        user_message: &'static str,
    ) -> Result<(), AuthzError> {
        match self {
            AuthLevel::Root => Ok(()),
            AuthLevel::Anonymous => Err(AuthzError::AuthenticationRequired(anonymous_message)),
            AuthLevel::User => Err(AuthzError::Forbidden(user_message)),
        }
    }
}

/// Canonical name of the admission-chain loop-prevention header.
pub const SKIP_ADMISSION_CHAIN_HEADER: &str = "x-memory-skip-admission-chain";

/// Parse the admission-chain skip list from the raw
/// `X-Memory-Skip-Admission-Chain` header value (comma-separated webhook
/// names). Entries are trimmed and empty tokens dropped, so `"a, ,b,"` →
/// `["a", "b"]`; `None` yields an empty list.
#[must_use]
pub fn parse_skip_admission_chain(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// The same list, but honoured only for a caller that holds
/// [`Capability::SkipAdmissionChain`].
///
/// The header is client-controlled, so a regular DB user must not be able to
/// set it and walk past a `reject`-policy admission webhook. Every transport
/// that forwards the skip list (MCP tools, admin routes, hook ingress) goes
/// through this one predicate rather than re-deriving the tier rule.
#[must_use]
pub fn skip_admission_chain_for(level: AuthLevel, raw: Option<&str>) -> Vec<String> {
    if level
        .authorize(Capability::SkipAdmissionChain, true)
        .is_ok()
    {
        parse_skip_admission_chain(raw)
    } else {
        Vec::new()
    }
}

impl ActorContext {
    /// `true` if at least one identity field is set.
    ///
    /// Cheap predicate for "should we record attribution?" — when this
    /// returns `false` the writer can skip the audit-log author_id
    /// stamp (saves a column write per operation) and emit pages without
    /// the `last_modified_by` frontmatter block.
    #[must_use]
    pub fn has_any(&self) -> bool {
        self.agent.is_some()
            || self.user.is_some()
            || self.name.is_some()
            || self.email.is_some()
            || self.session_id.is_some()
            || self.sub.is_some()
            || self.client.is_some()
    }

    /// Construct the canonical anonymous actor — same as
    /// [`Default::default`], but more readable at call sites where the
    /// intent is "this is an anonymous request".
    #[must_use]
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Does this actor name a specific human, and under what key?
    ///
    /// Every ownership decision in the engine — which rows a caller may read,
    /// which name a new row is stamped with — goes through here rather than
    /// reaching for [`Self::user`] directly, because "identified" is not the
    /// same question as "has a username". An ingress that terminates OIDC and
    /// forwards only the subject claim asserts `sub` with no
    /// `preferred_username`; the auth middleware already resolves that request
    /// to `AuthLevel::User`, so a per-site `.user` check would call the same
    /// request identified for authorization and anonymous for ownership — and
    /// the operator would stop seeing rows they had just written.
    ///
    /// The key is *qualified* — [`IdentityKey::Subject`] or
    /// [`IdentityKey::User`], never a bare string — because the two name
    /// spaces are populated by different parties. A username is chosen by a
    /// person; an OIDC subject is issued by an IdP. Stored raw in one TEXT
    /// column, a username equal to somebody else's subject would silently
    /// share that person's rows. Qualification makes the collision
    /// unrepresentable rather than unlikely.
    ///
    /// `sub` wins whenever it is present. OIDC pins this ordering:
    /// the spec defines `sub` as the stable, non-reassignable identifier and
    /// explicitly forbids relying on `preferred_username` for identity. It is
    /// also the direction that stays stable through the common upgrade — an
    /// ingress that forwarded only `sub` and later starts forwarding a
    /// username keeps the same key. The reverse upgrade (username-only, later
    /// adding `sub`) re-buckets once, at the moment the deployment starts
    /// asserting the stronger identifier; `docs/users.md` tells operators to
    /// forward `sub` from day one exactly so that moment never comes.
    ///
    /// Blank and whitespace-only values name nobody — they would otherwise
    /// mint an owner literally called `""` that the next blank-actor caller
    /// would match. Same rule [`OwnerFilter::for_actor_context`] applies.
    #[must_use]
    pub fn identity_key(&self) -> Option<IdentityKey> {
        let trimmed = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        if let Some(sub) = trimmed(&self.sub) {
            return Some(IdentityKey::Subject(sub));
        }
        trimmed(&self.user).map(IdentityKey::User)
    }
}

/// A qualified operator identity — the one value ownership is keyed on.
///
/// The variant is part of the identity: `User("alice")` and
/// `Subject("alice")` are different operators, always. Everything that
/// persists or compares an identity goes through [`Self::storage_key`] (DB
/// TEXT columns) or [`Self::path_segment`] (wiki paths); nothing stores the
/// raw value, so no call site can accidentally flatten the two name spaces
/// back into one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityKey {
    /// Named by an IdP-issued OIDC subject claim. Checked first: `sub` is the
    /// identifier the OIDC spec defines as stable and non-reassignable.
    Subject(String),
    /// Named by an asserted or configured username. Usernames are display
    /// names in OIDC terms — present, human-readable, and explicitly not
    /// guaranteed stable — so this variant keys a caller only when no
    /// subject was asserted.
    User(String),
}

impl IdentityKey {
    /// The TEXT form stored in owner columns and compared by
    /// [`OwnerFilter::admits`]: `sub:<subject>` or `user:<name>`.
    ///
    /// The prefix runs to the first `:`; only these two prefixes exist, so
    /// the encoding needs no escaping — whatever follows the first `:` is the
    /// raw value, even if it contains further colons (subjects are often
    /// URLs).
    #[must_use]
    pub fn storage_key(&self) -> String {
        match self {
            Self::Subject(sub) => format!("sub:{sub}"),
            Self::User(user) => format!("user:{user}"),
        }
    }

    /// Inverse of [`Self::storage_key`], for reading a stored owner back into
    /// the typed key.
    ///
    /// Rows persist the qualified TEXT form, and some paths must later act *as*
    /// the operator that TEXT names — a SessionEnd delivered by a spool drain
    /// attributes the session page to the session's recorded owner, not to
    /// whoever flushed the event. Re-wrapping the stored string in a fresh
    /// [`IdentityKey`] would double-qualify it (`user:sub:…`), so the parse
    /// lives here, next to the encoding it inverts. `None` means the TEXT is
    /// not a storage key at all — nothing this contract wrote.
    #[must_use]
    pub fn from_storage_key(key: &str) -> Option<Self> {
        key.strip_prefix("sub:")
            .map(|sub| Self::Subject(sub.to_owned()))
            .or_else(|| {
                key.strip_prefix("user:")
                    .map(|user| Self::User(user.to_owned()))
            })
    }

    /// The [`ActorContext`] this key names — `Subject` fills `sub`, `User`
    /// fills `user` — so [`ActorContext::identity_key`] round-trips to `self`.
    ///
    /// For paths that act on a STORED owner (see [`Self::from_storage_key`])
    /// and need to hand downstream code a real actor: stuffing the qualified
    /// storage TEXT into `ActorContext::user` instead would present a subject
    /// as a username and re-derive a different identity.
    #[must_use]
    pub fn to_actor_context(&self) -> ActorContext {
        match self {
            Self::Subject(sub) => ActorContext {
                sub: Some(sub.clone()),
                ..ActorContext::default()
            },
            Self::User(user) => ActorContext {
                user: Some(user.clone()),
                ..ActorContext::default()
            },
        }
    }

    /// A filesystem-safe, injective encoding for per-operator wiki paths
    /// (`_slots/<segment>/…`).
    ///
    /// Subjects and usernames may hold anything the IdP or operator chose —
    /// URLs are common subjects — and wiki pages are real files on every
    /// platform the server runs on, so the raw value cannot be a path
    /// component. Values made only of `[A-Za-z0-9._-]` (≤ 64 chars, no
    /// leading dot) pass through readably as `s-<value>` / `u-<value>`;
    /// anything else becomes lowercase hex of its UTF-8 bytes under the
    /// distinct `sx-` / `ux-` prefixes. The prefixes are what keep the
    /// encoding injective: a passthrough value that *looks* like hex
    /// (`s-c3a9`) can never collide with the value that *hexes* to the same
    /// digits (`sx-c3a9`).
    #[must_use]
    pub fn path_segment(&self) -> String {
        fn passthrough(value: &str) -> bool {
            value.len() <= 64
                && !value.starts_with('.')
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        }
        fn hex(value: &str) -> String {
            value.bytes().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            })
        }
        match self {
            Self::Subject(v) if passthrough(v) => format!("s-{v}"),
            Self::Subject(v) => format!("sx-{}", hex(v)),
            Self::User(v) if passthrough(v) => format!("u-{v}"),
            Self::User(v) => format!("ux-{}", hex(v)),
        }
    }
}

/// Which owned rows a caller is allowed to see or act on.
///
/// Used for handoffs and for sessions. A row whose owner is `None` is
/// *shared*: it predates ownership, was written by a caller with no actor, or
/// was deliberately published to the whole project. Shared rows stay visible
/// to everyone, which is what keeps single-operator servers behaving exactly
/// as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerFilter {
    /// An identified caller: their own rows plus the shared ones. Holds the
    /// [`IdentityKey::storage_key`] form — the same TEXT that
    /// [`owner_stamp`] writes — so admit checks are exact string equality
    /// with no re-derivation.
    User(String),
    /// A caller with no actor: shared rows only. Prevents an unattributed
    /// reader (or a browser hitting a read-only API) from draining or
    /// reading something that belongs to a specific operator.
    Unattributed,
    /// Explicit opt-in to every owner, for operator recovery ("give me
    /// whatever is pending here, even if it is not mine").
    Any,
}

impl OwnerFilter {
    /// Build the filter for a caller, applying the one identity rule in
    /// [`ActorContext::identity_key`] instead of re-deriving it at the call
    /// site.
    #[must_use]
    pub fn for_actor_context(actor: &ActorContext) -> Self {
        match actor.identity_key() {
            Some(key) => Self::User(key.storage_key()),
            None => Self::Unattributed,
        }
    }

    /// Does a row owned by `owner` pass this filter?
    #[must_use]
    pub fn admits(&self, owner: Option<&str>) -> bool {
        match (self, owner) {
            // Shared rows are visible to everyone (legacy + single-user).
            (_, None) => true,
            (Self::Any, _) => true,
            (Self::User(me), Some(owner)) => me == owner,
            (Self::Unattributed, Some(_)) => false,
        }
    }
}

/// The owner to stamp on a row a request creates — the write-side mirror of
/// [`OwnerFilter::for_actor_context`], which decides what that same request
/// may read.
///
/// `distinguishes_operators` is the deployment-level question the admin gates
/// already ask (`users` rows exist, or a trusted proxy asserts identities),
/// and it is what makes this more than `identity.map(storage_key)`.
///
/// # Why a deployment that names one operator must still stamp nothing
///
/// On a server with `[auth].bearer_token` + `[auth].root_username` and no
/// users and no proxy, every HTTP request resolves to that single name.
/// Stamping it does not separate anybody from anybody — there is only one
/// operator — but it does split that operator in two, because the transports
/// disagree about whether a request carries an actor at all: the HTTP write
/// would land owned, while the SAME person's stdio / in-process MCP transport
/// carries no actor, filters as [`OwnerFilter::Unattributed`], and could no
/// longer see what they just wrote. Producing the pre-ownership `NULL` there
/// is what keeps the transports agreeing.
///
/// The read side deliberately does **not** take this gate: a caller still
/// filters as `OwnerFilter::User(key)`, which admits both the shared rows and
/// any row already stamped with that key, so rows written while a deployment
/// did distinguish operators stay reachable after it stops (the last `users`
/// row is deleted).
#[must_use]
pub fn owner_stamp(
    identity: Option<&IdentityKey>,
    distinguishes_operators: bool,
) -> Option<String> {
    if !distinguishes_operators {
        return None;
    }
    identity.map(IdentityKey::storage_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_anonymous() {
        let a = ActorContext::default();
        assert!(!a.has_any(), "default actor must be fully anonymous");
        assert_eq!(a, ActorContext::anonymous());
    }

    #[test]
    fn admin_capability_preserves_single_user_mode() {
        for level in [AuthLevel::Anonymous, AuthLevel::Root, AuthLevel::User] {
            assert_eq!(level.authorize(Capability::Admin, false), Ok(()));
        }
    }

    #[test]
    fn admin_capability_is_root_only_in_multi_user_mode() {
        assert_eq!(AuthLevel::Root.authorize(Capability::Admin, true), Ok(()));
        assert!(matches!(
            AuthLevel::Anonymous.authorize(Capability::Admin, true),
            Err(AuthzError::AuthenticationRequired(
                "admin operation requires authentication in multi-user mode"
            ))
        ));
        assert!(matches!(
            AuthLevel::User.authorize(Capability::Admin, true),
            Err(AuthzError::Forbidden(
                "admin operation is root-only in multi-user mode"
            ))
        ));
    }

    #[test]
    fn user_management_is_always_root_only() {
        assert_eq!(
            AuthLevel::Root.authorize(Capability::UserManagement, false),
            Ok(())
        );
        assert_eq!(
            AuthLevel::Root.authorize(Capability::UserManagement, true),
            Ok(())
        );
        assert!(matches!(
            AuthLevel::Anonymous.authorize(Capability::UserManagement, false),
            Err(AuthzError::AuthenticationRequired(
                "user management requires authentication"
            ))
        ));
        assert!(matches!(
            AuthLevel::User.authorize(Capability::UserManagement, true),
            Err(AuthzError::Forbidden("user management is root-only"))
        ));
    }

    #[test]
    fn skip_admission_chain_rejects_db_users() {
        assert_eq!(
            AuthLevel::Root.authorize(Capability::SkipAdmissionChain, true),
            Ok(())
        );
        assert_eq!(
            AuthLevel::Anonymous.authorize(Capability::SkipAdmissionChain, true),
            Ok(())
        );
        assert!(matches!(
            AuthLevel::User.authorize(Capability::SkipAdmissionChain, true),
            Err(AuthzError::Forbidden("admission webhook skip is root-only"))
        ));
    }

    #[test]
    fn skip_admission_chain_parses_csv_and_honours_the_tier_rule() {
        assert_eq!(
            parse_skip_admission_chain(Some("a, ,b,")),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(parse_skip_admission_chain(None).is_empty());
        for level in [AuthLevel::Root, AuthLevel::Anonymous] {
            assert_eq!(
                skip_admission_chain_for(level, Some("mirror")),
                vec!["mirror".to_string()],
                "{level:?} may skip a webhook it re-entered from",
            );
        }
        assert!(
            skip_admission_chain_for(AuthLevel::User, Some("mirror")).is_empty(),
            "a DB user must not bypass a reject-policy webhook via a header",
        );
    }

    #[test]
    fn has_any_truth_table() {
        // Each field individually flips has_any() to true. Catches an
        // accidental omission if someone adds a new field and forgets
        // to update the predicate.
        let mut a = ActorContext::default();
        assert!(!a.has_any());

        a.agent = Some("claude-code".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.user = Some("alice".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.name = Some("Alice Smith".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.email = Some("alice@home".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.session_id = Some("s-1".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.sub = Some("8f3a".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.client = Some("72836f52".into());
        assert!(a.has_any());
    }

    /// An actor the auth middleware resolved to `AuthLevel::User` must be
    /// identified for ownership too, whichever field the proxy filled in. The
    /// sub-only rung is the one a per-site `.user` check silently drops.
    #[test]
    fn identity_key_accepts_sub_when_no_username_was_asserted() {
        let sub_only = ActorContext {
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(
            sub_only.identity_key(),
            Some(IdentityKey::Subject("oidc-subject-123".into()))
        );
    }

    /// `sub` outranks `user`: OIDC defines `sub` as the stable identifier and
    /// forbids relying on `preferred_username`. The concrete upgrade this
    /// protects: an ingress that forwarded only `sub` and later starts
    /// forwarding a username must keep the same key, or the operator's rows
    /// re-bucket the day the proxy config improves.
    #[test]
    fn identity_key_prefers_sub_over_user() {
        let both = ActorContext {
            user: Some("alice".into()),
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(
            both.identity_key(),
            Some(IdentityKey::Subject("oidc-subject-123".into()))
        );
    }

    /// The aliasing the qualified form exists to kill: a username equal to
    /// somebody else's subject is a DIFFERENT identity, in storage and in
    /// admit checks. Raw TEXT keys would have merged these two people.
    #[test]
    fn a_username_never_aliases_an_equal_subject() {
        let by_name = IdentityKey::User("alice".into());
        let by_subject = IdentityKey::Subject("alice".into());
        assert_ne!(by_name.storage_key(), by_subject.storage_key());
        assert_ne!(by_name.path_segment(), by_subject.path_segment());

        let names_filter = OwnerFilter::User(by_name.storage_key());
        assert!(!names_filter.admits(Some(&by_subject.storage_key())));
    }

    /// Storage keys must read back as the identity that wrote them — including
    /// a subject that CONTAINS a colon (URLs are common subjects) — and a
    /// stored value this contract never produced must parse to nobody rather
    /// than to a guessed operator.
    #[test]
    fn storage_key_round_trips_through_from_storage_key() {
        for key in [
            IdentityKey::User("alice".into()),
            IdentityKey::Subject("oidc-subject-123".into()),
            IdentityKey::Subject("https://idp.example/id/42".into()),
            // The aliasing case: a username that LOOKS like a subject key must
            // come back as the username it is.
            IdentityKey::User("sub:alice".into()),
        ] {
            assert_eq!(
                IdentityKey::from_storage_key(&key.storage_key()).as_ref(),
                Some(&key)
            );
            assert_eq!(
                key.to_actor_context().identity_key().as_ref(),
                Some(&key),
                "to_actor_context must name the same operator"
            );
        }
        assert_eq!(IdentityKey::from_storage_key("alice"), None);
        assert_eq!(IdentityKey::from_storage_key(""), None);
    }

    /// Subjects are IdP-issued and often URLs; wiki paths are real files on
    /// every platform. Path-hostile values hex-encode under a DISTINCT prefix
    /// so a passthrough value that merely looks like hex cannot collide with
    /// the value that hexes to the same digits.
    #[test]
    fn path_segment_is_filesystem_safe_and_injective() {
        assert_eq!(IdentityKey::User("alice".into()).path_segment(), "u-alice");
        assert_eq!(
            IdentityKey::Subject("103459784".into()).path_segment(),
            "s-103459784"
        );
        let url_sub = IdentityKey::Subject("https://idp.example/id/42".into());
        let seg = url_sub.path_segment();
        assert!(seg.starts_with("sx-"), "url subject must hex-encode: {seg}");
        assert!(
            seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "segment must be path-safe: {seg}"
        );
        // The ambiguity the split prefixes prevent: "c3a9" passes through,
        // "é" hexes to c3a9 — different prefixes, no collision.
        assert_eq!(IdentityKey::Subject("c3a9".into()).path_segment(), "s-c3a9");
        assert_eq!(IdentityKey::Subject("é".into()).path_segment(), "sx-c3a9");
    }

    /// The write-side gate: identity alone is not enough to stamp — the
    /// deployment must actually distinguish operators, or a single-operator
    /// server would split its own transports (HTTP names the operator, stdio
    /// carries no actor).
    #[test]
    fn owner_stamp_requires_both_identity_and_a_distinguishing_deployment() {
        let key = IdentityKey::Subject("oidc-subject-123".into());
        assert_eq!(owner_stamp(Some(&key), false), None);
        assert_eq!(owner_stamp(None, true), None);
        assert_eq!(
            owner_stamp(Some(&key), true),
            Some("sub:oidc-subject-123".into())
        );
    }

    /// The admit matrix in one place: shared rows reach everyone, owned rows
    /// reach their owner and `Any`, and an unattributed caller sees only the
    /// shared ones.
    #[test]
    fn owner_filter_admit_matrix() {
        let alice = OwnerFilter::for_actor_context(&ActorContext {
            user: Some("alice".into()),
            ..ActorContext::default()
        });
        let owned = IdentityKey::User("alice".into()).storage_key();
        let other = IdentityKey::User("bob".into()).storage_key();

        for filter in [&alice, &OwnerFilter::Unattributed, &OwnerFilter::Any] {
            assert!(filter.admits(None), "shared rows reach everyone");
        }
        assert!(alice.admits(Some(&owned)));
        assert!(!alice.admits(Some(&other)));
        assert!(!OwnerFilter::Unattributed.admits(Some(&owned)));
        assert!(OwnerFilter::Any.admits(Some(&other)));
    }

    /// Naming nobody stays naming nobody: an agent/session-only actor carries
    /// transport detail, not identity, and blanks are not names.
    #[test]
    fn identity_key_is_none_without_a_named_human() {
        assert_eq!(ActorContext::anonymous().identity_key(), None);
        let transport_only = ActorContext {
            agent: Some("claude-code".into()),
            session_id: Some("s-1".into()),
            client: Some("72836f52".into()),
            ..ActorContext::default()
        };
        assert_eq!(transport_only.identity_key(), None);
        let blank = ActorContext {
            user: Some("   ".into()),
            sub: Some("\t".into()),
            ..ActorContext::default()
        };
        assert_eq!(blank.identity_key(), None);
    }

    /// A blank `user` beside a real `sub` must fall through rather than
    /// resolving the whole actor to "nobody".
    #[test]
    fn identity_key_skips_a_blank_user_and_uses_sub() {
        let actor = ActorContext {
            user: Some("  ".into()),
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(
            actor.identity_key(),
            Some(IdentityKey::Subject("oidc-subject-123".into()))
        );
    }

    #[test]
    fn anonymous_serialises_to_empty_object() {
        // Every absent field is omitted (not `null`) — keeps the
        // webhook payload + /api/v1 response shape lean.
        let json = serde_json::to_string(&ActorContext::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn partial_actor_serialises_only_set_fields() {
        let a = ActorContext {
            user: Some("boss".into()),
            email: Some("boss@example.com".into()),
            ..ActorContext::default()
        };
        let json = serde_json::to_string(&a).unwrap();
        // Stable field order is set by the struct definition; serde
        // emits fields in declaration order.
        assert_eq!(json, r#"{"user":"boss","email":"boss@example.com"}"#);
    }

    #[test]
    fn round_trip_preserves_all_set_fields() {
        let original = ActorContext {
            agent: Some("codex".into()),
            user: Some("alice".into()),
            name: Some("Alice Smith".into()),
            email: Some("alice@home".into()),
            session_id: Some("019e6d".into()),
            sub: Some("8f3a-uuid".into()),
            client: Some("72836f52-uuid".into()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: ActorContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn missing_fields_deserialise_to_none() {
        // Forward-compat: a payload from an older sender that omits
        // newly-added fields still deserialises cleanly.
        let parsed: ActorContext = serde_json::from_str(r#"{"user":"boss"}"#).unwrap();
        assert_eq!(parsed.user.as_deref(), Some("boss"));
        assert!(parsed.agent.is_none());
        assert!(parsed.email.is_none());
        assert!(parsed.sub.is_none());
    }

    #[test]
    fn explicit_null_fields_deserialise_to_none() {
        // Some senders (older webhooks, hand-written JSON) emit `null`
        // for absent fields instead of omitting them. Both forms must
        // round-trip to the same anonymous actor.
        let parsed: ActorContext = serde_json::from_str(r#"{"user":null,"agent":null}"#).unwrap();
        assert!(!parsed.has_any());
    }
}
