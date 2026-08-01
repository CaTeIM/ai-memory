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
    /// Issuer for the external-auth-proxy rung's OIDC subject. A subject is
    /// unique only within its issuer, so proxy authentication accepts these
    /// two fields only as a pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// OIDC `sub` claim asserted by an external authenticating proxy.
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
            || self.issuer.is_some()
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
    /// forwards only the issuer and subject claims asserts no
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
    /// An `(issuer, sub)` pair wins whenever both fields are present. OIDC pins
    /// this ordering: the spec defines that pair as the stable identifier and
    /// explicitly forbids relying on `preferred_username` for identity. It is
    /// also the direction that stays stable through the common upgrade — an
    /// ingress that forwarded only `sub` and later starts forwarding a
    /// username keeps the same key. The reverse upgrade (username-only, later
    /// adding the OIDC pair) re-buckets once, at the moment the deployment starts
    /// asserting the stronger identifier; `docs/users.md` tells operators to
    /// forward `sub` from day one exactly so that moment never comes.
    ///
    /// Blank and whitespace-only values name nobody. A partial OIDC pair is
    /// deliberately not an identity; trusted-proxy ingress rejects it.
    #[must_use]
    pub fn identity_key(&self) -> Option<IdentityKey> {
        let trimmed = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        if let (Some(issuer), Some(subject)) = (trimmed(&self.issuer), trimmed(&self.sub)) {
            return Some(IdentityKey::Subject { issuer, subject });
        }
        trimmed(&self.user).map(IdentityKey::User)
    }
}

/// A qualified operator identity — the one value ownership is keyed on.
///
/// The variant is part of the identity: a username and an OIDC subject with
/// equal text are different operators. Everything that persists or compares
/// an identity goes through [`Self::storage_key`], so call sites cannot flatten
/// the namespaces or discard an OIDC issuer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityKey {
    /// Named by the OIDC issuer and subject pair. `sub` alone is not globally
    /// unique when a proxy accepts tokens from more than one issuer.
    Subject {
        /// Exact OIDC `iss` value validated by the proxy.
        issuer: String,
        /// Exact OIDC `sub` value validated by the proxy.
        subject: String,
    },
    /// Named by an asserted or configured username. Usernames are display
    /// names in OIDC terms — present, human-readable, and explicitly not
    /// guaranteed stable — so this variant keys a caller only when no
    /// subject was asserted.
    User(String),
}

impl IdentityKey {
    /// The TEXT form used for in-memory routing and future owner columns:
    /// `oidc:<issuer-byte-length>:<issuer><subject>` or `user:<name>`.
    ///
    /// Length-prefixing the issuer makes the OIDC form unambiguous without
    /// constraining either value or adding an encoding dependency.
    #[must_use]
    pub fn storage_key(&self) -> String {
        match self {
            Self::Subject { issuer, subject } => {
                format!("oidc:{}:{issuer}{subject}", issuer.len())
            }
            Self::User(user) => format!("user:{user}"),
        }
    }
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

        a.issuer = Some("https://idp.example".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.sub = Some("8f3a".into());
        assert!(a.has_any());
        a = ActorContext::default();

        a.client = Some("72836f52".into());
        assert!(a.has_any());
    }

    /// OIDC identity is the issuer and subject pair, never the subject alone.
    #[test]
    fn identity_key_accepts_oidc_pair_without_username() {
        let oidc = ActorContext {
            issuer: Some("https://idp.example".into()),
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(
            oidc.identity_key(),
            Some(IdentityKey::Subject {
                issuer: "https://idp.example".into(),
                subject: "oidc-subject-123".into(),
            })
        );
    }

    /// The stable OIDC pair outranks the display username.
    #[test]
    fn identity_key_prefers_oidc_pair_over_user() {
        let both = ActorContext {
            user: Some("alice".into()),
            issuer: Some("https://idp.example".into()),
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(
            both.identity_key(),
            Some(IdentityKey::Subject {
                issuer: "https://idp.example".into(),
                subject: "oidc-subject-123".into(),
            })
        );
    }

    #[test]
    fn identity_storage_keys_keep_namespaces_and_issuers_distinct() {
        let by_name = IdentityKey::User("alice".into());
        let issuer_a = IdentityKey::Subject {
            issuer: "https://idp-a.example".into(),
            subject: "alice".into(),
        };
        let issuer_b = IdentityKey::Subject {
            issuer: "https://idp-b.example".into(),
            subject: "alice".into(),
        };
        assert_ne!(by_name.storage_key(), issuer_a.storage_key());
        assert_ne!(issuer_a.storage_key(), issuer_b.storage_key());
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
            issuer: Some("\n".into()),
            sub: Some("\t".into()),
            ..ActorContext::default()
        };
        assert_eq!(blank.identity_key(), None);
    }

    #[test]
    fn partial_oidc_pair_does_not_override_username() {
        let actor = ActorContext {
            user: Some("alice".into()),
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(
            actor.identity_key(),
            Some(IdentityKey::User("alice".into()))
        );
        let sub_only = ActorContext {
            sub: Some("oidc-subject-123".into()),
            ..ActorContext::default()
        };
        assert_eq!(sub_only.identity_key(), None);
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
            issuer: Some("https://idp.example".into()),
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
