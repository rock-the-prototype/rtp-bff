use super::policy::{
    PathConstraint, QueryConstraint, ResourceRoutePolicyDefinition, ResourceRoutePolicyRegistry,
    RoutePolicyError, RoutePolicySnapshot, UpstreamRouteDefinition,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier},
    thread,
};

const PROJECT_ID: &str = "8d5717b2-5b9d-4d8c-baf7-61cf9bc5f3ea";
fn project_route(host: &str, upstream_path: &str) -> ResourceRoutePolicyDefinition {
    ResourceRoutePolicyDefinition {
        id: "projects.read".to_owned(),
        browser_path: "/api/projects/{id}".to_owned(),
        methods: vec!["GET".to_owned(), "HEAD".to_owned()],
        upstream: UpstreamRouteDefinition {
            scheme: "https".to_owned(),
            host: host.to_owned(),
            port: 443,
            path_template: upstream_path.to_owned(),
            follow_redirects: false,
        },
        path_parameters: BTreeMap::from([("id".to_owned(), PathConstraint::Uuid)]),
        query_parameters: BTreeMap::new(),
        request_headers_to_forward: vec!["Accept".to_owned(), "If-None-Match".to_owned()],
        response_headers_to_forward: vec!["Content-Type".to_owned(), "ETag".to_owned()],
    }
}
fn snapshot() -> RoutePolicySnapshot {
    RoutePolicySnapshot::try_new(
        "test-1",
        vec![project_route(
            "projects-api.example.invalid",
            "/v1/projects/{id}",
        )],
    )
    .expect("test policy must be valid")
}
#[test]
fn approved_get_resolves_fixed_logical_resource() {
    let resolved = snapshot()
        .resolve("projects.read", "GET", &[("id", PROJECT_ID)], &[])
        .expect("approved route must resolve");
    assert_eq!(resolved.route_id(), "projects.read");
    assert_eq!(resolved.method(), "GET");
    assert_eq!(resolved.origin().scheme(), "https");
    assert_eq!(resolved.origin().host(), "projects-api.example.invalid");
    assert_eq!(resolved.origin().port(), 443);
    assert_eq!(
        resolved.path_and_query(),
        format!("/v1/projects/{PROJECT_ID}")
    );
}
#[test]
fn approved_head_resolves_fixed_logical_resource() {
    let resolved = snapshot()
        .resolve("projects.read", "HEAD", &[("id", PROJECT_ID)], &[])
        .expect("approved HEAD route must resolve");

    assert_eq!(resolved.method(), "HEAD");
}

#[test]
fn lowercase_method_is_rejected_as_distinct_http_method() {
    let error = snapshot()
        .resolve("projects.read", "get", &[("id", PROJECT_ID)], &[])
        .expect_err("HTTP method tokens are case-sensitive");

    assert_eq!(
        error,
        RoutePolicyError::MethodNotAllowed {
            route_id: "projects.read".to_owned(),
            method: "get".to_owned(),
        }
    );
}

#[test]
fn lowercase_policy_method_is_rejected_instead_of_normalized() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.methods = vec!["get".to_owned()];

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("policy methods must use the exact approved HTTP method token");

    assert_eq!(error, RoutePolicyError::UnsupportedMethod("get".to_owned()));
}
#[test]
fn unknown_route_is_default_deny() {
    let error = snapshot()
        .resolve("unknown", "GET", &[("id", PROJECT_ID)], &[])
        .expect_err("unknown route must fail closed");

    assert_eq!(error, RoutePolicyError::UnknownRoute("unknown".to_owned()));
}
#[test]
fn unsafe_methods_are_rejected_by_policy_validation() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.methods.push("POST".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("state-changing methods are outside this slice");

    assert_eq!(
        error,
        RoutePolicyError::UnsupportedMethod("POST".to_owned())
    );
}
#[test]
fn disallowed_method_is_rejected_before_any_network_layer_exists() {
    let error = snapshot()
        .resolve("projects.read", "POST", &[("id", PROJECT_ID)], &[])
        .expect_err("POST must not resolve");

    assert!(matches!(error, RoutePolicyError::MethodNotAllowed { .. }));
}
#[test]
fn http_upstream_is_rejected() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.upstream.scheme = "http".to_owned();

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("production resource policy is HTTPS-only");

    assert_eq!(
        error,
        RoutePolicyError::UnsupportedScheme("http".to_owned())
    );
}
#[test]
fn invalid_host_is_rejected() {
    let route = project_route("evil.example.invalid/path", "/v1/projects/{id}");

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("host must not contain a path");

    assert_eq!(
        error,
        RoutePolicyError::InvalidHost("evil.example.invalid/path".to_owned())
    );
}
#[test]
fn redirect_following_is_rejected_by_policy_validation() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.upstream.follow_redirects = true;

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("route policy must not permit redirect following");

    assert_eq!(
        error,
        RoutePolicyError::RedirectFollowingForbidden("projects.read".to_owned())
    );
}
#[test]
fn duplicate_route_ids_are_rejected() {
    let first = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    let second = project_route("projects-api-2.example.invalid", "/v2/projects/{id}");

    let error = RoutePolicySnapshot::try_new("test", vec![first, second])
        .expect_err("duplicate route IDs are ambiguous");

    assert_eq!(
        error,
        RoutePolicyError::DuplicateRouteId("projects.read".to_owned())
    );
}
#[test]
fn duplicate_browser_path_and_method_are_rejected() {
    let first = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    let mut second = project_route("archive-api.example.invalid", "/v1/archive/{id}");
    second.id = "projects.archive".to_owned();

    let error = RoutePolicySnapshot::try_new("test", vec![first, second])
        .expect_err("same browser method/path must not map ambiguously");
    assert!(matches!(
        error,
        RoutePolicyError::AmbiguousBrowserRoute { .. }
    ));
}
#[test]
fn equivalent_browser_path_shapes_are_rejected_as_ambiguous() {
    let first = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    let mut second = project_route("archive-api.example.invalid", "/v1/archive/{project_id}");
    second.id = "projects.archive".to_owned();
    second.browser_path = "/api/projects/{project_id}".to_owned();
    second.path_parameters = BTreeMap::from([("project_id".to_owned(), PathConstraint::Uuid)]);
    let error = RoutePolicySnapshot::try_new("test", vec![first, second])
        .expect_err("equivalent browser route shapes must be rejected");

    assert!(matches!(
        error,
        RoutePolicyError::AmbiguousBrowserRoute { .. }
    ));
}
#[test]
fn static_browser_route_overlapping_uuid_parameter_route_is_rejected() {
    let parameterized = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    let mut static_route = project_route("archive-api.example.invalid", "/v1/archive/fixed");
    static_route.id = "projects.fixed".to_owned();
    static_route.browser_path = format!("/api/projects/{PROJECT_ID}");
    static_route.path_parameters = BTreeMap::new();

    let error = RoutePolicySnapshot::try_new("test", vec![parameterized, static_route])
        .expect_err("static route matching the UUID constraint must be ambiguous");

    assert!(matches!(
        error,
        RoutePolicyError::AmbiguousBrowserRoute { .. }
    ));
}

#[test]
fn static_browser_route_outside_uuid_constraint_does_not_overlap() {
    let parameterized = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    let mut static_route = project_route("archive-api.example.invalid", "/v1/archive");
    static_route.id = "projects.latest".to_owned();
    static_route.browser_path = "/api/projects/latest".to_owned();
    static_route.upstream.path_template = "/v1/archive".to_owned();
    static_route.path_parameters = BTreeMap::new();

    let snapshot = RoutePolicySnapshot::try_new("test", vec![parameterized, static_route])
        .expect("non-UUID static segment must not overlap UUID parameter route");

    assert_eq!(snapshot.route_count(), 2);
}

#[test]
fn overlapping_browser_paths_with_disjoint_methods_are_allowed() {
    let mut parameterized = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    parameterized.methods = vec!["GET".to_owned()];

    let mut static_route = project_route("archive-api.example.invalid", "/v1/archive/fixed");
    static_route.id = "projects.fixed".to_owned();
    static_route.browser_path = format!("/api/projects/{PROJECT_ID}");
    static_route.path_parameters = BTreeMap::new();
    static_route.methods = vec!["HEAD".to_owned()];

    let snapshot = RoutePolicySnapshot::try_new("test", vec![parameterized, static_route])
        .expect("overlapping paths are unambiguous when their method sets are disjoint");

    assert_eq!(snapshot.route_count(), 2);
}

#[test]
fn root_browser_path_is_rejected() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects");
    route.browser_path = "/".to_owned();
    route.path_parameters = BTreeMap::new();

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("root browser path must be rejected");

    assert_eq!(error, RoutePolicyError::InvalidBrowserPath("/".to_owned()));
}
#[test]
fn unsafe_static_upstream_template_is_rejected() {
    let route = project_route("projects-api.example.invalid", "/v1/../projects/{id}");

    assert!(matches!(
        RoutePolicySnapshot::try_new("test", vec![route]),
        Err(RoutePolicyError::InvalidPathTemplate(_))
    ));
}
#[test]
fn percent_encoded_upstream_template_is_rejected() {
    let route = project_route("projects-api.example.invalid", "/v1/projects/%2F/{id}");

    assert!(matches!(
        RoutePolicySnapshot::try_new("test", vec![route]),
        Err(RoutePolicyError::InvalidPathTemplate(_))
    ));
}
#[test]
fn path_traversal_value_is_rejected() {
    let error = snapshot()
        .resolve("projects.read", "GET", &[("id", "..")], &[])
        .expect_err("path traversal must not satisfy UUID constraint");

    assert_eq!(
        error,
        RoutePolicyError::InvalidPathParameter("id".to_owned())
    );
}
#[test]
fn encoded_separator_value_is_rejected() {
    let error = snapshot()
        .resolve("projects.read", "GET", &[("id", "%2F")], &[])
        .expect_err("encoded slash must not satisfy UUID constraint");

    assert_eq!(
        error,
        RoutePolicyError::InvalidPathParameter("id".to_owned())
    );
}
#[test]
fn absolute_url_value_cannot_override_destination() {
    let error = snapshot()
        .resolve(
            "projects.read",
            "GET",
            &[("id", "https://evil.example.invalid")],
            &[],
        )
        .expect_err("absolute URL cannot satisfy UUID path constraint");

    assert_eq!(
        error,
        RoutePolicyError::InvalidPathParameter("id".to_owned())
    );
}
#[test]
fn unexpected_path_parameter_is_rejected() {
    let error = snapshot()
        .resolve(
            "projects.read",
            "GET",
            &[("id", PROJECT_ID), ("host", "evil.example.invalid")],
            &[],
        )
        .expect_err("unexpected path parameter must fail closed");

    assert_eq!(
        error,
        RoutePolicyError::UnexpectedPathParameter("host".to_owned())
    );
}
#[test]
fn missing_path_parameter_is_rejected() {
    let error = snapshot()
        .resolve("projects.read", "GET", &[], &[])
        .expect_err("required path parameter must be present");

    assert_eq!(
        error,
        RoutePolicyError::MissingPathParameter("id".to_owned())
    );
}
#[test]
fn unlisted_query_parameter_is_rejected() {
    let error = snapshot()
        .resolve(
            "projects.read",
            "GET",
            &[("id", PROJECT_ID)],
            &[("target", "evil.example.invalid")],
        )
        .expect_err("query parameters are deny-by-default");

    assert_eq!(
        error,
        RoutePolicyError::QueryParameterNotAllowed("target".to_owned())
    );
}
#[test]
fn explicitly_allowed_query_parameter_is_constrained_and_canonicalized() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.query_parameters.insert(
        "view".to_owned(),
        QueryConstraint::AsciiToken { max_len: 16 },
    );
    let snapshot =
        RoutePolicySnapshot::try_new("test", vec![route]).expect("query policy must be valid");
    let resolved = snapshot
        .resolve(
            "projects.read",
            "GET",
            &[("id", PROJECT_ID)],
            &[("view", "summary")],
        )
        .expect("allowlisted query must resolve");

    assert_eq!(
        resolved.path_and_query(),
        format!("/v1/projects/{PROJECT_ID}?view=summary")
    );
}
#[test]
fn unsafe_query_value_is_rejected() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.query_parameters.insert(
        "view".to_owned(),
        QueryConstraint::AsciiToken { max_len: 64 },
    );
    let snapshot =
        RoutePolicySnapshot::try_new("test", vec![route]).expect("query policy must be valid");
    let error = snapshot
        .resolve(
            "projects.read",
            "GET",
            &[("id", PROJECT_ID)],
            &[("view", "https://evil.example.invalid")],
        )
        .expect_err("unsafe query value must fail closed");

    assert_eq!(
        error,
        RoutePolicyError::InvalidQueryParameter("view".to_owned())
    );
}
#[test]
fn browser_authorization_cannot_be_allowlisted_for_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .request_headers_to_forward
        .push("Authorization".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("browser Authorization must never be an allowlisted forwarded header");
    assert_eq!(
        error,
        RoutePolicyError::ForbiddenRequestForwardHeader("authorization".to_owned())
    );
}
#[test]
fn browser_host_cannot_be_allowlisted_for_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.request_headers_to_forward.push("Host".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("browser Host must never override the approved upstream authority");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenRequestForwardHeader("host".to_owned())
    );
}

#[test]
fn keep_alive_cannot_be_allowlisted_for_request_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .request_headers_to_forward
        .push("Keep-Alive".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("hop-by-hop Keep-Alive must never be forwarded upstream");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenRequestForwardHeader("keep-alive".to_owned())
    );
}

#[test]
fn session_cookie_cannot_be_allowlisted_for_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route.request_headers_to_forward.push("Cookie".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("browser Cookie must never be an allowlisted forwarded header");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenRequestForwardHeader("cookie".to_owned())
    );
}
#[test]
fn upstream_set_cookie_cannot_be_allowlisted_for_response_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .response_headers_to_forward
        .push("Set-Cookie".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("Set-Cookie must never be a forwarded response header");
    assert_eq!(
        error,
        RoutePolicyError::ForbiddenResponseForwardHeader("set-cookie".to_owned())
    );
}
#[test]
fn keep_alive_cannot_be_allowlisted_for_response_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .response_headers_to_forward
        .push("Keep-Alive".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("hop-by-hop Keep-Alive must never be forwarded to the browser");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenResponseForwardHeader("keep-alive".to_owned())
    );
}

#[test]
fn proxy_authorization_cannot_be_allowlisted_for_response_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .response_headers_to_forward
        .push("Proxy-Authorization".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("proxy credentials must never be forwarded to the browser");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenResponseForwardHeader("proxy-authorization".to_owned())
    );
}

#[test]
fn proxy_authentication_info_cannot_be_allowlisted_for_response_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .response_headers_to_forward
        .push("Proxy-Authentication-Info".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("proxy authentication metadata must not cross the BFF response boundary");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenResponseForwardHeader("proxy-authentication-info".to_owned())
    );
}

#[test]
fn active_snapshot_has_stable_non_secret_digest() {
    let first = snapshot();
    let second = snapshot();

    assert_eq!(first.digest(), second.digest());
    assert!(first.digest().starts_with("sha256:"));
    assert_eq!(first.digest().len(), 71);
}
#[test]
fn digest_changes_when_security_relevant_destination_changes() {
    let first = snapshot();
    let second = RoutePolicySnapshot::try_new(
        "test-1",
        vec![project_route(
            "projects-api-2.example.invalid",
            "/v1/projects/{id}",
        )],
    )
    .expect("second policy must be valid");

    assert_ne!(first.digest(), second.digest());
}
#[test]
fn digest_frames_version_to_prevent_serialization_collision() {
    let regular = snapshot();

    let injected_version = concat!(
        "test-1\n",
        "route=projects.read\n",
        "browser=/api/projects/{id}\n",
        "methods=GET,HEAD\n",
        "origin=https://projects-api.example.invalid:443\n",
        "path=/v1/projects/{id}\n",
        "path-param=id:uuid\n",
        "request-headers=accept,if-none-match\n",
        "response-headers=content-type,e-tag"
    );

    let empty = RoutePolicySnapshot::try_new(injected_version, vec![])
        .expect("version remains syntactically permitted");

    assert_ne!(
        regular.digest(),
        empty.digest(),
        "version framing must prevent canonical serialization collisions"
    );
}
#[test]
fn invalid_policy_update_keeps_last_known_valid_snapshot() {
    let registry = ResourceRoutePolicyRegistry::new(snapshot());
    let before = registry
        .active_snapshot()
        .expect("registry must be readable")
        .digest()
        .to_owned();

    let mut invalid = project_route("evil.example.invalid", "/v2/projects/{id}");
    invalid.upstream.scheme = "http".to_owned();
    assert!(
        registry
            .activate_candidate("invalid", vec![invalid])
            .is_err()
    );

    let after = registry
        .active_snapshot()
        .expect("registry must remain readable")
        .digest()
        .to_owned();
    assert_eq!(before, after);
}
#[test]
fn successful_policy_activation_replaces_complete_snapshot() {
    let registry = ResourceRoutePolicyRegistry::new(snapshot());

    registry
        .activate_candidate(
            "test-2",
            vec![project_route(
                "projects-api-2.example.invalid",
                "/v2/projects/{id}",
            )],
        )
        .expect("valid candidate must activate");
    let resolved = registry
        .resolve("projects.read", "GET", &[("id", PROJECT_ID)], &[])
        .expect("new policy must resolve");

    assert_eq!(resolved.origin().host(), "projects-api-2.example.invalid");
    assert_eq!(
        resolved.path_and_query(),
        format!("/v2/projects/{PROJECT_ID}")
    );
}
#[test]
fn concurrent_readers_observe_complete_snapshots_across_replacement() {
    const READER_COUNT: usize = 4;

    let registry = Arc::new(ResourceRoutePolicyRegistry::new(snapshot()));
    let readers_ready = Arc::new(Barrier::new(READER_COUNT + 1));
    let replacement_complete = Arc::new(Barrier::new(READER_COUNT + 1));
    let mut readers = Vec::new();

    for _ in 0..READER_COUNT {
        let registry = Arc::clone(&registry);
        let readers_ready = Arc::clone(&readers_ready);
        let replacement_complete = Arc::clone(&replacement_complete);

        readers.push(thread::spawn(move || {
            // Capture the result first, but do not assert or unwrap before both
            // synchronization points. A pre-barrier panic would strand the
            // remaining participants and deadlock the test.
            let old_snapshot_result = registry.active_snapshot();

            readers_ready.wait();
            replacement_complete.wait();

            let old_snapshot = old_snapshot_result.expect("registry must be readable");
            assert_eq!(old_snapshot.version(), "test-1");

            let old_resolved = old_snapshot
                .resolve("projects.read", "GET", &[("id", PROJECT_ID)], &[])
                .expect("captured old snapshot must remain valid");

            assert_eq!(old_resolved.origin().host(), "projects-api.example.invalid");
            assert_eq!(
                old_resolved.path_and_query(),
                format!("/v1/projects/{PROJECT_ID}")
            );

            let new_snapshot = registry
                .active_snapshot()
                .expect("registry must remain readable");

            assert_eq!(new_snapshot.version(), "test-2");

            let new_resolved = new_snapshot
                .resolve("projects.read", "GET", &[("id", PROJECT_ID)], &[])
                .expect("replacement snapshot must resolve");

            assert_eq!(
                new_resolved.origin().host(),
                "projects-api-2.example.invalid"
            );
            assert_eq!(
                new_resolved.path_and_query(),
                format!("/v2/projects/{PROJECT_ID}")
            );
        }));
    }

    readers_ready.wait();

    let activation_result = registry.activate_candidate(
        "test-2",
        vec![project_route(
            "projects-api-2.example.invalid",
            "/v2/projects/{id}",
        )],
    );

    // Always release the readers before asserting activation success. If the
    // activation unexpectedly fails, no reader can remain blocked forever.
    replacement_complete.wait();
    activation_result.expect("valid candidate must activate");

    for reader in readers {
        reader.join().expect("reader thread must not panic");
    }
}
#[test]
fn uuid_query_parameter_accepts_canonical_uuid() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .query_parameters
        .insert("cursor".to_owned(), QueryConstraint::Uuid);

    let snapshot =
        RoutePolicySnapshot::try_new("test", vec![route]).expect("UUID query policy must be valid");

    let resolved = snapshot
        .resolve(
            "projects.read",
            "GET",
            &[("id", PROJECT_ID)],
            &[("cursor", PROJECT_ID)],
        )
        .expect("canonical UUID query parameter must resolve");

    assert_eq!(
        resolved.path_and_query(),
        format!("/v1/projects/{PROJECT_ID}?cursor={PROJECT_ID}")
    );
}

#[test]
fn uuid_query_parameter_rejects_non_uuid_value() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .query_parameters
        .insert("cursor".to_owned(), QueryConstraint::Uuid);

    let snapshot =
        RoutePolicySnapshot::try_new("test", vec![route]).expect("UUID query policy must be valid");

    let error = snapshot
        .resolve(
            "projects.read",
            "GET",
            &[("id", PROJECT_ID)],
            &[("cursor", "not-a-uuid")],
        )
        .expect_err("non-UUID query parameter must fail closed");

    assert_eq!(
        error,
        RoutePolicyError::InvalidQueryParameter("cursor".to_owned())
    );
}
#[test]
fn authorization_cannot_be_allowlisted_for_response_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .response_headers_to_forward
        .push("Authorization".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("Authorization must never be a forwarded response header");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenResponseForwardHeader("authorization".to_owned())
    );
}

#[test]
fn authentication_info_cannot_be_allowlisted_for_response_forwarding() {
    let mut route = project_route("projects-api.example.invalid", "/v1/projects/{id}");
    route
        .response_headers_to_forward
        .push("Authentication-Info".to_owned());

    let error = RoutePolicySnapshot::try_new("test", vec![route])
        .expect_err("Authentication-Info must never be a forwarded response header");

    assert_eq!(
        error,
        RoutePolicyError::ForbiddenResponseForwardHeader("authentication-info".to_owned())
    );
}
