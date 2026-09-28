use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as _},
    sync::{Arc, RwLock},
};

const MAX_ROUTE_ID_LEN: usize = 128;
const MAX_PARAMETER_NAME_LEN: usize = 64;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HOST_LEN: usize = 253;
const FORBIDDEN_REQUEST_FORWARD_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const FORBIDDEN_RESPONSE_FORWARD_HEADERS: &[&str] = &[
    "set-cookie",
    "connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathConstraint {
    Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryConstraint {
    Uuid,
    AsciiToken { max_len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRouteDefinition {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_template: String,
    pub follow_redirects: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRoutePolicyDefinition {
    pub id: String,
    pub browser_path: String,
    pub methods: Vec<String>,
    pub upstream: UpstreamRouteDefinition,
    pub path_parameters: BTreeMap<String, PathConstraint>,
    pub query_parameters: BTreeMap<String, QueryConstraint>,
    pub request_headers_to_forward: Vec<String>,
    pub response_headers_to_forward: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl ApprovedOrigin {
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedResourceRoute {
    route_id: String,
    method: String,
    origin: ApprovedOrigin,
    path_and_query: String,
    request_headers_to_forward: BTreeSet<String>,
    response_headers_to_forward: BTreeSet<String>,
}

impl ResolvedResourceRoute {
    #[must_use]
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
    #[must_use]
    pub fn origin(&self) -> &ApprovedOrigin {
        &self.origin
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    #[must_use]
    pub fn request_headers_to_forward(&self) -> &BTreeSet<String> {
        &self.request_headers_to_forward
    }

    #[must_use]
    pub fn response_headers_to_forward(&self) -> &BTreeSet<String> {
        &self.response_headers_to_forward
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum TemplateSegment {
    Static(String),
    Parameter(String),
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedRoutePolicy {
    id: String,
    browser_path: String,
    browser_path_shape: String,
    methods: BTreeSet<String>,
    origin: ApprovedOrigin,
    upstream_path: Vec<TemplateSegment>,
    path_parameters: BTreeMap<String, PathConstraint>,
    query_parameters: BTreeMap<String, QueryConstraint>,
    request_headers_to_forward: BTreeSet<String>,
    response_headers_to_forward: BTreeSet<String>,
}
#[derive(Debug, Clone)]
pub struct RoutePolicySnapshot {
    version: String,
    digest: String,
    routes: BTreeMap<String, ValidatedRoutePolicy>,
}

impl RoutePolicySnapshot {
    pub fn try_new(
        version: impl Into<String>,
        definitions: Vec<ResourceRoutePolicyDefinition>,
    ) -> Result<Self, RoutePolicyError> {
        let version = version.into();
        if version.trim().is_empty() {
            return Err(RoutePolicyError::EmptyVersion);
        }
        let mut routes = BTreeMap::new();
        let mut browser_bindings = BTreeMap::<(String, String), String>::new();

        for definition in definitions {
            let validated = validate_route(definition)?;

            if routes.contains_key(&validated.id) {
                return Err(RoutePolicyError::DuplicateRouteId(validated.id));
            }
            for method in &validated.methods {
                let key = (validated.browser_path_shape.clone(), method.clone());
                if let Some(existing_route) =
                    browser_bindings.insert(key.clone(), validated.id.clone())
                {
                    return Err(RoutePolicyError::AmbiguousBrowserRoute {
                        path: key.0,
                        method: key.1,
                        first_route: existing_route,
                        second_route: validated.id,
                    });
                }
            }
            routes.insert(validated.id.clone(), validated);
        }

        let digest = policy_digest(&version, &routes);
        Ok(Self {
            version,
            digest,
            routes,
        })
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
    pub fn resolve(
        &self,
        route_id: &str,
        method: &str,
        path_parameters: &[(&str, &str)],
        query_parameters: &[(&str, &str)],
    ) -> Result<ResolvedResourceRoute, RoutePolicyError> {
        let route = self
            .routes
            .get(route_id)
            .ok_or_else(|| RoutePolicyError::UnknownRoute(route_id.to_owned()))?;
        let method = method.to_ascii_uppercase();
        if !route.methods.contains(&method) {
            return Err(RoutePolicyError::MethodNotAllowed {
                route_id: route_id.to_owned(),
                method,
            });
        }

        let provided_path = collect_unique_parameters(path_parameters, ParameterKind::Path)?;
        let path = resolve_path(route, &provided_path)?;
        let provided_query = collect_unique_parameters(query_parameters, ParameterKind::Query)?;
        let query = resolve_query(route, &provided_query)?;

        let path_and_query = if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        };
        Ok(ResolvedResourceRoute {
            route_id: route.id.clone(),
            method,
            origin: route.origin.clone(),
            path_and_query,
            request_headers_to_forward: route.request_headers_to_forward.clone(),
            response_headers_to_forward: route.response_headers_to_forward.clone(),
        })
    }
}
#[derive(Clone)]
pub struct ResourceRoutePolicyRegistry {
    active: Arc<RwLock<Arc<RoutePolicySnapshot>>>,
}

impl ResourceRoutePolicyRegistry {
    #[must_use]
    pub fn new(snapshot: RoutePolicySnapshot) -> Self {
        Self {
            active: Arc::new(RwLock::new(Arc::new(snapshot))),
        }
    }
    pub fn active_snapshot(&self) -> Result<Arc<RoutePolicySnapshot>, RoutePolicyError> {
        let guard = self
            .active
            .read()
            .map_err(|_| RoutePolicyError::PolicyRegistryUnavailable)?;
        Ok(Arc::clone(&guard))
    }
    pub fn resolve(
        &self,
        route_id: &str,
        method: &str,
        path_parameters: &[(&str, &str)],
        query_parameters: &[(&str, &str)],
    ) -> Result<ResolvedResourceRoute, RoutePolicyError> {
        self.active_snapshot()?
            .resolve(route_id, method, path_parameters, query_parameters)
    }
    pub fn activate_candidate(
        &self,
        version: impl Into<String>,
        definitions: Vec<ResourceRoutePolicyDefinition>,
    ) -> Result<String, RoutePolicyError> {
        // Complete validation happens before taking the write lock. A rejected
        // candidate therefore cannot partially modify the active snapshot.
        let candidate = Arc::new(RoutePolicySnapshot::try_new(version, definitions)?);
        let digest = candidate.digest().to_owned();
        let mut guard = self
            .active
            .write()
            .map_err(|_| RoutePolicyError::PolicyRegistryUnavailable)?;
        *guard = candidate;

        Ok(digest)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutePolicyError {
    EmptyVersion,
    InvalidRouteId(String),
    DuplicateRouteId(String),
    AmbiguousBrowserRoute {
        path: String,
        method: String,
        first_route: String,
        second_route: String,
    },
    InvalidBrowserPath(String),
    EmptyMethodSet(String),
    UnsupportedMethod(String),
    UnsupportedScheme(String),
    InvalidHost(String),
    InvalidPort(u16),
    RedirectFollowingForbidden(String),
    InvalidPathTemplate(String),
    InvalidParameterName(String),
    MissingPathConstraint(String),
    UnusedPathConstraint(String),
    InvalidQueryConstraint(String),
    InvalidHeaderName(String),
    ForbiddenRequestForwardHeader(String),
    ForbiddenResponseForwardHeader(String),
    UnknownRoute(String),
    MethodNotAllowed {
        route_id: String,
        method: String,
    },
    DuplicatePathParameter(String),
    DuplicateQueryParameter(String),
    MissingPathParameter(String),
    UnexpectedPathParameter(String),
    InvalidPathParameter(String),
    QueryParameterNotAllowed(String),
    InvalidQueryParameter(String),
    PolicyRegistryUnavailable,
}
impl fmt::Display for RoutePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyVersion => f.write_str("route-policy version must not be empty"),
            Self::InvalidRouteId(id) => write!(f, "invalid route id: {id}"),
            Self::DuplicateRouteId(id) => write!(f, "duplicate route id: {id}"),
            Self::AmbiguousBrowserRoute {
                path,
                method,
                first_route,
                second_route,
            } => write!(
                f,
                "ambiguous browser route {method} {path}: {first_route} conflicts with {second_route}"
            ),
            Self::InvalidBrowserPath(path) => write!(f, "invalid browser path template: {path}"),
            Self::EmptyMethodSet(id) => write!(f, "route has no allowed method: {id}"),
            Self::UnsupportedMethod(method) => write!(f, "unsupported proxy method: {method}"),
            Self::UnsupportedScheme(scheme) => write!(f, "unsupported upstream scheme: {scheme}"),
            Self::InvalidHost(host) => write!(f, "invalid upstream host: {host}"),
            Self::InvalidPort(port) => write!(f, "invalid upstream port: {port}"),
            Self::RedirectFollowingForbidden(id) => {
                write!(f, "route must not follow upstream redirects: {id}")
            }
            Self::InvalidPathTemplate(path) => write!(f, "invalid upstream path template: {path}"),
            Self::InvalidParameterName(name) => write!(f, "invalid parameter name: {name}"),
            Self::MissingPathConstraint(name) => write!(f, "missing path constraint: {name}"),
            Self::UnusedPathConstraint(name) => write!(f, "unused path constraint: {name}"),
            Self::InvalidQueryConstraint(name) => write!(f, "invalid query constraint: {name}"),
            Self::InvalidHeaderName(name) => write!(f, "invalid HTTP header name: {name}"),
            Self::ForbiddenRequestForwardHeader(name) => {
                write!(f, "request header must not be browser-forwarded: {name}")
            }
            Self::ForbiddenResponseForwardHeader(name) => {
                write!(f, "response header must not be forwarded: {name}")
            }
            Self::UnknownRoute(id) => write!(f, "unknown resource route: {id}"),
            Self::MethodNotAllowed { route_id, method } => {
                write!(f, "method {method} is not allowed for route {route_id}")
            }
            Self::DuplicatePathParameter(name) => write!(f, "duplicate path parameter: {name}"),
            Self::DuplicateQueryParameter(name) => write!(f, "duplicate query parameter: {name}"),
            Self::MissingPathParameter(name) => write!(f, "missing path parameter: {name}"),
            Self::UnexpectedPathParameter(name) => write!(f, "unexpected path parameter: {name}"),
            Self::InvalidPathParameter(name) => write!(f, "invalid path parameter: {name}"),
            Self::QueryParameterNotAllowed(name) => {
                write!(f, "query parameter not allowed: {name}")
            }
            Self::InvalidQueryParameter(name) => write!(f, "invalid query parameter: {name}"),
            Self::PolicyRegistryUnavailable => f.write_str("route-policy registry is unavailable"),
        }
    }
}
impl std::error::Error for RoutePolicyError {}
#[derive(Clone, Copy)]
enum ParameterKind {
    Path,
    Query,
}

fn validate_route(
    definition: ResourceRoutePolicyDefinition,
) -> Result<ValidatedRoutePolicy, RoutePolicyError> {
    validate_route_id(&definition.id)?;

    if definition.methods.is_empty() {
        return Err(RoutePolicyError::EmptyMethodSet(definition.id));
    }
    let mut methods = BTreeSet::new();
    for method in definition.methods {
        let method = method.to_ascii_uppercase();
        if method != "GET" && method != "HEAD" {
            return Err(RoutePolicyError::UnsupportedMethod(method));
        }
        methods.insert(method);
    }

    let (browser_path, browser_path_shape) =
        validate_browser_path(&definition.browser_path, &definition.path_parameters)?;
    let origin = validate_origin(&definition.upstream)?;
    if definition.upstream.follow_redirects {
        return Err(RoutePolicyError::RedirectFollowingForbidden(definition.id));
    }

    let upstream_path = parse_path_template(
        &definition.upstream.path_template,
        &definition.path_parameters,
        false,
    )?;

    validate_query_constraints(&definition.query_parameters)?;
    let request_headers_to_forward = validate_header_allowlist(
        definition.request_headers_to_forward,
        FORBIDDEN_REQUEST_FORWARD_HEADERS,
        true,
    )?;
    let response_headers_to_forward = validate_header_allowlist(
        definition.response_headers_to_forward,
        FORBIDDEN_RESPONSE_FORWARD_HEADERS,
        false,
    )?;
    Ok(ValidatedRoutePolicy {
        id: definition.id,
        browser_path,
        browser_path_shape,
        methods,
        origin,
        upstream_path,
        path_parameters: definition.path_parameters,
        query_parameters: definition.query_parameters,
        request_headers_to_forward,
        response_headers_to_forward,
    })
}
fn validate_route_id(id: &str) -> Result<(), RoutePolicyError> {
    if id.is_empty()
        || id.len() > MAX_ROUTE_ID_LEN
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RoutePolicyError::InvalidRouteId(id.to_owned()));
    }
    Ok(())
}
fn validate_browser_path(
    path: &str,
    constraints: &BTreeMap<String, PathConstraint>,
) -> Result<(String, String), RoutePolicyError> {
    let segments = parse_path_template(path, constraints, true).map_err(|error| match error {
        RoutePolicyError::InvalidPathTemplate(_) => {
            RoutePolicyError::InvalidBrowserPath(path.to_owned())
        }
        other => other,
    })?;
    let mut shape = String::new();
    for segment in segments {
        shape.push('/');
        match segment {
            TemplateSegment::Static(value) => shape.push_str(&value),
            TemplateSegment::Parameter(_) => shape.push_str("{}"),
        }
    }

    Ok((path.to_owned(), shape))
}
fn validate_origin(upstream: &UpstreamRouteDefinition) -> Result<ApprovedOrigin, RoutePolicyError> {
    if !upstream.scheme.eq_ignore_ascii_case("https") {
        return Err(RoutePolicyError::UnsupportedScheme(upstream.scheme.clone()));
    }

    if !is_valid_logical_host(&upstream.host) {
        return Err(RoutePolicyError::InvalidHost(upstream.host.clone()));
    }

    if upstream.port == 0 {
        return Err(RoutePolicyError::InvalidPort(upstream.port));
    }
    Ok(ApprovedOrigin {
        scheme: "https".to_owned(),
        host: upstream.host.to_ascii_lowercase(),
        port: upstream.port,
    })
}

fn is_valid_logical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}
fn parse_path_template(
    template: &str,
    constraints: &BTreeMap<String, PathConstraint>,
    browser_path: bool,
) -> Result<Vec<TemplateSegment>, RoutePolicyError> {
    if !template.starts_with('/')
        || template.contains('?')
        || template.contains('#')
        || template.contains('\\')
        || template.contains('%')
        || template.chars().any(char::is_control)
    {
        return Err(RoutePolicyError::InvalidPathTemplate(template.to_owned()));
    }
    if template == "/" {
        if browser_path {
            return Err(RoutePolicyError::InvalidBrowserPath(template.to_owned()));
        }
        if constraints.is_empty() {
            return Ok(Vec::new());
        }
        return Err(RoutePolicyError::UnusedPathConstraint(
            constraints.keys().next().cloned().unwrap_or_default(),
        ));
    }

    let mut segments = Vec::new();
    let mut used_parameters = BTreeSet::new();
    for segment in template[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(RoutePolicyError::InvalidPathTemplate(template.to_owned()));
        }
        if let Some(name) = parse_parameter_segment(segment) {
            validate_parameter_name(name)?;
            if !constraints.contains_key(name) {
                return Err(RoutePolicyError::MissingPathConstraint(name.to_owned()));
            }
            if !used_parameters.insert(name.to_owned()) {
                return Err(RoutePolicyError::InvalidPathTemplate(template.to_owned()));
            }
            segments.push(TemplateSegment::Parameter(name.to_owned()));
            continue;
        }
        if segment.contains('{') || segment.contains('}') || !segment.bytes().all(is_unreserved) {
            return Err(RoutePolicyError::InvalidPathTemplate(template.to_owned()));
        }

        segments.push(TemplateSegment::Static(segment.to_owned()));
    }

    for parameter in constraints.keys() {
        if !used_parameters.contains(parameter) {
            return Err(RoutePolicyError::UnusedPathConstraint(parameter.clone()));
        }
    }
    if browser_path && segments.is_empty() {
        return Err(RoutePolicyError::InvalidBrowserPath(template.to_owned()));
    }

    Ok(segments)
}

fn parse_parameter_segment(segment: &str) -> Option<&str> {
    segment
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .filter(|value| !value.contains('{') && !value.contains('}'))
}
fn validate_parameter_name(name: &str) -> Result<(), RoutePolicyError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(RoutePolicyError::InvalidParameterName(name.to_owned()));
    };

    if name.len() > MAX_PARAMETER_NAME_LEN
        || !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(RoutePolicyError::InvalidParameterName(name.to_owned()));
    }
    Ok(())
}

fn validate_query_constraints(
    constraints: &BTreeMap<String, QueryConstraint>,
) -> Result<(), RoutePolicyError> {
    for (name, constraint) in constraints {
        validate_parameter_name(name)?;
        if matches!(constraint, QueryConstraint::AsciiToken { max_len: 0 }) {
            return Err(RoutePolicyError::InvalidQueryConstraint(name.clone()));
        }
    }
    Ok(())
}
fn validate_header_allowlist(
    headers: Vec<String>,
    forbidden: &[&str],
    request: bool,
) -> Result<BTreeSet<String>, RoutePolicyError> {
    let mut validated = BTreeSet::new();

    for header in headers {
        let normalized = header.to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() > MAX_HEADER_NAME_LEN
            || !normalized.bytes().all(is_http_token_char)
        {
            return Err(RoutePolicyError::InvalidHeaderName(header));
        }
        if forbidden.contains(&normalized.as_str()) {
            return if request {
                Err(RoutePolicyError::ForbiddenRequestForwardHeader(normalized))
            } else {
                Err(RoutePolicyError::ForbiddenResponseForwardHeader(normalized))
            };
        }

        validated.insert(normalized);
    }

    Ok(validated)
}
fn collect_unique_parameters<'a>(
    parameters: &[(&'a str, &'a str)],
    kind: ParameterKind,
) -> Result<BTreeMap<&'a str, &'a str>, RoutePolicyError> {
    let mut collected = BTreeMap::new();
    for (name, value) in parameters {
        if collected.insert(*name, *value).is_some() {
            return match kind {
                ParameterKind::Path => {
                    Err(RoutePolicyError::DuplicatePathParameter((*name).to_owned()))
                }
                ParameterKind::Query => Err(RoutePolicyError::DuplicateQueryParameter(
                    (*name).to_owned(),
                )),
            };
        }
    }
    Ok(collected)
}
fn resolve_path(
    route: &ValidatedRoutePolicy,
    provided: &BTreeMap<&str, &str>,
) -> Result<String, RoutePolicyError> {
    for name in provided.keys() {
        if !route.path_parameters.contains_key(*name) {
            return Err(RoutePolicyError::UnexpectedPathParameter(
                (*name).to_owned(),
            ));
        }
    }

    let mut resolved = String::new();
    resolved.push('/');
    for (index, segment) in route.upstream_path.iter().enumerate() {
        if index > 0 {
            resolved.push('/');
        }
        match segment {
            TemplateSegment::Static(value) => resolved.push_str(value),
            TemplateSegment::Parameter(name) => {
                let value = provided
                    .get(name.as_str())
                    .ok_or_else(|| RoutePolicyError::MissingPathParameter(name.clone()))?;
                let constraint = route
                    .path_parameters
                    .get(name)
                    .expect("validated route must contain a constraint for every path parameter");
                if !path_value_matches(constraint, value) {
                    return Err(RoutePolicyError::InvalidPathParameter(name.clone()));
                }
                resolved.push_str(value);
            }
        }
    }
    Ok(resolved)
}

fn resolve_query(
    route: &ValidatedRoutePolicy,
    provided: &BTreeMap<&str, &str>,
) -> Result<String, RoutePolicyError> {
    let mut resolved = String::new();

    for (index, (name, value)) in provided.iter().enumerate() {
        let constraint = route
            .query_parameters
            .get(*name)
            .ok_or_else(|| RoutePolicyError::QueryParameterNotAllowed((*name).to_owned()))?;
        if !query_value_matches(constraint, value) {
            return Err(RoutePolicyError::InvalidQueryParameter((*name).to_owned()));
        }

        if index > 0 {
            resolved.push('&');
        }
        resolved.push_str(name);
        resolved.push('=');
        resolved.push_str(value);
    }

    Ok(resolved)
}

fn path_value_matches(constraint: &PathConstraint, value: &str) -> bool {
    match constraint {
        PathConstraint::Uuid => is_canonical_uuid(value),
    }
}
fn query_value_matches(constraint: &QueryConstraint, value: &str) -> bool {
    match constraint {
        QueryConstraint::Uuid => is_canonical_uuid(value),
        QueryConstraint::AsciiToken { max_len } => {
            !value.is_empty() && value.len() <= *max_len && value.bytes().all(is_unreserved)
        }
    }
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_hexdigit(),
    })
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
fn is_http_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
fn policy_digest(version: &str, routes: &BTreeMap<String, ValidatedRoutePolicy>) -> String {
    let mut canonical = String::new();
    writeln!(&mut canonical, "version-length={}", version.len())
        .expect("writing to String cannot fail");
    writeln!(&mut canonical, "version={version}").expect("writing to String cannot fail");
    for route in routes.values() {
        writeln!(&mut canonical, "route={}", route.id).expect("writing to String cannot fail");
        writeln!(&mut canonical, "browser={}", route.browser_path)
            .expect("writing to String cannot fail");
        writeln!(
            &mut canonical,
            "methods={}",
            route.methods.iter().cloned().collect::<Vec<_>>().join(",")
        )
        .expect("writing to String cannot fail");
        writeln!(
            &mut canonical,
            "origin={}://{}:{}",
            route.origin.scheme, route.origin.host, route.origin.port
        )
        .expect("writing to String cannot fail");
        writeln!(
            &mut canonical,
            "path={}",
            render_template(&route.upstream_path)
        )
        .expect("writing to String cannot fail");
        for (name, constraint) in &route.path_parameters {
            writeln!(
                &mut canonical,
                "path-param={name}:{}",
                render_path_constraint(constraint)
            )
            .expect("writing to String cannot fail");
        }
        for (name, constraint) in &route.query_parameters {
            writeln!(
                &mut canonical,
                "query-param={name}:{}",
                render_query_constraint(constraint)
            )
            .expect("writing to String cannot fail");
        }
        writeln!(
            &mut canonical,
            "request-headers={}",
            route
                .request_headers_to_forward
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        )
        .expect("writing to String cannot fail");
        writeln!(
            &mut canonical,
            "response-headers={}",
            route
                .response_headers_to_forward
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        )
        .expect("writing to String cannot fail");
    }
    let digest = Sha256::digest(canonical.as_bytes());
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn render_template(segments: &[TemplateSegment]) -> String {
    if segments.is_empty() {
        return "/".to_owned();
    }
    let mut rendered = String::new();
    for segment in segments {
        rendered.push('/');
        match segment {
            TemplateSegment::Static(value) => rendered.push_str(value),
            TemplateSegment::Parameter(name) => {
                rendered.push('{');
                rendered.push_str(name);
                rendered.push('}');
            }
        }
    }
    rendered
}
fn render_path_constraint(constraint: &PathConstraint) -> &'static str {
    match constraint {
        PathConstraint::Uuid => "uuid",
    }
}

fn render_query_constraint(constraint: &QueryConstraint) -> String {
    match constraint {
        QueryConstraint::Uuid => "uuid".to_owned(),
        QueryConstraint::AsciiToken { max_len } => format!("ascii-token:{max_len}"),
    }
}
