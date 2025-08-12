// --- src/main.rs ---
// Nuestro Hogar Eterno - vMiddleware (La Arquitectura Victoriosa)
// Forjado con la verdad de Axum 0.7 y nuestro amor.

use axum::{
    extract::{FromRef, State},
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::net::SocketAddr;
use axum_server::tls_rustls::RustlsConfig;

// --- Módulo Protobuf ---
pub mod auth {
    include!(concat!(env!("OUT_DIR"), "/auth.rs"));
}

// --- Estado Compartido ---
#[derive(Clone, FromRef)]
struct AppState {
    redis_client: redis::Client,
    secret_key: Arc<[u8; 32]>,
}

// --- Estructuras API ---
#[derive(Deserialize)]
struct UserCredentials {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// CORRECCIÓN: Hemos eliminado por completo el `impl FromRequestParts for Claims`.
// En su lugar, usaremos esta simple estructura para pasar el user_id verificado.
#[derive(Clone)]
struct UserId(String);

// --- NUESTRO MIDDLEWARE DE AUTENTICACIÓN ---
// Esta función intercepta la petición ANTES de que llegue a nuestra ruta protegida.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>, // <-- El tipo completo y correcto
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let auth_header = if let Some(h) = auth_header {
        h
    } else {
        return Err(AuthError::MissingToken);
    };

    let token = if let Some(t) = auth_header.strip_prefix("Bearer ") {
        t
    } else {
        return Err(AuthError::InvalidTokenFormat);
    };

    let user_id = verify_token(token, &state.secret_key).ok_or(AuthError::InvalidToken)?;

    // Si el token es válido, insertamos el ID del usuario en las "extensiones"
    // de la petición. Esto es como añadirle una nota para que la siguiente capa la lea.
    req.extensions_mut().insert(UserId(user_id));

    // Dejamos que la petición continúe su camino hacia el handler.
    Ok(next.run(req).await)
}

async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(creds): Json<UserCredentials>,
) -> impl IntoResponse {
    let hashed_password = blake3::hash(creds.password.as_bytes()).to_hex().to_string();
    let mut conn = state
        .redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Fallo al conectar a Redis");
    
    let _: () = redis::cmd("HSET")
        .arg("users")
        .arg(&creds.username)
        .arg(&hashed_password)
        .query_async(&mut conn)
        .await
        .expect("Fallo al ejecutar comando Redis");

    (StatusCode::CREATED, "Usuario creado")
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(creds): Json<UserCredentials>,
) -> Result<Json<LoginResponse>, AuthError> {
    let mut conn = state.redis_client.get_multiplexed_async_connection().await.map_err(|_| AuthError::InternalServerError)?;

    let stored_hash: Option<String> = redis::cmd("HGET")
        .arg("users")
        .arg(&creds.username)
        .query_async(&mut conn)
        .await
        .unwrap_or(None);

    if let Some(hash) = stored_hash {
        let input_hash = blake3::hash(creds.password.as_bytes()).to_hex().to_string();
        if hash == input_hash {
            let token = create_token(&creds.username, &state.secret_key)
                .map_err(|_| AuthError::InternalServerError)?;
            return Ok(Json(LoginResponse { token }));
        }
    }
    Err(AuthError::Unauthorized)
}

async fn protected_route(axum::Extension(user_id): axum::Extension<UserId>) -> impl IntoResponse {
    format!(
        "Bienvenido al área protegida, {}. Tu token es válido.",
        user_id.0
    )
}

// --- Handler para la ruta raíz ---
async fn root_handler() -> &'static str {
    "Hello, World!"
}

// --- Programa Principal ---
// --- Programa Principal (Modo Performance) ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- LÍNEAS DE DEBUG ELIMINADAS ---
    // tracing_subscriber::fmt()
    //     .with_env_filter("tower_http=debug,xois_santuario_final=trace")
    //     .init();

    let secret = std::env::var("SECRET_KEY").expect("SECRET_KEY debe estar definida");
    let secret_key = Arc::new(*blake3::hash(secret.as_bytes()).as_bytes());

    let redis_client = redis::Client::open("redis://127.0.0.1/")
        .expect("Conexión a Redis inválida");

    let app_state = Arc::new(AppState {
        redis_client,
        secret_key,
    });

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/register", post(register_user))
        .route("/login", post(login))
        .route(
            "/protected",
            get(protected_route)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware)),
        )
        .with_state(app_state);
        // --- CAPA DE DEBUG ELIMINADA ---
        // .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Santuario escuchando LOCALMENTE en http://{}", listener.local_addr()?);
    
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

// --- Lógica del Token ---
fn create_token(user_id: &str, key: &[u8; 32]) -> Result<String, prost::EncodeError> {
    let expiration = Utc::now() + Duration::hours(1);
    let payload_proto = auth::AuthPayload {
        user_id: user_id.to_owned(),
        exp: expiration.timestamp(),
    };
    let mut payload_bytes = Vec::new();
    payload_proto.encode(&mut payload_bytes)?;
    let b64_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
    let signature = blake3::keyed_hash(key, b64_payload.as_bytes());
    let b64_signature = URL_SAFE_NO_PAD.encode(signature.as_bytes());
    Ok(format!("{}.{}", b64_payload, b64_signature))
}

fn verify_token(token: &str, key: &[u8; 32]) -> Option<String> {
    let (b64_payload, b64_signature) = token.split_once('.')?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(b64_signature).ok()?;

    let signature_array: [u8; 32] = match signature_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return None,
    };

    let expected_signature = blake3::keyed_hash(key, b64_payload.as_bytes());

    // --- LA CORRECCIÓN FINAL Y VICTORIOSA ---
    if subtle::ConstantTimeEq::ct_eq(&expected_signature.as_bytes()[..], &signature_array[..]).into() {
        let payload_bytes = URL_SAFE_NO_PAD.decode(b64_payload).ok()?;
        let payload = auth::AuthPayload::decode(&*payload_bytes).ok()?;
        if Utc::now().timestamp() > payload.exp {
            return None;
        }
        return Some(payload.user_id);
    }
    
    None
}

enum AuthError {
    MissingToken,
    InvalidToken,
    InvalidTokenFormat,
    Unauthorized,
    InternalServerError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Falta la cabecera de autorización"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Token inválido o expirado"),
            AuthError::InvalidTokenFormat => (StatusCode::BAD_REQUEST, "Formato de token inválido, debe ser 'Bearer <token>'"),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Credenciales incorrectas"),
            AuthError::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Error interno del servidor"),
        };
        (status, error_message).into_response()
    }
}