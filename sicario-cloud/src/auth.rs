//! JWT authentication middleware for the Sicario Cloud REST API.

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

use crate::db::AppState;
use crate::models::ApiError;

/// JWT claims embedded in every authenticated request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // user ID
    pub org_id: String,    // organization ID
    pub exp: usize,        // expiration (UNIX timestamp)
    pub iat: usize,        // issued at
}

/// Axum middleware that validates the `Authorization: Bearer <token>` header.
pub async fn jwt_auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let token = match auth_header {
        Some(ref h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "unauthorized".to_string(),
                    message: "Missing or invalid Authorization header. Use: Bearer <token>".to_string(),
                }),
            )
                .into_response();
        }
    };

    let validation = Validation::new(Algorithm::HS256);
    match decode::<Claims>(token, &DecodingKey::from_secret(state.jwt_secret.as_bytes()), &validation) {
        Ok(_token_data) => next.run(request).await,
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "unauthorized".to_string(),
                message: "Invalid or expired JWT token. Run `sicario login` to re-authenticate.".to_string(),
            }),
        )
            .into_response(),
    }
}
