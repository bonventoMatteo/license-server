//! License Server — PC Optimizer
//! Deploy on Render.com (free tier)
//!
//! Endpoints:
//!   POST /admin/create          — create a new license key (admin only)
//!   POST /admin/revoke          — revoke a license (admin only)
//!   GET  /admin/list            — list all licenses (admin only)
//!   POST /license/activate      — client activates license on a machine
//!   POST /license/verify        — client verifies license is still valid
//!   POST /license/deactivate    — client releases a machine slot

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub key: String,
    pub client_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_machines: u32,
    pub activated_machines: Vec<MachineRecord>,
    pub active: bool,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineRecord {
    pub machine_id: String,        // Hash of hardware fingerprint
    pub activated_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hostname: String,
}

impl License {
    pub fn is_valid(&self) -> (bool, &'static str) {
        if !self.active {
            return (false, "License has been revoked");
        }
        if let Some(exp) = self.expires_at {
            if Utc::now() > exp {
                return (false, "License has expired");
            }
        }
        (true, "OK")
    }

    pub fn machine_authorized(&self, machine_id: &str) -> bool {
        self.activated_machines.iter().any(|m| m.machine_id == machine_id)
    }

    pub fn can_activate_new(&self) -> bool {
        self.activated_machines.len() < self.max_machines as usize
    }
}

// ── State ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AppState {
    pub licenses: RwLock<HashMap<String, License>>,
    pub admin_key: String,
    pub db_path: String,
}

type SharedState = Arc<AppState>;

// ── Request/Response types ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateLicenseReq {
    client_name: String,
    max_machines: Option<u32>,
    expires_days: Option<i64>,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct RevokeReq {
    key: String,
}

#[derive(Deserialize)]
struct ActivateReq {
    key: String,
    machine_id: String,   // SHA256 of hardware fingerprint
    hostname: String,
}

#[derive(Deserialize)]
struct VerifyReq {
    key: String,
    machine_id: String,
}

#[derive(Deserialize)]
struct DeactivateReq {
    key: String,
    machine_id: String,
}

#[derive(Serialize)]
struct LicenseResponse {
    valid: bool,
    message: String,
    expires_at: Option<DateTime<Utc>>,
    machines_used: usize,
    machines_max: u32,
}

#[derive(Serialize)]
struct CreateResponse {
    key: String,
    client_name: String,
    expires_at: Option<DateTime<Utc>>,
    max_machines: u32,
}

// ── Admin middleware ──────────────────────────────────────────────────────────

fn check_admin(headers: &HeaderMap, state: &AppState) -> bool {
    headers.get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .map(|k| k == state.admin_key)
        .unwrap_or(false)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn create_license(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CreateLicenseReq>,
) -> Result<Json<CreateResponse>, StatusCode> {
    if !check_admin(&headers, &state) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let key = format!("PCO-{}", Uuid::new_v4().to_string().to_uppercase().replace('-', "")[..20].to_string());
    let expires_at = req.expires_days.map(|d| Utc::now() + Duration::days(d));

    let license = License {
        key: key.clone(),
        client_name: req.client_name.clone(),
        created_at: Utc::now(),
        expires_at,
        max_machines: req.max_machines.unwrap_or(1),
        activated_machines: Vec::new(),
        active: true,
        notes: req.notes.unwrap_or_default(),
    };

    let response = CreateResponse {
        key: key.clone(),
        client_name: req.client_name,
        expires_at: license.expires_at,
        max_machines: license.max_machines,
    };

    state.licenses.write().unwrap().insert(key, license);
    save_db(&state);

    Ok(Json(response))
}

async fn revoke_license(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RevokeReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_admin(&headers, &state) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut licenses = state.licenses.write().unwrap();
    if let Some(lic) = licenses.get_mut(&req.key) {
        lic.active = false;
        drop(licenses);
        save_db(&state);
        Ok(Json(serde_json::json!({ "revoked": true, "key": req.key })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn list_licenses(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    if !check_admin(&headers, &state) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let licenses = state.licenses.read().unwrap();
    let list: Vec<serde_json::Value> = licenses.values().map(|l| {
        let (valid, reason) = l.is_valid();
        serde_json::json!({
            "key": l.key,
            "client_name": l.client_name,
            "active": l.active,
            "valid": valid,
            "status": reason,
            "machines": l.activated_machines.len(),
            "max_machines": l.max_machines,
            "expires_at": l.expires_at,
            "notes": l.notes,
        })
    }).collect();

    Ok(Json(list))
}

async fn activate_license(
    State(state): State<SharedState>,
    Json(req): Json<ActivateReq>,
) -> Json<LicenseResponse> {
    let mut licenses = state.licenses.write().unwrap();

    let Some(lic) = licenses.get_mut(&req.key) else {
        return Json(LicenseResponse {
            valid: false,
            message: "License key not found".to_string(),
            expires_at: None,
            machines_used: 0,
            machines_max: 0,
        });
    };

    let (valid, reason) = lic.is_valid();
    if !valid {
        return Json(LicenseResponse {
            valid: false,
            message: reason.to_string(),
            expires_at: lic.expires_at,
            machines_used: lic.activated_machines.len(),
            machines_max: lic.max_machines,
        });
    }

    // Already activated on this machine?
    if lic.machine_authorized(&req.machine_id) {
        // Update last seen
        if let Some(m) = lic.activated_machines.iter_mut().find(|m| m.machine_id == req.machine_id) {
            m.last_seen = Utc::now();
        }
        let resp = Json(LicenseResponse {
            valid: true,
            message: "Already activated on this machine".to_string(),
            expires_at: lic.expires_at,
            machines_used: lic.activated_machines.len(),
            machines_max: lic.max_machines,
        });
        drop(licenses);
        save_db(&state);
        return resp;
    }

    // New machine — check slot
    if !lic.can_activate_new() {
        return Json(LicenseResponse {
            valid: false,
            message: format!("Machine limit reached ({}/{})", lic.activated_machines.len(), lic.max_machines),
            expires_at: lic.expires_at,
            machines_used: lic.activated_machines.len(),
            machines_max: lic.max_machines,
        });
    }

    lic.activated_machines.push(MachineRecord {
        machine_id: req.machine_id,
        activated_at: Utc::now(),
        last_seen: Utc::now(),
        hostname: req.hostname,
    });

    let resp = Json(LicenseResponse {
        valid: true,
        message: "Activated successfully".to_string(),
        expires_at: lic.expires_at,
        machines_used: lic.activated_machines.len(),
        machines_max: lic.max_machines,
    });

    drop(licenses);
    save_db(&state);
    resp
}

async fn verify_license(
    State(state): State<SharedState>,
    Json(req): Json<VerifyReq>,
) -> Json<LicenseResponse> {
    let mut licenses = state.licenses.write().unwrap();

    let Some(lic) = licenses.get_mut(&req.key) else {
        return Json(LicenseResponse {
            valid: false,
            message: "License not found".to_string(),
            expires_at: None,
            machines_used: 0,
            machines_max: 0,
        });
    };

    let (valid, reason) = lic.is_valid();
    if !valid {
        return Json(LicenseResponse {
            valid: false,
            message: reason.to_string(),
            expires_at: lic.expires_at,
            machines_used: lic.activated_machines.len(),
            machines_max: lic.max_machines,
        });
    }

    if !lic.machine_authorized(&req.machine_id) {
        return Json(LicenseResponse {
            valid: false,
            message: "This machine is not authorized".to_string(),
            expires_at: lic.expires_at,
            machines_used: lic.activated_machines.len(),
            machines_max: lic.max_machines,
        });
    }

    // Update last seen timestamp
    if let Some(m) = lic.activated_machines.iter_mut().find(|m| m.machine_id == req.machine_id) {
        m.last_seen = Utc::now();
    }

    let resp = Json(LicenseResponse {
        valid: true,
        message: "OK".to_string(),
        expires_at: lic.expires_at,
        machines_used: lic.activated_machines.len(),
        machines_max: lic.max_machines,
    });

    drop(licenses);
    save_db(&state);
    resp
}

async fn deactivate_license(
    State(state): State<SharedState>,
    Json(req): Json<DeactivateReq>,
) -> Json<serde_json::Value> {
    let mut licenses = state.licenses.write().unwrap();
    if let Some(lic) = licenses.get_mut(&req.key) {
        lic.activated_machines.retain(|m| m.machine_id != req.machine_id);
        drop(licenses);
        save_db(&state);
        Json(serde_json::json!({ "deactivated": true }))
    } else {
        Json(serde_json::json!({ "deactivated": false, "reason": "License not found" }))
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "PC Optimizer License Server" }))
}

// ── Persistence ───────────────────────────────────────────────────────────────

fn save_db(state: &AppState) {
    let licenses = state.licenses.read().unwrap();
    if let Ok(data) = serde_json::to_string_pretty(&*licenses) {
        let _ = std::fs::write(&state.db_path, data);
    }
}

fn load_db(path: &str) -> HashMap<String, License> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let admin_key = std::env::var("ADMIN_KEY")
        .unwrap_or_else(|_| "change-this-secret-key".to_string());
    let db_path = std::env::var("DB_PATH")
        .unwrap_or_else(|_| "licenses.json".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string());

    println!("PC Optimizer License Server starting...");
    println!("Admin key: {}", &admin_key[..4.min(admin_key.len())]);
    println!("DB path: {}", db_path);
    println!("Port: {}", port);

    let state = Arc::new(AppState {
        licenses: RwLock::new(load_db(&db_path)),
        admin_key,
        db_path,
    });

    let app = Router::new()
        .route("/health",            get(health))
        .route("/admin/create",      post(create_license))
        .route("/admin/revoke",      post(revoke_license))
        .route("/admin/list",        get(list_licenses))
        .route("/license/activate",  post(activate_license))
        .route("/license/verify",    post(verify_license))
        .route("/license/deactivate",post(deactivate_license))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("Listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}