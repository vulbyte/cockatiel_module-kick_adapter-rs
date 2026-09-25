use futures_util::{SinkExt, StreamExt};
use prost::Message;
use cockatiel_client::{proto::container::Payload, proto::*, CockatielClient, PromptKind};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message as WsMessage},
};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

type WsWriteHalf = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    WsMessage,
>;

/// The module's engine-session identity (auth token + assigned instance + name).
/// Held in a shared Mutex so a reconnect can swap it in place and every other
/// task (read loop, platform send path) always uses the CURRENT session's
/// credentials — a stale token after a reconnect would be rejected by the
/// engine and the module would look dead.
#[derive(Clone, Default)]
struct EngineIdentity {
    auth: String,
    instance: String,
    module: String,
}

/// Re-register the adapter's chat commands with the engine (called on the
/// initial connect AND after every reconnect — the engine forgets a session's
/// commands when the socket drops).
async fn register_commands(
    write: &Arc<tokio::sync::Mutex<WsWriteHalf>>,
    identity: &Arc<tokio::sync::Mutex<EngineIdentity>>,
) {
    let (auth, module, instance) = {
        let id = identity.lock().await;
        (id.auth.clone(), id.module.clone(), id.instance.clone())
    };
    let commands = Container {
        version: 1,
        auth_token: auth.clone(),
        module_name: module.clone(),
        module_instance_uuid7: instance.clone(),
        payload: Some(Payload::CommandsPayload(Commands {
            commands: vec![
                Command {
                    command_name: "ban".to_string(),
                    command_flag: "!".to_string(),
                    command_description: "ban a user".to_string(),
                    command_flags: vec![],
                },
                Command {
                    command_name: "timeout".to_string(),
                    command_flag: "!".to_string(),
                    command_description: "timeout a user".to_string(),
                    command_flags: vec![],
                },
            ],
            alert_on_unknown_command: false,
        })),
    };
    let mut cbuf = Vec::new();
    if commands.encode(&mut cbuf).is_ok() {
        let mut w = write.lock().await;
        let _ = w.send(WsMessage::Binary(cbuf.into())).await;
    }
    info!("registered !ban / !timeout commands");
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
struct KickAdapterConfig {
    channel_name: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    oauth_token: Option<String>,
    default_timeout_secs: i64,
    http_timeout_secs: u64,
    outbound_queue_cap: usize,
    reconnect_base_secs: u64,
    reconnect_max_secs: u64,
    chatroom_resolve_base_secs: u64,
    chatroom_resolve_max_secs: u64,
    pusher_ping_interval_secs: u64,
    pusher_reconnect_delay_secs: u64,
    ws_retry_delay_secs: u64,
    prompt_timeout_secs: u32,
}

impl Default for KickAdapterConfig {
    fn default() -> Self {
        Self {
            channel_name: None,
            client_id: None,
            client_secret: None,
            oauth_token: None,
            default_timeout_secs: 300,
            http_timeout_secs: 15,
            outbound_queue_cap: 64,
            reconnect_base_secs: 1,
            reconnect_max_secs: 30,
            chatroom_resolve_base_secs: 1,
            chatroom_resolve_max_secs: 30,
            pusher_ping_interval_secs: 30,
            pusher_reconnect_delay_secs: 5,
            ws_retry_delay_secs: 5,
            prompt_timeout_secs: 300,
        }
    }
}

/// Build a moderator query from the engine-routed command. The engine already
/// parsed + routed `!ban`/`!timeout`; here we map command_name -> query and
/// extract the target/reason from the message args (no re-parsing).
fn build_mod_query(
    command_name: &str,
    message: &str,
    author: &str,
    default_timeout_secs: i64,
) -> Option<(String, serde_json::Value)> {
    let mut tokens = message.trim().split_whitespace();
    let _cmd = tokens.next()?;
    match command_name {
        "ban" => {
            let target = tokens.next()?.trim_start_matches('@').to_string();
            if target.is_empty() {
                return None;
            }
            return Some((
                "mod_ban".to_string(),
                serde_json::json!({
                    "platform": "kick",
                    "handle": target,
                    "reason": tokens.collect::<Vec<_>>().join(" "),
                    "actor": { "platform": "kick", "handle": author },
                }),
            ));
        }

        "timeout" => {
            let target = tokens.next()?.trim_start_matches('@').to_string();
            if target.is_empty() {
                return None;
            }
            let mut duration_secs = default_timeout_secs;
            let mut reason = String::new();
            if let Some(d) = tokens.next() {
                if let Ok(secs) = d.parse::<i64>() {
                    duration_secs = secs;
                } else {
                    reason = d.to_string();
                }
            }
            let rest: Vec<&str> = tokens.collect();
            if !rest.is_empty() {
                if !reason.is_empty() {
                    reason = format!("{} {}", reason, rest.join(" "));
                } else {
                    reason = rest.join(" ");
                }
            }
            return Some((
                "mod_timeout".to_string(),
                serde_json::json!({
                    "platform": "kick",
                    "handle": target,
                    "duration_secs": duration_secs,
                    "reason": reason,
                    "actor": { "platform": "kick", "handle": author },
                }),
            ));
        }

        _ => None,
    }
}

/// Backfill any missing tunables into `module_specific` with their defaults,
/// so every setting is always present and editable in place. Leaves
/// `channel_name` (managed by save_adapter_config) untouched.
fn backfill_adapter_config_defaults() {
    let path = PathBuf::from("config.json");
    let mut json_val = std::fs::read_to_string(&path)
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut ms = json_val
        .get("module_specific")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let before = ms.clone();
    let defaults: [(&str, i64); 11] = [
        ("default_timeout_secs", 300),
        ("http_timeout_secs", 15),
        ("outbound_queue_cap", 64),
        ("reconnect_base_secs", 1),
        ("reconnect_max_secs", 30),
        ("chatroom_resolve_base_secs", 1),
        ("chatroom_resolve_max_secs", 30),
        ("pusher_ping_interval_secs", 30),
        ("pusher_reconnect_delay_secs", 5),
        ("ws_retry_delay_secs", 5),
        ("prompt_timeout_secs", 300),
    ];
    for (key, value) in defaults {
        if ms.get(key).is_none() {
            ms[key] = serde_json::json!(value);
        }
    }
    if ms != before {
        json_val["module_specific"] = ms;
        if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
            let _ = std::fs::write(&path, pretty);
        }
    }
}

fn load_adapter_config() -> Option<KickAdapterConfig> {
    // The channel name is PUBLIC (visible to anyone on the stream) → config.json;
    // client id/secret/oauth are secrets → `.env` (env vars loaded at startup).
    // Missing tuning keys are backfilled with their defaults into module_specific.
    backfill_adapter_config_defaults();
    let saved = std::fs::read_to_string("config.json")
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .and_then(|v| v.get("module_specific").cloned())
        .unwrap_or_else(|| serde_json::json!({}));
    let channel_name = saved
        .get("channel_name")
        .and_then(|c| c.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| std::env::var("KICK_CHANNEL_NAME").unwrap_or_default());
    let mut cfg: KickAdapterConfig = serde_json::from_value(saved).unwrap_or_default();
    cfg.channel_name = Some(channel_name);
    cfg.client_id = Some(std::env::var("KICK_CLIENT_ID").unwrap_or_default());
    cfg.client_secret = Some(std::env::var("KICK_CLIENT_SECRET").unwrap_or_default());
    cfg.oauth_token = Some(std::env::var("KICK_OAUTH_TOKEN").unwrap_or_default());
    Some(cfg)
    .filter(|c| {
        !c.channel_name.as_deref().unwrap_or("").is_empty()
            && !c.client_id.as_deref().unwrap_or("").is_empty()
            && !c.client_secret.as_deref().unwrap_or("").is_empty()
    })
}

fn save_adapter_config(
    channel_name: &str,
    client_id: &str,
    client_secret: &str,
    oauth_token: &str,
) {
    // The channel name is public → config.json; secrets → `.env`.
    // Merge the channel name in WITHOUT clobbering the tuning knobs, so a
    // re-configure never resets tuned values back to their defaults. Creates
    // config.json if it doesn't exist yet.
    let path = PathBuf::from("config.json");
    let mut json_val = std::fs::read_to_string(&path)
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .unwrap_or_else(|| json!({}));
    if json_val.get("module_specific").and_then(|v| v.as_object()).is_none() {
        json_val["module_specific"] = serde_json::json!({});
    }
    let ms = json_val["module_specific"].as_object_mut().unwrap();
    ms.insert("channel_name".to_string(), serde_json::json!(channel_name));
    if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
        let _ = std::fs::write(&path, pretty);
    }
    // Ensure the tuning knobs exist on disk even on a first run.
    backfill_adapter_config_defaults();
    cockatiel_client::write_env_file(
        ".env",
        &[
            ("KICK_CLIENT_ID", client_id),
            ("KICK_CLIENT_SECRET", client_secret),
            ("KICK_OAUTH_TOKEN", oauth_token),
        ],
    );
    info!("Successfully saved Kick configuration (channel → config.json, secrets → .env)");
}

/// The operator's choice when a configured Kick channel is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TieChoice {
    /// Re-test the same channel (the failure may be transient).
    Retry,
    /// Keep the channel but skip it for now (noted in the log).
    Ignore,
    /// Remove the channel from the config.
    Remove,
    /// Prompt for a replacement value, save it, and re-test.
    Edit,
}

fn parse_tie_choice(answer: &str) -> Option<TieChoice> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "t" | "try" | "retry" | "try again" => Some(TieChoice::Retry),
        "i" | "ignore" => Some(TieChoice::Ignore),
        "r" | "remove" => Some(TieChoice::Remove),
        "e" | "edit" => Some(TieChoice::Edit),
        _ => None,
    }
}

fn tie_choices_help() -> String {
    "Enter one of: (t)ry again, (i)gnore, (r)emove, (e)dit".to_string()
}

/// Ask the operator how to handle an invalid entry: (t)ry / (i)gnore /
/// (r)emove / (e)dit. Reprompts until a valid choice (or None on cancel).
async fn prompt_tie_choice(
    write_ws: &tokio::sync::Mutex<WsWriteHalf>,
    prompt_rx: &mut mpsc::UnboundedReceiver<PromptResponse>,
    auth_token: &str,
    module_name: &str,
    instance_uuid: &str,
    subject: &str,
    prompt_timeout_secs: u32,
) -> Option<TieChoice> {
    loop {
        let answer = prompt_for_input(
            write_ws,
            prompt_rx,
            auth_token,
            module_name,
            instance_uuid,
            "Invalid Kick Entry",
            &format!("{}\n\n{}", subject, tie_choices_help()),
            "t / i / r / e",
            PromptKind::String,
            prompt_timeout_secs,
        )
        .await;
        match answer.as_deref().and_then(parse_tie_choice) {
            Some(c) => return Some(c),
            None if answer.is_some() => {
                warn!("Unrecognized choice — expected t / i / r / e.");
            }
            None => return None, // cancelled
        }
    }
}

/// Send a Prompt to the engine (forwarded to connected UIs) and wait for the
/// operator's response (`PromptResponse.reason`). Returns None on cancel/timeout.
///
/// The write lock is taken ONLY to send the prompt and released before waiting
/// for the answer — holding it across the wait would block the read loop's
/// AuthVerify reply and make the module look unresponsive to the engine's
/// liveness probe (which severs it).
async fn prompt_for_input(
    write_ws: &tokio::sync::Mutex<WsWriteHalf>,
    prompt_rx: &mut mpsc::UnboundedReceiver<PromptResponse>,
    auth_token: &str,
    module_name: &str,
    instance_uuid: &str,
    title: &str,
    details: &str,
    input_label: &str,
    kind: PromptKind,
    timeout: u32,
) -> Option<String> {
    let prompt_id = uuid::Uuid::now_v7().to_string();
    let prompt_type = match kind {
        PromptKind::Boolean => PromptType::Boolean,
        PromptKind::String => PromptType::String,
        PromptKind::Credential => PromptType::Credential,
    };
    let prompt = Prompt {
        prompt_id_uuid7: prompt_id.clone(),
        prompt: title.to_string(),
        details: details.to_string(),
        yes_dialog: "Submit".to_string(),
        no_dialog: "Cancel".to_string(),
        timeout,
        origin: module_name.to_string(),
        origin_uuid7: String::new(),
        instructions: String::new(),
        link: String::new(),
        input_label: input_label.to_string(),
        prompt_type: prompt_type as i32,
    };
    let container = Container {
        version: 1,
        auth_token: auth_token.to_string(),
        module_name: module_name.to_string(),
        module_instance_uuid7: instance_uuid.to_string(),
        payload: Some(Payload::Prompt(prompt)),
    };
    let mut buf = Vec::new();
    if container.encode(&mut buf).is_err() {
        return None;
    }
    {
        let mut w = write_ws.lock().await;
        if w.send(WsMessage::Binary(buf.into())).await.is_err() {
            return None;
        }
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout as u64 + 10);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(10), prompt_rx.recv()).await {
            Ok(Some(resp)) if resp.prompt_id_uuid7 == prompt_id => {
                return if resp.accepted {
                    Some(resp.reason)
                } else {
                    None
                };
            }
            Ok(Some(_)) => continue, // a different prompt's response
            Ok(None) => return None,
            // The 10s poll interval elapsed with no response yet: keep waiting
            // until the real deadline (the `timeout` seconds above), rather than
            // bailing out 10 seconds in and auto-cancelling every prompt.
            Err(_) => continue,
        }
    }
    None
}

async fn fetch_chatroom_id(
    client: &reqwest::Client,
    name: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let clean_name = name.trim().strip_prefix('@').unwrap_or(name.trim());
    let url = format!("https://kick.com/api/v2/channels/{}", clean_name);

    let res = client
        .get(&url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(chatroom) = res.get("chatroom") {
        if let Some(id) = chatroom.get("id").and_then(|i| i.as_u64()) {
            return Ok(id);
        }
    }

    Err(format!(
        "Could not find chatroom ID for Kick channel: {}",
        clean_name
    )
    .into())
}

async fn fetch_app_access_token(
    client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    let res = client
        .post("https://id.kick.com/oauth/token")
        .form(&params)
        .send()
        .await?;

    if res.status().is_success() {
        let json_res: serde_json::Value = res.json().await?;
        if let Some(token) = json_res.get("access_token").and_then(|t| t.as_str()) {
            return Ok(token.to_string());
        }
    } else {
        let err_text = res.text().await.unwrap_or_default();
        return Err(format!("Failed to obtain OAuth token from Kick: {}", err_text).into());
    }

    Err("Invalid response structure from Kick OAuth server".into())
}

async fn send_kick_message(
    client: &reqwest::Client,
    oauth_token: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if oauth_token.is_empty() {
        return Ok(());
    }

    let url = "https://api.kick.com/public/v1/chat";
    let body = json!({
        "content": message,
        "type": "user"
    });

    let res = client
        .post(url)
        .header("Authorization", format!("Bearer {}", oauth_token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if res.status().is_success() {
        info!("[Kick Outbound] Successfully sent message to chat.");
    } else {
        let err_text = res.text().await.unwrap_or_default();
        error!("[Kick Outbound] Failed to send message: {}", err_text);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!("Starting Kick Adapter Module...");

    // Credentials live in `.env` (written by the engine via set_credentials);
    // load them first so both load_adapter_config() below and the env-var reads
    // pick them up.
    cockatiel_client::load_env_file(".env");

    // Tunables live in config.json under `module_specific` (backfilled with
    // defaults on load). Read once and thread the values into the HTTP client,
    // the configure phase, the engine reconnect supervisor, and the Pusher loop.
    let adapter_config = load_adapter_config().unwrap_or_default();

    let http_client = reqwest::Client::builder()
        // A black-holed Kick API must never leak a task: every platform send
        // (and the channel/token fetches, which share this client) times out.
        .timeout(Duration::from_secs(adapter_config.http_timeout_secs))
        .build()?;

    // Re-acquire credentials whenever Kick rejects them (bad channel/oauth).
    // Env vars are read once; on rejection the locals are cleared so the
    // prompt path runs and asks for fresh, valid credentials.
    let env_channel = std::env::var("KICK_CHANNEL_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            // Channel name is public → config.json.
            std::fs::read_to_string("config.json")
                .ok()
                .and_then(|d| serde_json::from_str::<serde_json::Value>(&d).ok())
                .and_then(|v| v.get("module_specific").cloned())
                .and_then(|s| s.get("channel_name").cloned())
                .and_then(|c| c.as_str().map(|s| s.to_string()))
        })
        .unwrap_or_default();
    let env_client_id = std::env::var("KICK_CLIENT_ID").unwrap_or_default();
    let env_client_secret = std::env::var("KICK_CLIENT_SECRET").unwrap_or_default();
    let env_oauth = std::env::var("KICK_OAUTH_TOKEN").unwrap_or_default();

    // Connect to the engine BEFORE any prompts so the engine WebSocket exists
    // when the first `prompt_for_input` fires.
    let cockatiel = CockatielClient::connect("config.json").await?;

    let (write_ws_cockatiel, read_ws_cockatiel) = cockatiel.stream.split();
    let write_ws_cockatiel = Arc::new(tokio::sync::Mutex::new(write_ws_cockatiel));
    // Shared session identity: the read loop AND the platform send path read
    // the CURRENT token/instance here, so a reconnect (which swaps this) never
    // leaves stale credentials behind.
    let identity: Arc<tokio::sync::Mutex<EngineIdentity>> = Arc::new(tokio::sync::Mutex::new(
        EngineIdentity {
            auth: cockatiel.auth_token.clone(),
            instance: cockatiel.instance_uuid7.clone(),
            module: cockatiel.config.module_name.clone(),
        },
    ));

    // Initial identity, used by the (one-time) setup phase prompts. Runtime
    // sends read the CURRENT identity from the shared handle instead.
    let (auth_token, instance_uuid, module_name) = {
        let id = identity.lock().await;
        (id.auth.clone(), id.instance.clone(), id.module.clone())
    };

    // Register the mod commands with the engine command system: the engine now
    // parses `!ban` / `!timeout` and routes them back with the parsed Command.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    register_commands(&write_ws_cockatiel, &identity).await;

    // Channel carrying PromptResponses from the engine to the configure loop,
    // so `prompt_for_input` can await the operator's typed answer.
    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<PromptResponse>();
    let prompt_tx_task = prompt_tx.clone();

    // Values threaded into the engine reconnect supervisor spawn below.
    let default_timeout_secs = adapter_config.default_timeout_secs;
    let reconnect_base_secs = adapter_config.reconnect_base_secs;
    let reconnect_max_secs = adapter_config.reconnect_max_secs;

    // Shared OAuth token: the configure loop refreshes it each iteration and
    // the outbound worker uses the latest value for platform sends. It's a
    // tokio Mutex so no `.lock().unwrap()` can panic a task on a poisoned lock.
    let shared_token: Arc<tokio::sync::Mutex<String>> = Arc::new(tokio::sync::Mutex::new(String::new()));
    let token_for_task = shared_token.clone();
    let client_clone = http_client.clone();
    let write_task = write_ws_cockatiel.clone();
    let identity_task = identity.clone();

    // Bounded outbound send queue: the read loop try_sends (never blocks, never
    // spawns a per-message task) and a single fixed worker drains it. A reply
    // flood can't spawn unbounded tasks, and a black-holed Kick API can't leak
    // them indefinitely — at most 64 messages sit in the queue.
    let (outbound_tx, outbound_rx) = mpsc::channel::<String>(adapter_config.outbound_queue_cap);
    let outbound_tx_task = outbound_tx.clone();
    let client_worker = client_clone.clone();
    let token_worker = token_for_task.clone();
    tokio::spawn(async move {
        let mut outbound_rx = outbound_rx;
        while let Some(msg) = outbound_rx.recv().await {
            // Fresh token at send time — a reconnect may have rotated creds.
            let token = token_worker.lock().await.clone();
            if let Err(err) = send_kick_message(&client_worker, &token, &msg).await {
                error!("Error sending outbound Kick message: {}", err);
            }
        }
    });
    tokio::spawn(async move {
        // Read-loop + engine-session supervisor. When the socket drops the
        // module RECONNECTS instead of going zombie on a dead socket (the old
        // behavior: the platform loop kept pushing into a dead WS forever).
        let mut read = read_ws_cockatiel;
        let outbound_tx = outbound_tx_task;
        loop {
            // Read until the connection dies.
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(WsMessage::Binary(data)) => {
                        if let Ok(container) = cockatiel_client::proto::Container::decode(data.as_ref()) {
                            // Use the CURRENT session identity (a reconnect swaps it).
                            let (auth, instance, module) = {
                                let id = identity_task.lock().await;
                                (id.auth.clone(), id.instance.clone(), id.module.clone())
                            };
                            info!("Received from engine: {:?}", container.payload.as_ref().map(|p| std::mem::discriminant(p)));

                            if let Some(Payload::AuthVerify(_)) = container.payload {
                                // Answer the engine's liveness probe with our auth
                                // token so a quiet period never severs us.
                                let reply = Container {
                                    version: 1,
                                    auth_token: auth.clone(),
                                    module_name: module.clone(),
                                    module_instance_uuid7: instance.clone(),
                                    payload: Some(Payload::AuthVerify(AuthVerify {
                                        cur_auth: auth.clone(),
                                    })),
                                };
                                let mut buf = Vec::new();
                                if reply.encode(&mut buf).is_ok() {
                                    let mut w = write_task.lock().await;
                                    let _ = w.send(WsMessage::Binary(buf.into())).await;
                                }
                            } else if let Some(Payload::SendToPlatforms(send)) = container.payload {
                                // Bounded handoff to the outbound worker — never
                                // block the read loop and never spawn a task per
                                // message. Overflow is dropped with a warning.
                                match outbound_tx.try_send(send.msg) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        warn!("Outbound Kick queue full — dropping platform message");
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        error!("Outbound Kick queue closed — platform message dropped");
                                    }
                                }
                            } else if let Some(Payload::PromptResponse(resp)) = container.payload {
                                // Forward operator answers to the awaiting prompt.
                                let _ = prompt_tx_task.send(resp);
                            }
                            // Routed chat command: the engine parsed `!ban` / `!timeout`
                            // and delivered it here with the parsed Command attached.
                            else if let Some(Payload::MessagePreProcess(pre)) = container.payload {
                                let Some(chat) = pre.raw_message else { continue };
                                let Some(cmd) = chat.command.as_ref() else { continue };
                                if cmd.command_name == "ban" || cmd.command_name == "timeout" {
                                    let author = chat
                                        .user_data
                                        .as_ref()
                                        .map(|u| u.username.clone())
                                        .unwrap_or_default();
                                    if let Some((qid, payload)) = build_mod_query(&cmd.command_name, &chat.raw_message, &author, default_timeout_secs) {
                                        let query = Container {
                                            version: 1,
                                            auth_token: auth.clone(),
                                            module_name: module.clone(),
                                            module_instance_uuid7: instance.clone(),
                                            payload: Some(Payload::DatabaseQuery(DatabaseQuery {
                                                query_id: qid,
                                                sql: payload.to_string(),
                                                params: vec![],
                                            })),
                                        };
                                        let mut qbuf = Vec::new();
                                        if query.encode(&mut qbuf).is_ok() {
                                            let mut w = write_task.lock().await;
                                            let _ = w.send(WsMessage::Binary(qbuf.into())).await;
                                        }
                                    } else {
                                        error!(
                                            "Routed {} command unparseable — executing nothing (still acking)",
                                            cmd.command_name
                                        );
                                    }
                                }
                                // ACK the stage: echo the raw ChatMessage back with the
                                // SAME message_uuid7 so the engine clears this adapter's
                                // pending pre-process ack and the message doesn't strand
                                // until the timeout sweep. Sent on every routed-command
                                // path (success and error). NEVER ack with an EMPTY
                                // uuid7 — the engine treats that as a NEW message ingest.
                                if !pre.message_uuid7.is_empty() {
                                    let ack = Container {
                                        version: 1,
                                        auth_token: auth.clone(),
                                        module_name: module.clone(),
                                        module_instance_uuid7: instance.clone(),
                                        payload: Some(Payload::MessagePreProcess(MessagePreProcess {
                                            message_uuid7: pre.message_uuid7.clone(),
                                            raw_message: Some(chat.clone()),
                                            audio: vec![],
                                            audio_type: String::new(),
                                        })),
                                    };
                                    let mut abuf = Vec::new();
                                    if ack.encode(&mut abuf).is_ok() {
                                        let mut w = write_task.lock().await;
                                        let _ = w.send(WsMessage::Binary(abuf)).await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        info!("Engine closed connection");
                        break;
                    }
                    Err(e) => {
                        error!("Engine WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }

            // The engine connection dropped — reconnect with backoff instead of
            // leaving the platform loop pushing into a dead socket.
            info!("Engine disconnected — reconnecting...");
            let mut backoff = reconnect_base_secs;
            loop {
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                match CockatielClient::connect("config.json").await {
                    Ok(conn) => {
                        info!("Reconnected to engine");
                        let (w, r) = conn.stream.split();
                        *write_task.lock().await = w;
                        *identity_task.lock().await = EngineIdentity {
                            auth: conn.auth_token,
                            instance: conn.instance_uuid7,
                            module: conn.config.module_name,
                        };
                        // The engine forgets a session's commands when the
                        // socket drops — re-register on the fresh session.
                        register_commands(&write_task, &identity_task).await;
                        read = r;
                        break;
                    }
                    Err(e) => {
                        error!("Engine reconnect failed: {} — retrying in {}s", e, backoff);
                        backoff = (backoff * 2).min(reconnect_max_secs);
                    }
                }
            }
        }
    });

    // Set when Kick rejects the saved credentials (bad channel / failed
    // chatroom lookup); skips the saved-config fast paths so the module prompts
    // for fresh credentials via the prompt subwindow instead of looping.
    // Never set anymore: the old re-acquire-on-bad-channel spin loop was
    // replaced by the bounded t/i/r/e resolution below, so it stays false and
    // the saved-config fast path always runs.
    let force_prompt = false;

    // Linear setup phase: resolve config + channel once, then fall through to
    // the receive-only Pusher loop (never re-prompts in a spin loop).
    {
        let mut channel_name = env_channel.clone();
        let mut client_id = env_client_id.clone();
        let mut client_secret = env_client_secret.clone();
        let mut oauth_token = env_oauth.clone();
        // Clear the shared token so a stale one isn't used while re-acquiring.
        shared_token.lock().await.clear();

        // Non-interactive fast path: if a usable saved config exists, use it without
        // prompting (enables the TUI to supply credentials via file). channel +
        // client_id + client_secret is enough — the OAuth token is generated
        // automatically below from the client id/secret.
        if !force_prompt
            && channel_name.is_empty()
            && client_id.is_empty()
            && client_secret.is_empty()
            && oauth_token.is_empty()
        {
            if let Some(saved) = load_adapter_config() {
                let saved_channel = saved.channel_name.unwrap_or_default();
                let saved_cid = saved.client_id.unwrap_or_default();
                let saved_secret = saved.client_secret.unwrap_or_default();
                let saved_oauth = saved.oauth_token.unwrap_or_default();
                if !saved_channel.is_empty() && !saved_cid.is_empty() && !saved_secret.is_empty() {
                    info!(
                        "Using saved Kick configuration for channel '{}' (no prompt).",
                        saved_channel
                    );
                    channel_name = saved_channel;
                    client_id = saved_cid;
                    client_secret = saved_secret;
                    oauth_token = saved_oauth;
                }
            }
        }

        if channel_name.is_empty() {
        if !force_prompt {
            if let Some(saved) = load_adapter_config() {
            if let Some(saved_name) = saved.channel_name {
                let confirm = prompt_for_input(
                    &write_ws_cockatiel,
                    &mut prompt_rx,
                    &auth_token,
                    &module_name,
                    &instance_uuid,
                    "Use Saved Kick Configuration?",
                    &format!(
                        "A saved configuration was found for channel '{}'.\n\n\
                         Use this configuration?",
                        saved_name
                    ),
                    // Empty input_label + boolean kind → true y/n prompt (y accepts, n/Esc
                    // cancels). The caller treats Some(..) as "yes".
                    "",
                    PromptKind::Boolean,
                    120,
                )
                .await;

                if let Some(choice) = confirm {
                    if choice.trim().eq_ignore_ascii_case("y") || choice.trim().eq_ignore_ascii_case("yes") {
                        channel_name = saved_name;
                        client_id = saved.client_id.unwrap_or_default();
                        client_secret = saved.client_secret.unwrap_or_default();
                        oauth_token = saved.oauth_token.unwrap_or_default();
                    }
                }
            }
            }
        }
    }

    if channel_name.is_empty() {
        let input = prompt_for_input(
            &write_ws_cockatiel,
            &mut prompt_rx,
            &auth_token,
            &module_name,
            &instance_uuid,
            "Kick Live Chat Configuration Required",
            "Enter your Kick Channel Name / Username (e.g. vulbyte).",
            "Kick Channel Name",
            PromptKind::String,
            adapter_config.prompt_timeout_secs,
        )
        .await;
        if let Some(val) = input {
            channel_name = val.trim().to_string();
        }

        let input = prompt_for_input(
            &write_ws_cockatiel,
            &mut prompt_rx,
            &auth_token,
            &module_name,
            &instance_uuid,
            "Kick Application Setup",
            "Kick Application Setup (Required for bot replies/moderation):\n\n\
             1. Go to: https://kick.com/settings/developer\n\
             2. Click 'Create new' with these exact settings:\n\
                - Application Name:  tielbot\n\
                - App Description:   Stream chat adapter for Cockatiel\n\
                - Redirect URL:      http://localhost\n\
                - Enable webhooks:   Off (Disabled)\n\
                - Scopes Requested:  Check **ALL** permissions\n\
             3. Copy your Client ID when prompted below.\n\n\
             Note: If you only want read-only monitoring, press Cancel to skip\n\
             credentials.",
            "Client ID",
            PromptKind::String,
            adapter_config.prompt_timeout_secs,
        )
        .await;
        if let Some(val) = input {
            client_id = val.trim().to_string();
        }

        if !client_id.is_empty() {
            let input = prompt_for_input(
                &write_ws_cockatiel,
                &mut prompt_rx,
                &auth_token,
                &module_name,
                &instance_uuid,
                "Kick Client Secret",
                "Enter the Client Secret for the Kick application above.",
                "Client Secret",
                PromptKind::Credential,
                adapter_config.prompt_timeout_secs,
            )
            .await;
            if let Some(val) = input {
                client_secret = val.trim().to_string();
            }

            if !client_secret.is_empty() {
                info!("Requesting automated OAuth token from Kick API...");
                match fetch_app_access_token(&http_client, &client_id, &client_secret).await {
                    Ok(token) => {
                        info!("Successfully generated Kick OAuth Token automatically!");
                        oauth_token = token;
                    }
                    Err(e) => {
                        error!(
                            "Failed to generate OAuth token: {}. Continuing in read-only mode.",
                            e
                        );
                    }
                }
            }
        }

        save_adapter_config(&channel_name, &client_id, &client_secret, &oauth_token);
    } else if oauth_token.is_empty() && !client_id.is_empty() && !client_secret.is_empty() {
        if let Ok(token) = fetch_app_access_token(&http_client, &client_id, &client_secret).await {
            oauth_token = token;
        }
    }
    // Publish the latest token so the outbound worker uses it for platform sends.
    *shared_token.lock().await = oauth_token.clone();

    info!(
        "Resolving Kick channel '{}' to chatroom ID...",
        channel_name
    );
    // Bounded resolution: on failure the operator explicitly picks how to
    // proceed (t/i/r/e). The loop NEVER breaks with chatroom_id 0 — the Pusher
    // subscribe would silently target `chatrooms.0.v2` and idle forever. Any
    // unresolvable outcome logs a clear error and retries with capped backoff.
    let mut setup_log = String::new();
    let mut resolve_backoff = adapter_config.chatroom_resolve_base_secs;
    let chatroom_id = loop {
        match fetch_chatroom_id(&http_client, &channel_name).await {
            Ok(id) if id > 0 => {
                info!("Successfully resolved chatroom ID: {}", id);
                break id;
            }
            Ok(_) => {
                error!(
                    "Kick returned a zero/bogus chatroom ID for channel '{}' — treating as unresolved.",
                    channel_name
                );
            }
            Err(e) => {
                error!("Failed to resolve Kick chatroom ID: {}", e);
            }
        }

        // Resolution failed for this channel name — ask the operator what to
        // do (t/i/r/e), or fall back to a backoff retry below.
        let subject = format!("Channel '{}' could not be resolved on Kick.", channel_name);
        let mut replacement: Option<String> = None;
        match prompt_tie_choice(
            &write_ws_cockatiel,
            &mut prompt_rx,
            &auth_token,
            &module_name,
            &instance_uuid,
            &subject,
            adapter_config.prompt_timeout_secs,
        )
        .await
        {
            Some(TieChoice::Retry) => {
                // Re-resolve the same name (the failure may be transient).
                continue;
            }
            Some(TieChoice::Ignore) => {
                setup_log.push_str(&format!(
                    "channel '{}' invalid — ignored (retrying resolution)\n",
                    channel_name
                ));
            }
            Some(TieChoice::Remove) => {
                setup_log.push_str(&format!(
                    "channel '{}' invalid — removed\n",
                    channel_name
                ));
                replacement = prompt_for_input(
                    &write_ws_cockatiel,
                    &mut prompt_rx,
                    &auth_token,
                    &module_name,
                    &instance_uuid,
                    "Kick Channel Name",
                    "Enter a new Kick Channel Name / Username (e.g. vulbyte).",
                    "Kick Channel Name",
                    PromptKind::String,
                    adapter_config.prompt_timeout_secs,
                )
                .await;
            }
            Some(TieChoice::Edit) => {
                replacement = prompt_for_input(
                    &write_ws_cockatiel,
                    &mut prompt_rx,
                    &auth_token,
                    &module_name,
                    &instance_uuid,
                    "Edit Kick Channel Name",
                    "Enter the correct Kick Channel Name / Username (e.g. vulbyte).",
                    "Kick Channel Name",
                    PromptKind::String,
                    adapter_config.prompt_timeout_secs,
                )
                .await;
            }
            None => {
                setup_log.push_str(&format!(
                    "channel '{}' invalid — skipped (cancelled)\n",
                    channel_name
                ));
            }
        }

        if let Some(t) = replacement {
            let t = t.trim().to_string();
            if !t.is_empty() {
                channel_name = t;
                resolve_backoff = adapter_config.chatroom_resolve_base_secs;
                continue;
            }
        }

        // Never proceed with chatroom_id 0. Log a clear error and retry the
        // resolution with capped backoff (the module self-heals when Kick's
        // API recovers instead of silently subscribing to chatroom 0).
        error!(
            "Kick channel '{}' could not be resolved — NOT subscribing to chatroom 0. Retrying resolution in {}s.",
            channel_name, resolve_backoff
        );
        setup_log.push_str(&format!(
            "channel '{}' unresolved — retrying resolution in {}s\n",
            channel_name, resolve_backoff
        ));
        tokio::time::sleep(Duration::from_secs(resolve_backoff)).await;
        resolve_backoff = (resolve_backoff * 2).min(adapter_config.chatroom_resolve_max_secs);
    };

    // Surface the setup summary to the operator (the accumulated log).
    if !setup_log.trim().is_empty() {
        let log = Container {
            version: 1,
            auth_token: auth_token.clone(),
            module_name: module_name.clone(),
            module_instance_uuid7: instance_uuid.clone(),
            payload: Some(Payload::Log(cockatiel_client::proto::Log {
                log: format!("[kick-adapter] setup:\n{}", setup_log.trim_end()),
                blob: vec![],
            })),
        };
        let mut lbuf = Vec::new();
        if log.encode(&mut lbuf).is_ok() {
            let _ = write_ws_cockatiel
                .lock()
                .await
                .send(WsMessage::Binary(lbuf))
                .await;
        }
    }

    let pusher_url = "wss://ws-us2.pusher.com/app/32cbd69e4b950bf97679?protocol=7&client=js&version=7.6.0&flash=false";

    loop {
        info!("Connecting to Kick Pusher WebSocket...");

        let mut req = match pusher_url.into_client_request() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to build WebSocket request: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    adapter_config.ws_retry_delay_secs,
                ))
                .await;
                continue;
            }
        };

        let headers = req.headers_mut();
        headers.insert("Origin", "https://kick.com".parse().unwrap());
        headers.insert("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".parse().unwrap());

        let (mut ws_stream, _) = match connect_async(req).await {
            Ok(conn) => conn,
            Err(e) => {
                error!(
                    "Failed to connect to Kick WebSocket: {}. Retrying in {} seconds...",
                    e,
                    adapter_config.ws_retry_delay_secs
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    adapter_config.ws_retry_delay_secs,
                ))
                .await;
                continue;
            }
        };

        info!("Connected to Kick WebSocket layer!");

        let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(
            adapter_config.pusher_ping_interval_secs,
        ));

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {}
                msg = ws_stream.next() => {
                    match msg {
                        Some(Ok(WsMessage::Text(text))) => {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                                let event = parsed.get("event").and_then(|e| e.as_str()).unwrap_or("");

                                if event == "pusher:connection_established" {
                                    info!("Pusher handshake established. Subscribing to chatroom {}...", chatroom_id);
                                    let subscribe_msg = json!({
                                        "event": "pusher:subscribe",
                                        "data": {
                                            "auth": "",
                                            "channel": format!("chatrooms.{}.v2", chatroom_id)
                                        }
                                    });
                                    if let Err(e) = ws_stream.send(WsMessage::Text(subscribe_msg.to_string())).await {
                                        error!("Failed to send subscription frame: {}", e);
                                        break;
                                    }
                                } else if event == "pusher_internal:subscription_succeeded" {
                                    info!("Successfully subscribed to Kick chatroom: chatrooms.{}.v2", chatroom_id);
                                } else if event == "App\\Events\\ChatMessageEvent" {
                                    if let Some(data_str) = parsed.get("data").and_then(|d| d.as_str()) {
                                        if let Ok(data_json) = serde_json::from_str::<serde_json::Value>(data_str) {
                                            let sender = data_json.get("sender")
                                                .and_then(|s| s.get("username"))
                                                .and_then(|u| u.as_str())
                                                .unwrap_or("Unknown");

                                            let content = data_json.get("content")
                                                .and_then(|c| c.as_str())
                                                .unwrap_or("");

                                            if !content.is_empty() {
                                                info!("[Kick Chat] {}: {}", sender, content);
                                                let pre_process = MessagePreProcess {
                        audio: vec![],
                        audio_type: String::new(),
                                                    message_uuid7: String::new(),
                                                    raw_message: Some(ChatMessage {
                                                        platform: "kick".into(),
                                                        raw_data: data_json.to_string().as_bytes().to_vec(),
                                                        raw_message: content.to_string(),
                                                        user_uuid7: sender.to_string(),
                                                        command: None,
                                                        channel_id: channel_name.clone(),
                                                        user_data: None,
                                                    }),
                                                };
                                                // Use the CURRENT session identity (a
                                                // reconnect swaps it) for every engine
                                                // send, not stale setup-phase clones.
                                                let (auth, instance, module) = {
                                                    let id = identity.lock().await;
                                                    (id.auth.clone(), id.instance.clone(), id.module.clone())
                                                };
                                                let container = cockatiel_client::proto::Container {
                                                    version: 1,
                                                    auth_token: auth,
                                                    module_name: module,
                                                    module_instance_uuid7: instance,
                                                    payload: Some(Payload::MessagePreProcess(pre_process)),
                                                };
                                                let mut buf = Vec::new();
                                                use prost::Message;
                                                if container.encode(&mut buf).is_ok() {
                                                    if let Err(e) = write_ws_cockatiel.lock().await.send(WsMessage::Binary(buf.into())).await {
                                                        error!("Failed to send message to engine: {}", e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else if event == "pusher:ping" {
                                    let pong = json!({ "event": "pusher:pong", "data": {} });
                                    let _ = ws_stream.send(WsMessage::Text(pong.to_string())).await;
                                }
                            }
                        }
                        Some(Ok(WsMessage::Ping(p))) => {
                            let _ = ws_stream.send(WsMessage::Pong(p)).await;
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error: {}. Reconnecting...", e);
                            break;
                        }
                        None => {
                            error!("WebSocket connection closed. Reconnecting...");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(
            adapter_config.pusher_reconnect_delay_secs,
        ))
        .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_parses_target_and_reason() {
        let (qid, p) = build_mod_query("ban", "!ban @user being awful", "mod", 300).unwrap();
        assert_eq!(qid, "mod_ban");
        assert_eq!(p["handle"], "user");
        assert_eq!(p["reason"], "being awful");
        assert_eq!(p["actor"]["handle"], "mod");
    }

    #[test]
    fn timeout_parses_duration_and_reason() {
        let (qid, p) = build_mod_query("timeout", "!timeout @user 600 spamming", "mod", 300).unwrap();
        assert_eq!(qid, "mod_timeout");
        assert_eq!(p["duration_secs"], 600);
        assert_eq!(p["reason"], "spamming");
    }

    #[test]
    fn unrouted_command_is_none() {
        assert!(build_mod_query("!help", "!help", "mod", 300).is_none());
    }

    #[test]
    fn tie_choice_parses_all_options() {
        assert_eq!(parse_tie_choice("t"), Some(TieChoice::Retry));
        assert_eq!(parse_tie_choice("try"), Some(TieChoice::Retry));
        assert_eq!(parse_tie_choice("retry"), Some(TieChoice::Retry));
        assert_eq!(parse_tie_choice("try again"), Some(TieChoice::Retry));
        assert_eq!(parse_tie_choice("i"), Some(TieChoice::Ignore));
        assert_eq!(parse_tie_choice("IGNORE"), Some(TieChoice::Ignore));
        assert_eq!(parse_tie_choice("r"), Some(TieChoice::Remove));
        assert_eq!(parse_tie_choice("remove"), Some(TieChoice::Remove));
        assert_eq!(parse_tie_choice("e"), Some(TieChoice::Edit));
        assert_eq!(parse_tie_choice("EDIT"), Some(TieChoice::Edit));
        assert_eq!(parse_tie_choice("x"), None);
        assert_eq!(parse_tie_choice(""), None);
        assert_eq!(parse_tie_choice("  edit  "), Some(TieChoice::Edit));
    }
}
