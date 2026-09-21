use futures_util::{SinkExt, StreamExt};
use prost::Message;
use cockatiel_client::{proto::container::Payload, proto::*, CockatielClient, PromptKind};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message as WsMessage},
};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

type WsWriteHalf = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    WsMessage,
>;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KickAdapterConfig {
    channel_name: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    oauth_token: Option<String>,
}

/// Parse a moderator command (!ban / !timeout) from a chat message.
fn parse_mod_command(message: &str, author: &str) -> Option<(String, serde_json::Value)> {
    let trimmed = message.trim();
    let lower = trimmed.to_lowercase();

    if lower.starts_with("!ban") {
        let args = trimmed[5..].trim();
        let (target, rest) = match args.split_once(char::is_whitespace) {
            Some((t, r)) => (t, r),
            None => (args, ""),
        };
        let target = target.trim_start_matches('@').to_string();
        if target.is_empty() {
            return None;
        }
        return Some((
            "mod_ban".to_string(),
            serde_json::json!({
                "platform": "kick",
                "handle": target,
                "reason": rest.trim().to_string(),
                "actor": { "platform": "kick", "handle": author },
            }),
        ));
    }

    if lower.starts_with("!timeout") {
        let args = trimmed[9..].trim();
        let mut parts = args.split_whitespace();
        let target = parts.next().unwrap_or("").trim_start_matches('@').to_string();
        if target.is_empty() {
            return None;
        }
        let mut duration_secs = 300i64;
        let mut reason = String::new();
        if let Some(d) = parts.next() {
            if let Ok(secs) = d.parse::<i64>() {
                duration_secs = secs;
            } else {
                reason = d.to_string();
            }
        }
        let rest: Vec<&str> = parts.collect();
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

    None
}

fn load_adapter_config() -> Option<KickAdapterConfig> {
    // The channel name is PUBLIC (visible to anyone on the stream) → config.json;
    // client id/secret/oauth are secrets → `.env` (env vars loaded at startup).
    let channel_name = std::fs::read_to_string("config.json")
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .and_then(|v| v.get("module_specific").cloned())
        .and_then(|s| s.get("channel_name").cloned())
        .and_then(|c| c.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| std::env::var("KICK_CHANNEL_NAME").unwrap_or_default());
    Some(KickAdapterConfig {
        channel_name: Some(channel_name),
        client_id: Some(std::env::var("KICK_CLIENT_ID").unwrap_or_default()),
        client_secret: Some(std::env::var("KICK_CLIENT_SECRET").unwrap_or_default()),
        oauth_token: Some(std::env::var("KICK_OAUTH_TOKEN").unwrap_or_default()),
    })
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
    let path = PathBuf::from("config.json");
    let mut json_val = if let Ok(data) = std::fs::read_to_string(&path) {
        serde_json::from_str::<serde_json::Value>(&data).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    json_val["module_specific"] = json!({ "channel_name": channel_name });
    if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
        let _ = std::fs::write(&path, pretty);
    }
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

/// Send a Prompt to the engine (forwarded to connected UIs) and wait for the
/// operator's response (`PromptResponse.reason`). Returns None on cancel/timeout.
async fn prompt_for_input(
    write_ws: &mut WsWriteHalf,
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
    if write_ws.send(WsMessage::Binary(buf.into())).await.is_err() {
        return None;
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

    let http_client = reqwest::Client::new();

    // Credentials live in `.env` (written by the engine via set_credentials);
    // load them so the env-var reads below pick them up.
    cockatiel_client::load_env_file(".env");

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

    let (write_ws_cockatiel, mut read_ws_cockatiel) = cockatiel.stream.split();
    let write_ws_cockatiel = Arc::new(tokio::sync::Mutex::new(write_ws_cockatiel));
    let auth_token = cockatiel.auth_token.clone();
    let instance_uuid = cockatiel.instance_uuid7.clone();
    let module_name = cockatiel.config.module_name.clone();

    // Channel carrying PromptResponses from the engine to the configure loop,
    // so `prompt_for_input` can await the operator's typed answer.
    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<PromptResponse>();
    let prompt_tx_task = prompt_tx.clone();

    // Shared OAuth token: the configure loop refreshes it each iteration and
    // the read task uses the latest value for outbound sends.
    let shared_token: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let token_for_task = shared_token.clone();
    let client_clone = http_client.clone();
    let write_task = write_ws_cockatiel.clone();
    let auth_task = auth_token.clone();
    let module_task = module_name.clone();
    let instance_task = instance_uuid.clone();
    tokio::spawn(async move {
        while let Some(msg) = read_ws_cockatiel.next().await {
            match msg {
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(container) = cockatiel_client::proto::Container::decode(data.as_ref()) {
                        info!("Received from engine: {:?}", container.payload.as_ref().map(|p| std::mem::discriminant(p)));

                        if let Some(Payload::AuthVerify(_)) = container.payload {
                            // Answer the engine's liveness probe with our auth
                            // token so a quiet period never severs us.
                            let reply = Container {
                                version: 1,
                                auth_token: auth_task.clone(),
                                module_name: module_task.clone(),
                                module_instance_uuid7: instance_task.clone(),
                                payload: Some(Payload::AuthVerify(AuthVerify {
                                    cur_auth: auth_task.clone(),
                                })),
                            };
                            let mut buf = Vec::new();
                            if reply.encode(&mut buf).is_ok() {
                                let mut w = write_task.lock().await;
                                let _ = w.send(WsMessage::Binary(buf.into())).await;
                            }
                        } else if let Some(Payload::SendToPlatforms(send)) = container.payload {
                            let client_ref = client_clone.clone();
                            let t_ref = token_for_task.lock().unwrap().clone();
                            tokio::spawn(async move {
                                if let Err(err) = send_kick_message(&client_ref, &t_ref, &send.msg).await {
                                    error!("Error sending outbound Kick message: {}", err);
                                }
                            });
                        } else if let Some(Payload::PromptResponse(resp)) = container.payload {
                            // Forward operator answers to the awaiting prompt.
                            let _ = prompt_tx_task.send(resp);
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
    });

    // Set when Kick rejects the saved credentials (bad channel / failed
    // chatroom lookup); skips the saved-config fast paths so the module prompts
    // for fresh credentials via the prompt subwindow instead of looping.
    let mut force_prompt = false;

    'configure: loop {
        let mut channel_name = env_channel.clone();
        let mut client_id = env_client_id.clone();
        let mut client_secret = env_client_secret.clone();
        let mut oauth_token = env_oauth.clone();
        // Clear the shared token so a stale one isn't used while re-acquiring.
        shared_token.lock().unwrap().clear();

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
                    &mut *write_ws_cockatiel.lock().await,
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
            &mut *write_ws_cockatiel.lock().await,
            &mut prompt_rx,
            &auth_token,
            &module_name,
            &instance_uuid,
            "Kick Live Chat Configuration Required",
            "Enter your Kick Channel Name / Username (e.g. vulbyte).",
            "Kick Channel Name",
            PromptKind::String,
            300,
        )
        .await;
        if let Some(val) = input {
            channel_name = val.trim().to_string();
        }

        let input = prompt_for_input(
            &mut *write_ws_cockatiel.lock().await,
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
            300,
        )
        .await;
        if let Some(val) = input {
            client_id = val.trim().to_string();
        }

        if !client_id.is_empty() {
            let input = prompt_for_input(
                &mut *write_ws_cockatiel.lock().await,
                &mut prompt_rx,
                &auth_token,
                &module_name,
                &instance_uuid,
                "Kick Client Secret",
                "Enter the Client Secret for the Kick application above.",
                "Client Secret",
                PromptKind::Credential,
                300,
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
    // Publish the latest token so the read task uses it for outbound sends.
    *shared_token.lock().unwrap() = oauth_token.clone();

    info!(
        "Resolving Kick channel '{}' to chatroom ID...",
        channel_name
    );
    let chatroom_id = match fetch_chatroom_id(&http_client, &channel_name).await {
        Ok(id) => {
            info!("Successfully resolved chatroom ID: {}", id);
            id
        }
        Err(e) => {
            error!("Failed to resolve Kick chatroom ID: {}. Re-acquiring credentials...", e);
            force_prompt = true;
            channel_name.clear();
            client_id.clear();
            client_secret.clear();
            oauth_token.clear();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue 'configure;
        }
    };

    let pusher_url = "wss://ws-us2.pusher.com/app/32cbd69e4b950bf97679?protocol=7&client=js&version=7.6.0&flash=false";

    loop {
        info!("Connecting to Kick Pusher WebSocket...");

        let mut req = match pusher_url.into_client_request() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to build WebSocket request: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
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
                    "Failed to connect to Kick WebSocket: {}. Retrying in 5 seconds...",
                    e
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("Connected to Kick WebSocket layer!");

        let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

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
                                                        user_data: None,
                                                    }),
                                                };
                                                let container = cockatiel_client::proto::Container {
                                                    version: 1,
                                                    auth_token: auth_token.clone(),
                                                    module_name: module_name.clone(),
                                                    module_instance_uuid7: instance_uuid.clone(),
                                                    payload: Some(Payload::MessagePreProcess(pre_process)),
                                                };
                                                let mut buf = Vec::new();
                                                use prost::Message;
                                                if container.encode(&mut buf).is_ok() {
                                                    if let Err(e) = write_ws_cockatiel.lock().await.send(WsMessage::Binary(buf.into())).await {
                                                        error!("Failed to send message to engine: {}", e);
                                                    }
                                                }

                                                // Handle moderator commands (!ban / !timeout).
                                                if let Some((qid, payload)) = parse_mod_command(content, sender) {
                                                    info!("Mod command detected: {} payload={}", qid, payload);
                                                    let query = Container {
                                                        version: 1,
                                                        auth_token: auth_token.clone(),
                                                        module_name: module_name.clone(),
                                                        module_instance_uuid7: instance_uuid.clone(),
                                                        payload: Some(Payload::DatabaseQuery(DatabaseQuery {
                                                            query_id: qid,
                                                            sql: payload.to_string(),
                                                            params: vec![],
                                                        })),
                                                    };
                                                    let mut qbuf = Vec::new();
                                                    if query.encode(&mut qbuf).is_ok() {
                                                        if let Err(e) = write_ws_cockatiel.lock().await.send(WsMessage::Binary(qbuf.into())).await {
                                                            error!("Failed to send mod command to engine: {}", e);
                                                        }
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

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}
