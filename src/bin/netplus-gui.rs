#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

use eframe::egui::{self, Color32, RichText, Stroke};
use serde::{Deserialize, Serialize};

const MAX_LOG_LINES: usize = 5_000;
const MAX_ACTIVITY_ROWS: usize = 500;
const ACCENT: Color32 = Color32::from_rgb(46, 113, 128);
const ACCENT_DARK: Color32 = Color32::from_rgb(34, 82, 94);
const SIDEBAR: Color32 = Color32::from_rgb(39, 44, 48);
const WORKSPACE: Color32 = Color32::from_rgb(240, 244, 245);
const CARD: Color32 = Color32::from_rgb(250, 252, 252);
const TEXT: Color32 = Color32::from_rgb(43, 51, 55);
const MUTED_TEXT: Color32 = Color32::from_rgb(111, 124, 130);
const SUCCESS: Color32 = Color32::from_rgb(42, 120, 99);
const ERROR_TEXT: Color32 = Color32::from_rgb(168, 75, 75);
const WARNING_TEXT: Color32 = Color32::from_rgb(130, 85, 10);

fn main() -> eframe::Result<()> {
    let _ = std::any::TypeId::of::<netplus::Config>();
    if !is_elevated() && restart_as_administrator().is_ok() {
        return Ok(());
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([747.0, 507.0])
            .with_min_inner_size([680.0, 480.0])
            .with_resizable(true)
            .with_maximize_button(true),
        ..Default::default()
    };
    eframe::run_native(
        "netplus",
        options,
        Box::new(|context| {
            configure_style(&context.egui_ctx);
            Ok(Box::new(NetplusApp::new()))
        }),
    )
}

struct NetplusApp {
    config_path: PathBuf,
    config: Profile,
    listen_text: String,
    process_ids_text: String,
    upstream_test_status: UpstreamTestStatus,
    upstream_test_sender: Sender<Result<String, String>>,
    upstream_test_receiver: Receiver<Result<String, String>>,
    is_elevated: bool,
    yaml_text: String,
    selected_view: View,
    status: Status,
    child: Option<Child>,
    shutdown_file: Option<PathBuf>,
    log_sender: Sender<String>,
    log_receiver: Receiver<String>,
    log_lines: VecDeque<String>,
    activity: VecDeque<Activity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum View {
    Connections,
    Proxy,
    Applications,
    Rules,
    Log,
    Advanced,
}

impl View {
    const ALL: [Self; 6] = [
        Self::Connections,
        Self::Proxy,
        Self::Applications,
        Self::Rules,
        Self::Log,
        Self::Advanced,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Connections => "Connections",
            Self::Proxy => "Proxy Server",
            Self::Applications => "Applications",
            Self::Rules => "Routing Rules",
            Self::Log => "Event Log",
            Self::Advanced => "Advanced YAML",
        }
    }

    fn symbol(self) -> &'static str {
        match self {
            Self::Connections => "●",
            Self::Proxy => "↗",
            Self::Applications => "▣",
            Self::Rules => "≡",
            Self::Log => "≣",
            Self::Advanced => "{ }",
        }
    }
}

#[derive(Clone, Debug)]
enum Status {
    Stopped,
    Running,
    Stopping,
    Error(String),
}

#[derive(Clone, Debug)]
enum UpstreamTestStatus {
    Idle,
    Testing,
    Success(String),
    Error(String),
}

#[derive(Clone, Debug)]
struct Activity {
    process: String,
    target: String,
    action: String,
    state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    #[serde(default)]
    log_level: LogLevel,
    upstream: Option<String>,
    #[serde(default)]
    routing: RoutingProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_mode: Option<ProcessProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tun_mode: Option<TunProfile>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            log_level: LogLevel::Info,
            upstream: Some("socks5://127.0.0.1:1081".into()),
            routing: RoutingProfile::default(),
            process_mode: None,
            tun_mode: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    const ALL: [Self; 5] = [
        Self::Trace,
        Self::Debug,
        Self::Info,
        Self::Warn,
        Self::Error,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Trace => "Trace",
            Self::Debug => "Debug",
            Self::Info => "Info",
            Self::Warn => "Warning",
            Self::Error => "Error",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessProfile {
    #[serde(default)]
    backend: ProcessBackend,
    #[serde(default = "default_netch_runtime_dir")]
    netch_runtime_dir: PathBuf,
    #[serde(default)]
    executable_names: Vec<String>,
    #[serde(default)]
    process_ids: Vec<u32>,
    #[serde(default = "default_true")]
    bypass_private: bool,
}

impl Default for ProcessProfile {
    fn default() -> Self {
        Self {
            backend: ProcessBackend::Windivert,
            netch_runtime_dir: default_netch_runtime_dir(),
            executable_names: Vec::new(),
            process_ids: Vec::new(),
            bypass_private: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TunProfile {
    #[serde(default = "default_tun_interface_name")]
    interface_name: String,
    #[serde(default)]
    ipv6: bool,
    #[serde(default = "default_tun_mtu")]
    mtu: u16,
    #[serde(default = "default_tun_max_sessions")]
    max_sessions: usize,
}

impl Default for TunProfile {
    fn default() -> Self {
        Self {
            interface_name: default_tun_interface_name(),
            ipv6: false,
            mtu: default_tun_mtu(),
            max_sessions: default_tun_max_sessions(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ProcessBackend {
    #[default]
    Windivert,
    Netch,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoutingProfile {
    #[serde(default = "default_route")]
    default: RouteAction,
    #[serde(default)]
    rules: Vec<RouteRule>,
}

impl Default for RoutingProfile {
    fn default() -> Self {
        Self {
            default: RouteAction::Proxy,
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RouteAction {
    Direct,
    Proxy,
    Block,
}

impl RouteAction {
    const ALL: [Self; 3] = [Self::Proxy, Self::Direct, Self::Block];

    fn label(self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Proxy => "Proxy",
            Self::Block => "Block",
        }
    }

    fn color(self) -> Color32 {
        match self {
            Self::Direct => SUCCESS,
            Self::Proxy => ACCENT,
            Self::Block => ERROR_TEXT,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteRule {
    action: RouteAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cidrs: Vec<String>,
    #[serde(skip)]
    domains_text: String,
    #[serde(skip)]
    cidrs_text: String,
}

impl Default for RouteRule {
    fn default() -> Self {
        Self {
            action: RouteAction::Proxy,
            domains: Vec::new(),
            cidrs: Vec::new(),
            domains_text: String::new(),
            cidrs_text: String::new(),
        }
    }
}

impl NetplusApp {
    fn new() -> Self {
        let (log_sender, log_receiver) = mpsc::channel();
        let (upstream_test_sender, upstream_test_receiver) = mpsc::channel();
        let config_path = default_config_path();
        let (mut config, yaml_text, status) = read_profile(&config_path).unwrap_or_else(|error| {
            let config = Profile::default();
            let yaml = serialize_profile(&config).unwrap_or_default();
            (config, yaml, Status::Error(error))
        });
        prepare_rule_editors(&mut config);
        let listen_text = config.listen.to_string();
        let process_ids_text = process_ids_text(&config);
        Self {
            config_path,
            config,
            listen_text,
            process_ids_text,
            upstream_test_status: UpstreamTestStatus::Idle,
            upstream_test_sender,
            upstream_test_receiver,
            is_elevated: is_elevated(),
            yaml_text,
            selected_view: View::Connections,
            status,
            child: None,
            shutdown_file: None,
            log_sender,
            log_receiver,
            log_lines: VecDeque::new(),
            activity: VecDeque::new(),
        }
    }

    fn save_config(&mut self) -> bool {
        if let Err(error) = self.sync_text_fields() {
            self.set_error(error);
            return false;
        }
        let mut config = self.config.clone();
        if config.process_mode.as_ref().is_some_and(|processes| {
            processes.executable_names.is_empty() && processes.process_ids.is_empty()
        }) {
            config.process_mode = None;
        }
        let yaml = match serialize_profile(&config) {
            Ok(yaml) => yaml,
            Err(error) => {
                self.set_error(error);
                return false;
            }
        };
        match std::fs::write(&self.config_path, &yaml) {
            Ok(()) => {
                self.yaml_text = yaml;
                self.push_log("Configuration saved".into());
                true
            }
            Err(error) => {
                self.set_error(format!("Failed to save configuration: {error}"));
                false
            }
        }
    }

    fn sync_text_fields(&mut self) -> Result<(), String> {
        self.config.listen = self
            .listen_text
            .parse()
            .map_err(|error| format!("Invalid local SOCKS listener: {error}"))?;

        let process_ids = parse_process_ids(&self.process_ids_text)?;
        if !process_ids.is_empty()
            && self
                .config
                .process_mode
                .as_ref()
                .is_some_and(|profile| profile.backend == ProcessBackend::Netch)
        {
            return Err(
                "The Netch test backend supports executable names but not process IDs".into(),
            );
        }
        if !process_ids.is_empty() {
            self.config
                .process_mode
                .get_or_insert_with(ProcessProfile::default)
                .process_ids = process_ids;
        } else if let Some(profile) = self.config.process_mode.as_mut() {
            profile.process_ids.clear();
        }
        Ok(())
    }

    fn apply_yaml(&mut self) {
        match serde_yaml::from_str::<Profile>(&self.yaml_text) {
            Ok(config) => {
                self.config = config;
                prepare_rule_editors(&mut self.config);
                self.listen_text = self.config.listen.to_string();
                self.process_ids_text = process_ids_text(&self.config);
                self.status = Status::Stopped;
                self.push_log("Advanced YAML applied".into());
            }
            Err(error) => self.set_error(format!("Invalid YAML: {error}")),
        }
    }

    fn start(&mut self) {
        if self.child.is_some() || !self.save_config() {
            return;
        }
        let executable = match service_executable() {
            Ok(path) => path,
            Err(error) => {
                self.set_error(error);
                return;
            }
        };
        let shutdown_file =
            std::env::temp_dir().join(format!("netplus-gui-{}.stop", std::process::id()));
        if let Err(error) = remove_file_if_present(&shutdown_file) {
            self.set_error(format!("Failed to prepare shutdown signal: {error}"));
            return;
        }
        let mut command = Command::new(executable);
        command
            .arg("--config")
            .arg(&self.config_path)
            .arg("--shutdown-file")
            .arg(&shutdown_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        hide_child_console(&mut command);

        match command.spawn() {
            Ok(mut child) => {
                if let Some(stdout) = child.stdout.take() {
                    spawn_log_reader(stdout, self.log_sender.clone());
                }
                if let Some(stderr) = child.stderr.take() {
                    spawn_log_reader(stderr, self.log_sender.clone());
                }
                self.child = Some(child);
                self.shutdown_file = Some(shutdown_file);
                self.status = Status::Running;
                self.push_log("Started netplus service".into());
            }
            Err(error) => self.set_error(format!("Failed to start netplus: {error}")),
        }
    }

    fn test_upstream(&mut self) {
        if matches!(self.upstream_test_status, UpstreamTestStatus::Testing) || !self.save_config() {
            return;
        }
        let executable = match service_executable() {
            Ok(path) => path,
            Err(error) => {
                self.upstream_test_status = UpstreamTestStatus::Error(error);
                return;
            }
        };
        let config_path = self.config_path.clone();
        let sender = self.upstream_test_sender.clone();
        self.upstream_test_status = UpstreamTestStatus::Testing;
        std::thread::spawn(move || {
            let mut command = Command::new(executable);
            command
                .arg("--config")
                .arg(config_path)
                .arg("--test-upstream")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            hide_child_console(&mut command);
            let result = command
                .output()
                .map_err(|error| format!("Failed to run upstream test: {error}"))
                .and_then(|output| {
                    if output.status.success() {
                        let output = String::from_utf8_lossy(&output.stdout);
                        Ok(output.trim().to_owned())
                    } else {
                        let error = String::from_utf8_lossy(&output.stderr);
                        Err(strip_ansi(error.trim()))
                    }
                });
            let _ = sender.send(result);
        });
    }

    fn stop(&mut self) {
        if self.child.is_none() {
            return;
        }
        let Some(shutdown_file) = self.shutdown_file.as_ref() else {
            self.set_error("Failed to stop netplus: shutdown signal is unavailable".into());
            return;
        };
        if let Err(error) = std::fs::write(shutdown_file, b"stop") {
            self.set_error(format!("Failed to stop netplus: {error}"));
            return;
        }
        self.status = Status::Stopping;
        self.push_log("Stopping netplus service and restoring routes".into());
    }

    fn refresh_process(&mut self) {
        if let Ok(result) = self.upstream_test_receiver.try_recv() {
            match result {
                Ok(message) => {
                    self.push_log(message.clone());
                    self.upstream_test_status = UpstreamTestStatus::Success(message);
                }
                Err(error) => {
                    self.push_log(format!("Upstream test failed: {error}"));
                    self.upstream_test_status = UpstreamTestStatus::Error(error);
                }
            }
        }
        while let Ok(line) = self.log_receiver.try_recv() {
            let line = strip_ansi(&line);
            self.record_activity(&line);
            self.push_log(line);
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let was_stopping = matches!(self.status, Status::Stopping);
        match child.try_wait() {
            Ok(Some(status)) => {
                self.child = None;
                self.clear_shutdown_file();
                if status.success() {
                    self.status = Status::Stopped;
                    if was_stopping {
                        self.push_log("Stopped netplus service".into());
                    }
                } else {
                    self.set_error(format!("netplus exited with {status}"));
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.child = None;
                self.clear_shutdown_file();
                self.set_error(format!("Failed to read process status: {error}"));
            }
        }
    }

    fn record_activity(&mut self, line: &str) {
        let state = if line.contains("routing") && line.contains("connection") {
            "Connecting"
        } else if line.contains("connection closed") {
            "Closed"
        } else if line.contains("connection failed") {
            "Failed"
        } else {
            return;
        };
        let target = field_value(line, "target").unwrap_or_else(|| "Unknown".into());
        let process = field_value(line, "process").unwrap_or_else(|| "—".into());
        let action = field_value(line, "action").unwrap_or_else(|| "—".into());
        if self.activity.len() == MAX_ACTIVITY_ROWS {
            self.activity.pop_back();
        }
        self.activity.push_front(Activity {
            process,
            target,
            action,
            state: state.into(),
        });
    }

    fn push_log(&mut self, line: String) {
        if self.log_lines.len() == MAX_LOG_LINES {
            self.log_lines.pop_front();
        }
        self.log_lines.push_back(line);
    }

    fn clear_shutdown_file(&mut self) {
        if let Some(path) = self.shutdown_file.take() {
            let _ = remove_file_if_present(&path);
        }
    }

    fn set_error(&mut self, message: String) {
        self.push_log(message.clone());
        self.status = Status::Error(message);
    }

    fn status_text(&self) -> (&str, Color32) {
        match &self.status {
            Status::Stopped => ("Stopped", Color32::GRAY),
            Status::Running => ("Running", SUCCESS),
            Status::Stopping => ("Stopping", WARNING_TEXT),
            Status::Error(_) => ("Error", ERROR_TEXT),
        }
    }

    fn show_toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(CARD)
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(225, 228, 233))),
            )
            .show(ui, |ui| {
                ui.visuals_mut().override_text_color = Some(TEXT);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(self.selected_view.label())
                            .size(18.0)
                            .strong()
                            .color(TEXT),
                    );
                    ui.separator();
                    let (status, color) = self.status_text();
                    ui.label(RichText::new("●").color(color));
                    ui.label(RichText::new(status).color(color).strong());
                    if let Status::Error(message) = &self.status {
                        ui.label(RichText::new(message).color(ERROR_TEXT));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !self.is_elevated
                            && ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Restart as Administrator")
                                            .color(Color32::WHITE),
                                    )
                                    .fill(Color32::from_rgb(148, 105, 47))
                                    .corner_radius(6),
                                )
                                .clicked()
                        {
                            match restart_as_administrator() {
                                Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                                Err(error) => self.set_error(error),
                            }
                        }
                        ui.add_space(12.0);
                        if ui
                            .add_enabled(
                                matches!(self.status, Status::Running),
                                egui::Button::new("■  Stop")
                                    .fill(ERROR_TEXT)
                                    .corner_radius(6),
                            )
                            .clicked()
                        {
                            self.stop();
                        }
                        if ui
                            .add_enabled(
                                self.child.is_none() && self.is_elevated,
                                egui::Button::new(RichText::new("▶  Start").color(Color32::WHITE))
                                    .fill(ACCENT)
                                    .corner_radius(6),
                            )
                            .clicked()
                        {
                            self.start();
                        }
                    });
                });
            });
    }

    fn show_navigation(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(178.0)
            .frame(
                egui::Frame::new()
                    .fill(SIDEBAR)
                    .inner_margin(egui::Margin::symmetric(12, 12)),
            )
            .show(ui, |ui| {
                ui.visuals_mut().override_text_color = Some(Color32::WHITE);
                ui.horizontal(|ui| {
                    egui::Frame::new()
                        .fill(ACCENT)
                        .corner_radius(7)
                        .inner_margin(egui::Margin::same(7))
                        .show(ui, |ui| {
                            ui.label(RichText::new("N+").strong().color(Color32::WHITE));
                        });
                    ui.label(
                        RichText::new("netplus")
                            .size(18.0)
                            .strong()
                            .color(Color32::WHITE),
                    );
                });
                ui.label(
                    RichText::new("Process Traffic Forwarder")
                        .small()
                        .color(Color32::from_rgb(158, 170, 175)),
                );
                ui.add_space(22.0);
                ui.label(
                    RichText::new("PROFILE")
                        .small()
                        .strong()
                        .color(Color32::GRAY),
                );
                ui.add_space(6.0);
                for view in View::ALL {
                    let selected = self.selected_view == view;
                    let text = format!("{}   {}", view.symbol(), view.label());
                    if ui
                        .add_sized(
                            [154.0, 34.0],
                            egui::Button::selectable(
                                selected,
                                RichText::new(text).size(12.0).color(Color32::WHITE),
                            )
                            .fill(if selected {
                                ACCENT
                            } else {
                                Color32::TRANSPARENT
                            })
                            .stroke(Stroke::NONE)
                            .corner_radius(8),
                        )
                        .clicked()
                    {
                        self.selected_view = view;
                    }
                }
                ui.add_space(18.0);
                ui.separator();
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Configuration")
                        .small()
                        .strong()
                        .color(Color32::GRAY),
                );
                ui.label(
                    RichText::new("config")
                        .monospace()
                        .color(Color32::from_rgb(202, 211, 214)),
                );
                ui.label(
                    RichText::new("Stored beside netplus")
                        .small()
                        .color(Color32::from_rgb(145, 157, 162)),
                );
            });
    }

    fn show_connections(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Connections",
            "Recent connections captured from selected applications.",
        );
        ui.horizontal(|ui| {
            metric_card(ui, "Service", self.status_text().0, self.status_text().1);
            metric_card(
                ui,
                "Recent events",
                &self.activity.len().to_string(),
                ACCENT,
            );
            metric_card(
                ui,
                "Applications",
                &self
                    .config
                    .process_mode
                    .as_ref()
                    .map_or(0, |profile| profile.executable_names.len())
                    .to_string(),
                ACCENT,
            );
        });
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            ui.heading("Connection activity");
            if ui.button("Clear").clicked() {
                self.activity.clear();
            }
        });
        ui.separator();
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("connections_grid")
                    .num_columns(4)
                    .striped(true)
                    .min_col_width(90.0)
                    .show(ui, |ui| {
                        table_header(ui, "Application");
                        table_header(ui, "Destination");
                        table_header(ui, "Route");
                        table_header(ui, "State");
                        ui.end_row();
                        for activity in &self.activity {
                            ui.label(&activity.process);
                            ui.label(&activity.target);
                            ui.label(&activity.action);
                            let color = if activity.state == "Failed" {
                                Color32::RED
                            } else if activity.state == "Closed" {
                                Color32::GRAY
                            } else {
                                SUCCESS
                            };
                            ui.label(RichText::new(&activity.state).color(color));
                            ui.end_row();
                        }
                    });
            });
    }

    fn show_proxy(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Proxy Server",
            "Configure the SOCKS5 server used by proxy routing rules.",
        );
        card(ui, |ui| {
            ui.heading("SOCKS5 upstream");
            ui.add_space(8.0);
            form_row(ui, "Server URL", |ui| {
                ui.add(
                    egui::TextEdit::singleline(
                        self.config
                            .upstream
                            .get_or_insert_with(|| "socks5://127.0.0.1:1081".into()),
                    )
                    .desired_width(300.0)
                    .hint_text("socks5://user:password@host:port"),
                );
            });
            form_row(ui, "Local SOCKS listener", |ui| {
                if ui
                    .add(egui::TextEdit::singleline(&mut self.listen_text).desired_width(200.0))
                    .changed()
                    && let Ok(address) = self.listen_text.parse()
                {
                    self.config.listen = address;
                }
            });
            form_row(ui, "Log level", |ui| {
                egui::ComboBox::from_id_salt("log_level")
                    .selected_text(self.config.log_level.label())
                    .show_ui(ui, |ui| {
                        for level in LogLevel::ALL {
                            ui.selectable_value(&mut self.config.log_level, level, level.label());
                        }
                    });
            });
            form_row(ui, "Public IP check", |ui| {
                if ui
                    .add_enabled(
                        !matches!(self.upstream_test_status, UpstreamTestStatus::Testing),
                        egui::Button::new("Test connection"),
                    )
                    .clicked()
                {
                    self.test_upstream();
                }
                ui.label(
                    RichText::new("via ifconfig.me with automatic fallback")
                        .small()
                        .color(MUTED_TEXT),
                );
            });
            form_row(ui, "Test status", |ui| match &self.upstream_test_status {
                UpstreamTestStatus::Idle => {
                    ui.label(RichText::new("Not tested").color(Color32::GRAY));
                }
                UpstreamTestStatus::Testing => {
                    ui.spinner();
                    ui.label("Connecting through SOCKS5 and checking public IP…");
                }
                UpstreamTestStatus::Success(message) => {
                    ui.label(RichText::new("✓").color(SUCCESS).strong());
                    ui.label(RichText::new(message).color(SUCCESS));
                }
                UpstreamTestStatus::Error(message) => {
                    ui.label(RichText::new("×").color(Color32::RED).strong());
                    ui.label(RichText::new(message).color(ERROR_TEXT));
                }
            });
        });
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "Credentials may be included in the URL. Use percent-encoding for reserved characters.",
            )
            .color(Color32::GRAY),
        );
    }

    fn show_applications(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Traffic Capture",
            "Choose selected-application interception or full-system Wintun routing.",
        );
        egui::ScrollArea::vertical().show(ui, |ui| {
            card(ui, |ui| {
                ui.heading("Capture mode");
                let mut full_system = self.config.tun_mode.is_some();
                let was_full_system = full_system;
                ui.radio_value(&mut full_system, false, "Selected applications");
                ui.radio_value(&mut full_system, true, "Full system (Wintun)");
                if full_system != was_full_system {
                    if full_system {
                        self.config.tun_mode = Some(TunProfile::default());
                        self.config.process_mode = None;
                        self.process_ids_text.clear();
                    } else {
                        self.config.tun_mode = None;
                        self.config.process_mode = Some(ProcessProfile::default());
                    }
                }
                if full_system {
                    ui.label(
                        RichText::new(
                            "Routes system TCP and UDP traffic through the SOCKS5 upstream.",
                        )
                        .small()
                        .color(MUTED_TEXT),
                    );
                }
            });
            ui.add_space(12.0);

            if let Some(profile) = self.config.tun_mode.as_mut() {
                card(ui, |ui| {
                    ui.heading("Wintun settings");
                    form_row(ui, "Interface name", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut profile.interface_name)
                                .desired_width(220.0),
                        );
                    });
                    form_row(ui, "MTU", |ui| {
                        ui.add(egui::DragValue::new(&mut profile.mtu).range(576..=9000));
                    });
                    form_row(ui, "Maximum sessions", |ui| {
                        ui.add(
                            egui::DragValue::new(&mut profile.max_sessions)
                                .range(1..=1_000_000),
                        );
                    });
                    form_row(ui, "IPv6", |ui| {
                        ui.add_enabled(
                            false,
                            egui::Checkbox::new(&mut profile.ipv6, "Not supported yet"),
                        );
                    });
                    ui.label(
                        RichText::new(
                            "wintun.dll must be beside netplus.exe. Stop netplus gracefully so routes and DNS are restored.",
                        )
                        .small()
                        .color(WARNING_TEXT),
                    );
                });
                return;
            }

            let profile = self
                .config
                .process_mode
                .get_or_insert_with(ProcessProfile::default);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Process targets");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("+ Add application").clicked() {
                            profile.executable_names.push("application.exe".into());
                        }
                    });
                });
                ui.horizontal(|ui| {
                    ui.label("Interception backend");
                    let previous_backend = profile.backend;
                    egui::ComboBox::from_id_salt("process_backend")
                        .selected_text(match profile.backend {
                            ProcessBackend::Windivert => "WinDivert",
                            ProcessBackend::Netch => "Netch (local test)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut profile.backend,
                                ProcessBackend::Windivert,
                                "WinDivert",
                            );
                            ui.selectable_value(
                                &mut profile.backend,
                                ProcessBackend::Netch,
                                "Netch (local test)",
                            );
                        });
                    if previous_backend != profile.backend
                        && profile.backend == ProcessBackend::Netch
                    {
                        profile.process_ids.clear();
                        self.process_ids_text.clear();
                    }
                });
                if profile.backend == ProcessBackend::Netch {
                    ui.horizontal(|ui| {
                        ui.label("Runtime directory");
                        let mut runtime = profile.netch_runtime_dir.to_string_lossy().into_owned();
                        if ui
                            .add(egui::TextEdit::singleline(&mut runtime).desired_width(250.0))
                            .changed()
                        {
                            profile.netch_runtime_dir = PathBuf::from(runtime);
                        }
                    });
                }
                ui.add_space(8.0);
                egui::Grid::new("applications_grid")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        table_header(ui, "Executable name");
                        table_header(ui, "Type");
                        ui.label("");
                        ui.end_row();
                        let mut remove = None;
                        for (index, name) in profile.executable_names.iter_mut().enumerate() {
                            ui.add(egui::TextEdit::singleline(name).desired_width(250.0));
                            ui.label("Executable");
                            if ui.small_button("Remove").clicked() {
                                remove = Some(index);
                            }
                            ui.end_row();
                        }
                        if let Some(index) = remove {
                            profile.executable_names.remove(index);
                        }
                    });
                ui.add_space(10.0);
                ui.checkbox(
                    &mut profile.bypass_private,
                    "Bypass localhost, LAN, link-local, and shared-network destinations",
                );
                ui.label(
                    RichText::new(
                        "Recommended for launchers and games that communicate with local helper services.",
                    )
                    .small()
                    .color(MUTED_TEXT),
                );
            });
            ui.add_space(12.0);
            card(ui, |ui| {
                ui.heading("Explicit process IDs");
                ui.add_enabled_ui(profile.backend == ProcessBackend::Windivert, |ui| {
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.process_ids_text)
                                .desired_width(320.0)
                                .hint_text("1234, 5678"),
                        )
                        .changed()
                        && let Ok(process_ids) = parse_process_ids(&self.process_ids_text)
                    {
                        profile.process_ids = process_ids;
                    }
                });
                if profile.backend == ProcessBackend::Netch {
                    ui.label(
                        RichText::new("Process IDs are unavailable with the Netch test backend.")
                            .small()
                            .color(MUTED_TEXT),
                    );
                }
            });
        });
    }

    fn show_rules(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Routing Rules",
            "Rules are evaluated from top to bottom. Process-mode traffic supports CIDR matching.",
        );
        ui.horizontal(|ui| {
            ui.label("Default action:");
            action_combo(ui, "default_action", &mut self.config.routing.default);
            ui.separator();
            if ui.button("+ Add rule").clicked() {
                self.config.routing.rules.push(RouteRule::default());
            }
        });
        ui.add_space(12.0);
        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("rules_grid")
                .num_columns(5)
                .striped(true)
                .min_col_width(100.0)
                .show(ui, |ui| {
                    table_header(ui, "#");
                    table_header(ui, "Action");
                    table_header(ui, "Domains");
                    table_header(ui, "CIDR networks");
                    ui.label("");
                    ui.end_row();
                    let mut remove = None;
                    let mut move_rule = None;
                    let rule_count = self.config.routing.rules.len();
                    for (index, rule) in self.config.routing.rules.iter_mut().enumerate() {
                        ui.label((index + 1).to_string());
                        action_combo(ui, ("rule_action", index), &mut rule.action);
                        list_editor(
                            ui,
                            &mut rule.domains_text,
                            &mut rule.domains,
                            "*.example.com, localhost",
                        );
                        list_editor(
                            ui,
                            &mut rule.cidrs_text,
                            &mut rule.cidrs,
                            "10.0.0.0/8, 192.168.0.0/16",
                        );
                        ui.horizontal(|ui| {
                            if ui.add_enabled(index > 0, egui::Button::new("↑")).clicked() {
                                move_rule = Some((index, index - 1));
                            }
                            if ui
                                .add_enabled(index + 1 < rule_count, egui::Button::new("↓"))
                                .clicked()
                            {
                                move_rule = Some((index, index + 1));
                            }
                            if ui.small_button("×").clicked() {
                                remove = Some(index);
                            }
                        });
                        ui.end_row();
                    }
                    if let Some((from, to)) = move_rule {
                        self.config.routing.rules.swap(from, to);
                    }
                    if let Some(index) = remove {
                        self.config.routing.rules.remove(index);
                    }
                });
        });
    }

    fn show_log(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Event Log",
            "Diagnostic output from the forwarding service.",
        );
        ui.horizontal(|ui| {
            if ui.button("Clear log").clicked() {
                self.log_lines.clear();
            }
            ui.label(RichText::new(format!("{} lines", self.log_lines.len())).color(Color32::GRAY));
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log_lines {
                    let color = if line.contains("ERROR") || line.contains("failed") {
                        ERROR_TEXT
                    } else if line.contains("WARN") {
                        WARNING_TEXT
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.label(RichText::new(line).monospace().color(color));
                }
            });
    }

    fn show_advanced(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Advanced YAML",
            "Direct profile editing for settings not exposed elsewhere.",
        );
        ui.horizontal(|ui| {
            if ui.button("Refresh from profile").clicked()
                && let Ok(yaml) = serialize_profile(&self.config)
            {
                self.yaml_text = yaml;
            }
            if ui.button("Apply YAML").clicked() {
                self.apply_yaml();
            }
        });
        ui.add_space(8.0);
        let editor_size = egui::vec2(ui.available_width(), ui.available_height().max(120.0));
        ui.add_sized(
            editor_size,
            egui::TextEdit::multiline(&mut self.yaml_text)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY),
        );
    }
}

impl eframe::App for NetplusApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.refresh_process();
        if self.child.is_some() || matches!(self.upstream_test_status, UpstreamTestStatus::Testing)
        {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }

        self.show_navigation(ui);
        self.show_toolbar(ui);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(WORKSPACE)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ui, |ui| {
                if !self.is_elevated {
                    elevation_warning(ui);
                    ui.add_space(14.0);
                }
                match self.selected_view {
                    View::Connections => self.show_connections(ui),
                    View::Proxy => self.show_proxy(ui),
                    View::Applications => self.show_applications(ui),
                    View::Rules => self.show_rules(ui),
                    View::Log => self.show_log(ui),
                    View::Advanced => self.show_advanced(ui),
                }
            });
    }
}

impl Drop for NetplusApp {
    fn drop(&mut self) {
        if let Some(path) = self.shutdown_file.as_ref() {
            let _ = std::fs::write(path, b"stop");
        }
        if let Some(child) = self.child.as_mut() {
            let _ = wait_for_child_shutdown(child);
        }
        self.clear_shutdown_file();
    }
}

fn wait_for_child_shutdown(child: &mut Child) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "netplus did not stop within 60 seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn configure_style(context: &egui::Context) {
    context.set_theme(egui::Theme::Light);
    let mut style = (*context.style_of(egui::Theme::Light)).clone();
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(18.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(12.5));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(12.5));
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(10.5));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(11.5));
    style.spacing.item_spacing = egui::vec2(7.0, 7.0);
    style.spacing.button_padding = egui::vec2(9.0, 5.0);
    style.visuals.widgets.active.bg_fill = ACCENT;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(220, 235, 238);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    style.visuals.selection.bg_fill = ACCENT;
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT_DARK);
    style.visuals.panel_fill = WORKSPACE;
    style.visuals.window_fill = CARD;
    style.visuals.override_text_color = Some(TEXT);
    context.set_style_of(egui::Theme::Light, style);
}

fn page_header(ui: &mut egui::Ui, title: &str, description: &str) {
    ui.heading(RichText::new(title).size(20.0));
    ui.label(RichText::new(description).color(MUTED_TEXT));
    ui.add_space(18.0);
}

fn elevation_warning(ui: &mut egui::Ui) {
    egui::Frame::new()
        .fill(Color32::from_rgb(255, 245, 220))
        .stroke(Stroke::new(1.0, Color32::from_rgb(225, 170, 70)))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("!").size(16.0).strong().color(WARNING_TEXT));
                ui.vertical(|ui| {
                    ui.label(RichText::new("Administrator privileges required").strong());
                    ui.label(
                        RichText::new(
                            "Process interception is disabled. Use “Restart as Administrator” above.",
                        )
                        .color(MUTED_TEXT),
                    );
                });
            });
        });
}

fn card(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, Color32::from_rgb(226, 230, 235)))
        .corner_radius(12)
        .inner_margin(egui::Margin::same(12))
        .show(ui, contents);
}

fn metric_card(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, Color32::from_rgb(226, 230, 235)))
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_min_width(110.0);
            ui.label(RichText::new(label).color(MUTED_TEXT));
            ui.label(RichText::new(value).size(16.0).strong().color(color));
        });
}

fn table_header(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).strong().color(TEXT));
}

fn form_row(ui: &mut egui::Ui, label: &str, contents: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.set_min_height(32.0);
        ui.add_sized([125.0, 24.0], egui::Label::new(label));
        contents(ui);
    });
}

fn action_combo(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    action: &mut RouteAction,
) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(RichText::new(action.label()).color(action.color()))
        .show_ui(ui, |ui| {
            for candidate in RouteAction::ALL {
                ui.selectable_value(action, candidate, candidate.label());
            }
        });
}

fn list_editor(ui: &mut egui::Ui, text: &mut String, values: &mut Vec<String>, hint: &str) {
    if ui
        .add(
            egui::TextEdit::singleline(text)
                .desired_width(200.0)
                .hint_text(hint),
        )
        .changed()
    {
        *values = split_values(text);
    }
}

fn split_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_process_ids(value: &str) -> Result<Vec<u32>, String> {
    split_values(value)
        .into_iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("Invalid process ID: {value}"))
        })
        .collect()
}

fn prepare_rule_editors(profile: &mut Profile) {
    for rule in &mut profile.routing.rules {
        rule.domains_text = rule.domains.join(", ");
        rule.cidrs_text = rule.cidrs.join(", ");
    }
}

fn process_ids_text(profile: &Profile) -> String {
    profile
        .process_mode
        .as_ref()
        .map(|processes| {
            processes
                .process_ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn field_value(line: &str, field: &str) -> Option<String> {
    let marker = format!("{field}=");
    let start = line.find(&marker)? + marker.len();
    let value = line[start..].split_whitespace().next()?;
    Some(value.trim_matches('"').to_owned())
}

fn strip_ansi(value: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Text,
        Escape,
        ControlSequence,
    }

    let mut state = State::Text;
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        state = match state {
            State::Text if character == '\u{1b}' => State::Escape,
            State::Text => {
                output.push(character);
                State::Text
            }
            State::Escape if character == '[' => State::ControlSequence,
            State::Escape => State::Text,
            State::ControlSequence if ('@'..='~').contains(&character) => State::Text,
            State::ControlSequence => State::ControlSequence,
        };
    }
    output
}

fn read_profile(path: &Path) -> Result<(Profile, String, Status), String> {
    let yaml = match std::fs::read_to_string(path) {
        Ok(yaml) => yaml,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let profile = Profile::default();
            let yaml = serialize_profile(&profile)?;
            std::fs::write(path, &yaml)
                .map_err(|error| format!("Failed to create {}: {error}", path.display()))?;
            yaml
        }
        Err(error) => return Err(format!("Failed to load {}: {error}", path.display())),
    };
    let profile = serde_yaml::from_str(&yaml)
        .map_err(|error| format!("Invalid profile {}: {error}", path.display()))?;
    Ok((profile, yaml, Status::Stopped))
}

fn serialize_profile(profile: &Profile) -> Result<String, String> {
    serde_yaml::to_string(profile).map_err(|error| format!("Failed to serialize profile: {error}"))
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:1080".parse().expect("valid listen address")
}

fn default_route() -> RouteAction {
    RouteAction::Proxy
}

fn default_true() -> bool {
    true
}

fn default_netch_runtime_dir() -> PathBuf {
    PathBuf::from("netch")
}

fn default_tun_interface_name() -> String {
    "netplus".into()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_max_sessions() -> usize {
    1024
}

fn default_config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_owned))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("config")
}

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn service_executable() -> Result<PathBuf, String> {
    let directory = std::env::current_exe()
        .map_err(|error| format!("Cannot locate the GUI executable: {error}"))?
        .parent()
        .map(Path::to_owned)
        .ok_or_else(|| "Cannot locate the application directory".to_owned())?;
    let executable = directory.join(if cfg!(windows) {
        "netplus.exe"
    } else {
        "netplus"
    });
    executable
        .is_file()
        .then_some(executable)
        .ok_or_else(|| "netplus service executable is missing beside the GUI".to_owned())
}

fn spawn_log_reader(reader: impl Read + Send + 'static, sender: Sender<String>) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(format!("Failed to read service output: {error}"));
                    return;
                }
            }
        }
    });
}

#[cfg(windows)]
fn hide_child_console(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
}

#[cfg(not(windows))]
fn hide_child_console(_command: &mut Command) {}

#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

#[cfg(windows)]
fn restart_as_administrator() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::{iter, ptr};
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let executable = std::env::current_exe()
        .map_err(|error| format!("Cannot locate the GUI executable: {error}"))?;
    let verb = "runas"
        .encode_utf16()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let executable = executable
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            executable.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        Err(format!(
            "Windows elevation request failed with code {}",
            result as isize
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn restart_as_administrator() -> Result<(), String> {
    Err("Administrator restart is only available on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_round_trip_preserves_rules() {
        let profile: Profile = serde_yaml::from_str(
            "upstream: socks5://127.0.0.1:1081\nrouting:\n  default: proxy\n  rules:\n    - action: direct\n      cidrs: [10.0.0.0/8]\n",
        )
        .unwrap();
        let serialized = serialize_profile(&profile).unwrap();
        let restored: Profile = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(restored.routing.rules[0].action, RouteAction::Direct);
    }

    #[test]
    fn extracts_activity_fields() {
        let line =
            "DEBUG routing process connection process=game.exe target=example.com:443 action=Proxy";
        assert_eq!(field_value(line, "process").as_deref(), Some("game.exe"));
        assert_eq!(
            field_value(line, "target").as_deref(),
            Some("example.com:443")
        );
        assert_eq!(field_value(line, "action").as_deref(), Some("Proxy"));
    }

    #[test]
    fn removes_terminal_color_sequences() {
        let colored = "\u{1b}[2m2026-10-08\u{1b}[0m \u{1b}[34mDEBUG\u{1b}[0m connection";
        assert_eq!(strip_ansi(colored), "2026-10-08 DEBUG connection");
    }

    #[test]
    fn rejects_invalid_process_ids() {
        assert_eq!(parse_process_ids("1234, 5678").unwrap(), [1234, 5678]);
        assert_eq!(
            parse_process_ids("1234, invalid").unwrap_err(),
            "Invalid process ID: invalid"
        );
    }
}
