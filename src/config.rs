use std::{
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use url::Url;

use crate::router::{Action, Router, Rule};

const DEFAULT_CONFIG: &str = "\
listen: 127.0.0.1:1080
log_level: info
upstream: socks5://127.0.0.1:1081

routing:
  default: proxy
  rules: []
";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub log_level: LogLevel,
    pub upstream: Option<String>,
    #[serde(default)]
    pub routing: RoutingConfig,
    pub process_mode: Option<ProcessModeConfig>,
    pub tun_mode: Option<TunModeConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn filter(self) -> &'static str {
        match self {
            Self::Trace => "netplus=trace",
            Self::Debug => "netplus=debug",
            Self::Info => "netplus=info",
            Self::Warn => "netplus=warn",
            Self::Error => "netplus=error",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessModeConfig {
    #[serde(default)]
    pub backend: ProcessBackend,
    #[serde(default = "default_netch_runtime_dir")]
    pub netch_runtime_dir: PathBuf,
    #[serde(default)]
    pub executable_names: Vec<String>,
    #[serde(default)]
    pub process_ids: Vec<u32>,
    #[serde(default = "default_true")]
    pub bypass_private: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProcessBackend {
    #[default]
    Windivert,
    Netch,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunModeConfig {
    #[serde(default = "default_tun_name")]
    pub interface_name: String,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(default = "default_tun_sessions")]
    pub max_sessions: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_action")]
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default: default_action(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    pub async fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = match tokio::fs::read_to_string(path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                tokio::fs::write(path, DEFAULT_CONFIG).await?;
                DEFAULT_CONFIG.to_owned()
            }
            Err(error) => return Err(error.into()),
        };
        let mut config: Self = serde_yaml::from_str(&contents)?;
        config.resolve_paths(path);
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn router(&self) -> anyhow::Result<Router> {
        Router::new(self.routing.default, &self.routing.rules)
    }

    pub(crate) fn upstream(&self) -> anyhow::Result<Option<Upstream>> {
        self.upstream.as_deref().map(Upstream::parse).transpose()
    }

    fn validate(&self) -> anyhow::Result<()> {
        let upstream = self.upstream()?;
        ensure!(
            self.routing.default != Action::Proxy || upstream.is_some(),
            "an upstream is required when the default action is proxy"
        );
        ensure!(
            !self
                .routing
                .rules
                .iter()
                .any(|rule| rule.action == Action::Proxy)
                || upstream.is_some(),
            "an upstream is required by proxy routing rules"
        );
        self.router()?;
        ensure!(
            self.process_mode.is_none() || self.tun_mode.is_none(),
            "process_mode and tun_mode cannot be enabled together"
        );
        if let Some(process_mode) = &self.process_mode {
            ensure!(
                !process_mode.executable_names.is_empty() || !process_mode.process_ids.is_empty(),
                "process_mode requires at least one executable name or process ID"
            );
            ensure!(
                process_mode
                    .executable_names
                    .iter()
                    .all(|name| !name.trim().is_empty()),
                "process executable names must not be empty"
            );
            if process_mode.backend == ProcessBackend::Netch {
                ensure!(
                    process_mode.process_ids.is_empty(),
                    "the experimental Netch backend does not support process_ids; use executable_names"
                );
            }
        }
        if let Some(tun_mode) = &self.tun_mode {
            ensure!(upstream.is_some(), "tun_mode requires a SOCKS5 upstream");
            ensure!(
                !tun_mode.ipv6,
                "tun_mode.ipv6 is not supported on Windows yet"
            );
            ensure!(
                !tun_mode.interface_name.trim().is_empty(),
                "tun_mode interface_name must not be empty"
            );
            ensure!(
                tun_mode
                    .interface_name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric()
                        || matches!(character, '-' | '_' | '.')),
                "tun_mode interface_name may only contain ASCII letters, numbers, '-', '_', or '.'"
            );
            ensure!(
                (576..=9000).contains(&tun_mode.mtu),
                "tun_mode MTU must be between 576 and 9000"
            );
            ensure!(
                tun_mode.max_sessions > 0,
                "tun_mode max_sessions must be greater than zero"
            );
        }
        Ok(())
    }

    fn resolve_paths(&mut self, config_path: &Path) {
        let Some(process_mode) = self.process_mode.as_mut() else {
            return;
        };
        if process_mode.netch_runtime_dir.is_relative() {
            let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
            process_mode.netch_runtime_dir = parent.join(&process_mode.netch_runtime_dir);
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Upstream {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Upstream {
    fn parse(value: &str) -> anyhow::Result<Self> {
        let url = Url::parse(value).context("upstream must be a valid socks5 URL")?;
        ensure!(url.scheme() == "socks5", "upstream scheme must be socks5");
        ensure!(
            url.path().is_empty() || url.path() == "/",
            "upstream URL must not contain a path"
        );
        ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "upstream URL must not contain a query or fragment"
        );
        let host = url
            .host_str()
            .context("upstream host is missing")?
            .to_owned();
        let username = (!url.username().is_empty())
            .then(|| decode_credential(url.username()))
            .transpose()?;
        let password = url.password().map(decode_credential).transpose()?;
        ensure!(
            username.is_some() || password.is_none(),
            "upstream password requires a username"
        );

        Ok(Self {
            host,
            port: url.port().unwrap_or(1080),
            username,
            password,
        })
    }
}

fn decode_credential(value: &str) -> anyhow::Result<String> {
    percent_decode_str(value)
        .decode_utf8()
        .context("upstream credentials must be valid UTF-8")
        .map(|value| value.into_owned())
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:1080"
        .parse()
        .expect("valid default listen address")
}

fn default_action() -> Action {
    Action::Proxy
}

fn default_true() -> bool {
    true
}

fn default_netch_runtime_dir() -> PathBuf {
    PathBuf::from("netch")
}

fn default_tun_name() -> String {
    "netplus".into()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_sessions() -> usize {
    1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_proxy_configuration_without_upstream() {
        let config: Config = serde_yaml::from_str("routing:\n  default: proxy\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_authenticated_upstream() {
        let upstream = Upstream::parse("socks5://al%40ice:s%2Fecret@proxy.example:1081").unwrap();
        assert_eq!(upstream.host, "proxy.example");
        assert_eq!(upstream.port, 1081);
        assert_eq!(upstream.username.as_deref(), Some("al@ice"));
        assert_eq!(upstream.password.as_deref(), Some("s/ecret"));
    }

    #[test]
    fn rejects_unknown_log_level() {
        let result = serde_yaml::from_str::<Config>(
            "log_level: verbose\nupstream: socks5://127.0.0.1:1080\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_process_ids_for_netch_backend() {
        let config: Config = serde_yaml::from_str(
            "upstream: socks5://127.0.0.1:1080\n\
             process_mode:\n  backend: netch\n  process_ids: [42]\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_process_and_tun_modes_together() {
        let config: Config = serde_yaml::from_str(
            "upstream: socks5://127.0.0.1:1080\n\
             process_mode:\n  executable_names: [game.exe]\n\
             tun_mode:\n  interface_name: netplus\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validates_tun_mode() {
        let config: Config = serde_yaml::from_str(
            "upstream: socks5://127.0.0.1:1080\n\
             tun_mode:\n  interface_name: netplus\n  mtu: 1500\n",
        )
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_unsafe_tun_interface_name() {
        let config: Config = serde_yaml::from_str(
            "upstream: socks5://127.0.0.1:1080\n\
             tun_mode:\n  interface_name: \"netplus'; Remove-NetRoute\"\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }
}
