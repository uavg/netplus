use std::net::IpAddr;

use anyhow::Context;
use ipnet::IpNet;
use serde::Deserialize;

use crate::socks5::Target;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Direct,
    #[default]
    Proxy,
    Block,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub action: Action,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Router {
    default: Action,
    rules: Vec<CompiledRule>,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    action: Action,
    domains: Vec<String>,
    networks: Vec<IpNet>,
}

impl Router {
    pub fn new(default: Action, rules: &[Rule]) -> anyhow::Result<Self> {
        let rules = rules
            .iter()
            .map(CompiledRule::try_from)
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { default, rules })
    }

    pub fn action_for(&self, target: &Target) -> Action {
        self.rules
            .iter()
            .find(|rule| rule.matches(target))
            .map_or(self.default, |rule| rule.action)
    }
}

impl TryFrom<&Rule> for CompiledRule {
    type Error = anyhow::Error;

    fn try_from(rule: &Rule) -> Result<Self, Self::Error> {
        let networks = rule
            .cidrs
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNet>()
                    .with_context(|| format!("invalid routing CIDR {cidr}"))
            })
            .collect::<anyhow::Result<_>>()?;
        let domains = rule
            .domains
            .iter()
            .map(|domain| domain.trim_start_matches("*.").to_ascii_lowercase())
            .collect();
        Ok(Self {
            action: rule.action,
            domains,
            networks,
        })
    }
}

impl CompiledRule {
    fn matches(&self, target: &Target) -> bool {
        match target {
            Target::Ip(ip, _) => self.matches_ip(*ip),
            Target::Domain(domain, _) => self.matches_domain(domain),
        }
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|network| network.contains(&ip))
    }

    fn matches_domain(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.domains
            .iter()
            .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: Action, domains: &[&str], cidrs: &[&str]) -> Rule {
        Rule {
            action,
            domains: domains.iter().map(|value| (*value).to_owned()).collect(),
            cidrs: cidrs.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    #[test]
    fn uses_first_matching_rule() {
        let router = Router::new(
            Action::Proxy,
            &[
                rule(Action::Block, &["ads.example"], &[]),
                rule(Action::Direct, &["example"], &[]),
            ],
        )
        .unwrap();

        assert_eq!(
            router.action_for(&Target::Domain("ads.example".into(), 443)),
            Action::Block
        );
        assert_eq!(
            router.action_for(&Target::Domain("www.example".into(), 443)),
            Action::Direct
        );
    }

    #[test]
    fn matches_ip_networks() {
        let router =
            Router::new(Action::Proxy, &[rule(Action::Direct, &[], &["10.0.0.0/8"])]).unwrap();
        let target = Target::Ip("10.2.3.4".parse().unwrap(), 80);
        assert_eq!(router.action_for(&target), Action::Direct);
    }
}
