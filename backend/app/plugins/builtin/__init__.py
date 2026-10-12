"""
SOCIS-AI-PT — Builtin Plugin Registry
All 12 pre-built enterprise integrations.
"""

from app.plugins.builtin.jira_plugin import JiraPlugin, PLUGIN_META as JIRA_META
from app.plugins.builtin.slack_plugin import SlackPlugin, PLUGIN_META as SLACK_META
from app.plugins.builtin.teams_plugin import TeamsPlugin, PLUGIN_META as TEAMS_META
from app.plugins.builtin.pagerduty_plugin import PagerDutyPlugin, PLUGIN_META as PAGERDUTY_META
from app.plugins.builtin.servicenow_plugin import ServiceNowPlugin, PLUGIN_META as SERVICENOW_META
from app.plugins.builtin.splunk_plugin import SplunkPlugin, PLUGIN_META as SPLUNK_META
from app.plugins.builtin.elastic_plugin import ElasticPlugin, PLUGIN_META as ELASTIC_META
from app.plugins.builtin.sentinel_plugin import SentinelPlugin, PLUGIN_META as SENTINEL_META
from app.plugins.builtin.defectdojo_plugin import DefectDojoPlugin, PLUGIN_META as DEFECTDOJO_META
from app.plugins.builtin.thehive_plugin import TheHivePlugin, PLUGIN_META as THEHIVE_META
from app.plugins.builtin.virustotal_plugin import VirusTotalPlugin, PLUGIN_META as VIRUSTOTAL_META
from app.plugins.builtin.webhook_plugin import CustomWebhookPlugin, PLUGIN_META as WEBHOOK_META

# Registry: plugin_id → (class, metadata)
BUILTIN_REGISTRY: dict[str, tuple] = {
    "jira":           (JiraPlugin,           JIRA_META),
    "slack":          (SlackPlugin,          SLACK_META),
    "teams":          (TeamsPlugin,          TEAMS_META),
    "pagerduty":      (PagerDutyPlugin,      PAGERDUTY_META),
    "servicenow":     (ServiceNowPlugin,     SERVICENOW_META),
    "splunk_hec":     (SplunkPlugin,         SPLUNK_META),
    "elastic":        (ElasticPlugin,        ELASTIC_META),
    "sentinel":       (SentinelPlugin,       SENTINEL_META),
    "defectdojo":     (DefectDojoPlugin,     DEFECTDOJO_META),
    "thehive":        (TheHivePlugin,        THEHIVE_META),
    "virustotal":     (VirusTotalPlugin,     VIRUSTOTAL_META),
    "custom_webhook": (CustomWebhookPlugin,  WEBHOOK_META),
}


def get_plugin_class(plugin_id: str):
    """Return the plugin class for the given plugin_id, or None."""
    entry = BUILTIN_REGISTRY.get(plugin_id)
    return entry[0] if entry else None


def get_plugin_meta(plugin_id: str) -> dict | None:
    """Return the metadata dict for the given plugin_id, or None."""
    entry = BUILTIN_REGISTRY.get(plugin_id)
    return entry[1] if entry else None


def get_all_plugin_ids() -> list[str]:
    return list(BUILTIN_REGISTRY.keys())
