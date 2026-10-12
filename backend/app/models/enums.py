from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"
    RECON_ONLY = "recon_only"
    VULN_SCAN = "vuln_scan"
    WORKFLOW = "workflow"


class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
