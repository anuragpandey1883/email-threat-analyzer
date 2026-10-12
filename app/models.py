from pydantic import BaseModel, Field
from typing import Optional, Any

class Finding(BaseModel):
    severity: str
    title: str
    detail: str

class URLResult(BaseModel):
    url: str
    normalized_url: str
    visible_text: Optional[str] = None
    link_mismatch: bool = False
    indicators: list[str] = Field(default_factory=list)
    dns: dict[str, Any] = Field(default_factory=dict)
    reputation: dict[str, Any] = Field(default_factory=dict)

class YaraMatch(BaseModel):
    rule: str
    tags: list[str] = Field(default_factory=list)

class AttachmentResult(BaseModel):
    filename: str
    mime_type: str
    size: int
    sha256: str
    detected_type: str
    indicators: list[str] = Field(default_factory=list)
    yara_matches: list[YaraMatch] = Field(default_factory=list)
    document_analysis: dict[str, Any] = Field(default_factory=dict)
    archive_analysis: dict[str, Any] = Field(default_factory=dict)

class AnalysisResult(BaseModel):
    risk_level: str
    risk_score: int
    confidence: str
    assessment_note: str
    sender: dict
    authentication: dict
    received_chain: list[dict]
    urls: list[URLResult]
    attachments: list[AttachmentResult]
    findings: list[Finding]
