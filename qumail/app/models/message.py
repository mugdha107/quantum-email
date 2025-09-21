from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class OutgoingMessage:
    sender: str
    recipients: List[str]
    subject: str
    body_text: str
    attachments: List[Tuple[str, bytes]] = field(default_factory=list)
    level: int = 4
