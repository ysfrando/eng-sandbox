from typing import Optional
import charset
from dataclasses import dataclass
from enum import Enum

class ValidationStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"

@dataclass
class ValidationResult:
    status: ValidationStatus
    message: Optional[str] = None

class DocumentValidator:
