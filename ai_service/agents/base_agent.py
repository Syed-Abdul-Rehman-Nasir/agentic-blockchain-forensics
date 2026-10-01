"""Shared agent interface: checkpointing helpers and abstract analyse()."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, List

from ai_service.db.database import (
    get_completed_stages as db_get_completed_stages,
)
from ai_service.db.database import get_connection
from ai_service.db.database import log_audit
from ai_service.db.database import (
    mark_stage_complete as db_mark_stage_complete,
)


class BaseAgent(ABC):
    """Common checkpointing and audit helpers for all forensic agents."""

    def mark_stage_complete(
        self,
        case_id: str,
        stage_name: str,
        conn=None,
    ) -> None:
        db_mark_stage_complete(case_id, stage_name, conn=conn)

    def get_completed_stages(self, case_id: str, conn=None) -> List[str]:
        return db_get_completed_stages(case_id, conn=conn)

    def log_action(
        self,
        case_id: str,
        action: str,
        details: str,
        conn=None,
    ) -> None:
        log_audit(case_id, action, details, conn=conn)

    def _conn(self, conn=None):
        """Return an open connection; caller owns close if we opened it."""
        if conn is not None:
            return conn, False
        return get_connection(), True

    @abstractmethod
    def analyse(self, *args: Any, **kwargs: Any) -> Any:
        """Subclasses implement their analysis pipeline."""
        raise NotImplementedError
