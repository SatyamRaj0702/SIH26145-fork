from __future__ import annotations

import os
from typing import Any

from .schemas import Alert


class AppwriteAlertSink:
    """Optional application sink; detection remains local if Appwrite is unavailable."""

    def __init__(self) -> None:
        self.endpoint = os.getenv("APPWRITE_ENDPOINT")
        self.project_id = os.getenv("APPWRITE_PROJECT_ID")
        self.database_id = os.getenv("APPWRITE_DATABASE_ID")
        self.collection_id = os.getenv("APPWRITE_ALERTS_COLLECTION_ID")
        self.api_key = os.getenv("APPWRITE_API_KEY")
        self.enabled = all(
            [self.endpoint, self.project_id, self.database_id, self.collection_id, self.api_key]
        )
        self.persisted_count = 0
        self.last_error: str | None = None
        self._databases: Any = None
        if self.enabled:
            try:
                from appwrite.client import Client
                from appwrite.services.databases import Databases
            except ImportError:
                self.enabled = False
                self.last_error = "appwrite SDK not installed; install backend[appwrite]"
                return

            client = Client()
            client.set_endpoint(self.endpoint)
            client.set_project(self.project_id)
            client.set_key(self.api_key)
            self._databases = Databases(client)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "persisted_count": self.persisted_count,
            "last_error": self.last_error,
        }

    def persist(self, alert: Alert) -> bool:
        if not self.enabled:
            return False
        data = alert.model_dump(mode="json")
        self._databases.create_document(
            database_id=self.database_id,
            collection_id=self.collection_id,
            document_id=alert.alert_id,
            data=data,
        )
        self.persisted_count += 1
        return True
